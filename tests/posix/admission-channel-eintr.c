/* Deterministic host I/O interruptions; no TCP or map policy is emulated. */
#define _GNU_SOURCE
#include "../check.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long interrupt_number;
static unsigned interrupt_budget, interrupt_count;

static int interrupt_io(long number)
{
    if (number != interrupt_number || !interrupt_budget) return 0;
    --interrupt_budget;
    ++interrupt_count;
    errno = EINTR;
    return 1;
}

/* Interpose only this source's syscall sites. Uninterrupted operations use
 * real SOCK_SEQPACKET I/O and real SCM_CREDENTIALS/pidfd authentication. */
#define syscall(number, ...) (interrupt_io(number) ? -1L : syscall(number, __VA_ARGS__))
#include "../../src/posix/ff-admission-channel.c"
#undef syscall

static unsigned admits, revokes;
static int active(void *context) { (void)context; return 1; }
static int map_admit(const struct ker_ff_admission_key *key, int *created, void *context)
{
    (void)context;
    CHECK(key->source_port == 1234);
    ++admits;
    *created = 1;
    return 1;
}
static int map_revoke(const struct ker_ff_admission_key *key, void *context)
{
    (void)context;
    CHECK(key->source_port == 1234);
    ++revokes;
    return 1;
}
static void interrupt_next(long number, unsigned count)
{
    CHECK(!interrupt_budget);
    interrupt_number = number;
    interrupt_budget = count;
}

int main(void)
{
    int endpoints[2];
    CHECK(!ker_ff_admission_channel_pair(endpoints));
    struct ker_ff_admission_channel *controller = NULL, *owner = NULL;
    CHECK(!ker_ff_admission_channel_open(endpoints[0], getpid(), getuid(), getgid(), 1, &controller));
    CHECK(!ker_ff_admission_channel_open(endpoints[1], getpid(), getuid(), getgid(), 1, &owner));
    const struct ker_ff_admission_map_ops ops = {.active = active, .admit = map_admit, .revoke = map_revoke};
    struct ker_ff_admission_result result;
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    struct ker_ff_admission_request request = {.lease = 1, .command_id = 1,
        .deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec + UINT64_C(5000000000),
        .packet_id = 1, .key = {.source_port = 1234, .destination_port = 80}};

    /* One bounded owner step per interruption, with no receive or callback. */
    interrupt_next(SYS_recvmsg, 2);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN);
    CHECK(interrupt_budget == 1 && !admits);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN);
    CHECK(!interrupt_budget && !admits);
    interrupt_next(SYS_sendmsg, 1);
    CHECK(ker_ff_admission_channel_send_admit(controller, &request) == -EAGAIN);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && !admits);
    CHECK(!ker_ff_admission_channel_send_admit(controller, &request));
    interrupt_next(SYS_recvmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && !admits);
    interrupt_next(SYS_sendmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && admits == 1);
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops) && admits == 1);
    interrupt_next(SYS_recvmsg, 1);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == -EAGAIN);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_RESULT);
    CHECK(!result.status && result.allowed == 1 && result.created == 1);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == -EAGAIN);

    interrupt_next(SYS_sendmsg, 1);
    CHECK(ker_ff_admission_channel_send_control(controller, KER_FF_ADMISSION_PREPARE_ACCEPT, 1, 1) == -EAGAIN);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN);
    CHECK(!ker_ff_admission_channel_send_control(controller, KER_FF_ADMISSION_PREPARE_ACCEPT, 1, 1));
    interrupt_next(SYS_sendmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN);
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    interrupt_next(SYS_recvmsg, 1);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == -EAGAIN);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_PREPARED && !result.status);
    CHECK(!ker_ff_admission_channel_send_control(controller, KER_FF_ADMISSION_FINALIZE, 1, 1));
    interrupt_next(SYS_recvmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN);
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_FINALIZED && !result.status);
    CHECK(admits == 1 && !revokes);

    request.command_id = 2; request.packet_id = 2;
    CHECK(!ker_ff_admission_channel_send_admit(controller, &request));
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_RESULT);
    CHECK(!ker_ff_admission_channel_send_control(controller, KER_FF_ADMISSION_CANCEL, 2, 2));
    interrupt_next(SYS_sendmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && revokes == 1);
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops) && revokes == 1);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_CANCELLED && !result.status);
    CHECK(admits == 2 && revokes == 1 && !interrupt_budget && interrupt_count == 11);
    ker_ff_admission_channel_close(controller);
    ker_ff_admission_channel_close(owner);
    close(endpoints[0]); close(endpoints[1]);
    puts("ADMISSION_EINTR_PASS interrupts=11 admits=2 revokes=1");
    return 0;
}
