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
#include <sys/wait.h>
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
static int retire(void *context) { (void)context; return 0; }
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

static void cached_peer_exit(const struct ker_ff_admission_map_ops *ops,
                             struct ker_ff_admission_request request)
{
    int endpoints[2], ready[2], release[2];
    CHECK(!ker_ff_admission_channel_pair(endpoints));
    CHECK(!pipe(ready) && !pipe(release));
    pid_t parent = getpid(), child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(endpoints[0]); close(ready[0]); close(release[1]);
        struct ker_ff_admission_channel *sender = NULL;
        CHECK(!ker_ff_admission_channel_open(endpoints[1], parent, getuid(), getgid(), 1, &sender));
        struct timespec now;
        CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
        request.deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec + UINT64_C(5000000000);
        request.command_id = 1;
        CHECK(!ker_ff_admission_channel_send_admit(sender, &request));
        CHECK(write(ready[1], "R", 1) == 1);
        char byte;
        CHECK(read(release[0], &byte, 1) == 0);
        ker_ff_admission_channel_close(sender);
        _exit(0);
    }
    close(endpoints[1]); close(ready[1]); close(release[0]);
    struct ker_ff_admission_channel *receiver = NULL;
    CHECK(!ker_ff_admission_channel_open(endpoints[0], child, getuid(), getgid(), 1, &receiver));
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'R');
    unsigned before = admits;
    interrupt_next(SYS_poll, 1);
    CHECK(ker_ff_admission_channel_owner_step(receiver, ops) == -EAGAIN && admits == before);
    close(release[1]);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(ker_ff_admission_channel_owner_step(receiver, ops) == -ESRCH && admits == before);
    ker_ff_admission_channel_close(receiver);
    close(ready[0]);
}

static void preseal_eof_is_fatal(const struct ker_ff_admission_map_ops *ops)
{
    int endpoints[2];
    CHECK(!ker_ff_admission_channel_pair(endpoints));
    struct ker_ff_admission_channel *controller = NULL, *owner = NULL;
    CHECK(!ker_ff_admission_channel_open(endpoints[0], getpid(), getuid(), getgid(), 9, &controller));
    CHECK(!ker_ff_admission_channel_open(endpoints[1], getpid(), getuid(), getgid(), 9, &owner));
    CHECK(!ker_ff_admission_channel_send_retire(controller, 1));
    CHECK(!ker_ff_admission_channel_owner_step(owner, ops));
    struct ker_ff_admission_result result;
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_RETIRED);
    CHECK(!result.status && result.lease == 9);
    ker_ff_admission_channel_close(controller);
    CHECK(ker_ff_admission_channel_owner_step(owner, ops) == -ECONNRESET);
    ker_ff_admission_channel_close(owner);
}

int main(void)
{
    int endpoints[2];
    CHECK(!ker_ff_admission_channel_pair(endpoints));
    struct ker_ff_admission_channel *controller = NULL, *owner = NULL;
    CHECK(!ker_ff_admission_channel_open(endpoints[0], getpid(), getuid(), getgid(), 1, &controller));
    CHECK(!ker_ff_admission_channel_open(endpoints[1], getpid(), getuid(), getgid(), 1, &owner));
    const struct ker_ff_admission_map_ops ops = {.active = active, .admit = map_admit,
        .revoke = map_revoke, .retire = retire};
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
    CHECK(ker_ff_admission_channel_send_seal(controller, 99) == -EINVAL);
    interrupt_next(SYS_recvmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && !admits);
    interrupt_next(SYS_poll, 2);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && !admits && interrupt_budget == 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && !admits && !interrupt_budget);
    interrupt_next(SYS_newfstatat, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && !admits);
    interrupt_next(SYS_openat, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && !admits);
    interrupt_next(SYS_sendmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && admits == 1);
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops) && admits == 1);
    interrupt_next(SYS_recvmsg, 1);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == -EAGAIN);
    interrupt_next(SYS_poll, 1);
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
    CHECK(admits == 2 && revokes == 1 && !interrupt_budget && interrupt_count == 16);
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    request.command_id = 3; request.packet_id = 3;
    request.deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec + UINT64_C(50000000);
    CHECK(!ker_ff_admission_channel_send_admit(controller, &request));
    interrupt_next(SYS_poll, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN && admits == 2);
    do {
        struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
        CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    } while ((uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec < request.deadline_ns);
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_RESULT);
    CHECK(result.status == -ETIMEDOUT && !result.allowed && !result.created && admits == 2);
    CHECK(!ker_ff_admission_channel_send_control(controller, KER_FF_ADMISSION_CANCEL, 3, 3));
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_CANCELLED);
    CHECK(!result.status && revokes == 1);

    /* A seal is unavailable before RETIRED, and wrong-lease/replay records
     * cannot detach the owner. A valid correlated ACK is the only detach. */
    CHECK(ker_ff_admission_channel_send_seal(controller, 4) == -EINVAL);
    CHECK(!ker_ff_admission_channel_send_retire(controller, 4));
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_RETIRED);
    CHECK(!result.status && result.lease == 1 && result.command_id == 4 && result.epoch == 1);
    struct ker_ff_admission_wire forged = {0};
    forged.magic = KER_FF_ADMISSION_CHANNEL_MAGIC;
    forged.version = KER_FF_ADMISSION_CHANNEL_VERSION;
    forged.command = KER_FF_ADMISSION_SEAL;
    forged.length = sizeof(forged);
    forged.lease = 2;
    forged.command_id = 5;
    forged.epoch = 1;
    CHECK(!send_wire(controller, &forged));
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EPROTO);
    forged.lease = 1;
    forged.epoch = 2;
    CHECK(!send_wire(controller, &forged));
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    CHECK(ker_ff_admission_channel_receive(controller, &result) == -EPROTO);
    CHECK(!ker_ff_admission_channel_send_seal(controller, 5));
    interrupt_next(SYS_sendmsg, 1);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == -EAGAIN);
    CHECK(!owner->owner_seal_ack_sent && owner->response_pending);
    CHECK(ker_ff_admission_channel_owner_step(owner, &ops) == KER_FF_ADMISSION_OWNER_SEALED);
    CHECK(ker_ff_admission_channel_receive(controller, &result) == KER_FF_ADMISSION_SEALED);
    CHECK(!result.status && result.lease == 1 && result.command_id == 5 && result.epoch == 1);
    forged.lease = 1;
    forged.epoch = 1;
    CHECK(!send_wire(controller, &forged));
    CHECK(!ker_ff_admission_channel_owner_step(owner, &ops));
    CHECK(ker_ff_admission_channel_receive(controller, &result) == -EPROTO);

    ker_ff_admission_channel_close(controller);
    ker_ff_admission_channel_close(owner);
    preseal_eof_is_fatal(&ops);
    cached_peer_exit(&ops, request);
    CHECK(interrupt_count == 19 && !interrupt_budget && admits == 2 && revokes == 1);
    puts("ADMISSION_EINTR_PASS interrupts=19 admits=2 revokes=1 expired=1 dead_peer=1 seal=1 preseal_eof=fatal");
    return 0;
}
