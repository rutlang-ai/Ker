#define _GNU_SOURCE
#include "rx-decision-consumer.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "check failed at %s:%d: %s\n", \
    __FILE__, __LINE__, #c); goto fail; } } while (0)

struct fixture {
    int app_fd;
    int worker_fd;
    int release_pipe[2];
    int settle_pipe[2];
    pid_t worker_pid;
    int worker_pidfd;
    int supervisor_pidfd;
    uint8_t nonce[KER_RX_DECISION_NONCE_BYTES];
    uint64_t epoch;
    const char *mode;
};

void *wrong_thread_start(void *unused);

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int start_ticks(pid_t pid, uint64_t *ticks)
{
    char path[64], text[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *file = fopen(path, "re");
    if (!file) return -1;
    size_t length = fread(text, 1, sizeof(text) - 1, file);
    fclose(file);
    text[length] = '\0';
    char *close_comm = strrchr(text, ')');
    if (!close_comm || close_comm[1] != ' ') return -1;
    char *save = NULL;
    char *field = strtok_r(close_comm + 2, " ", &save);
    for (unsigned index = 3; field && index < 22; ++index)
        field = strtok_r(NULL, " ", &save);
    if (!field) return -1;
    char *end = NULL;
    unsigned long long value = strtoull(field, &end, 10);
    if (end == field || *end) return -1;
    *ticks = value;
    return 0;
}

static int pidfd_open_for(pid_t pid)
{
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int send_bootstrap(int fd, uint32_t role, pid_t target_pid,
    int target_pidfd, pid_t supervisor_pid, int supervisor_pidfd,
    const uint8_t nonce[KER_RX_DECISION_NONCE_BYTES], uint64_t epoch)
{
    uint64_t target_ticks = 0, supervisor_ticks = 0;
    if (start_ticks(target_pid, &target_ticks) || start_ticks(supervisor_pid, &supervisor_ticks))
        return -1;
    struct ker_rx_decision_header header = {
        .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
        .type = KER_RX_DECISION_BOOTSTRAP, .header_bytes = sizeof(header),
        .message_bytes = sizeof(header) + sizeof(struct ker_rx_decision_bootstrap),
        .worker_epoch = epoch, .control_id = KER_RX_DECISION_BOOTSTRAP_CONTROL_ID,
    };
    memcpy(header.run_nonce, nonce, sizeof(header.run_nonce));
    struct ker_rx_decision_bootstrap body = {
        .target_role = role, .target_pid = (uint32_t)target_pid,
        .target_uid = (uint32_t)getuid(), .target_gid = (uint32_t)getgid(),
        .target_start_ticks = target_ticks,
        .supervisor_pid = (uint32_t)supervisor_pid,
        .supervisor_uid = (uint32_t)getuid(), .supervisor_gid = (uint32_t)getgid(),
        .supervisor_start_ticks = supervisor_ticks,
    };
    struct iovec vectors[] = {{&header, sizeof(header)}, {&body, sizeof(body)}};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(2 * sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int fds[] = {target_pidfd, supervisor_pidfd};
    memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));
    message.msg_controllen = CMSG_SPACE(sizeof(fds));
    ssize_t sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    return sent == (ssize_t)header.message_bytes ? 0 : -1;
}

static int wait_fd(int fd)
{
    struct pollfd event = {.fd = fd, .events = POLLIN};
    int result;
    do { result = poll(&event, 1, 1000); } while (result < 0 && errno == EINTR);
    return result == 1 && (event.revents & POLLIN) ? 0 : -1;
}

static int receive_packet(int fd, unsigned char *buffer, size_t capacity, size_t *length,
    pid_t expected_pid, bool allow_two_rights)
{
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred)) +
        CMSG_SPACE(2 * sizeof(int))]; } control;
    struct iovec vector = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    ssize_t count = recvmsg(fd, &message, MSG_TRUNC);
    if (count < 0 || (size_t)count > capacity || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
        return -1;
    bool credential = false;
    size_t rights_count = 0;
    for (struct cmsghdr *item = CMSG_FIRSTHDR(&message); item;
         item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_CREDENTIALS &&
            item->cmsg_len == CMSG_LEN(sizeof(struct ucred)) && !credential) {
            struct ucred sender;
            memcpy(&sender, CMSG_DATA(item), sizeof(sender));
            if (sender.pid != expected_pid || sender.uid != getuid() || sender.gid != getgid())
                return -1;
            credential = true;
        } else if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_RIGHTS) {
            int *fds = (int *)CMSG_DATA(item);
            size_t n = (item->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < n; ++i) close(fds[i]);
            rights_count += n;
        } else return -1;
    }
    if (!credential || (allow_two_rights ? rights_count != 2 : rights_count != 0)) return -1;
    *length = (size_t)count;
    return 0;
}

static int child_worker(struct fixture *fixture)
{
    unsigned char bytes[KER_RX_DECISION_MAX_MESSAGE];
    size_t length = 0;
    if (receive_packet(fixture->worker_fd, bytes, sizeof(bytes), &length, getppid(), true)) return 20;
    if (length != sizeof(struct ker_rx_decision_header) + sizeof(struct ker_rx_decision_bootstrap)) return 21;
    struct ker_rx_decision_header header;
    struct ker_rx_decision_bootstrap bootstrap;
    memcpy(&header, bytes, sizeof(header));
    memcpy(&bootstrap, bytes + sizeof(header), sizeof(bootstrap));
    if (header.type != KER_RX_DECISION_BOOTSTRAP ||
        bootstrap.target_role != KER_RX_DECISION_TARGET_CONSUMER ||
        bootstrap.target_pid != (uint32_t)getppid() ||
        memcmp(header.run_nonce, fixture->nonce, sizeof(fixture->nonce))) return 22;
    char release;
    if (read(fixture->release_pipe[0], &release, 1) != 1) return 23;
    if (receive_packet(fixture->worker_fd, bytes, sizeof(bytes), &length, getppid(), false)) return 24;
    memcpy(&header, bytes, sizeof(header));
    if (length != sizeof(header) || header.type != KER_RX_DECISION_HELLO ||
        header.control_id != KER_RX_DECISION_HELLO_CONTROL_ID || header.packet_id ||
        header.deadline_ns || memcmp(header.run_nonce, fixture->nonce, sizeof(fixture->nonce))) return 25;
    struct ker_rx_decision_header ready = {
        .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
        .type = KER_RX_DECISION_READY, .header_bytes = sizeof(ready),
        .message_bytes = sizeof(ready), .worker_epoch = fixture->epoch,
        .control_id = KER_RX_DECISION_HELLO_CONTROL_ID,
    };
    if (!strcmp(fixture->mode, "old-version-ready")) ready.version = 1;
    memcpy(ready.run_nonce, fixture->nonce, sizeof(ready.run_nonce));
    if (!strcmp(fixture->mode, "wrong-worker-credential")) {
        pid_t impostor = fork();
        if (impostor < 0) return 39;
        if (!impostor) {
            ssize_t sent = send(fixture->worker_fd, &ready, sizeof(ready), MSG_NOSIGNAL);
            _exit(sent == sizeof(ready) ? 0 : 40);
        }
        int status = 0;
        if (waitpid(impostor, &status, 0) != impostor || !WIFEXITED(status) ||
            WEXITSTATUS(status)) return 41;
        return 0;
    }
    if (send(fixture->worker_fd, &ready, sizeof(ready), MSG_NOSIGNAL) != sizeof(ready)) return 26;
    if (!strcmp(fixture->mode, "old-version-ready")) {
        /* Keep SCM_CREDENTIALS and pidfd identity valid until startup has
         * consumed and rejected this deliberately old READY message. */
        if (read(fixture->settle_pipe[0], &release, 1) != 1 || release != 'x') return 42;
        return 0;
    }
    if (!strcmp(fixture->mode, "bad-ready")) return 27;

    struct ker_rx_decision_header data_header = {
        .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
        .type = KER_RX_DECISION_DATA, .header_bytes = sizeof(data_header),
        .worker_epoch = fixture->epoch, .packet_id = 1,
        .deadline_ns = monotonic_ns() + KER_RX_DECISION_DEADLINE_NS,
    };
    struct ker_rx_decision_data data = {
        .packet_bytes = 64, .first_segment_bytes = 23, .data_offset = 128,
        .segment_count = 2, .queue_id = 0, .queue_count = 1,
        .data_room_bytes = 2048,
    };
    if (!strcmp(fixture->mode, "bad-sequence")) data_header.packet_id = 2;
    if (!strcmp(fixture->mode, "expired")) data_header.deadline_ns = monotonic_ns() - 1;
    if (!strcmp(fixture->mode, "bad-bounds")) data.data_room_bytes = 150;
    if (!strcmp(fixture->mode, "bad-flags")) data.rx_offload_flags = UINT64_C(1) << 4;
    if (!strcmp(fixture->mode, "replay")) data_header.packet_id = 1;
    if (!strcmp(fixture->mode, "old-version-data")) data_header.version = 1;
    if (!strcmp(fixture->mode, "over-cap")) data.packet_bytes = KER_RX_DECISION_MAX_FRAME + 1;
    memcpy(data_header.run_nonce, fixture->nonce, sizeof(data_header.run_nonce));
    data_header.message_bytes = sizeof(data_header) + sizeof(data) + data.packet_bytes;
    unsigned char snapshot[KER_RX_DECISION_MAX_FRAME + 1];
    for (size_t i = 0; i < data.packet_bytes; ++i) snapshot[i] = (unsigned char)(i ^ 0x5a);
    size_t payload_bytes = data.packet_bytes;
    if (!strcmp(fixture->mode, "truncated-frame")) payload_bytes--;
    if (!strcmp(fixture->mode, "trailing-frame")) {
        data.packet_bytes--;
        payload_bytes = data.packet_bytes + 1;
    }
    struct iovec vectors[] = {{&data_header, sizeof(data_header)}, {&data, sizeof(data)},
        {snapshot, payload_bytes}};
    struct msghdr send_message = {.msg_iov = vectors, .msg_iovlen = 3};
    if (sendmsg(fixture->worker_fd, &send_message, MSG_NOSIGNAL) !=
            (ssize_t)(sizeof(data_header) + sizeof(data) + payload_bytes))
        return 28;
    bool should_resolve = !strcmp(fixture->mode, "positive") ||
        !strcmp(fixture->mode, "defer") || !strcmp(fixture->mode, "shutdown-pending") ||
        !strcmp(fixture->mode, "drop") || !strcmp(fixture->mode, "wrong-thread") ||
        !strcmp(fixture->mode, "no-handler") || !strcmp(fixture->mode, "alive-uncertain") ||
        !strcmp(fixture->mode, "dead-peer") || !strcmp(fixture->mode, "replay") ||
        !strcmp(fixture->mode, "bad-action");
    if (!strcmp(fixture->mode, "late-complete")) {
        usleep(150000);
        return 0;
    }
    if (!strcmp(fixture->mode, "worker-death-defer")) return 0;
    if (!strcmp(fixture->mode, "late-settle")) {
        usleep(120000);
        unsigned char stop_bytes[KER_RX_DECISION_MAX_MESSAGE];
        size_t stop_length = 0;
        if (receive_packet(fixture->worker_fd, stop_bytes, sizeof(stop_bytes),
                &stop_length, getppid(), false) || stop_length != sizeof(header)) return 44;
        memcpy(&header, stop_bytes, sizeof(header));
        if (header.type != KER_RX_DECISION_STOP ||
            header.control_id != KER_RX_DECISION_STOP_CONTROL_ID) return 45;
        struct ker_rx_decision_header settled_header = {
            .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
            .type = KER_RX_DECISION_SETTLED, .header_bytes = sizeof(settled_header),
            .message_bytes = sizeof(settled_header) + sizeof(struct ker_rx_decision_settled),
            .worker_epoch = fixture->epoch,
            .control_id = KER_RX_DECISION_STOP_CONTROL_ID,
        };
        memcpy(settled_header.run_nonce, fixture->nonce, sizeof(settled_header.run_nonce));
        struct ker_rx_decision_settled false_settled = {.last_packet_id = 0};
        struct iovec settled_vectors[] = {{&settled_header, sizeof(settled_header)},
            {&false_settled, sizeof(false_settled)}};
        struct msghdr settled_message = {.msg_iov = settled_vectors, .msg_iovlen = 2};
        return sendmsg(fixture->worker_fd, &settled_message, MSG_NOSIGNAL) ==
            settled_header.message_bytes ? 0 : 46;
    }
    if (!should_resolve) for (;;) pause();
    if (!strcmp(fixture->mode, "replay")) {
        if (receive_packet(fixture->worker_fd, bytes, sizeof(bytes), &length, getppid(), false)) return 29;
        if (length != sizeof(struct ker_rx_decision_header) + sizeof(struct ker_rx_decision_result)) return 30;
        if (sendmsg(fixture->worker_fd, &send_message, MSG_NOSIGNAL) != data_header.message_bytes) return 31;
        /* Keep the pidfd live until the parent verifies replay rejection. */
        if (read(fixture->settle_pipe[0], &release, 1) != 1) return 42;
    }
    if (strcmp(fixture->mode, "positive") && strcmp(fixture->mode, "drop") &&
        strcmp(fixture->mode, "defer") && strcmp(fixture->mode, "shutdown-pending") &&
        strcmp(fixture->mode, "bad-action") && strcmp(fixture->mode, "wrong-thread") &&
        strcmp(fixture->mode, "no-handler") && strcmp(fixture->mode, "alive-uncertain") &&
        strcmp(fixture->mode, "dead-peer")) return 0;
    if (receive_packet(fixture->worker_fd, bytes, sizeof(bytes), &length, getppid(), false)) return 32;
    if (length != sizeof(struct ker_rx_decision_header) + sizeof(struct ker_rx_decision_result)) return 33;
    struct ker_rx_decision_result decision;
    memcpy(&header, bytes, sizeof(header));
    memcpy(&decision, bytes + sizeof(header), sizeof(decision));
    uint32_t expected_action = (!strcmp(fixture->mode, "drop") ||
        !strcmp(fixture->mode, "shutdown-pending")) ? KER_RX_DECISION_DROP :
        KER_RX_DECISION_LOCAL;
    if (header.type != KER_RX_DECISION_RESULT || header.packet_id != 1 ||
        decision.action != expected_action) return 34;
    if (receive_packet(fixture->worker_fd, bytes, sizeof(bytes), &length, getppid(), false)) return 35;
    memcpy(&header, bytes, sizeof(header));
    if (length != sizeof(header) ||
        header.type != KER_RX_DECISION_STOP || header.control_id != KER_RX_DECISION_STOP_CONTROL_ID)
        return 36;
    if (!strcmp(fixture->mode, "alive-uncertain")) {
        if (read(fixture->settle_pipe[0], &release, 1) != 1) return 38;
    }
    if (!strcmp(fixture->mode, "dead-peer")) return 0;
    struct ker_rx_decision_header settled_header = {
        .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
        .type = KER_RX_DECISION_SETTLED, .header_bytes = sizeof(settled_header),
        .message_bytes = sizeof(settled_header) + sizeof(struct ker_rx_decision_settled),
        .worker_epoch = fixture->epoch, .control_id = KER_RX_DECISION_STOP_CONTROL_ID,
    };
    memcpy(settled_header.run_nonce, fixture->nonce, sizeof(settled_header.run_nonce));
    struct ker_rx_decision_settled settled = {.last_packet_id = 1};
    struct iovec final_vectors[] = {{&settled_header, sizeof(settled_header)},
        {&settled, sizeof(settled)}};
    struct msghdr final_message = {.msg_iov = final_vectors, .msg_iovlen = 2};
    if (sendmsg(fixture->worker_fd, &final_message, MSG_NOSIGNAL) != settled_header.message_bytes) return 37;
    /* The real worker stays alive after RX settlement for independent shutdown. */
    char byte;
    if (read(fixture->worker_fd, &byte, 1) != 0) return 43;
    return 0;
}

struct callback_state {
    int calls;
    pthread_t owner;
    int action;
    bool defer;
    uint64_t packet_id;
    unsigned char snapshot[64];
};
static int decide(const struct ker_rx_decision_packet *packet, void *context)
{
    struct callback_state *state = context;
    state->calls++;
    if (!pthread_equal(state->owner, pthread_self()) || packet->packet_id != 1 ||
        packet->packet_bytes != 64 || packet->full_frame_bytes != 64 ||
        packet->first_segment_bytes != 23 || packet->first_segment != packet->full_frame ||
        packet->data_room_bytes != 2048 || packet->data_offset != 128 ||
        packet->queue_id || packet->queue_count != 1) return 99;
    const unsigned char *frame = packet->full_frame;
    for (size_t i = 0; i < packet->full_frame_bytes; ++i)
        if (frame[i] != (unsigned char)(i ^ 0x5a)) return 99;
    if (state->defer) {
        state->packet_id = packet->packet_id;
        memcpy(state->snapshot, frame, sizeof(state->snapshot));
        return KER_RX_DECISION_DEFER;
    }
    return state->action;
}

struct complete_thread_args { uint64_t packet_id; int result; int error; };
static void *wrong_thread_complete(void *opaque)
{
    struct complete_thread_args *args = opaque;
    args->result = ker_posix_rx_decision_complete(args->packet_id,
        KER_RX_DECISION_LOCAL);
    args->error = errno;
    return NULL;
}

static int run_case(const char *mode)
{
    struct fixture fixture = {.app_fd = -1, .worker_fd = -1,
        .release_pipe = {-1, -1}, .settle_pipe = {-1, -1},
        .worker_pid = -1, .worker_pidfd = -1,
        .supervisor_pidfd = -1, .epoch = 19, .mode = mode};
    for (size_t i = 0; i < sizeof(fixture.nonce); ++i) fixture.nonce[i] = (uint8_t)(i + 1);
    int endpoints[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, endpoints) == 0);
    fixture.app_fd = endpoints[0];
    fixture.worker_fd = endpoints[1];
    int pass = 1;
    CHECK(setsockopt(fixture.app_fd, SOL_SOCKET, SO_PASSCRED, &pass, sizeof(pass)) == 0);
    CHECK(setsockopt(fixture.worker_fd, SOL_SOCKET, SO_PASSCRED, &pass, sizeof(pass)) == 0);
    CHECK(pipe2(fixture.release_pipe, O_CLOEXEC) == 0);
    CHECK(pipe2(fixture.settle_pipe, O_CLOEXEC) == 0);
    fixture.worker_pid = fork();
    CHECK(fixture.worker_pid >= 0);
    if (fixture.worker_pid == 0) {
        close(fixture.app_fd);
        close(fixture.release_pipe[1]);
        close(fixture.settle_pipe[1]);
        _exit(child_worker(&fixture));
    }
    close(fixture.release_pipe[0]);
    fixture.release_pipe[0] = -1;
    close(fixture.settle_pipe[0]);
    fixture.settle_pipe[0] = -1;
    fixture.worker_pidfd = pidfd_open_for(fixture.worker_pid);
    fixture.supervisor_pidfd = pidfd_open_for(getpid());
    CHECK(fixture.worker_pidfd >= 0 && fixture.supervisor_pidfd >= 0);
    CHECK(send_bootstrap(fixture.app_fd, KER_RX_DECISION_TARGET_CONSUMER,
        getpid(), fixture.supervisor_pidfd, getpid(), fixture.supervisor_pidfd,
        fixture.nonce, fixture.epoch) == 0);
    uint32_t role = !strcmp(mode, "wrong-role") ? KER_RX_DECISION_TARGET_CONSUMER :
        KER_RX_DECISION_TARGET_WORKER;
    pid_t bootstrap_target = !strcmp(mode, "wrong-target") ? getpid() : fixture.worker_pid;
    CHECK(send_bootstrap(fixture.worker_fd, role, bootstrap_target,
        fixture.worker_pidfd, getpid(), fixture.supervisor_pidfd,
        fixture.nonce, fixture.epoch) == 0);
    close(fixture.worker_fd);
    fixture.worker_fd = -1;

    int callback_action = !strcmp(mode, "drop") ? KER_RX_DECISION_DROP :
        !strcmp(mode, "bad-action") ? 99 : KER_RX_DECISION_LOCAL;
    struct callback_state callback = {.calls = 0, .owner = pthread_self(),
        .action = callback_action,
        .defer = !strcmp(mode, "defer") || !strcmp(mode, "shutdown-pending") ||
            !strcmp(mode, "late-complete") || !strcmp(mode, "late-settle") ||
            !strcmp(mode, "worker-death-defer")};
    if (!strcmp(mode, "wrong-role") || !strcmp(mode, "wrong-target")) {
        CHECK(ker_posix_rx_decision_register(fixture.app_fd, decide, &callback) < 0);
        CHECK(errno == (!strcmp(mode, "wrong-role") ? EACCES : ESTALE));
        close(fixture.app_fd);
        fixture.app_fd = -1;
        kill(fixture.worker_pid, SIGKILL);
        int status;
        CHECK(waitpid(fixture.worker_pid, &status, 0) == fixture.worker_pid);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.release_pipe[1]);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    if (!strcmp(mode, "no-handler")) {
        CHECK(ker_posix_rx_decision_register(fixture.app_fd, NULL, &callback) < 0);
        CHECK(errno == EINVAL);
    }
    CHECK(ker_posix_rx_decision_register(fixture.app_fd, decide, &callback) == 0);
    int consumer_fd = fixture.app_fd;
    fixture.app_fd = -1; /* Successful registration owns the endpoint. */
    CHECK(ker_rx_decision_consumer_registered() == 1);
    CHECK(ker_posix_rx_decision_is_ready() == 0);
    CHECK(write(fixture.release_pipe[1], "x", 1) == 1);
    close(fixture.release_pipe[1]);

    if (!strcmp(mode, "wrong-worker-credential")) {
        CHECK(ker_rx_decision_consumer_start() == -EACCES);
        int child_status = 0;
        CHECK(waitpid(fixture.worker_pid, &child_status, 0) == fixture.worker_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
        fixture.worker_pid = -1;
        int shutdown = ker_rx_decision_consumer_prepare_runtime_shutdown();
        if (shutdown == -EBUSY) shutdown = ker_rx_decision_consumer_prepare_runtime_shutdown();
        CHECK(shutdown == 1);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    if (!strcmp(mode, "wrong-thread")) {
        pthread_t wrong_thread;
        /* The worker is waiting for HELLO; wrong-thread start must have no side effect. */
        CHECK(pthread_create(&wrong_thread, NULL, wrong_thread_start, NULL) == 0);
        void *thread_result = NULL;
        CHECK(pthread_join(wrong_thread, &thread_result) == 0);
        CHECK((intptr_t)thread_result == -EPERM);
    }
    int consumer_start = ker_rx_decision_consumer_start();
    if (!strcmp(mode, "old-version-ready")) {
        CHECK(consumer_start == -EPROTO);
        CHECK(write(fixture.settle_pipe[1], "x", 1) == 1);
        int child_status = 0;
        pid_t expected_worker = fixture.worker_pid;
        pid_t reaped_worker = waitpid(expected_worker, &child_status, 0);
        if (reaped_worker == expected_worker) fixture.worker_pid = -1;
        CHECK(reaped_worker == expected_worker);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    CHECK(consumer_start == 0);
    CHECK(ker_posix_rx_decision_is_ready() == 1);
    if (strcmp(mode, "positive") && strcmp(mode, "defer") &&
        strcmp(mode, "shutdown-pending") && strcmp(mode, "late-complete") &&
        strcmp(mode, "worker-death-defer") && strcmp(mode, "late-settle") &&
        strcmp(mode, "drop") &&
        strcmp(mode, "wrong-thread") &&
        strcmp(mode, "no-handler") && strcmp(mode, "alive-uncertain") &&
        strcmp(mode, "dead-peer")) {
        CHECK(wait_fd(consumer_fd) == 0);
        if (!strcmp(mode, "replay")) {
            CHECK(ker_rx_decision_consumer_pump() == 0);
            CHECK(callback.calls == 1);
            CHECK(wait_fd(consumer_fd) == 0);
            CHECK(ker_rx_decision_consumer_pump() == -EPROTO);
            CHECK(write(fixture.settle_pipe[1], "x", 1) == 1);
            int status;
            CHECK(waitpid(fixture.worker_pid, &status, 0) == fixture.worker_pid);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
            close(fixture.worker_pidfd);
            close(fixture.supervisor_pidfd);
            close(fixture.settle_pipe[1]);
            return 0;
        }
        int expected = !strcmp(mode, "bad-sequence") || !strcmp(mode, "replay") ||
            !strcmp(mode, "bad-action") || !strcmp(mode, "old-version-data") ||
            !strcmp(mode, "truncated-frame") || !strcmp(mode, "trailing-frame") ? -EPROTO :
            !strcmp(mode, "over-cap") ? -EOPNOTSUPP :
            !strcmp(mode, "expired") ? -ETIMEDOUT : -EOPNOTSUPP;
        CHECK(ker_rx_decision_consumer_pump() == expected);
        CHECK(callback.calls == (!strcmp(mode, "bad-action") ? 1 : 0));
        kill(fixture.worker_pid, SIGKILL);
        int status;
        CHECK(waitpid(fixture.worker_pid, &status, 0) == fixture.worker_pid);
        close(fixture.release_pipe[1]);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    CHECK(wait_fd(consumer_fd) == 0);
    for (unsigned attempt = 0; attempt < 100 && callback.calls == 0; ++attempt) {
        int result = ker_rx_decision_consumer_pump();
        CHECK(result == 0);
        if (!callback.calls) usleep(1000);
    }
    CHECK(callback.calls == 1);
    if (!strcmp(mode, "defer")) {
        CHECK(callback.packet_id == 1);
        for (size_t i = 0; i < sizeof(callback.snapshot); ++i)
            CHECK(callback.snapshot[i] == (unsigned char)(i ^ 0x5a));
        CHECK(ker_rx_decision_consumer_pump() == 0);
        CHECK(callback.calls == 1);
        CHECK(ker_posix_rx_decision_complete(callback.packet_id + 1,
            KER_RX_DECISION_LOCAL) == -1 && errno == ESTALE);
        CHECK(ker_posix_rx_decision_complete(callback.packet_id,
            KER_RX_DECISION_DEFER) == -1 && errno == EINVAL);
        struct complete_thread_args wrong_thread = {.packet_id = callback.packet_id};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, wrong_thread_complete, &wrong_thread) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        CHECK(wrong_thread.result == -1 && wrong_thread.error == EPERM);
        CHECK(ker_posix_rx_decision_complete(callback.packet_id,
            KER_RX_DECISION_LOCAL) == 0);
        CHECK(ker_posix_rx_decision_complete(callback.packet_id,
            KER_RX_DECISION_LOCAL) == -1 && errno == EALREADY);
    }
    if (!strcmp(mode, "late-complete")) {
        usleep(120000);
        CHECK(ker_posix_rx_decision_complete(callback.packet_id,
            KER_RX_DECISION_LOCAL) == -1 && errno == ETIMEDOUT);
        int child_status = 0;
        CHECK(waitpid(fixture.worker_pid, &child_status, 0) == fixture.worker_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
        fixture.worker_pid = -1;
        CHECK(ker_rx_decision_consumer_prepare_runtime_shutdown() == 1);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    if (!strcmp(mode, "late-settle")) {
        usleep(120000);
        CHECK(ker_rx_decision_consumer_pump() == -ETIMEDOUT);
        CHECK(ker_rx_decision_consumer_prepare_runtime_shutdown() == -EBUSY);
        int child_status = 0;
        CHECK(waitpid(fixture.worker_pid, &child_status, 0) == fixture.worker_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
        fixture.worker_pid = -1;
        CHECK(ker_rx_decision_consumer_prepare_runtime_shutdown() == 1);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    if (!strcmp(mode, "worker-death-defer")) {
        int child_status = 0;
        CHECK(waitpid(fixture.worker_pid, &child_status, 0) == fixture.worker_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
        fixture.worker_pid = -1;
        CHECK(ker_posix_rx_decision_complete(callback.packet_id,
            KER_RX_DECISION_LOCAL) == -1 && errno == ESRCH);
        CHECK(ker_rx_decision_consumer_prepare_runtime_shutdown() == 1);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    if (!strcmp(mode, "shutdown-pending")) {
        CHECK(ker_rx_decision_consumer_prepare_runtime_shutdown() == 0);
        int child_status = 0;
        CHECK(waitpid(fixture.worker_pid, &child_status, 0) == fixture.worker_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
        close(fixture.worker_pidfd);
        close(fixture.supervisor_pidfd);
        close(fixture.settle_pipe[1]);
        return 0;
    }
    if (!strcmp(mode, "alive-uncertain")) {
        CHECK(ker_rx_decision_consumer_prepare_runtime_shutdown() == -EBUSY);
        CHECK(ker_rx_decision_consumer_registered() == 1);
        CHECK(write(fixture.settle_pipe[1], "x", 1) == 1);
    }
    int shutdown = ker_rx_decision_consumer_prepare_runtime_shutdown();
    if (!strcmp(mode, "dead-peer")) {
        if (shutdown == -EBUSY) {
            CHECK(ker_rx_decision_consumer_registered() == 1);
            int child_status = 0;
            CHECK(waitpid(fixture.worker_pid, &child_status, 0) == fixture.worker_pid);
            CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
            fixture.worker_pid = -1;
            shutdown = ker_rx_decision_consumer_prepare_runtime_shutdown();
        }
        CHECK(shutdown == 1);
        CHECK(ker_rx_decision_consumer_error() < 0);
    } else CHECK(shutdown == 0);
    int status = 0;
    if (fixture.worker_pid > 0) {
        CHECK(waitpid(fixture.worker_pid, &status, 0) == fixture.worker_pid);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(ker_posix_rx_decision_is_ready() == 0);
    close(fixture.worker_pidfd);
    close(fixture.supervisor_pidfd);
    close(fixture.settle_pipe[1]);
    return 0;
fail:
    if (fixture.worker_pid > 0) {
        (void)kill(fixture.worker_pid, SIGKILL);
        (void)waitpid(fixture.worker_pid, NULL, 0);
    }
    if (fixture.app_fd >= 0) close(fixture.app_fd);
    if (fixture.worker_fd >= 0) close(fixture.worker_fd);
    if (fixture.release_pipe[0] >= 0) close(fixture.release_pipe[0]);
    if (fixture.release_pipe[1] >= 0) close(fixture.release_pipe[1]);
    if (fixture.settle_pipe[0] >= 0) close(fixture.settle_pipe[0]);
    if (fixture.settle_pipe[1] >= 0) close(fixture.settle_pipe[1]);
    if (fixture.worker_pidfd >= 0) close(fixture.worker_pidfd);
    if (fixture.supervisor_pidfd >= 0) close(fixture.supervisor_pidfd);
    return 1;
}

struct supervisor_case_notice { pid_t consumer_pid; pid_t worker_pid; };
struct supervisor_case_result { int complete_errno; int shutdown_result; };
struct supervisor_case_callback { uint64_t packet_id; };

static int defer_supervisor_case(const struct ker_rx_decision_packet *packet,
    void *opaque)
{
    struct supervisor_case_callback *state = opaque;
    if (!packet || !packet->first_segment || packet->packet_id != 1 ||
        packet->deadline_ns <= monotonic_ns()) return -1;
    state->packet_id = packet->packet_id;
    return KER_RX_DECISION_DEFER;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;
    while (length) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;
    while (length) {
        ssize_t count = read(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    return 0;
}

static int supervisor_case_worker(int fd, int release_fd, pid_t consumer_pid,
    pid_t supervisor_pid, const uint8_t nonce[KER_RX_DECISION_NONCE_BYTES],
    uint64_t epoch)
{
    unsigned char bytes[KER_RX_DECISION_MAX_MESSAGE];
    size_t length = 0;
    if (receive_packet(fd, bytes, sizeof(bytes), &length, supervisor_pid, true) ||
        length != sizeof(struct ker_rx_decision_header) +
            sizeof(struct ker_rx_decision_bootstrap)) return 1;
    struct ker_rx_decision_header header;
    struct ker_rx_decision_bootstrap bootstrap;
    memcpy(&header, bytes, sizeof(header));
    memcpy(&bootstrap, bytes + sizeof(header), sizeof(bootstrap));
    if (header.type != KER_RX_DECISION_BOOTSTRAP ||
        bootstrap.target_role != KER_RX_DECISION_TARGET_CONSUMER ||
        bootstrap.target_pid != (uint32_t)consumer_pid ||
        bootstrap.supervisor_pid != (uint32_t)supervisor_pid ||
        memcmp(header.run_nonce, nonce, sizeof(header.run_nonce))) return 2;
    char release;
    if (read(release_fd, &release, 1) != 1) return 3;
    if (receive_packet(fd, bytes, sizeof(bytes), &length, consumer_pid, false) ||
        length != sizeof(header)) return 4;
    memcpy(&header, bytes, sizeof(header));
    if (header.type != KER_RX_DECISION_HELLO ||
        header.control_id != KER_RX_DECISION_HELLO_CONTROL_ID) return 5;
    struct ker_rx_decision_header ready = {
        .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
        .type = KER_RX_DECISION_READY, .header_bytes = sizeof(ready),
        .message_bytes = sizeof(ready), .worker_epoch = epoch,
        .control_id = KER_RX_DECISION_HELLO_CONTROL_ID,
    };
    memcpy(ready.run_nonce, nonce, sizeof(ready.run_nonce));
    if (send(fd, &ready, sizeof(ready), MSG_NOSIGNAL) != sizeof(ready)) return 6;
    struct ker_rx_decision_header data_header = {
        .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
        .type = KER_RX_DECISION_DATA, .header_bytes = sizeof(data_header),
        .worker_epoch = epoch, .packet_id = 1,
        .deadline_ns = monotonic_ns() + KER_RX_DECISION_DEADLINE_NS,
    };
    memcpy(data_header.run_nonce, nonce, sizeof(data_header.run_nonce));
    struct ker_rx_decision_data data = {
        .packet_bytes = 64, .first_segment_bytes = 64, .data_offset = 128,
        .segment_count = 1, .queue_id = 0, .queue_count = 1,
        .data_room_bytes = 2048,
    };
    data_header.message_bytes = sizeof(data_header) + sizeof(data) + 64;
    unsigned char snapshot[64];
    memset(snapshot, 0x5a, sizeof(snapshot));
    struct iovec vectors[] = {{&data_header, sizeof(data_header)},
        {&data, sizeof(data)}, {snapshot, sizeof(snapshot)}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 3};
    if (sendmsg(fd, &message, MSG_NOSIGNAL) != data_header.message_bytes) return 7;
    /* Only STOP is permitted after the supervisor dies; a result would mean
     * the revoked lease was incorrectly authorized. */
    if (receive_packet(fd, bytes, sizeof(bytes), &length, consumer_pid, false) ||
        length != sizeof(header)) return 8;
    memcpy(&header, bytes, sizeof(header));
    if (header.type != KER_RX_DECISION_STOP) return 9;
    return 0;
}

static int supervisor_death_defer_case(void)
{
    int notice_pipe[2] = {-1, -1}, release_pipe[2] = {-1, -1};
    pid_t supervisor = -1, consumer = -1, worker = -1;
    int supervisor_pidfd = -1;
    bool supervisor_reaped = false;
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    CHECK(pipe2(notice_pipe, O_CLOEXEC) == 0);
    CHECK(pipe2(release_pipe, O_CLOEXEC) == 0);
    supervisor = fork();
    CHECK(supervisor >= 0);
    if (supervisor == 0) {
        close(notice_pipe[0]);
        close(release_pipe[1]);
        int app_pair[2], worker_release[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, app_pair) ||
            pipe2(worker_release, O_CLOEXEC)) _exit(10);
        int pass = 1;
        if (setsockopt(app_pair[0], SOL_SOCKET, SO_PASSCRED, &pass, sizeof(pass)) ||
            setsockopt(app_pair[1], SOL_SOCKET, SO_PASSCRED, &pass, sizeof(pass))) _exit(11);
        uint8_t nonce[KER_RX_DECISION_NONCE_BYTES];
        for (size_t i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0xa0 + i);
        const uint64_t epoch = 37;
        pid_t consumer_pid = fork();
        if (consumer_pid < 0) _exit(13);
        if (!consumer_pid) {
            close(app_pair[1]); close(worker_release[0]); close(worker_release[1]);
            struct supervisor_case_callback callback = {0};
            if (ker_posix_rx_decision_register(app_pair[0], defer_supervisor_case,
                    &callback) || ker_rx_decision_consumer_start()) _exit(14);
            for (unsigned i = 0; i < 100 && !callback.packet_id; ++i) {
                int pumped = ker_rx_decision_consumer_pump();
                if (pumped) _exit(15);
                if (!callback.packet_id) usleep(1000);
            }
            if (!callback.packet_id || write_all(notice_pipe[1], "D", 1) ||
                read_all(release_pipe[0], (char[1]){0}, 1)) _exit(16);
            errno = 0;
            int complete = ker_posix_rx_decision_complete(callback.packet_id,
                KER_RX_DECISION_LOCAL);
            int complete_errno = complete == -1 ? errno : 0;
            struct supervisor_case_result outcome = {
                .complete_errno = complete_errno,
                .shutdown_result = -999,
            };
            outcome.shutdown_result = ker_rx_decision_consumer_prepare_runtime_shutdown();
            int success = outcome.complete_errno == ESRCH && outcome.shutdown_result == 1;
            if (write_all(notice_pipe[1], &outcome, sizeof(outcome))) _exit(17);
            _exit(success ? 0 : 18);
        }
        pid_t worker = fork();
        if (worker < 0) _exit(12);
        if (!worker) {
            close(app_pair[0]); close(worker_release[1]);
            _exit(supervisor_case_worker(app_pair[1], worker_release[0],
                consumer_pid, getppid(), nonce, epoch));
        }
        int worker_pidfd = pidfd_open_for(worker);
        int consumer_pidfd = pidfd_open_for(consumer_pid);
        int supervisor_pidfd = pidfd_open_for(getpid());
        if (worker_pidfd < 0 || consumer_pidfd < 0 || supervisor_pidfd < 0) _exit(19);
        if (send_bootstrap(app_pair[0], KER_RX_DECISION_TARGET_CONSUMER,
                consumer_pid, consumer_pidfd, getpid(), supervisor_pidfd,
                nonce, epoch) ||
            send_bootstrap(app_pair[1], KER_RX_DECISION_TARGET_WORKER,
                worker, worker_pidfd, getpid(), supervisor_pidfd, nonce, epoch)) _exit(20);
        close(consumer_pidfd); close(worker_pidfd); close(supervisor_pidfd);
        close(app_pair[0]); close(app_pair[1]);
        close(worker_release[0]);
        struct supervisor_case_notice notice = {consumer_pid, worker};
        if (write_all(notice_pipe[1], &notice, sizeof(notice))) _exit(22);
        /* DATA can reach the consumer as soon as the worker is released; its
         * D marker shares this pipe, so publish the identity record first. */
        if (write_all(worker_release[1], "R", 1)) _exit(21);
        close(worker_release[1]);
        for (;;) pause();
    }
    close(notice_pipe[1]); close(release_pipe[0]);
    struct supervisor_case_notice notice;
    struct supervisor_case_result outcome;
    supervisor_pidfd = pidfd_open_for(supervisor);
    CHECK(supervisor_pidfd >= 0);
    CHECK(read_all(notice_pipe[0], &notice, sizeof(notice)) == 0);
    consumer = notice.consumer_pid;
    worker = notice.worker_pid;
    char ready;
    CHECK(read_all(notice_pipe[0], &ready, 1) == 0 && ready == 'D');
    CHECK(kill(supervisor, SIGKILL) == 0);
    struct pollfd exited = {.fd = supervisor_pidfd, .events = POLLIN};
    CHECK(poll(&exited, 1, 1000) == 1 && (exited.revents & POLLIN));
    /* Keep the dead supervisor unreaped until the consumer has checked its
     * pidfd, so the test exercises a dead PID rather than parentage changes. */
    CHECK(write_all(release_pipe[1], "X", 1) == 0);
    CHECK(read_all(notice_pipe[0], &outcome, sizeof(outcome)) == 0);
    int supervisor_status = 0;
    CHECK(waitpid(supervisor, &supervisor_status, 0) == supervisor);
    supervisor_reaped = true;
    supervisor = -1;
    CHECK(WIFSIGNALED(supervisor_status) && WTERMSIG(supervisor_status) == SIGKILL);
    int consumer_status = 0, worker_status = 0;
    CHECK(waitpid(consumer, &consumer_status, 0) == consumer);
    consumer = -1;
    CHECK(waitpid(worker, &worker_status, 0) == worker);
    worker = -1;
    bool consumer_ok = WIFEXITED(consumer_status) && WEXITSTATUS(consumer_status) == 0;
    bool worker_ok = WIFEXITED(worker_status) && WEXITSTATUS(worker_status) == 0;
    if (!(consumer_ok && worker_ok && outcome.complete_errno == ESRCH &&
            outcome.shutdown_result == 1))
        fprintf(stderr, "supervisor case consumer=%d worker=%d errno=%d shutdown=%d\n",
            consumer_ok, worker_ok, outcome.complete_errno, outcome.shutdown_result);
    CHECK(consumer_ok && worker_ok && outcome.complete_errno == ESRCH &&
        outcome.shutdown_result == 1);
    close(supervisor_pidfd); supervisor_pidfd = -1;
    close(notice_pipe[0]); notice_pipe[0] = -1;
    close(release_pipe[1]); release_pipe[1] = -1;
    return 0;
fail:
    /* Only signal children for which this fixture still owns an unreaped
     * identity.  In particular, never reuse a numeric PID after waitpid. */
    if (supervisor > 0 && !supervisor_reaped) (void)kill(supervisor, SIGKILL);
    if (consumer > 0) (void)kill(consumer, SIGKILL);
    if (worker > 0) (void)kill(worker, SIGKILL);
    if (supervisor > 0 && !supervisor_reaped) {
        (void)waitpid(supervisor, NULL, 0);
        supervisor = -1;
    }
    if (consumer > 0) { (void)waitpid(consumer, NULL, 0); consumer = -1; }
    if (worker > 0) { (void)waitpid(worker, NULL, 0); worker = -1; }
    if (supervisor_pidfd >= 0) close(supervisor_pidfd);
    if (notice_pipe[0] >= 0) close(notice_pipe[0]);
    if (notice_pipe[1] >= 0) close(notice_pipe[1]);
    if (release_pipe[0] >= 0) close(release_pipe[0]);
    if (release_pipe[1] >= 0) close(release_pipe[1]);
    return 1;
}

void *wrong_thread_start(void *unused)
{
    (void)unused;
    return (void *)(intptr_t)ker_rx_decision_consumer_start();
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "supervisor-death-defer"))
        return supervisor_death_defer_case();
    return run_case(argv[1]);
}
