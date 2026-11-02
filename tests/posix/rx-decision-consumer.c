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
    if (!strcmp(fixture->mode, "bad-ready")) return 27;

    struct ker_rx_decision_header data_header = {
        .magic = KER_RX_DECISION_MAGIC, .version = KER_RX_DECISION_VERSION,
        .type = KER_RX_DECISION_DATA, .header_bytes = sizeof(data_header),
        .worker_epoch = fixture->epoch, .packet_id = 1,
        .deadline_ns = monotonic_ns() + KER_RX_DECISION_DEADLINE_NS,
    };
    struct ker_rx_decision_data data = {
        .packet_bytes = 64, .first_segment_bytes = 64, .data_offset = 128,
        .segment_count = 1, .queue_id = 0, .queue_count = 1,
        .data_room_bytes = 2048,
    };
    if (!strcmp(fixture->mode, "bad-sequence")) data_header.packet_id = 2;
    if (!strcmp(fixture->mode, "expired")) data_header.deadline_ns = monotonic_ns() - 1;
    if (!strcmp(fixture->mode, "bad-bounds")) data.data_room_bytes = 150;
    if (!strcmp(fixture->mode, "bad-flags")) data.rx_offload_flags = UINT64_C(1) << 4;
    if (!strcmp(fixture->mode, "replay")) data_header.packet_id = 1;
    memcpy(data_header.run_nonce, fixture->nonce, sizeof(data_header.run_nonce));
    data_header.message_bytes = sizeof(data_header) + sizeof(data) + data.first_segment_bytes;
    unsigned char snapshot[64];
    for (size_t i = 0; i < sizeof(snapshot); ++i) snapshot[i] = (unsigned char)(i ^ 0x5a);
    struct iovec vectors[] = {{&data_header, sizeof(data_header)}, {&data, sizeof(data)},
        {snapshot, sizeof(snapshot)}};
    struct msghdr send_message = {.msg_iov = vectors, .msg_iovlen = 3};
    if (sendmsg(fixture->worker_fd, &send_message, MSG_NOSIGNAL) != data_header.message_bytes)
        return 28;
    if (!strcmp(fixture->mode, "replay")) {
        if (receive_packet(fixture->worker_fd, bytes, sizeof(bytes), &length, getppid(), false)) return 29;
        if (length != sizeof(struct ker_rx_decision_header) + sizeof(struct ker_rx_decision_result)) return 30;
        if (sendmsg(fixture->worker_fd, &send_message, MSG_NOSIGNAL) != data_header.message_bytes) return 31;
    }
    if (strcmp(fixture->mode, "positive") && strcmp(fixture->mode, "wrong-thread") &&
        strcmp(fixture->mode, "no-handler") && strcmp(fixture->mode, "alive-uncertain") &&
        strcmp(fixture->mode, "dead-peer")) return 0;
    if (receive_packet(fixture->worker_fd, bytes, sizeof(bytes), &length, getppid(), false)) return 32;
    if (length != sizeof(struct ker_rx_decision_header) + sizeof(struct ker_rx_decision_result)) return 33;
    struct ker_rx_decision_result decision;
    memcpy(&header, bytes, sizeof(header));
    memcpy(&decision, bytes + sizeof(header), sizeof(decision));
    if (header.type != KER_RX_DECISION_RESULT || header.packet_id != 1 ||
        decision.action != KER_RX_DECISION_LOCAL) return 34;
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
    return 0;
}

struct callback_state { int calls; pthread_t owner; };
static int decide(const struct ker_rx_decision_packet *packet, void *context)
{
    struct callback_state *state = context;
    state->calls++;
    if (!pthread_equal(state->owner, pthread_self()) || packet->packet_id != 1 ||
        packet->packet_bytes != 64 || packet->first_segment_bytes != 64 ||
        packet->data_room_bytes != 2048 || packet->data_offset != 128 ||
        packet->queue_id || packet->queue_count != 1) return 99;
    const unsigned char *snapshot = packet->first_segment;
    for (size_t i = 0; i < 64; ++i)
        if (snapshot[i] != (unsigned char)(i ^ 0x5a)) return 99;
    return KER_RX_DECISION_LOCAL;
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

    struct callback_state callback = {.calls = 0, .owner = pthread_self()};
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
    CHECK(ker_rx_decision_consumer_start() == 0);
    CHECK(ker_posix_rx_decision_is_ready() == 1);
    if (strcmp(mode, "positive") && strcmp(mode, "wrong-thread") &&
        strcmp(mode, "no-handler") && strcmp(mode, "alive-uncertain") &&
        strcmp(mode, "dead-peer")) {
        CHECK(wait_fd(consumer_fd) == 0);
        if (!strcmp(mode, "replay")) {
            CHECK(ker_rx_decision_consumer_pump() == 0);
            CHECK(callback.calls == 1);
            CHECK(wait_fd(consumer_fd) == 0);
            CHECK(ker_rx_decision_consumer_pump() == -EPROTO);
            kill(fixture.worker_pid, SIGKILL);
            int status;
            CHECK(waitpid(fixture.worker_pid, &status, 0) == fixture.worker_pid);
            close(fixture.worker_pidfd);
            close(fixture.supervisor_pidfd);
            close(fixture.settle_pipe[1]);
            return 0;
        }
        int expected = !strcmp(mode, "bad-sequence") || !strcmp(mode, "replay") ? -EPROTO :
            !strcmp(mode, "expired") ? -ETIMEDOUT : -EOPNOTSUPP;
        CHECK(ker_rx_decision_consumer_pump() == expected);
        CHECK(callback.calls == 0);
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

void *wrong_thread_start(void *unused)
{
    (void)unused;
    return (void *)(intptr_t)ker_rx_decision_consumer_start();
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    return run_case(argv[1]);
}
