#define KER_NGINX_OWNER_TEST_ALIAS 1
#include "../../src/posix/fstack-nginx-owner-activation-module.c"

#include <sys/wait.h>
#include <sys/prctl.h>
#include <dirent.h>

static int test_mode;
static int supervisor_pidfd = -1;
static unsigned dispatch_calls;

static int open_fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    while (readdir(directory)) ++count;
    closedir(directory);
    return count;
}

static int test_dispatch(void *frame, uint16_t *length, uint16_t queue_id,
    uint16_t queue_count, uint16_t vlan_tci, uint8_t vlan_stripped,
    int32_t *result)
{
    (void)vlan_tci;
    (void)vlan_stripped;
    if (!frame || !length || queue_id != 0 ||
        queue_count != (test_mode == 12 ? 2 : 1)) return -EPROTO;
    ++dispatch_calls;
    if (test_mode == 1) {
        if (syscall(SYS_pidfd_send_signal, supervisor_pidfd, SIGKILL, NULL, 0))
            return -errno;
        struct pollfd pfd = {.fd = supervisor_pidfd, .events = POLLIN};
        int ready;
        do { ready = poll(&pfd, 1, 2000); } while (ready < 0 && errno == EINTR);
        if (ready != 1 || !(pfd.revents & POLLIN)) return -ETIMEDOUT;
    }
    if (test_mode == 2) return -EIO;
    if (test_mode == 10) {
        struct timespec delay = {.tv_nsec = 300000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
    if (test_mode == 3) ((uint8_t *)frame)[0] ^= 1;
    if (test_mode == 4) --*length;
    *result = 0;
    if (test_mode == 3 || test_mode == 4) *result = 0;
    if (test_mode == 5) *result = -3; /* Original dispatcher PEER: caller must fail closed. */
    if (test_mode == 6) *result = -2; /* RESPONSE is not a local decision. */
    if (test_mode == 7) *result = -1; /* ERROR is not a local decision. */
    if (test_mode == 12) *result = 1; /* A different queue is never current-queue LOCAL. */
    return 0;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    while (length) {
        ssize_t count = write(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
    uint8_t *bytes = buffer;
    while (length) {
        ssize_t count = read(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

static int send_fds(int fd, const void *record, size_t record_bytes,
    const int *fds, size_t fd_count)
{
    struct iovec iov = {.iov_base = (void *)record, .iov_len = record_bytes};
    char control[CMSG_SPACE(sizeof(int) * 3)] = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = CMSG_SPACE(sizeof(int) * fd_count)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * fd_count);
    return sendmsg(fd, &msg, MSG_NOSIGNAL) == (ssize_t)record_bytes ? 0 : -1;
}

static int child_app(int fd, int start_fd, int result_fd, int release_fd,
    pid_t owner_pid, uint64_t epoch, const uint8_t nonce[16], int mode)
{
    struct {
        uint32_t supervisor_pid;
        uint64_t owner_start;
        uint64_t supervisor_start;
    } identity;
    if (read_all(start_fd, &identity, sizeof(identity))) return 31;
    uint8_t frame[64];
    memset(frame, 0x5a, sizeof(frame));
    struct ker_rx_owner_relay_header request = {
        .magic = KER_RX_OWNER_RELAY_MAGIC, .version = KER_RX_OWNER_RELAY_VERSION,
        .type = KER_RX_OWNER_RELAY_REQUEST, .packet_id = 1,
        .worker_epoch = epoch, .owner_start_ticks = identity.owner_start,
        .app_pid = (uint32_t)getpid(), .owner_pid = (uint32_t)owner_pid,
        .owner_tid = (uint32_t)owner_pid,
        .supervisor_start_ticks = identity.supervisor_start,
        .supervisor_pid = identity.supervisor_pid,
        .frame_bytes = sizeof(frame), .queue_id = 0,
        .queue_count = mode == 12 ? 2 : 1,
    };
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 32;
    request.deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec + UINT64_C(10000000000);
    if (mode == 9) request.deadline_ns = 1;
    if (mode == 10) request.deadline_ns =
        (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec + UINT64_C(200000000);
    memcpy(request.run_nonce, nonce, sizeof(request.run_nonce));
    if (mode == 13) request.run_nonce[0] ^= 0x20;
    uint64_t app_start = 0;
    if (cycle_read_start_ticks(getpid(), &app_start)) return 33;
    request.app_start_ticks = app_start;
    struct iovec vectors[] = {{.iov_base = &request, .iov_len = sizeof(request)},
        {.iov_base = frame, .iov_len = sizeof(frame)}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    char data_control[CMSG_SPACE(sizeof(int))] = {0};
    if (mode == 14) {
        message.msg_control = data_control;
        message.msg_controllen = sizeof(data_control);
        struct cmsghdr *rights = CMSG_FIRSTHDR(&message);
        rights->cmsg_level = SOL_SOCKET;
        rights->cmsg_type = SCM_RIGHTS;
        rights->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(rights), &start_fd, sizeof(start_fd));
    }
    if (sendmsg(fd, &message, MSG_NOSIGNAL) != (ssize_t)(sizeof(request) + sizeof(frame)))
        return 34;
    struct pollfd wait = {.fd = fd, .events = POLLIN};
    int polled;
    do { polled = poll(&wait, 1, 1000); } while (polled < 0 && errno == EINTR);
    int outcome = -1;
    bool expect_reply = mode != 1 && mode != 2 && mode != 9 && mode != 10 &&
        mode != 13 && mode != 14;
    if (expect_reply) {
        uint8_t response[sizeof(request) + sizeof(frame)];
        ssize_t got = polled == 1 ? recv(fd, response, sizeof(response), MSG_TRUNC) : -1;
        struct ker_rx_owner_relay_header *reply = (void *)response;
        bool expected_changed = mode == 3 || mode == 4;
        int32_t expected_result = mode == 5 ? -3 : mode == 6 ? -2 :
            mode == 12 ? 1 :
            mode == 7 || expected_changed ? -1 : 0;
        outcome = got == (ssize_t)sizeof(response) &&
            reply->type == KER_RX_OWNER_RELAY_REPLY &&
            reply->dispatcher_result == expected_result &&
            reply->frame_unchanged == !expected_changed ? 0 : 1;
    } else {
        outcome = polled == 0 ? 0 : 1;
    }
    if (write_all(result_fd, &outcome, sizeof(outcome))) return 35;
    if (mode == 8) {
        if (sendmsg(fd, &message, MSG_NOSIGNAL) !=
            (ssize_t)(sizeof(request) + sizeof(frame))) return 36;
        struct pollfd duplicate_wait = {.fd = fd, .events = POLLIN};
        int duplicate_poll;
        do { duplicate_poll = poll(&duplicate_wait, 1, 250); }
        while (duplicate_poll < 0 && errno == EINTR);
        int duplicate_outcome = duplicate_poll == 0 ? 0 : 1;
        if (write_all(result_fd, &duplicate_outcome, sizeof(duplicate_outcome)))
            return 37;
    }
    char go;
    if (read_all(release_fd, &go, 1)) return 35;
    return outcome ? 36 : 0;
}

static int run_case(int kill_supervisor)
{
    int sockets[2], app_go[2], result[2], release[2], supervisor_control[2], auth_done[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) ||
        pipe2(app_go, O_CLOEXEC) || pipe2(result, O_CLOEXEC) ||
        pipe2(release, O_CLOEXEC) || pipe2(supervisor_control, O_CLOEXEC) ||
        pipe2(auth_done, O_CLOEXEC)) return 2;
    int enabled = 1;
    if (setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) return 3;
    memset(rx_owner_relay_nonce, 0x41 + kill_supervisor, sizeof(rx_owner_relay_nonce));
    rx_owner_relay_epoch = 700 + kill_supervisor;
    rx_owner_relay_last_packet = 0;
    rx_owner_relay_authenticated = false;
    rx_owner_relay_app_pidfd = -1;
    rx_owner_relay_supervisor_pidfd = -1;
    rx_owner_relay_fd = sockets[0];
    rx_owner_relay_supervisor_pid = -1;
    rx_owner_relay_dispatch = test_dispatch;
    test_mode = kill_supervisor;
    dispatch_calls = 0;

    pid_t app = fork();
    if (app < 0) { perror("fork-app"); return 4; }
    if (!app) {
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(sockets[0]); close(app_go[1]); close(result[0]); close(release[1]);
        close(supervisor_control[0]); close(supervisor_control[1]);
        close(auth_done[0]); close(auth_done[1]);
        int rc = child_app(sockets[1], app_go[0], result[1], release[0], getppid(),
            700 + kill_supervisor, rx_owner_relay_nonce, kill_supervisor);
        _exit(rc);
    }
    close(app_go[0]); close(result[1]); close(release[0]);
    uint64_t owner_start = 0;
    if (cycle_read_start_ticks(getpid(), &owner_start)) { perror("owner-start"); return 5; }
    int app_pidfd = (int)syscall(SYS_pidfd_open, app, 0);
    if (app_pidfd < 0) { perror("app-pidfd"); return 6; }
    pid_t supervisor = fork();
    if (supervisor < 0) { perror("fork-supervisor"); return 7; }
    if (!supervisor) {
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(sockets[0]); close(app_go[1]); close(result[0]); close(result[1]);
        close(release[1]); close(supervisor_control[1]); close(auth_done[0]);
        uint64_t app_start = 0, supervisor_start = 0;
        if (cycle_read_start_ticks(app, &app_start) ||
            cycle_read_start_ticks(getpid(), &supervisor_start)) _exit(41);
        int own_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
        if (own_pidfd < 0) _exit(42);
        struct ker_rx_owner_relay_header auth = {
            .magic = KER_RX_OWNER_RELAY_MAGIC, .version = KER_RX_OWNER_RELAY_VERSION,
            .type = KER_RX_OWNER_RELAY_APP_AUTH, .worker_epoch = 700 + kill_supervisor,
            .app_start_ticks = app_start, .owner_start_ticks = owner_start,
            .supervisor_start_ticks = supervisor_start, .app_pid = (uint32_t)app,
            .owner_pid = (uint32_t)getppid(), .owner_tid = (uint32_t)getppid(),
            .supervisor_pid = (uint32_t)getpid(),
        };
        memset(auth.run_nonce, 0x41 + kill_supervisor, sizeof(auth.run_nonce));
        if (kill_supervisor == 11) auth.run_nonce[0] ^= 0x20;
        if (kill_supervisor == 15) ++auth.worker_epoch;
        int fds[] = {app_pidfd, own_pidfd, own_pidfd};
        size_t rights_count = kill_supervisor == 16 ? 3 : 2;
        if (kill_supervisor == 17) fds[0] = own_pidfd;
        if (send_fds(sockets[1], &auth, sizeof(auth), fds, rights_count)) _exit(43);
        if (write_all(auth_done[1], "S", 1)) _exit(47);
        if (kill_supervisor == 11 || kill_supervisor == 15 ||
            kill_supervisor == 16 ||
            kill_supervisor == 17) {
            struct pollfd unexpected = {.fd = sockets[1], .events = POLLIN};
            int got;
            do { got = poll(&unexpected, 1, 250); } while (got < 0 && errno == EINTR);
            if (got != 0) _exit(48);
            if (write_all(auth_done[1], "N", 1)) _exit(49);
            char command;
            if (read_all(supervisor_control[0], &command, 1)) _exit(50);
            close(own_pidfd);
            _exit(0);
        }
        struct ker_rx_owner_relay_header ack;
        if (recv(sockets[1], &ack, sizeof(ack), 0) != sizeof(ack) ||
            ack.type != KER_RX_OWNER_RELAY_AUTH_ACK) _exit(44);
        if (write_all(auth_done[1], "A", 1)) _exit(45);
        char command;
        if (read_all(supervisor_control[0], &command, 1)) _exit(46);
        close(own_pidfd);
        _exit(0);
    }
    close(sockets[1]); close(supervisor_control[0]); close(auth_done[1]);
    rx_owner_relay_supervisor_pid = supervisor;
    uint64_t supervisor_start = 0;
    if (cycle_read_start_ticks(supervisor, &supervisor_start)) { perror("supervisor-start"); return 8; }
    supervisor_pidfd = (int)syscall(SYS_pidfd_open, supervisor, 0);
    if (supervisor_pidfd < 0) { perror("supervisor-pidfd"); return 8; }
    struct pollfd auth_wait = {.fd = sockets[0], .events = POLLIN};
    int auth_fds_before = open_fd_count();
    int auth_poll = poll(&auth_wait, 1, 2000);
    int auth_pump = auth_poll == 1 ? rx_owner_relay_pump(&rx_owner_relay_fd) : -999;
    if (kill_supervisor == 11 || kill_supervisor == 15 ||
        kill_supervisor == 16 || kill_supervisor == 17) {
        char stage = 0, rejected = 0;
        int expected_auth = kill_supervisor == 16 ? -EMSGSIZE :
            kill_supervisor == 17 ? -EACCES : -EPROTO;
        if (auth_poll != 1 || auth_pump != expected_auth ||
            read_all(auth_done[0], &stage, 1) || stage != 'S' ||
            read_all(auth_done[0], &rejected, 1) || rejected != 'N' ||
            rx_owner_relay_authenticated || dispatch_calls ||
            open_fd_count() != auth_fds_before) return 9;
        struct pollfd app_live = {.fd = app_pidfd, .events = POLLIN};
        if (poll(&app_live, 1, 0) != 0 ||
            syscall(SYS_pidfd_send_signal, app_pidfd, SIGKILL, NULL, 0)) return 10;
        struct pollfd app_dead = {.fd = app_pidfd, .events = POLLIN};
        int dead;
        do { dead = poll(&app_dead, 1, 2000); } while (dead < 0 && errno == EINTR);
        int app_status = 0;
        pid_t app_waited;
        do { app_waited = waitpid(app, &app_status, 0); }
        while (app_waited < 0 && errno == EINTR);
        if (dead != 1 || app_waited != app || !WIFSIGNALED(app_status) ||
            WTERMSIG(app_status) != SIGKILL) return 11;
        app = -1;
        if (write_all(supervisor_control[1], "X", 1)) return 12;
        int supervisor_status = 0;
        pid_t supervisor_waited;
        do { supervisor_waited = waitpid(supervisor, &supervisor_status, 0); }
        while (supervisor_waited < 0 && errno == EINTR);
        if (supervisor_waited != supervisor || !WIFEXITED(supervisor_status) ||
            WEXITSTATUS(supervisor_status)) return 13;
        supervisor = -1;
        fprintf(stderr, "RX_OWNER_PUMP mode=%d auth=%d ack=none dispatches=0 app_killed=1 fd_delta=0\n",
            kill_supervisor, auth_pump);
        close(app_pidfd); close(supervisor_pidfd); close(sockets[0]);
        close(app_go[1]); close(result[0]); close(release[1]);
        close(supervisor_control[1]); close(auth_done[0]);
        return 0;
    }
    if (auth_poll != 1 || auth_pump) {
        int status = 0; pid_t w = waitpid(supervisor, &status, WNOHANG);
        fprintf(stderr, "pump-auth mode=%d poll=%d revents=%x status=%d supervisor_wait=%d child_status=%d\n",
            kill_supervisor, auth_poll, auth_wait.revents, auth_pump, (int)w, status);
        return 9;
    }
    char ready;
    if (read_all(auth_done[0], &ready, 1) || ready != 'S') {
        int status = 0; pid_t waited = waitpid(supervisor, &status, WNOHANG);
        fprintf(stderr, "auth-done mode=%d byte=%d supervisor_wait=%d status=%d\n",
            kill_supervisor, (int)(unsigned char)ready, (int)waited, status);
        return 10;
    }
    if (read_all(auth_done[0], &ready, 1) || ready != 'A') {
        int status = 0; pid_t waited = waitpid(supervisor, &status, WNOHANG);
        fprintf(stderr, "auth-ack mode=%d supervisor_wait=%d status=%d\n",
            kill_supervisor, (int)waited, status);
        return 10;
    }
    struct {
        uint32_t supervisor_pid;
        uint64_t owner_start;
        uint64_t supervisor_start;
    } identity = {(uint32_t)supervisor, owner_start, supervisor_start};
    if (write_all(app_go[1], &identity, sizeof(identity))) { perror("app-ident"); return 11; }
    struct pollfd data_wait = {.fd = sockets[0], .events = POLLIN};
    int data_poll = poll(&data_wait, 1, 2000);
    if (data_poll != 1) {
        int status=0; pid_t w=waitpid(app,&status,WNOHANG);
        fprintf(stderr, "pump-data mode=%d poll=%d revents=%x appwait=%d status=%d\n",
            kill_supervisor,data_poll,data_wait.revents,(int)w,status);
        return 12;
    }
    int data_fds_before = open_fd_count();
    int pump_status = rx_owner_relay_pump(&rx_owner_relay_fd);
    int child_outcome = -1;
    if (read_all(result[0], &child_outcome, sizeof(child_outcome))) { perror("app-outcome"); return 13; }
    int duplicate_status = 0, duplicate_outcome = 0;
    if (kill_supervisor == 8) {
        struct pollfd duplicate = {.fd = sockets[0], .events = POLLIN};
        if (poll(&duplicate, 1, 2000) != 1) return 14;
        duplicate_status = rx_owner_relay_pump(&rx_owner_relay_fd);
        if (read_all(result[0], &duplicate_outcome, sizeof(duplicate_outcome))) return 15;
    }
    struct pollfd app_liveness = {.fd = app_pidfd, .events = POLLIN};
    int app_alive = poll(&app_liveness, 1, 0) == 0;
    int expected_status = kill_supervisor == 1 || kill_supervisor == 10 ? -ESTALE :
        kill_supervisor == 2 ? -EIO :
        (kill_supervisor == 9 || kill_supervisor == 13 || kill_supervisor == 14) ?
            -EPROTO : 0;
    bool expected = pump_status == expected_status && child_outcome == 0 && app_alive;
    expected = expected && dispatch_calls ==
        ((kill_supervisor == 9 || kill_supervisor == 13 || kill_supervisor == 14) ? 0U : 1U);
    if (kill_supervisor == 13 || kill_supervisor == 14)
        expected = expected && open_fd_count() == data_fds_before;
    if (kill_supervisor == 8)
        expected = expected && duplicate_status == -EPROTO && duplicate_outcome == 0 &&
            dispatch_calls == 1;
    if (kill_supervisor != 1 && write_all(supervisor_control[1], "X", 1)) expected = false;
    if (kill_supervisor == 1) {
        int status = 0;
        pid_t waited;
        do { waited = waitpid(supervisor, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited == supervisor) supervisor = -1;
        if (waited < 0 || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL)
            expected = false;
    } else {
        int status = 0;
        pid_t waited;
        do { waited = waitpid(supervisor, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited == supervisor) supervisor = -1;
        if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "supervisor-child mode=%d wait=%d status=%d\n",
                kill_supervisor, (int)waited, status);
            expected = false;
        }
    }
    if (write_all(release[1], "R", 1)) expected = false;
    int app_status = 0;
    pid_t app_waited;
    do { app_waited = waitpid(app, &app_status, 0); } while (app_waited < 0 && errno == EINTR);
    if (app_waited == app) app = -1;
    if (app_waited < 0 || !WIFEXITED(app_status) || WEXITSTATUS(app_status) != 0) {
        fprintf(stderr, "app-child mode=%d wait=%d status=%d outcome=%d alive=%d\n",
            kill_supervisor, (int)app_waited, app_status, child_outcome, app_alive);
        expected = false;
    }
    fprintf(stderr, "RX_OWNER_PUMP mode=%d pump=%d outcome=%d app_live_after=%d expected=%d\n",
        kill_supervisor, pump_status, child_outcome, app_alive, expected);
    close(app_pidfd); close(supervisor_pidfd); close(sockets[0]);
    close(app_go[1]); close(result[0]); close(release[1]);
    close(supervisor_control[1]); close(auth_done[0]);
    return expected ? 0 : 20;
}

int main(void)
{
    for (int mode = 0; mode <= 17; ++mode) {
        int status = run_case(mode);
        if (status) return status;
    }
    return 0;
}
