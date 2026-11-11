#define main ker_socket_broker_fixture_unused_main
#include "../posix/socket-broker-rx-owner-relay-fixture.c"
#undef main

#include <sys/prctl.h>
#include <sys/wait.h>
#include <fcntl.h>

static int stop_calls;
static int completed_calls;
static enum ker_rx_decision_action completed_action;

int ker_posix_rx_decision_is_ready(void) { return 0; }
int ker_posix_rx_decision_complete(uint64_t packet_id, int action)
{
    if (!packet_id) return -EINVAL;
    ++completed_calls;
    completed_action = (enum ker_rx_decision_action)action;
    return 0;
}
void ker_posix_stop_run(void) { ++stop_calls; }

static int fail(const char *stage, int code)
{
    fprintf(stderr, "APP_LOOP_TEST_FAIL stage=%s code=%d errno=%d\n",
        stage, code, errno);
    return 1;
}

static int read_release_byte(int fd, char *value)
{
    for (;;) {
        ssize_t count = read(fd, value, 1);
        if (count == 1) return 0;
        if (count < 0 && errno == EINTR) continue;
        return -1;
    }
}

static int write_release_byte(int fd)
{
    const char value = 'R';
    for (;;) {
        ssize_t count = write(fd, &value, 1);
        if (count == 1) return 0;
        if (count < 0 && errno == EINTR) continue;
        return -1;
    }
}

int main(void)
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets))
        return fail("socketpair", -errno);
    struct fixture fixture = {
        .relay_fd = sockets[0], .owner_pidfd = -1, .supervisor_pidfd = -1,
        .owner_expected = true, .owner_authenticated = true, .ready = true,
        .packet_id = 44, .deadline_ns = 1, .frame_bytes = 64, .queue_count = 1,
    };
    atomic_init(&fixture.broker_done, true);
    int status = app_loop(&fixture);
    if (status != -EBUSY || stop_calls || completed_calls || fixture.packet_id != 44)
        return fail("pending-stop-must-remain-unsettled", status);

    fixture.packet_id = 0;
    status = app_loop(&fixture);
    if (status || stop_calls != 1 || completed_calls)
        return fail("stop-after-no-pending-lease", status);
    close(sockets[0]); close(sockets[1]);

    int response_sockets[2], release[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, response_sockets) ||
        pipe2(release, O_CLOEXEC)) return fail("response-pair", -errno);
    int enabled = 1;
    if (setsockopt(response_sockets[0], SOL_SOCKET, SO_PASSCRED, &enabled,
            sizeof(enabled))) return fail("passcred", -errno);
    struct fixture peer_fixture = {
        .relay_fd = response_sockets[0], .owner_pidfd = -1,
        .supervisor_pidfd = -1, .owner_expected = true,
        .owner_authenticated = true, .ready = true, .packet_id = 88,
        .deadline_ns = monotonic_ns() + UINT64_C(5000000000),
        .frame_bytes = 64, .queue_id = 0, .queue_count = 1,
        .epoch = 701, .vlan_tci = 0, .vlan_stripped = 0,
    };
    memset(peer_fixture.nonce, 0x7d, sizeof(peer_fixture.nonce));
    peer_fixture.app_start = 0;
    peer_fixture.supervisor_pid = (uint32_t)getpid();
    if (read_start_ticks(getpid(), &peer_fixture.app_start) ||
        read_start_ticks(getpid(), &peer_fixture.supervisor_start))
        return fail("self-start", -errno);
    peer_fixture.supervisor_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (peer_fixture.supervisor_pidfd < 0) return fail("self-pidfd", -errno);
    for (size_t i = 0; i < peer_fixture.frame_bytes; ++i)
        peer_fixture.pending_frame[i] = (uint8_t)(i ^ 0x5a);
    peer_fixture.current_frame_hash = frame_hash32(peer_fixture.pending_frame,
        peer_fixture.frame_bytes);
    atomic_init(&peer_fixture.broker_done, true);
    pid_t owner = fork();
    if (owner < 0) return fail("owner-fork", -errno);
    if (!owner) {
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(response_sockets[0]); close(release[1]);
        uint64_t owner_start = 0;
        if (read_start_ticks(getpid(), &owner_start)) _exit(51);
        struct ker_rx_owner_relay_header reply = {
            .magic = KER_RX_OWNER_RELAY_MAGIC,
            .version = KER_RX_OWNER_RELAY_VERSION,
            .type = KER_RX_OWNER_RELAY_REPLY,
            .packet_id = peer_fixture.packet_id,
            .deadline_ns = peer_fixture.deadline_ns,
            .worker_epoch = peer_fixture.epoch,
            .app_start_ticks = peer_fixture.app_start,
            .owner_start_ticks = owner_start,
            .supervisor_start_ticks = peer_fixture.supervisor_start,
            .app_pid = (uint32_t)getppid(), .owner_pid = (uint32_t)getpid(),
            .owner_tid = (uint32_t)getpid(),
            .supervisor_pid = peer_fixture.supervisor_pid,
            .frame_bytes = peer_fixture.frame_bytes,
            .queue_id = peer_fixture.queue_id,
            .queue_count = peer_fixture.queue_count,
            .dispatcher_result = -3,
            .frame_unchanged = 1,
            .frame_hash32 = peer_fixture.current_frame_hash,
        };
        memcpy(reply.run_nonce, peer_fixture.nonce, sizeof(reply.run_nonce));
        struct iovec vectors[] = {
            {.iov_base = &reply, .iov_len = sizeof(reply)},
            {.iov_base = peer_fixture.pending_frame,
                .iov_len = peer_fixture.frame_bytes},
        };
        struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
        if (sendmsg(response_sockets[1], &message, MSG_NOSIGNAL) !=
            (ssize_t)(sizeof(reply) + peer_fixture.frame_bytes)) _exit(52);
        char release_byte;
        if (read_release_byte(release[0], &release_byte)) _exit(53);
        _exit(0);
    }
    close(response_sockets[1]); close(release[0]);
    peer_fixture.owner_pid = owner;
    peer_fixture.owner_tid = (uint32_t)owner;
    if (read_start_ticks(owner, &peer_fixture.owner_start))
        return fail("owner-start", -errno);
    peer_fixture.owner_pidfd = (int)syscall(SYS_pidfd_open, owner, 0);
    if (peer_fixture.owner_pidfd < 0) return fail("owner-pidfd", -errno);
    struct pollfd response_ready = {.fd = response_sockets[0], .events = POLLIN};
    if (poll(&response_ready, 1, 2000) != 1)
        return fail("owner-reply-ready", -ETIMEDOUT);
    status = app_loop(&peer_fixture);
    if (status || peer_fixture.packet_id || completed_calls != 1 ||
        completed_action != KER_RX_DECISION_DROP || stop_calls != 2)
        return fail("peer-result-must-map-to-drop", status);
    if (write_release_byte(release[1])) return fail("release-owner", -errno);
    int owner_status = 0;
    pid_t waited;
    do { waited = waitpid(owner, &owner_status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != owner || !WIFEXITED(owner_status) || WEXITSTATUS(owner_status))
        return fail("owner-reap", owner_status);
    close(peer_fixture.owner_pidfd); close(peer_fixture.supervisor_pidfd);
    close(response_sockets[0]); close(release[1]);
    puts("APP_LOOP_PENDING_STOP pending=EBUSY/no-stop; PEER reply maps DROP before stop");
    return 0;
}
