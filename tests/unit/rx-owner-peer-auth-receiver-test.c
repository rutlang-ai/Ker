#define main ker_socket_broker_fixture_unused_main
#include "../posix/socket-broker-rx-owner-relay-fixture.c"
#undef main
#include <dirent.h>

static int fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    while (readdir(directory)) ++count;
    closedir(directory);
    return count;
}

int main(void)
{
    const char *control = getenv("KER_RX_OWNER_AUTH_FD");
    const char *relay = getenv("KER_RX_OWNER_RELAY_FD");
    const char *supervisor = getenv("KER_TEST_PEER_SUPERVISOR_PID");
    const char *supervisor_start = getenv("KER_TEST_PEER_SUPERVISOR_START");
    const char *expect = getenv("KER_TEST_PEER_EXPECT_STATUS");
    if (!control || !relay || !supervisor || !supervisor_start || !expect) return 2;
    struct fixture fixture = {.relay_fd = atoi(relay), .owner_pidfd = -1,
        .supervisor_pidfd = -1, .expected_owner_role = 1,
        .peer = {.fd = -1, .pidfd = -1}, .peer_auth_enabled = true,
        .supervisor_pid = (uint32_t)strtoul(supervisor, NULL, 10),
        .supervisor_start = strtoull(supervisor_start, NULL, 10), .epoch = 77};
    for (unsigned i = 0; i < sizeof(fixture.nonce); ++i) fixture.nonce[i] = (uint8_t)i;
    if (read_start_ticks(getpid(), &fixture.app_start)) return 2;
    int before = fd_count();
    int status = 0;
    uint64_t deadline = monotonic_ns() + UINT64_C(5000000000);
    while (!status && !fixture.owner_authenticated && monotonic_ns() < deadline) {
        status = fixture.owner_expected ? receive_owner_auth(&fixture) : receive_supervisor_owner_auth(&fixture);
        usleep(1000);
    }
    if (status || !fixture.owner_authenticated) {
        fprintf(stderr, "PEER_PRIMARY_AUTH_FAILED status=%d\n", status);
        return 3;
    }
    deadline = monotonic_ns() + UINT64_C(5000000000);
    while (!status && !fixture.peer_authenticated && monotonic_ns() < deadline) {
        status = receive_supervisor_peer_auth(&fixture);
        if (!status) status = receive_peer_owner_auth(&fixture);
        usleep(1000);
    }
    if (!status && !fixture.peer_authenticated) status = -ETIMEDOUT;
    int action = -1;
    if (!status && getenv("KER_TEST_PEER_DUPLICATE")) {
        struct pollfd wait = {.fd = atoi(control), .events = POLLIN};
        if (poll(&wait, 1, 2000) != 1) status = -ETIMEDOUT;
        else status = receive_supervisor_peer_auth(&fixture);
    }
    if (!status) {
        /* Let the supervisor validate the ACK while this exact receiver is
         * still alive, then explicitly release the test-owned sample frame. */
        struct pollfd wait = {.fd = atoi(control), .events = POLLIN};
        char release[8];
        if (poll(&wait, 1, 2000) != 1 || recv(wait.fd, release, sizeof(release), 0) != 8 ||
            memcmp(release, "CONTINUE", 8)) status = -EPROTO;
        if (!peer_authority_live(&fixture)) status = -ESTALE;
        unsigned char frame[64];
        for (unsigned i = 0; i < sizeof(frame); ++i) frame[i] = (uint8_t)i;
        struct ker_rx_owner_relay_header source = fixture.peer.identity;
        source.type = KER_RX_OWNER_RELAY_REPLY;
        source.owner_pid = (uint32_t)fixture.owner_pid;
        source.owner_tid = fixture.owner_tid;
        source.owner_start_ticks = fixture.owner_start;
        source.packet_id = 1;
        source.deadline_ns = monotonic_ns() + UINT64_C(80000000);
        source.frame_bytes = sizeof(frame);
        source.queue_count = 1;
        source.frame_hash32 = frame_hash32(frame, sizeof(frame));
        source.dispatcher_result = -3;
        source.frame_unchanged = 1;
        if (!status) status = ker_rx_owner_relay_peer_forward(&fixture.peer,
            &source, frame, sizeof(frame), &action);
        if (!status && !peer_authority_live(&fixture)) status = -ESTALE;
    }
    if (fixture.owner_pidfd >= 0) close(fixture.owner_pidfd);
    if (fixture.supervisor_pidfd >= 0) close(fixture.supervisor_pidfd);
    close_peer_binding(&fixture);
    int after = fd_count();
    fprintf(stderr, "PEER_AUTH_RECEIVER status=%d action=%d fds_before=%d fds_after=%d\n",
        status, action, before, after);
    int expected = atoi(expect);
    int expected_action = getenv("KER_TEST_PEER_EXPECT_ACTION") ?
        atoi(getenv("KER_TEST_PEER_EXPECT_ACTION")) : KER_RX_DECISION_LOCAL;
    return status == expected && (status || action == expected_action) && before == after ? 0 : 1;
}
