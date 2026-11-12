#define main ker_socket_broker_fixture_unused_main
#include "../posix/socket-broker-rx-owner-relay-fixture.c"
#undef main

static long env_long(const char *name)
{
    const char *text = getenv(name);
    char *end = NULL;
    errno = 0;
    long value = text ? strtol(text, &end, 10) : -1;
    return !text || errno || end == text || *end || value < 0 ? -1 : value;
}

static int finish_success(struct fixture *fixture)
{
    /* Keep the actual C31 pidfd live until the helper has validated its ACK.
     * Process teardown is not an authorization failure in this test model. */
    long fd = env_long("KER_TEST_SOURCE_RELEASE_FD");
    struct pollfd release = {.fd = (int)fd, .events = POLLIN};
    char byte;
    if (fd < 0 || poll(&release, 1, 5000) != 1 || read((int)fd, &byte, 1) != 1 || byte != 'R')
        return 19;
    close(fixture->owner_pidfd); close(fixture->supervisor_pidfd);
    return 0;
}

int main(void)
{
    long control = env_long("KER_RX_OWNER_AUTH_FD");
    long relay = env_long("KER_RX_OWNER_RELAY_FD");
    long supervisor = env_long("KER_TEST_SOURCE_SUPERVISOR_PID");
    long owner = env_long("KER_TEST_SOURCE_CURRENT_PID");
    long owner_start = env_long("KER_TEST_SOURCE_CURRENT_START");
    long owner_cookie = env_long("KER_TEST_SOURCE_CURRENT_COOKIE");
    long owner_device = env_long("KER_TEST_SOURCE_CURRENT_DEVICE");
    long owner_inode = env_long("KER_TEST_SOURCE_CURRENT_INODE");
    long marker = env_long("KER_TEST_SOURCE_MARKER_FD");
    if (control < 3 || relay < 3 || supervisor <= 0 || owner <= 0 ||
        owner_start <= 0 || owner_cookie <= 0 || owner_device <= 0 ||
        owner_inode <= 0 || marker < 0) return 2;
    struct fixture fixture = {.relay_fd = (int)relay, .owner_pidfd = -1,
        .supervisor_pidfd = -1, .source_master_pidfd = -1,
        .source_route_candidate_pidfd = -1, .source_route_candidate_channel = -1,
        .source_route_master_pidfd = -1, .expected_owner_role = 0,
        .owner_pid = (pid_t)owner, .owner_tid = (uint32_t)owner,
        .owner_start = (uint64_t)owner_start, .expected_owner_cookie = (uint64_t)owner_cookie,
        .expected_owner_slot_device = (uint64_t)owner_device,
        .expected_owner_slot_inode = (uint64_t)owner_inode, .owner_expected = true,
        .owner_authenticated = true, .source_route_enabled = true,
        .supervisor_pid = (uint32_t)supervisor, .peer = {.fd = -1, .pidfd = -1}};
    if (read_start_ticks(getpid(), &fixture.app_start) ||
        read_start_ticks((pid_t)supervisor, &fixture.supervisor_start) ||
        pthread_mutex_init(&fixture.source_route_lock, NULL)) return 2;
    fixture.epoch = 77;
    if (getenv("KER_TEST_SOURCE_INFLIGHT")) {
        fixture.packet_id = 991;
        fixture.deadline_ns = monotonic_ns() + UINT64_C(90000000);
        fixture.frame_bytes = 64;
        memset(fixture.pending_frame, 0x5a, fixture.frame_bytes);
    }
    for (unsigned i = 0; i < sizeof(fixture.nonce); ++i) fixture.nonce[i] = (uint8_t)i;
    fixture.owner_pidfd = (int)syscall(SYS_pidfd_open, fixture.owner_pid, 0);
    fixture.supervisor_pidfd = (int)syscall(SYS_pidfd_open, (pid_t)supervisor, 0);
    if (fixture.owner_pidfd < 0 || fixture.supervisor_pidfd < 0) return 2;
    uint64_t deadline = monotonic_ns() + UINT64_C(8000000000);
    bool staged = false;
    uint64_t expired_seen_sequence = 0;
    while (monotonic_ns() < deadline) {
        int status = receive_source_route_command(&fixture);
        if (status) { fprintf(stderr, "SOURCE_ROUTE_COMMAND status=%d\n", status); return 3; }
        if (staged && fixture.packet_id && fixture.source_route_pending &&
            fixture.source_route_last_type == KER_RX_OWNER_SOURCE_ROUTE_COMMIT) {
            uint64_t deadline_before = fixture.deadline_ns;
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || write((int)marker, "B", 1) != 1 ||
                fixture.deadline_ns != deadline_before) return 10;
            fixture.packet_id = 0;
        }
        if (staged && expired_seen_sequence != fixture.source_route_last_sequence &&
                getenv("KER_TEST_SOURCE_EXPIRED_COMMIT") &&
                fixture.source_route_pending && !fixture.source_route_active &&
                fixture.source_route_last_type == KER_RX_OWNER_SOURCE_ROUTE_COMMIT) {
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || write((int)marker, "T", 1) != 1) return 17;
            expired_seen_sequence = fixture.source_route_last_sequence;
        }
        status = authenticate_pending_source_candidate(&fixture);
        if (status) { fprintf(stderr, "SOURCE_ROUTE_AUTH status=%d\n", status); return 4; }
        if (!staged && (fixture.source_route_record.operation_id ||
            fixture.source_route_rejected_operation_id) &&
            !fixture.source_route_pending && !fixture.source_route_candidate_authenticated) {
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || write((int)marker, "N", 1) != 1) return 12;
            return finish_success(&fixture);
        }
        if (fixture.source_route_candidate_authenticated && !staged) {
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || fixture.source_route_active) return 5;
            if (write((int)marker, "P", 1) != 1) return 6;
            staged = true;
        }
        if (fixture.source_route_active) {
            if (fixture.source_route_quarantined) {
                if (current_owner_live(&fixture) || peer_authority_live(&fixture) ||
                        write((int)marker, "Q", 1) != 1) return 18;
                return finish_success(&fixture);
            }
            if (!fixture.peer_authenticated || fixture.peer.fd != (int)relay ||
                fixture.peer.identity.owner_pid != (uint32_t)owner ||
                fixture.owner_pid == (pid_t)owner || !fixture.owner_authenticated ||
                fixture.peer_record.authority_deadline_ns !=
                    fixture.source_route_record.pair.authority_deadline_ns) return 7;
            uint8_t frame[64];
            memset(frame, 0x5a, sizeof(frame));
            struct ker_rx_owner_relay_header source = {
                .magic = KER_RX_OWNER_RELAY_MAGIC,
                .version = KER_RX_OWNER_RELAY_VERSION,
                .type = KER_RX_OWNER_RELAY_REPLY,
                .packet_id = 1,
                .deadline_ns = monotonic_ns() + UINT64_C(80000000),
                .worker_epoch = fixture.epoch,
                .app_start_ticks = fixture.app_start,
                .owner_start_ticks = fixture.owner_start,
                .supervisor_start_ticks = fixture.supervisor_start,
                .app_pid = (uint32_t)getpid(),
                .owner_pid = (uint32_t)fixture.owner_pid,
                .owner_tid = fixture.owner_tid,
                .supervisor_pid = fixture.supervisor_pid,
                .frame_bytes = sizeof(frame), .queue_count = 1,
                .frame_hash32 = frame_hash32(frame, sizeof(frame)),
                .dispatcher_result = -3, .frame_unchanged = 1,
            };
            memcpy(source.run_nonce, fixture.nonce, sizeof(source.run_nonce));
            int action = -1;
            int peer_status = peer_authority_live(&fixture) ?
                ker_rx_owner_relay_peer_forward(&fixture.peer, &source, frame,
                    sizeof(frame), &action) : -ESTALE;
            if (peer_status || action != KER_RX_DECISION_LOCAL) {
                fprintf(stderr, "SOURCE_ROUTE_OLD_LOCAL status=%d action=%d\n",
                    peer_status, action);
                return 13;
            }
            if (write((int)marker, "C", 1) != 1) return 8;
            if (write((int)marker, "L", 1) != 1) return 14;
            if (getenv("KER_TEST_SOURCE_WAIT_MASTER_DEATH")) {
                struct pollfd master = {.fd = fixture.source_master_pidfd, .events = POLLIN};
                if (poll(&master, 1, 3000) != 1 || peer_authority_live(&fixture) ||
                    write((int)marker, "D", 1) != 1) return 15;
            }
            if (getenv("KER_TEST_SOURCE_WAIT_AUTHORITY_EXPIRY")) {
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
                while (monotonic_ns() < fixture.source_route_record.pair.authority_deadline_ns)
                    (void)nanosleep(&pause, NULL);
                if (current_owner_live(&fixture) || peer_authority_live(&fixture) ||
                    write((int)marker, "X", 1) != 1) return 16;
            }
            return finish_success(&fixture);
        }
        if (staged && !fixture.source_route_pending) {
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || write((int)marker, "A", 1) != 1) return 11;
            return finish_success(&fixture);
        }
        usleep(1000);
    }
    return 9;
}
