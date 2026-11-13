#define main ker_socket_broker_fixture_unused_main
#include "../posix/socket-broker-rx-owner-relay-fixture.c"
#undef main

#include <signal.h>

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

struct late_route_poll_barrier {
    int ready_fd;
    int release_fd;
    bool released;
};

static int release_after_empty_source_route_poll(void *opaque)
{
    struct late_route_poll_barrier *barrier = opaque;
    if (!barrier || barrier->released) return 0;
    char byte = 0;
    if (write(barrier->ready_fd, "E", 1) != 1 ||
        read(barrier->release_fd, &byte, 1) != 1 || byte != 'R') return -EIO;
    barrier->released = true;
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
    bool deferred_commit = getenv("KER_TEST_SOURCE_DEFERRED_COMMIT") != NULL;
    bool inflight = getenv("KER_TEST_SOURCE_INFLIGHT") != NULL;
    if (deferred_commit && !inflight) return 2;
    struct fixture fixture = {.relay_fd = (int)relay, .owner_pidfd = -1,
        .supervisor_pidfd = -1, .source_master_pidfd = -1,
        .source_route_candidate_pidfd = -1, .source_route_candidate_channel = -1,
        .source_route_master_pidfd = -1, .source_route_aborted_candidate_pidfd = -1,
        .source_route_aborted_master_pidfd = -1, .expected_owner_role = 0,
        .owner_pid = (pid_t)owner, .owner_tid = (uint32_t)owner,
        .owner_start = (uint64_t)owner_start, .expected_owner_cookie = (uint64_t)owner_cookie,
        .expected_owner_slot_device = (uint64_t)owner_device,
        .expected_owner_slot_inode = (uint64_t)owner_inode, .owner_expected = true,
        .owner_authenticated = true, .source_route_enabled = true,
        .supervisor_pid = (uint32_t)supervisor, .peer = {.fd = -1, .pidfd = -1}};
    bool late_route_arrival = getenv("KER_TEST_SOURCE_LATE_ROUTE_AFTER_EMPTY") != NULL;
    fixture.peer_auth_enabled = late_route_arrival;
    struct late_route_poll_barrier late_route_barrier = {
        .ready_fd = (int)env_long("KER_TEST_SOURCE_ROUTE_EMPTY_READY_FD"),
        .release_fd = (int)env_long("KER_TEST_SOURCE_ROUTE_EMPTY_RELEASE_FD")};
    if (late_route_arrival &&
        (late_route_barrier.ready_fd < 0 || late_route_barrier.release_fd < 0)) return 2;
    if (read_start_ticks(getpid(), &fixture.app_start) ||
        read_start_ticks((pid_t)supervisor, &fixture.supervisor_start) ||
        pthread_mutex_init(&fixture.source_route_lock, NULL)) return 2;
    fixture.epoch = 77;
    if (getenv("KER_TEST_SOURCE_INFLIGHT")) {
        fixture.packet_id = 991;
        fixture.deadline_ns = monotonic_ns() + UINT64_C(90000000);
        fixture.frame_bytes = 64;
        memset(fixture.pending_frame, 0x5a, fixture.frame_bytes);
        fixture.current_frame_hash = frame_hash32(fixture.pending_frame,
            fixture.frame_bytes);
    }
    for (unsigned i = 0; i < sizeof(fixture.nonce); ++i) fixture.nonce[i] = (uint8_t)i;
    fixture.owner_pidfd = (int)syscall(SYS_pidfd_open, fixture.owner_pid, 0);
    fixture.supervisor_pidfd = (int)syscall(SYS_pidfd_open, (pid_t)supervisor, 0);
    if (fixture.owner_pidfd < 0 || fixture.supervisor_pidfd < 0) return 2;
    uint64_t deadline = monotonic_ns() + UINT64_C(8000000000);
    bool staged = false;
    bool waiting_successor = false;
    bool retired_peer_reported = false;
    bool successor_inflight = getenv("KER_TEST_SOURCE_ROUTE_SUCCESSOR_INFLIGHT") != NULL;
    bool successor_inflight_reported = false;
    unsigned active_routes_seen = 0;
    uint64_t expired_seen_sequence = 0;
    while (monotonic_ns() < deadline) {
        if (waiting_successor && !retired_peer_reported) {
            struct pollfd retired = {.fd = fixture.peer.pidfd, .events = POLLIN};
            if (poll(&retired, 1, 0) == 1 && (retired.revents & POLLIN)) {
                if (write((int)marker, "D", 1) != 1) return 32;
                retired_peer_reported = true;
            }
        }
        int status = poll_owner_control(&fixture,
            late_route_arrival ? release_after_empty_source_route_poll : NULL,
            &late_route_barrier);
        if (getenv("KER_TEST_SOURCE_ROUTE_REPLAY") && status == -ESTALE &&
                fixture.source_route_active && active_routes_seen == 2 &&
                fixture.owner_pid ==
                    (pid_t)fixture.source_route_record.pair.owner.owner_pid &&
                write((int)marker, "R", 1) == 1)
            return finish_success(&fixture);
        if (getenv("KER_TEST_SOURCE_ROUTE_DEAD_CURRENT") && waiting_successor &&
                fixture.source_route_last_type ==
                    KER_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE &&
                fixture.source_route_rejected_operation_id &&
                fixture.source_route_last_sequence >
                    fixture.source_route_committed_record.command_sequence + 1 &&
                !fixture.source_route_pending && !current_owner_live(&fixture)) {
            if (!fixture.source_route_active || fixture.owner_pid == (pid_t)owner ||
                fixture.relay_fd == (int)relay || write((int)marker, "R", 1) != 1)
                return 33;
            return finish_success(&fixture);
        }
        if (getenv("KER_TEST_SOURCE_ROUTE_SECOND_SUCCESSOR") && waiting_successor &&
                fixture.source_route_successor_used &&
                fixture.source_route_last_type ==
                    KER_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE &&
                fixture.source_route_rejected_operation_id &&
                fixture.source_route_last_sequence >
                    fixture.source_route_committed_record.command_sequence &&
                !fixture.source_route_pending && current_owner_live(&fixture)) {
            if (!fixture.source_route_active || fixture.owner_pid == (pid_t)owner ||
                fixture.relay_fd == (int)relay || write((int)marker, "R", 1) != 1)
                return 34;
            return finish_success(&fixture);
        }
        if (status) { fprintf(stderr, "SOURCE_ROUTE_COMMAND status=%d\n", status); return 3; }
        if (successor_inflight && fixture.source_route_pending &&
                fixture.source_route_record.pair.owner.type ==
                    KER_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE &&
                fixture.source_route_candidate_authenticated && !successor_inflight_reported) {
            if (!fixture.source_route_active || fixture.packet_id != 991 ||
                !fixture.deadline_ns || fixture.owner_pid !=
                    (pid_t)fixture.source_route_record.pair.primary_pid ||
                fixture.relay_fd == fixture.source_route_candidate_channel ||
                fixture.peer.fd >= 0 || write((int)marker, "B", 1) != 1) return 35;
            successor_inflight_reported = true;
        }
        if (successor_inflight && fixture.source_route_cut_pending) {
            uint64_t deadline_before = fixture.deadline_ns;
            uint64_t packet_before = fixture.packet_id;
            uint32_t hash_before = fixture.current_frame_hash;
            if (!packet_before || packet_before != fixture.source_route_cut_packet_id ||
                deadline_before != fixture.source_route_cut_frame_deadline_ns ||
                hash_before != fixture.source_route_cut_frame_hash ||
                fixture.owner_pid != (pid_t)fixture.source_route_cut_record.pair.primary_pid ||
                fixture.relay_fd == fixture.source_route_candidate_channel ||
                fixture.peer.fd >= 0) return 36;
            fixture.source_route_cut_completed_id = packet_before;
            fixture.source_route_cut_completed_ns = monotonic_ns();
            fixture.packet_id = 0;
            fixture.completed++;
            if (fixture.deadline_ns != deadline_before ||
                fixture.source_route_cut_completed_ns >= deadline_before ||
                write((int)marker, "F", 1) != 1) return 37;
            status = progress_source_route_cut(&fixture);
            if (status || fixture.source_route_cut_pending ||
                fixture.deadline_ns != deadline_before || fixture.completed != 1 ||
                !fixture.source_route_active || fixture.owner_pid ==
                    (pid_t)fixture.source_route_cut_record.pair.primary_pid) return 38;
        }
        uint16_t expected_commit = deferred_commit ?
            KER_RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME :
            KER_RX_OWNER_SOURCE_ROUTE_COMMIT;
        if (!successor_inflight && staged && fixture.packet_id && fixture.source_route_pending &&
            fixture.source_route_last_type == expected_commit) {
            uint64_t deadline_before = fixture.deadline_ns;
            uint64_t packet_before = fixture.packet_id;
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || write((int)marker, "B", 1) != 1 ||
                fixture.deadline_ns != deadline_before) return 10;
            if (!deferred_commit) {
                fixture.packet_id = 0;
            } else {
                if (!fixture.source_route_cut_pending ||
                    fixture.source_route_cut_record.pair.owner.type !=
                        KER_RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME ||
                    fixture.source_route_cut_packet_id != packet_before ||
                    fixture.source_route_cut_frame_deadline_ns != deadline_before ||
                    fixture.source_route_cut_frame_hash != fixture.current_frame_hash ||
                    fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                    fixture.peer.fd >= 0) return 20;
                if (getenv("KER_TEST_SOURCE_DEFERRED_SECOND")) {
                    struct pollfd command = {.fd = (int)control, .events = POLLIN};
                    if (poll(&command, 1, 2000) != 1 || !(command.revents & POLLIN)) return 21;
                    status = receive_source_route_command(&fixture);
                    if (status >= 0 || fixture.source_route_cut_pending ||
                        fixture.source_route_active || fixture.owner_pid != (pid_t)owner ||
                        fixture.relay_fd != (int)relay || fixture.peer.fd >= 0 ||
                        write((int)marker, "T", 1) != 1) return 22;
                    return finish_success(&fixture);
                }
                if (getenv("KER_TEST_SOURCE_DEFERRED_EXPIRED")) {
                    struct timespec pause = {.tv_sec = 0, .tv_nsec = 120000000};
                    while (nanosleep(&pause, &pause) && errno == EINTR) { }
                    fprintf(stderr, "DEFERRED_DIAG expired context=%d actors=%d now=%llu frame=%llu command=%llu\n",
                        source_route_commit_context_live(&fixture,
                            &fixture.source_route_cut_record),
                        source_route_commit_actors_live(&fixture,
                            &fixture.source_route_cut_record, NULL),
                        (unsigned long long)monotonic_ns(),
                        (unsigned long long)fixture.deadline_ns,
                        (unsigned long long)fixture.source_route_cut_record.command_deadline_ns);
                    status = progress_source_route_cut(&fixture);
                    if (status >= 0 || fixture.source_route_cut_pending ||
                        fixture.source_route_active || fixture.owner_pid != (pid_t)owner ||
                        fixture.relay_fd != (int)relay || fixture.peer.fd >= 0 ||
                        fixture.deadline_ns != deadline_before ||
                        write((int)marker, "T", 1) != 1) return 23;
                    return finish_success(&fixture);
                }
                if (getenv("KER_TEST_SOURCE_DEFERRED_LATE_COMPLETION")) {
                    struct timespec pause = {.tv_sec = 0, .tv_nsec = 120000000};
                    while (nanosleep(&pause, &pause) && errno == EINTR) { }
                    fixture.source_route_cut_completed_id = packet_before;
                    fixture.source_route_cut_completed_ns = monotonic_ns();
                    fixture.packet_id = 0;
                    fixture.completed++;
                    fprintf(stderr, "DEFERRED_DIAG late context=%d actors=%d now=%llu frame=%llu command=%llu completed=%llu\n",
                        source_route_commit_context_live(&fixture,
                            &fixture.source_route_cut_record),
                        source_route_commit_actors_live(&fixture,
                            &fixture.source_route_cut_record, NULL),
                        (unsigned long long)monotonic_ns(),
                        (unsigned long long)fixture.deadline_ns,
                        (unsigned long long)fixture.source_route_cut_record.command_deadline_ns,
                        (unsigned long long)fixture.source_route_cut_completed_ns);
                    if (fixture.deadline_ns != deadline_before ||
                        write((int)marker, "F", 1) != 1) return 28;
                    status = progress_source_route_cut(&fixture);
                    if (status >= 0 || fixture.source_route_cut_pending ||
                        fixture.source_route_active || fixture.owner_pid != (pid_t)owner ||
                        fixture.relay_fd != (int)relay || fixture.peer.fd >= 0 ||
                        fixture.deadline_ns != deadline_before ||
                        write((int)marker, "T", 1) != 1) return 29;
                    return finish_success(&fixture);
                }
                if (getenv("KER_TEST_SOURCE_DEFERRED_DEAD")) {
                    if (syscall(SYS_pidfd_send_signal,
                            fixture.source_route_candidate_pidfd, SIGKILL, NULL, 0)) return 24;
                    struct pollfd dead = {.fd = fixture.source_route_candidate_pidfd,
                        .events = POLLIN};
                    if (poll(&dead, 1, 1000) != 1 || !(dead.revents & POLLIN)) return 30;
                }
                fixture.source_route_cut_completed_id = packet_before;
                fixture.source_route_cut_completed_ns = monotonic_ns();
                fixture.packet_id = 0;
                fixture.completed++;
                if (fixture.deadline_ns != deadline_before ||
                    fixture.source_route_cut_completed_id != packet_before ||
                    write((int)marker, "F", 1) != 1) return 25;
                status = progress_source_route_cut(&fixture);
                if (getenv("KER_TEST_SOURCE_DEFERRED_DEAD")) {
                    if (status >= 0 || fixture.source_route_cut_pending ||
                        fixture.source_route_active || fixture.owner_pid != (pid_t)owner ||
                        fixture.relay_fd != (int)relay || fixture.peer.fd >= 0 ||
                        fixture.deadline_ns != deadline_before ||
                        write((int)marker, "T", 1) != 1) return 26;
                    return finish_success(&fixture);
                }
                if (status || fixture.source_route_cut_pending || !fixture.source_route_active ||
                    fixture.owner_pid == (pid_t)owner || fixture.completed != 1 ||
                    fixture.deadline_ns != deadline_before) return 27;
            }
        }
        if (staged && expired_seen_sequence != fixture.source_route_last_sequence &&
                getenv("KER_TEST_SOURCE_EXPIRED_COMMIT") &&
                fixture.source_route_pending && !fixture.source_route_active &&
                fixture.source_route_last_type == KER_RX_OWNER_SOURCE_ROUTE_COMMIT) {
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || write((int)marker, "T", 1) != 1) return 17;
            expired_seen_sequence = fixture.source_route_last_sequence;
        }
        if (!staged && (fixture.source_route_record.operation_id ||
            fixture.source_route_rejected_operation_id) &&
            !fixture.source_route_pending && !fixture.source_route_candidate_authenticated &&
            !waiting_successor &&
            !(getenv("KER_TEST_SOURCE_ROUTE_RETRY") && fixture.source_route_aborted)) {
            if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                fixture.peer.fd >= 0 || write((int)marker, "N", 1) != 1) return 12;
            return finish_success(&fixture);
        }
        if (fixture.source_route_candidate_authenticated && !staged) {
            bool successor_candidate = fixture.source_route_record.pair.owner.type ==
                KER_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE;
            if (successor_candidate) {
                if (!fixture.source_route_active || fixture.peer.fd >= 0 ||
                    fixture.owner_pid != (pid_t)fixture.source_route_record.pair.primary_pid ||
                    fixture.relay_fd == fixture.source_route_candidate_channel) return 5;
            } else if (fixture.owner_pid != (pid_t)owner || fixture.relay_fd != (int)relay ||
                    fixture.peer.fd >= 0 || fixture.source_route_active) return 5;
            if (write((int)marker, "P", 1) != 1) return 6;
            staged = true;
            waiting_successor = false;
        }
        if (fixture.source_route_active && (active_routes_seen == 0 ||
                (getenv("KER_TEST_SOURCE_ROUTE_SUCCESSOR") && active_routes_seen == 1 &&
                 !fixture.source_route_pending &&
                 fixture.source_route_committed_record.source_epoch ==
                    KER_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_EPOCH))) {
            if (fixture.source_route_quarantined) {
                if (current_owner_live(&fixture) || peer_authority_live(&fixture) ||
                        write((int)marker, "Q", 1) != 1) return 18;
                return finish_success(&fixture);
            }
            if (!fixture.peer_authenticated || fixture.peer.fd < 0 ||
                fixture.peer.identity.owner_pid != fixture.source_route_record.pair.primary_pid ||
                fixture.owner_pid != (pid_t)fixture.source_route_record.pair.owner.owner_pid ||
                !fixture.owner_authenticated ||
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
            active_routes_seen++;
            if (successor_inflight && active_routes_seen == 1) {
                fixture.packet_id = 991;
                fixture.deadline_ns = monotonic_ns() + UINT64_C(500000000);
                fixture.frame_bytes = 64;
                memset(fixture.pending_frame, 0x5a, fixture.frame_bytes);
                fixture.current_frame_hash = frame_hash32(fixture.pending_frame,
                    fixture.frame_bytes);
            }
            if (getenv("KER_TEST_SOURCE_ROUTE_SUCCESSOR") && active_routes_seen == 1) {
                if (successor_inflight &&
                    (fixture.packet_id != 991 || fixture.peer_forward_pending)) return 31;
                staged = false;
                waiting_successor = true;
                continue;
            }
            if (getenv("KER_TEST_SOURCE_ROUTE_SECOND_SUCCESSOR") &&
                    active_routes_seen == 2) {
                staged = false;
                waiting_successor = true;
                continue;
            }
            if (getenv("KER_TEST_SOURCE_ROUTE_REPLAY") && active_routes_seen == 2) {
                staged = false;
                waiting_successor = true;
                continue;
            }
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
            if (getenv("KER_TEST_SOURCE_ROUTE_RETRY") &&
                    fixture.source_route_aborted &&
                    fixture.source_route_last_type == KER_RX_OWNER_SOURCE_ROUTE_ABORT &&
                    fixture.source_route_record.source_epoch == KER_RX_OWNER_SOURCE_ROUTE_EPOCH) {
                staged = false;
                continue;
            }
            return finish_success(&fixture);
        }
        usleep(1000);
    }
    return 9;
}
