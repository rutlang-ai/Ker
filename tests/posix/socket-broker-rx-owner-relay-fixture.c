#define _GNU_SOURCE
#include "rx-decision-consumer.h"
#include "rx-owner-relay-wire.h"
#include "rx-owner-auth-wire.h"
#include "rx-owner-relay-peer.h"
#include <ker/posix.h>
#include <ker/socket-broker-server.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct fixture {
    struct ker_socket_broker_server *broker;
    int relay_fd;
    struct ker_rx_owner_relay_peer peer;
    struct ker_rx_owner_peer_auth_record peer_record;
    struct ker_rx_owner_source_route_record source_route_record;
    int source_route_candidate_pidfd;
    int source_route_candidate_channel;
    int source_route_master_pidfd;
    int source_route_aborted_candidate_pidfd;
    int source_route_aborted_master_pidfd;
    struct ker_rx_owner_source_route_record source_route_first_record;
    uint64_t source_route_last_sequence;
    uint64_t source_route_last_operation_id;
    uint64_t source_route_rejected_operation_id;
    uint16_t source_route_last_type;
    bool source_route_pending;
    bool source_route_candidate_authenticated;
    bool source_route_aborted;
    bool source_route_retry_used;
    bool source_route_active;
    bool source_route_quarantined;
    bool source_route_enabled;
    bool source_route_cut_pending;
    bool source_route_cut_progress_traced;
    bool source_route_cut_reply_poll_traced;
    struct ker_rx_owner_source_route_record source_route_cut_record;
    uint64_t source_route_cut_packet_id;
    uint64_t source_route_cut_frame_deadline_ns;
    uint32_t source_route_cut_frame_hash;
    uint64_t source_route_cut_completed_id;
    uint64_t source_route_cut_completed_ns;
    pthread_mutex_t source_route_lock;
    bool peer_authenticated;
    bool peer_forward_pending;
    struct ker_rx_owner_relay_header peer_source_reply;
    bool peer_auth_enabled;
    uint64_t peer_auth_deadline_ns;
    atomic_bool broker_done;
    int broker_status;
    uint64_t callbacks;
    uint64_t deferred;
    uint64_t completed;
    uint64_t startup_drops;
    uint64_t probe_witnesses;
    uint64_t probe_packet_id;
    uint32_t probe_frame_hash;
    uint16_t probe_source_port;
    uint16_t expected_probe_source_port;
    uint64_t peer_packet_id;
    uint32_t peer_frame_hash;
    uint16_t peer_source_port;
    uint16_t expected_peer_source_port;
    uint64_t peer_witnesses;
    int32_t peer_dispatcher_result;
    uint16_t expected_probe_destination_port;
    int32_t probe_dispatcher_result;
    uint32_t current_frame_hash;
    const char *probe_token;
    bool pending_probe;
    bool pending_peer_probe;
    bool source_revoke_test;
    uint8_t pending_frame[KER_RX_OWNER_RELAY_MAX_FRAME];
    atomic_uint_fast64_t packet_id;
    uint64_t deadline_ns;
    uint32_t frame_bytes;
    uint16_t queue_id;
    uint16_t queue_count;
    uint16_t vlan_tci;
    uint8_t vlan_stripped;
    uint8_t nonce[KER_RX_OWNER_RELAY_NONCE_BYTES];
    uint8_t broker_nonce[KER_RX_OWNER_RELAY_NONCE_BYTES];
    uint8_t profile_hash[32];
    uint64_t epoch;
    int owner_pidfd;
    pid_t owner_pid;
    uint32_t owner_tid;
    uint64_t owner_start;
    int supervisor_pidfd;
    int source_master_pidfd;
    uint32_t expected_owner_role;
    uint64_t expected_owner_slot_device;
    uint64_t expected_owner_slot_inode;
    uint64_t expected_owner_cookie;
    bool owner_expected;
    uint32_t supervisor_pid;
    uint64_t supervisor_start;
    uint64_t app_start;
    bool owner_authenticated;
    bool ready;
    bool stop_requested_with_pending;
};

static int relay_decision(const struct ker_rx_decision_packet *packet, void *opaque);
static int app_loop(void *opaque);

static uint64_t monotonic_ns(void)
{
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static uint32_t frame_hash32(const void *data, size_t bytes)
{
    const uint8_t *cursor = data;
    uint32_t hash = UINT32_C(2166136261);
    for (size_t i = 0; i < bytes; ++i) {
        hash ^= cursor[i];
        hash *= UINT32_C(16777619);
    }
    return hash;
}

static bool frame_is_probe(const uint8_t *frame, size_t bytes,
    const char *token, uint16_t destination_port, uint16_t *source_port)
{
    if (!frame || !token || !*token || bytes < 14) return false;
    size_t offset = 14;
    uint16_t ethertype = (uint16_t)((uint16_t)frame[12] << 8 | frame[13]);
    if (ethertype == 0x8100 || ethertype == 0x88a8) {
        if (bytes < 18) return false;
        ethertype = (uint16_t)((uint16_t)frame[16] << 8 | frame[17]);
        offset = 18;
    }
    if (ethertype != 0x0800 || bytes < offset + 20 || (frame[offset] >> 4) != 4 ||
        frame[offset + 9] != 6) return false;
    size_t ip_header = (size_t)(frame[offset] & 0x0f) * 4;
    if (ip_header < 20 || bytes < offset + ip_header + 20) return false;
    size_t tcp = offset + ip_header;
    if (((uint16_t)frame[tcp + 2] << 8 | frame[tcp + 3]) != destination_port)
        return false;
    size_t tcp_header = (size_t)(frame[tcp + 12] >> 4) * 4;
    if (tcp_header < 20 || bytes < tcp + tcp_header) return false;
    const uint8_t *payload = frame + tcp + tcp_header;
    size_t payload_bytes = bytes - (size_t)(payload - frame);
    char request[128];
    int request_bytes = snprintf(request, sizeof(request), "GET /?probe=%s HTTP/1.1", token);
    if (request_bytes <= 0 || (size_t)request_bytes > payload_bytes ||
        memmem(payload, payload_bytes, request, (size_t)request_bytes) == NULL) return false;
    *source_port = (uint16_t)((uint16_t)frame[tcp] << 8 | frame[tcp + 1]);
    return true;
}

static bool frame_is_source_probe_ack(const uint8_t *frame, size_t bytes,
    uint16_t expected_source_port, uint16_t expected_destination_port,
    uint16_t *source_port)
{
    if (!frame || bytes < 54 ||
        ((uint16_t)frame[12] << 8 | frame[13]) != 0x0800 ||
        (frame[14] >> 4) != 4 || frame[23] != 6) return false;
    size_t ip_header = (size_t)(frame[14] & 0x0f) * 4;
    if (ip_header < 20 || bytes < 14 + ip_header + 20) return false;
    size_t tcp = 14 + ip_header;
    uint16_t port = (uint16_t)((uint16_t)frame[tcp] << 8 | frame[tcp + 1]);
    uint16_t destination = (uint16_t)((uint16_t)frame[tcp + 2] << 8 |
        frame[tcp + 3]);
    uint8_t flags = frame[tcp + 13];
    if (port != expected_source_port || destination != expected_destination_port ||
        !(flags & 0x10) || (flags & 0x02)) return false;
    *source_port = port;
    return true;
}

static bool frame_is_source_probe_syn(const uint8_t *frame, size_t bytes,
    uint16_t expected_source_port, uint16_t expected_destination_port,
    uint16_t *source_port)
{
    if (!frame || bytes < 54 ||
        ((uint16_t)frame[12] << 8 | frame[13]) != 0x0800 ||
        (frame[14] >> 4) != 4 || frame[23] != 6) return false;
    size_t ip_header = (size_t)(frame[14] & 0x0f) * 4;
    if (ip_header < 20 || bytes < 14 + ip_header + 20) return false;
    size_t tcp = 14 + ip_header;
    uint16_t port = (uint16_t)((uint16_t)frame[tcp] << 8 | frame[tcp + 1]);
    uint16_t destination = (uint16_t)((uint16_t)frame[tcp + 2] << 8 |
        frame[tcp + 3]);
    uint8_t flags = frame[tcp + 13];
    if (port != expected_source_port || destination != expected_destination_port ||
        !(flags & 0x02) || (flags & 0x10)) return false;
    *source_port = port;
    return true;
}

static int decode_hex(const char *text, uint8_t *out, size_t length)
{
    if (!text || strlen(text) != length * 2) return -1;
    for (size_t i = 0; i < length; ++i) {
        char pair[3] = {text[2 * i], text[2 * i + 1], 0};
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(pair, &end, 16);
        if (errno || !end || *end || value > UINT8_MAX) return -1;
        out[i] = (uint8_t)value;
    }
    return 0;
}

static int read_start_ticks(pid_t pid, uint64_t *ticks)
{
    char path[64], text[1024];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *file = fopen(path, "re");
    if (!file) return -errno;
    char *line = fgets(text, sizeof(text), file);
    int saved = errno;
    fclose(file);
    if (!line) return -saved;
    char *close = strrchr(text, ')');
    if (!close || close[1] != ' ') return -EPROTO;
    char *save = NULL, *token = strtok_r(close + 2, " ", &save);
    for (int index = 0; token; ++index, token = strtok_r(NULL, " ", &save)) {
        if (index == 19) {
            char *end = NULL;
            unsigned long long value = strtoull(token, &end, 10);
            if (!end || (*end && *end != '\n') || !value) return -EPROTO;
            *ticks = (uint64_t)value;
            return 0;
        }
    }
    return -EPROTO;
}

static int read_parent_pid(pid_t pid, pid_t *parent)
{
    char path[64], text[1024];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *file = fopen(path, "re");
    if (!file) return -errno;
    char *line = fgets(text, sizeof(text), file);
    int saved = errno;
    fclose(file);
    if (!line) return -saved;
    char *close = strrchr(text, ')');
    if (!close || close[1] != ' ') return -EPROTO;
    char *save = NULL, *token = strtok_r(close + 2, " ", &save);
    token = token ? strtok_r(NULL, " ", &save) : NULL;
    if (!token) return -EPROTO;
    char *end = NULL;
    long value = strtol(token, &end, 10);
    if (!end || *end || value <= 0 || value > INT32_MAX) return -EPROTO;
    *parent = (pid_t)value;
    return 0;
}

static bool process_thread_exists(pid_t pid, uint32_t tid)
{
    char path[96];
    int length = snprintf(path, sizeof(path), "/proc/%ld/task/%u", (long)pid, tid);
    struct stat status;
    return length > 0 && (size_t)length < sizeof(path) &&
        stat(path, &status) == 0 && S_ISDIR(status.st_mode);
}

static bool supervisor_authority_live(const struct fixture *fixture)
{
    struct pollfd pfd = {.fd = fixture->supervisor_pidfd,
        .events = POLLIN | POLLHUP | POLLERR};
    uint64_t start = 0;
    return fixture->supervisor_pidfd >= 0 &&
        poll(&pfd, 1, 0) == 0 && pfd.revents == 0 &&
        read_start_ticks((pid_t)fixture->supervisor_pid, &start) == 0 &&
        start == fixture->supervisor_start;
}

static int pidfd_pid(int fd, pid_t *pid)
{
    char path[64], text[256];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    FILE *file = fopen(path, "re");
    if (!file) return -errno;
    while (fgets(text, sizeof(text), file)) {
        if (!strncmp(text, "Pid:\t", 5)) {
            char *end = NULL;
            long value = strtol(text + 5, &end, 10);
            fclose(file);
            if (value <= 0 || !end || (*end && *end != '\n')) return -EPROTO;
            *pid = (pid_t)value;
            return 0;
        }
    }
    fclose(file);
    return -EPROTO;
}

static int parse_credentials(struct msghdr *message, struct ucred *cred,
    bool *have_cred, int received_fds[2], size_t *received_fd_count)
{
    *have_cred = false;
    *received_fd_count = 0;
    received_fds[0] = received_fds[1] = -1;
    bool invalid = false;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(message); cmsg;
         cmsg = CMSG_NXTHDR(message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
            cmsg->cmsg_len == CMSG_LEN(sizeof(*cred)) && !*have_cred) {
            memcpy(cred, CMSG_DATA(cmsg), sizeof(*cred));
            *have_cred = true;
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
                   cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
            if (bytes % sizeof(int)) { invalid = true; continue; }
            const int *fds = (const int *)CMSG_DATA(cmsg);
            size_t count = bytes / sizeof(int);
            for (size_t i = 0; i < count; ++i) {
                if (*received_fd_count < 2) {
                    received_fds[(*received_fd_count)++] = fds[i];
                } else {
                    close(fds[i]);
                    invalid = true;
                }
            }
            if (count > 2) invalid = true;
        } else invalid = true;
    }
    return invalid ? -EPROTO : 0;
}

static int receive_owner_auth(struct fixture *fixture)
{
    struct ker_rx_owner_relay_header ack = {0};
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &ack, .iov_len = sizeof(ack)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t received = recvmsg(fixture->relay_fd, &message,
        MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
    if (received < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -errno;
    struct ucred credentials = {0};
    bool have_credentials = false;
    int received_fds[2] = {-1, -1};
    size_t received_fd_count = 0;
    int ancillary_status = parse_credentials(&message, &credentials, &have_credentials,
        received_fds, &received_fd_count);
    if ((size_t)received != sizeof(ack) || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        ancillary_status || !have_credentials || received_fd_count != 1 ||
        credentials.pid != (pid_t)ack.owner_pid || credentials.uid != getuid() ||
        credentials.gid != getgid() || ack.magic != KER_RX_OWNER_RELAY_MAGIC ||
        ack.version != KER_RX_OWNER_RELAY_VERSION || ack.type != KER_RX_OWNER_RELAY_AUTH_ACK ||
        ack.app_pid != (uint32_t)getpid() || ack.worker_epoch != fixture->epoch ||
        ack.app_start_ticks != fixture->app_start ||
        ack.supervisor_pid != fixture->supervisor_pid ||
        ack.supervisor_start_ticks != fixture->supervisor_start ||
        memcmp(ack.run_nonce, fixture->nonce, sizeof(ack.run_nonce)) ||
        !ack.owner_pid || !ack.owner_tid || !ack.owner_start_ticks ||
        ack.owner_pid != (uint32_t)fixture->owner_pid ||
        ack.owner_tid != fixture->owner_tid ||
        ack.owner_start_ticks != fixture->owner_start ||
        ack.packet_id || ack.deadline_ns || ack.frame_bytes || ack.queue_id ||
        ack.queue_count || ack.action || ack.reserved || ack.frame_hash32 ||
        ack.dispatcher_result || ack.vlan_tci || ack.vlan_stripped ||
        ack.frame_unchanged) {
        for (size_t i = 0; i < received_fd_count; ++i) close(received_fds[i]);
        return -EPROTO;
    }
    int pidfd = received_fds[0];
    pid_t observed_pid = 0;
    uint64_t observed_start = 0;
    struct pollfd pollfd = {.fd = pidfd, .events = POLLIN | POLLHUP | POLLERR};
    if (pidfd_pid(pidfd, &observed_pid) || observed_pid != credentials.pid ||
        read_start_ticks(observed_pid, &observed_start) ||
        observed_start != ack.owner_start_ticks || poll(&pollfd, 1, 0) != 0) {
        close(pidfd);
        return -ESTALE;
    }
    close(pidfd);
    if (!fixture->owner_expected || fixture->owner_pid != observed_pid ||
        fixture->owner_tid != ack.owner_tid || fixture->owner_start != observed_start)
        return -ESTALE;
    fixture->owner_authenticated = true;
    fprintf(stderr, "RX_OWNER_RELAY_AUTH_ACK pid=%d tid=%u start=%llu\n",
        (int)fixture->owner_pid, fixture->owner_tid,
        (unsigned long long)fixture->owner_start);
    fflush(stderr);
    return 0;
}

static int receive_supervisor_owner_auth(struct fixture *fixture)
{
    const char *fd_text = getenv("KER_RX_OWNER_AUTH_FD");
    char *end = NULL;
    errno = 0;
    long fd = fd_text ? strtol(fd_text, &end, 10) : -1;
    if (!fd_text || errno || end == fd_text || *end || fd < 3 || fd > INT32_MAX)
        return -EINVAL;
    struct ker_rx_owner_auth_record record = {0};
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 3)] = {0};
    struct iovec iov = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t received = recvmsg((int)fd, &message,
        MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
    if (received < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -errno;
    struct ucred credentials = {0};
    bool have_credentials = false;
    int received_fds[2] = {-1, -1};
    size_t received_fd_count = 0;
    int ancillary_status = parse_credentials(&message, &credentials, &have_credentials,
        received_fds, &received_fd_count);
    if ((size_t)received != sizeof(record) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        ancillary_status || !have_credentials || received_fd_count != 2 ||
        credentials.pid != (pid_t)fixture->supervisor_pid ||
        credentials.uid != getuid() || credentials.gid != getgid() ||
        record.magic != KER_RX_OWNER_AUTH_MAGIC ||
        record.version != KER_RX_OWNER_AUTH_VERSION ||
        record.type != KER_RX_OWNER_AUTH_OWNER || record.record_bytes != sizeof(record) ||
        record.supervisor_pid != fixture->supervisor_pid ||
        record.supervisor_start_ticks != fixture->supervisor_start ||
        record.owner_role != fixture->expected_owner_role || record.flags || !record.owner_pid ||
        !record.owner_tid || !record.owner_start_ticks || !record.slot_device ||
        !record.slot_inode || !record.cookie || record.worker_epoch != fixture->epoch ||
        memcmp(record.run_nonce, fixture->nonce, sizeof(record.run_nonce))) {
        for (size_t i = 0; i < received_fd_count; ++i) close(received_fds[i]);
        return -EPROTO;
    }
    int pidfd = received_fds[0];
    int supervisor_pidfd = received_fds[1];
    pid_t observed_pid = 0;
    uint64_t observed_supervisor_start = 0;
    if (read_start_ticks(credentials.pid, &observed_supervisor_start) ||
        observed_supervisor_start != fixture->supervisor_start ||
        pidfd_pid(supervisor_pidfd, &observed_pid) || observed_pid != credentials.pid ||
        poll(&(struct pollfd){.fd = supervisor_pidfd, .events = POLLIN | POLLHUP | POLLERR},
            1, 0) != 0) {
        if (pidfd >= 0) close(pidfd);
        close(supervisor_pidfd);
        return -ESTALE;
    }
    uint64_t observed_start = 0;
    struct pollfd owner_poll = {.fd = pidfd, .events = POLLIN | POLLHUP | POLLERR};
    if (pidfd_pid(pidfd, &observed_pid) || observed_pid != (pid_t)record.owner_pid ||
        read_start_ticks(observed_pid, &observed_start) ||
        observed_start != record.owner_start_ticks ||
        !process_thread_exists(observed_pid, record.owner_tid) ||
        poll(&owner_poll, 1, 0) != 0) {
        close(pidfd);
        close(supervisor_pidfd);
        return -ESTALE;
    }
    fixture->owner_pidfd = pidfd;
    fixture->supervisor_pidfd = supervisor_pidfd;
    fixture->owner_pid = observed_pid;
    fixture->owner_tid = record.owner_tid;
    fixture->owner_start = observed_start;
    fixture->expected_owner_role = record.owner_role;
    fixture->expected_owner_slot_device = record.slot_device;
    fixture->expected_owner_slot_inode = record.slot_inode;
    fixture->expected_owner_cookie = record.cookie;
    fixture->owner_expected = true;
    record.type = KER_RX_OWNER_AUTH_ACK;
    if (send((int)fd, &record, sizeof(record), MSG_NOSIGNAL) != (ssize_t)sizeof(record))
        return errno ? -errno : -EIO;
    return 0;
}

static bool current_owner_live(const struct fixture *fixture)
{
    pid_t pid = 0;
    uint64_t start = 0;
    struct pollfd pfd = {.fd = fixture->owner_pidfd, .events = POLLIN};
    return !fixture->source_route_quarantined &&
        fixture->owner_expected && fixture->owner_authenticated &&
        !pidfd_pid(fixture->owner_pidfd, &pid) && pid == fixture->owner_pid &&
        !read_start_ticks(pid, &start) && start == fixture->owner_start &&
        process_thread_exists(pid, fixture->owner_tid) && poll(&pfd, 1, 0) == 0 &&
        (!fixture->source_route_active || (fixture->source_master_pidfd >= 0 &&
            monotonic_ns() < fixture->source_route_record.pair.authority_deadline_ns &&
            poll(&(struct pollfd){.fd = fixture->source_master_pidfd,
                .events = POLLIN | POLLHUP | POLLERR}, 1, 0) == 0));
}

static void close_peer_binding(struct fixture *fixture)
{
    if (fixture->peer.fd >= 0) close(fixture->peer.fd);
    if (fixture->peer.pidfd >= 0) close(fixture->peer.pidfd);
    fixture->peer = (struct ker_rx_owner_relay_peer){.fd = -1, .pidfd = -1};
    fixture->peer_authenticated = false;
    fixture->peer_auth_deadline_ns = 0;
}

static int receive_supervisor_peer_auth(struct fixture *fixture)
{
    const char *text = getenv("KER_RX_OWNER_AUTH_FD");
    char *end = NULL;
    errno = 0;
    long fd = text ? strtol(text, &end, 10) : -1;
    if (!text || errno || end == text || *end || fd < 3 || fd > INT32_MAX) return -EINVAL;
    struct ker_rx_owner_peer_auth_record record = {0};
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(3 * sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t received = recvmsg((int)fd, &message, MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
    if (received < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -errno;
    struct ucred credentials = {0};
    bool have_credentials = false;
    int fds[2] = {-1, -1};
    size_t count = 0;
    int ancillary = parse_credentials(&message, &credentials, &have_credentials, fds, &count);
    const struct ker_rx_owner_auth_record *owner = &record.owner;
    uint64_t now = monotonic_ns();
    int status = -EPROTO;
    if ((size_t)received != sizeof(record) || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        ancillary || count != 2 || !have_credentials ||
        credentials.pid != (pid_t)fixture->supervisor_pid ||
        credentials.uid != getuid() || credentials.gid != getgid() ||
        owner->magic != KER_RX_OWNER_AUTH_MAGIC || owner->version != KER_RX_OWNER_AUTH_VERSION ||
        owner->type != KER_RX_OWNER_AUTH_PEER || owner->record_bytes != sizeof(record) ||
        owner->supervisor_pid != fixture->supervisor_pid ||
        owner->supervisor_start_ticks != fixture->supervisor_start ||
        owner->worker_epoch != fixture->epoch || owner->owner_role != 0 || owner->flags ||
        !owner->owner_pid || !owner->owner_tid || !owner->owner_start_ticks ||
        !owner->slot_device || !owner->slot_inode || !owner->cookie ||
        memcmp(owner->run_nonce, fixture->nonce, sizeof(owner->run_nonce))) goto reject;
    status = -ESTALE;
    if (!supervisor_authority_live(fixture) || !current_owner_live(fixture) ||
        fixture->expected_owner_role != 1 || fixture->peer.fd >= 0 ||
        record.primary_pid != (uint32_t)fixture->owner_pid ||
        record.primary_tid != fixture->owner_tid || record.primary_start_ticks != fixture->owner_start ||
        record.primary_slot_device != fixture->expected_owner_slot_device ||
        record.primary_slot_inode != fixture->expected_owner_slot_inode ||
        record.primary_cookie != fixture->expected_owner_cookie ||
        owner->owner_pid == record.primary_pid || owner->cookie == record.primary_cookie ||
        (owner->slot_device == record.primary_slot_device && owner->slot_inode == record.primary_slot_inode) ||
        !now || record.authority_deadline_ns <= now ||
        record.authority_deadline_ns - now > KER_RX_OWNER_PEER_MAX_AUTHORITY_NS) goto reject;
    pid_t pid = 0;
    uint64_t start = 0;
    if (pidfd_pid(fds[0], &pid) || pid != (pid_t)owner->owner_pid ||
        read_start_ticks(pid, &start) || start != owner->owner_start_ticks ||
        !process_thread_exists(pid, owner->owner_tid) ||
        poll(&(struct pollfd){.fd = fds[0], .events = POLLIN}, 1, 0) != 0) goto reject;
    int type = 0, domain = 0, enabled = 1;
    socklen_t size = sizeof(type);
    status = -EPROTOTYPE;
    if (getsockopt(fds[1], SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_SEQPACKET) goto reject;
    size = sizeof(domain);
    if (getsockopt(fds[1], SOL_SOCKET, SO_DOMAIN, &domain, &size) || domain != AF_UNIX ||
        setsockopt(fds[1], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) goto reject;
    fixture->peer = (struct ker_rx_owner_relay_peer){.fd = fds[1], .pidfd = fds[0],
        .uid = credentials.uid, .gid = credentials.gid,
        .identity = {.magic = KER_RX_OWNER_RELAY_MAGIC, .version = KER_RX_OWNER_RELAY_VERSION,
            .type = KER_RX_OWNER_RELAY_APP_AUTH, .worker_epoch = fixture->epoch,
            .app_start_ticks = fixture->app_start, .owner_start_ticks = owner->owner_start_ticks,
            .supervisor_start_ticks = fixture->supervisor_start,
            .app_pid = (uint32_t)getpid(), .owner_pid = owner->owner_pid,
            .owner_tid = owner->owner_tid, .supervisor_pid = fixture->supervisor_pid}};
    memcpy(fixture->peer.identity.run_nonce, fixture->nonce, sizeof(fixture->nonce));
    fixture->peer_record = record;
    fixture->peer_authenticated = false;
    fixture->peer_auth_deadline_ns = now + UINT64_C(5000000000);
    if (fixture->peer_auth_deadline_ns > record.authority_deadline_ns)
        fixture->peer_auth_deadline_ns = record.authority_deadline_ns;
    return 0;
reject:
    for (size_t i = 0; i < count; ++i) close(fds[i]);
    return status;
}

static int receive_peer_owner_auth(struct fixture *fixture)
{
    if (fixture->peer.fd < 0 || fixture->peer_authenticated) return 0;
    int status = -ESTALE;
    if (!supervisor_authority_live(fixture) || !current_owner_live(fixture)) goto reject;
    if (monotonic_ns() >= fixture->peer_auth_deadline_ns) { status = -ETIMEDOUT; goto reject; }
    struct fixture old = {.relay_fd = fixture->peer.fd,
        .owner_expected = true, .owner_pid = (pid_t)fixture->peer.identity.owner_pid,
        .owner_tid = fixture->peer.identity.owner_tid, .owner_start = fixture->peer.identity.owner_start_ticks,
        .app_start = fixture->app_start, .supervisor_pid = fixture->supervisor_pid,
        .supervisor_start = fixture->supervisor_start, .epoch = fixture->epoch};
    memcpy(old.nonce, fixture->nonce, sizeof(old.nonce));
    status = receive_owner_auth(&old);
    if (status) goto reject;
    if (!old.owner_authenticated) return 0;
    if (monotonic_ns() >= fixture->peer_auth_deadline_ns) { status = -ETIMEDOUT; goto reject; }
    if (!supervisor_authority_live(fixture) || !current_owner_live(fixture)) { status = -ESTALE; goto reject; }
    const char *text = getenv("KER_RX_OWNER_AUTH_FD");
    char *end = NULL;
    errno = 0;
    long fd = text ? strtol(text, &end, 10) : -1;
    if (!text || errno || end == text || *end || fd < 3 || fd > INT32_MAX) { status = -EINVAL; goto reject; }
    struct ker_rx_owner_peer_auth_record ack = fixture->peer_record;
    ack.owner.type = KER_RX_OWNER_AUTH_PEER_ACK;
    if (send((int)fd, &ack, sizeof(ack), MSG_DONTWAIT | MSG_NOSIGNAL) != (ssize_t)sizeof(ack)) {
        status = -(errno ? errno : EIO); goto reject;
    }
    fixture->peer_authenticated = true;
    fixture->peer_auth_deadline_ns = 0;
    return 0;
reject:
    close_peer_binding(fixture);
    return status;
}

static void close_source_route_pending(struct fixture *fixture)
{
    if (fixture->source_route_candidate_pidfd >= 0)
        close(fixture->source_route_candidate_pidfd);
    if (fixture->source_route_candidate_channel >= 0)
        close(fixture->source_route_candidate_channel);
    if (fixture->source_route_master_pidfd >= 0)
        close(fixture->source_route_master_pidfd);
    fixture->source_route_candidate_pidfd = -1;
    fixture->source_route_candidate_channel = -1;
    fixture->source_route_master_pidfd = -1;
    fixture->source_route_pending = false;
    fixture->source_route_candidate_authenticated = false;
}

static void abort_source_route_pending(struct fixture *fixture)
{
    if (fixture->source_route_candidate_channel >= 0)
        close(fixture->source_route_candidate_channel);
    fixture->source_route_candidate_channel = -1;
    fixture->source_route_aborted_candidate_pidfd = fixture->source_route_candidate_pidfd;
    fixture->source_route_aborted_master_pidfd = fixture->source_route_master_pidfd;
    fixture->source_route_candidate_pidfd = -1;
    fixture->source_route_master_pidfd = -1;
    fixture->source_route_first_record = fixture->source_route_record;
    fixture->source_route_pending = false;
    fixture->source_route_candidate_authenticated = false;
    fixture->source_route_aborted = true;
}

static int source_route_reply_record(const struct ker_rx_owner_source_route_record *base,
    uint16_t type,
    uint64_t sequence, int status)
{
    const char *text = getenv("KER_RX_OWNER_AUTH_FD");
    char *end = NULL;
    errno = 0;
    long fd = text ? strtol(text, &end, 10) : -1;
    if (!text || errno || end == text || *end || fd < 3 || fd > INT32_MAX)
        return -EINVAL;
    struct ker_rx_owner_source_route_record reply = *base;
    reply.pair.owner.type = type;
    reply.command_sequence = sequence;
    reply.status = status;
    if (send((int)fd, &reply, sizeof(reply), MSG_DONTWAIT | MSG_NOSIGNAL) !=
        (ssize_t)sizeof(reply)) return -(errno ? errno : EIO);
    return 0;
}

static int source_route_reply(struct fixture *fixture, uint16_t type, int status)
{
    return source_route_reply_record(&fixture->source_route_record, type,
        fixture->source_route_last_sequence, status);
}

static bool source_route_commit_context_live(struct fixture *fixture,
    const struct ker_rx_owner_source_route_record *record)
{
    struct ker_rx_owner_peer_auth_record pair = record->pair;
    pair.owner.type = fixture->source_route_record.pair.owner.type;
    return supervisor_authority_live(fixture) && current_owner_live(fixture) &&
        fixture->source_route_pending && fixture->source_route_candidate_authenticated &&
        !fixture->source_route_active &&
        record->operation_id == fixture->source_route_record.operation_id &&
        record->command_sequence == fixture->source_route_last_sequence &&
        record->source_epoch == fixture->source_route_record.source_epoch &&
        record->source_master_pid == fixture->source_route_record.source_master_pid &&
        record->source_master_start_ticks == fixture->source_route_record.source_master_start_ticks &&
        !memcmp(&pair, &fixture->source_route_record.pair, sizeof(pair));
}

static bool source_route_commit_actors_live(struct fixture *fixture,
    const struct ker_rx_owner_source_route_record *record, pid_t *candidate_out)
{
    pid_t candidate = 0, master = 0;
    uint64_t candidate_start = 0, master_start = 0;
    pid_t parent = 0, current_parent = 0;
    struct pollfd pids[2] = {{.fd = fixture->source_route_candidate_pidfd, .events = POLLIN},
        {.fd = fixture->source_route_master_pidfd, .events = POLLIN}};
    if (pidfd_pid(fixture->source_route_master_pidfd, &master) ||
        master != (pid_t)record->source_master_pid ||
        pidfd_pid(fixture->source_route_candidate_pidfd, &candidate) ||
        candidate != (pid_t)record->pair.owner.owner_pid ||
        read_start_ticks(candidate, &candidate_start) ||
        candidate_start != record->pair.owner.owner_start_ticks ||
        read_parent_pid(candidate, &parent) || parent != master ||
        !process_thread_exists(candidate, record->pair.owner.owner_tid) ||
        read_parent_pid(fixture->owner_pid, &current_parent) || current_parent != master ||
        read_start_ticks(master, &master_start) || master_start != record->source_master_start_ticks ||
        poll(pids, 2, 0) != 0 || monotonic_ns() >= record->pair.authority_deadline_ns) return false;
    if (candidate_out) *candidate_out = candidate;
    return true;
}

static int source_route_cut_control_live(uint64_t deadline_ns)
{
    const char *text = getenv("KER_RX_OWNER_AUTH_FD");
    char *end = NULL;
    errno = 0;
    long fd = text ? strtol(text, &end, 10) : -1;
    if (!text || errno || end == text || *end || fd < 3 || fd > INT32_MAX) return -EINVAL;
    struct pollfd control = {.fd = (int)fd, .events = POLLIN | POLLHUP | POLLERR};
    int result;
    do { result = poll(&control, 1, 0); }
    while (result < 0 && errno == EINTR && monotonic_ns() < deadline_ns);
    if (result < 0) return errno == EINTR ? -ETIMEDOUT : -errno;
    if (control.revents & (POLLHUP | POLLERR | POLLNVAL)) return -ENOTCONN;
    /* A terminal command already owns this slot. Never consume a second one
     * or let it replace/renew the authenticated immutable first command. */
    return control.revents & POLLIN ? -EALREADY : 0;
}

static void source_route_cut_trace(const struct fixture *fixture, const char *event,
    uint64_t command_deadline_ns, int status)
{
    int saved_errno = errno;
    char text[384];
    int bytes = snprintf(text, sizeof(text),
        "SOURCE_ROUTE_CUT_STAGE event=%s now_ns=%llu packet=%llu frame_deadline=%llu hash=%u command_deadline=%llu pending=%u completed_id=%llu completed_ns=%llu status=%d\n",
        event, (unsigned long long)monotonic_ns(),
        (unsigned long long)fixture->packet_id,
        (unsigned long long)fixture->deadline_ns, fixture->current_frame_hash,
        (unsigned long long)command_deadline_ns,
        (unsigned)fixture->source_route_cut_pending,
        (unsigned long long)fixture->source_route_cut_completed_id,
        (unsigned long long)fixture->source_route_cut_completed_ns, status);
    if (bytes > 0 && (size_t)bytes < sizeof(text))
        (void)syscall(SYS_write, STDERR_FILENO, text, (size_t)bytes);
    errno = saved_errno;
}

static int apply_source_route_commit(struct fixture *fixture,
    const struct ker_rx_owner_source_route_record *request, bool may_defer)
{
    struct ker_rx_owner_source_route_record record = *request;
    struct ker_rx_owner_peer_auth_record *pair = &record.pair;
    bool after_frame = pair->owner.type == KER_RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME;
    uint16_t reply_type = after_frame ? KER_RX_OWNER_SOURCE_ROUTE_COMMITTED_AFTER_FRAME :
        KER_RX_OWNER_SOURCE_ROUTE_COMMITTED;
    if (after_frame) source_route_cut_trace(fixture, "apply-enter", record.command_deadline_ns, 0);
    pthread_mutex_lock(&fixture->source_route_lock);
    if (after_frame) source_route_cut_trace(fixture, "apply-locked", record.command_deadline_ns, 0);
    if (!after_frame && (fixture->packet_id || fixture->peer_forward_pending)) {
        pthread_mutex_unlock(&fixture->source_route_lock);
        return source_route_reply_record(&record, KER_RX_OWNER_SOURCE_ROUTE_COMMITTED,
            record.command_sequence, -EBUSY);
    }
    if (!source_route_commit_context_live(fixture, &record)) {
        pthread_mutex_unlock(&fixture->source_route_lock);
        return source_route_reply_record(&record, reply_type, record.command_sequence, -ESTALE);
    }
    if (after_frame) source_route_cut_trace(fixture, "context-live", record.command_deadline_ns, 0);
    pid_t candidate = 0;
    if (!source_route_commit_actors_live(fixture, &record, &candidate)) {
        close_source_route_pending(fixture);
        pthread_mutex_unlock(&fixture->source_route_lock);
        return source_route_reply_record(&record, reply_type,
            record.command_sequence, -ESTALE);
    }
    if (after_frame) source_route_cut_trace(fixture, "actors-live", record.command_deadline_ns, 0);
    /* A live master and finite grant do not extend an individual source
     * handover call. Check its absolute budget under the swap mutex. */
    if (!record.command_deadline_ns || monotonic_ns() >= record.command_deadline_ns ||
            record.command_deadline_ns > pair->authority_deadline_ns) {
        pthread_mutex_unlock(&fixture->source_route_lock);
        return source_route_reply_record(&record, reply_type,
            record.command_sequence, record.command_deadline_ns ? -ETIMEDOUT : -EINVAL);
    }
    if (after_frame) {
        int live = source_route_cut_control_live(record.command_deadline_ns);
        if (live) {
            fixture->source_route_quarantined = true;
            pthread_mutex_unlock(&fixture->source_route_lock);
            (void)source_route_reply_record(&record, reply_type, record.command_sequence, live);
            return live;
        }
        if (fixture->packet_id || fixture->peer_forward_pending) {
            if (!may_defer || fixture->source_route_cut_pending) {
                pthread_mutex_unlock(&fixture->source_route_lock);
                return -EPROTO;
            }
            fixture->source_route_cut_record = record;
            fixture->source_route_cut_packet_id = fixture->packet_id;
            fixture->source_route_cut_frame_deadline_ns = fixture->deadline_ns;
            fixture->source_route_cut_frame_hash = fixture->current_frame_hash;
            fixture->source_route_cut_completed_id = 0;
            fixture->source_route_cut_completed_ns = 0;
            fixture->source_route_cut_pending = true;
            fixture->source_route_cut_progress_traced = false;
            fixture->source_route_cut_reply_poll_traced = false;
            pthread_mutex_unlock(&fixture->source_route_lock);
            source_route_cut_trace(fixture, "wait-old-frame", record.command_deadline_ns, 0);
            return 0; /* ACK waits for the old frame's actual completion. */
        }
    }
#ifdef KER_SOCKET_BROKER_RX_OWNER_RELAY_TESTING
    if (getenv("KER_TEST_SOURCE_ROUTE_DELAY_SWAP")) {
        struct timespec delay = {.tv_nsec = 200000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) { }
    }
#endif
    fixture->peer = (struct ker_rx_owner_relay_peer){.fd = fixture->relay_fd,
        .pidfd = fixture->owner_pidfd, .uid = getuid(), .gid = getgid(),
        .identity = {.magic = KER_RX_OWNER_RELAY_MAGIC,
            .version = KER_RX_OWNER_RELAY_VERSION, .type = KER_RX_OWNER_RELAY_APP_AUTH,
            .worker_epoch = fixture->epoch, .app_start_ticks = fixture->app_start,
            .owner_start_ticks = fixture->owner_start,
            .supervisor_start_ticks = fixture->supervisor_start,
            .app_pid = (uint32_t)getpid(), .owner_pid = (uint32_t)fixture->owner_pid,
            .owner_tid = fixture->owner_tid, .supervisor_pid = fixture->supervisor_pid}};
    memcpy(fixture->peer.identity.run_nonce, fixture->nonce, sizeof(fixture->nonce));
    fixture->peer_record = fixture->source_route_record.pair;
    fixture->peer_authenticated = true;
    fixture->peer_auth_deadline_ns = 0;
    fixture->relay_fd = fixture->source_route_candidate_channel;
    fixture->owner_pidfd = fixture->source_route_candidate_pidfd;
    fixture->owner_pid = candidate;
    fixture->owner_tid = pair->owner.owner_tid;
    fixture->owner_start = pair->owner.owner_start_ticks;
    fixture->expected_owner_role = pair->owner.owner_role;
    fixture->expected_owner_slot_device = pair->owner.slot_device;
    fixture->expected_owner_slot_inode = pair->owner.slot_inode;
    fixture->expected_owner_cookie = pair->owner.cookie;
    fixture->owner_expected = true;
    fixture->owner_authenticated = true;
    fixture->source_master_pidfd = fixture->source_route_master_pidfd;
    fixture->source_route_candidate_channel = -1;
    fixture->source_route_candidate_pidfd = -1;
    fixture->source_route_master_pidfd = -1;
    fixture->source_route_pending = false;
    fixture->source_route_active = true;
    /* A scheduler pause can cross the budget after the pre-swap check. No
     * packet callback can enter under this mutex. Revoke both routes before
     * unlocking rather than certify a late successful handover. */
    if (monotonic_ns() >= record.command_deadline_ns) {
        fixture->source_route_quarantined = true;
        pthread_mutex_unlock(&fixture->source_route_lock);
        return source_route_reply_record(&record, reply_type,
            record.command_sequence, -ETIMEDOUT);
    }
    uint64_t swapped_ns = monotonic_ns();
    pthread_mutex_unlock(&fixture->source_route_lock);
    if (after_frame) {
        printf("SOURCE_ROUTE_AFTER_FRAME old_packet=%llu packet_deadline=%llu hash=%u completed_ns=%llu swap_ns=%llu command_deadline=%llu\n",
            (unsigned long long)fixture->source_route_cut_packet_id,
            (unsigned long long)fixture->source_route_cut_frame_deadline_ns,
            fixture->source_route_cut_frame_hash,
            (unsigned long long)fixture->source_route_cut_completed_ns,
            (unsigned long long)swapped_ns,
            (unsigned long long)record.command_deadline_ns);
        fflush(stdout);
    }
    return source_route_reply_record(&record, reply_type,
        record.command_sequence, 0);
}

static int progress_source_route_cut(struct fixture *fixture)
{
    if (!fixture->source_route_cut_pending) return 0;
    const struct ker_rx_owner_source_route_record record = fixture->source_route_cut_record;
    bool trace_progress = !fixture->source_route_cut_progress_traced;
    fixture->source_route_cut_progress_traced = true;
    if (trace_progress) source_route_cut_trace(fixture, "progress-enter", record.command_deadline_ns, 0);
    if (!fixture->packet_id && !fixture->peer_forward_pending)
        source_route_cut_trace(fixture, "progress-after-complete", record.command_deadline_ns, 0);
    int failure = source_route_cut_control_live(record.command_deadline_ns);
    if (trace_progress) source_route_cut_trace(fixture, "progress-control", record.command_deadline_ns, failure);
    uint64_t now = monotonic_ns();
    if (!failure && !source_route_commit_context_live(fixture, &record)) failure = -ESTALE;
    if (trace_progress) source_route_cut_trace(fixture, "progress-context", record.command_deadline_ns, failure);
    if (!failure && !source_route_commit_actors_live(fixture, &record, NULL)) failure = -ESTALE;
    if (trace_progress) source_route_cut_trace(fixture, "progress-actors", record.command_deadline_ns, failure);
    if (!failure && (!now || now >= record.command_deadline_ns ||
            now >= record.pair.authority_deadline_ns)) failure = -ETIMEDOUT;
    if (!failure && fixture->packet_id && now >= fixture->deadline_ns) failure = -ETIMEDOUT;
    if (!failure && (fixture->packet_id || fixture->peer_forward_pending)) return 0;
    if (!failure && (!fixture->source_route_cut_packet_id ||
            fixture->source_route_cut_completed_id != fixture->source_route_cut_packet_id ||
            !fixture->source_route_cut_completed_ns ||
            fixture->source_route_cut_completed_ns >= fixture->source_route_cut_frame_deadline_ns ||
            fixture->source_route_cut_completed_ns >= record.command_deadline_ns ||
            fixture->deadline_ns != fixture->source_route_cut_frame_deadline_ns ||
            fixture->current_frame_hash != fixture->source_route_cut_frame_hash ||
            frame_hash32(fixture->pending_frame, fixture->frame_bytes) != fixture->source_route_cut_frame_hash))
        failure = -EPROTO;
    fixture->source_route_cut_pending = false;
    if (failure) {
        source_route_cut_trace(fixture, "cancel", record.command_deadline_ns, failure);
        fixture->source_route_quarantined = true;
        (void)source_route_reply_record(&record, KER_RX_OWNER_SOURCE_ROUTE_COMMITTED_AFTER_FRAME,
            record.command_sequence, failure);
        return failure;
    }
    /* ker_posix_run invokes its next consumer pump only after this owner
     * callback returns. Thus no new frame can enter between this successful
     * old-frame completion and the locked route swap. Broker RPC servicing
     * continued normally while that frame was deferred. */
    return apply_source_route_commit(fixture, &record, false);
}

static int receive_source_route_command(struct fixture *fixture)
{
    if (fixture->source_route_cut_pending) return progress_source_route_cut(fixture);
    const char *text = getenv("KER_RX_OWNER_AUTH_FD");
    char *end = NULL;
    errno = 0;
    long fd = text ? strtol(text, &end, 10) : -1;
    if (!text || errno || end == text || *end || fd < 3 || fd > INT32_MAX)
        return -EINVAL;
    struct ker_rx_owner_source_route_record record = {0};
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(3 * sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t received = recvmsg((int)fd, &message,
        MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
    if (received < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -errno;
    struct ucred credentials = {0};
    bool have_credentials = false;
    int rights[3] = {-1, -1, -1};
    size_t rights_count = 0;
    bool invalid = false;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
            cmsg->cmsg_len == CMSG_LEN(sizeof(credentials)) && !have_credentials) {
            memcpy(&credentials, CMSG_DATA(cmsg), sizeof(credentials));
            have_credentials = true;
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
                   cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
            if (bytes % sizeof(int)) { invalid = true; continue; }
            size_t count = bytes / sizeof(int);
            int *fds = (int *)CMSG_DATA(cmsg);
            for (size_t i = 0; i < count; ++i) {
                if (rights_count < 3) rights[rights_count++] = fds[i];
                else { close(fds[i]); invalid = true; }
            }
        } else invalid = true;
    }
    int status = -EPROTO;
    struct ker_rx_owner_peer_auth_record *pair = &record.pair;
    uint64_t now = monotonic_ns();
    bool prepare = pair->owner.type == KER_RX_OWNER_SOURCE_ROUTE_PREPARE;
    if ((size_t)received != sizeof(record) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || invalid || !have_credentials ||
        credentials.pid != (pid_t)fixture->supervisor_pid || credentials.uid != getuid() ||
        credentials.gid != getgid() || pair->owner.magic != KER_RX_OWNER_AUTH_MAGIC ||
        pair->owner.version != KER_RX_OWNER_AUTH_VERSION ||
        pair->owner.record_bytes != sizeof(record) || pair->owner.flags ||
        pair->owner.supervisor_pid != fixture->supervisor_pid ||
        pair->owner.supervisor_start_ticks != fixture->supervisor_start ||
        pair->owner.worker_epoch != fixture->epoch || pair->owner.owner_role != 1 ||
        memcmp(pair->owner.run_nonce, fixture->nonce, sizeof(fixture->nonce)) ||
        record.reserved || record.status ||
        (record.source_epoch != KER_RX_OWNER_SOURCE_ROUTE_EPOCH &&
            record.source_epoch != KER_RX_OWNER_SOURCE_ROUTE_RETRY_EPOCH) ||
        !record.operation_id || !record.command_sequence || !record.source_master_pid ||
        !record.source_master_start_ticks || !pair->primary_pid || !pair->primary_tid ||
        !pair->primary_start_ticks || !pair->primary_slot_device || !pair->primary_slot_inode ||
        !pair->primary_cookie || !pair->owner.owner_pid || !pair->owner.owner_tid ||
        !pair->owner.owner_start_ticks || !pair->owner.slot_device || !pair->owner.slot_inode ||
        !pair->owner.cookie || !pair->authority_deadline_ns) goto reject;
    status = -ESTALE;
    fixture->source_route_last_type = pair->owner.type;
    bool invalid_prepare = prepare && (rights_count != 3 || fixture->source_route_pending ||
        pair->owner.owner_role != 1 ||
        record.operation_id <= fixture->source_route_last_operation_id ||
        (record.source_epoch == KER_RX_OWNER_SOURCE_ROUTE_EPOCH &&
            (fixture->source_route_aborted || fixture->source_route_retry_used)) ||
        (record.source_epoch == KER_RX_OWNER_SOURCE_ROUTE_RETRY_EPOCH &&
            (!fixture->source_route_aborted || fixture->source_route_retry_used)));
    if (!supervisor_authority_live(fixture) || !current_owner_live(fixture) ||
        !fixture->source_route_enabled || fixture->source_route_active ||
        fixture->expected_owner_role != 0 ||
        record.source_master_pid == (uint32_t)getpid() ||
        pair->primary_pid != (uint32_t)fixture->owner_pid ||
        pair->primary_tid != fixture->owner_tid ||
        pair->primary_start_ticks != fixture->owner_start ||
        pair->primary_slot_device != fixture->expected_owner_slot_device ||
        pair->primary_slot_inode != fixture->expected_owner_slot_inode ||
        pair->primary_cookie != fixture->expected_owner_cookie ||
        pair->owner.owner_pid == pair->primary_pid ||
        pair->owner.cookie == pair->primary_cookie || !now ||
        pair->authority_deadline_ns <= now ||
        pair->authority_deadline_ns - now > KER_RX_OWNER_PEER_MAX_AUTHORITY_NS ||
        record.command_sequence <= fixture->source_route_last_sequence ||
        invalid_prepare) goto reject;
    if (prepare) {
        if (record.command_deadline_ns) { status = -EPROTO; goto reject; }
        pid_t candidate = 0, master = 0;
        uint64_t candidate_start = 0, master_start = 0;
        pid_t parent = 0, current_parent = 0;
        struct pollfd pids[2] = {{.fd = rights[0], .events = POLLIN},
            {.fd = rights[2], .events = POLLIN}};
        int type = 0, domain = 0, enabled = 1;
        socklen_t size = sizeof(type);
        if (record.source_epoch == KER_RX_OWNER_SOURCE_ROUTE_RETRY_EPOCH) {
            struct pollfd aborted = {.fd = fixture->source_route_aborted_candidate_pidfd,
                .events = POLLIN};
            pid_t aborted_master = 0;
            uint64_t aborted_master_start = 0;
            if (fixture->source_route_aborted_candidate_pidfd < 0 ||
                fixture->source_route_aborted_master_pidfd < 0 ||
                poll(&aborted, 1, 0) != 1 || !(aborted.revents & POLLIN) ||
                pidfd_pid(fixture->source_route_aborted_master_pidfd, &aborted_master) ||
                aborted_master != (pid_t)fixture->source_route_first_record.source_master_pid ||
                read_start_ticks(aborted_master, &aborted_master_start) ||
                aborted_master_start != fixture->source_route_first_record.source_master_start_ticks ||
                record.source_master_pid != fixture->source_route_first_record.source_master_pid ||
                record.source_master_start_ticks != fixture->source_route_first_record.source_master_start_ticks ||
                pair->primary_pid != fixture->source_route_first_record.pair.primary_pid ||
                pair->primary_tid != fixture->source_route_first_record.pair.primary_tid ||
                pair->primary_start_ticks !=
                    fixture->source_route_first_record.pair.primary_start_ticks ||
                pair->primary_slot_device !=
                    fixture->source_route_first_record.pair.primary_slot_device ||
                pair->primary_slot_inode !=
                    fixture->source_route_first_record.pair.primary_slot_inode ||
                pair->primary_cookie !=
                    fixture->source_route_first_record.pair.primary_cookie ||
                pair->authority_deadline_ns >
                    fixture->source_route_first_record.pair.authority_deadline_ns ||
                pair->owner.owner_pid ==
                    fixture->source_route_first_record.pair.owner.owner_pid ||
                pair->owner.owner_pid ==
                    fixture->source_route_first_record.pair.primary_pid ||
                pair->owner.owner_start_ticks ==
                    fixture->source_route_first_record.pair.owner.owner_start_ticks ||
                pair->owner.owner_start_ticks ==
                    fixture->source_route_first_record.pair.primary_start_ticks ||
                pair->owner.cookie == fixture->source_route_first_record.pair.owner.cookie ||
                pair->owner.cookie == fixture->source_route_first_record.pair.primary_cookie ||
                (pair->owner.slot_device == fixture->source_route_first_record.pair.owner.slot_device &&
                 pair->owner.slot_inode == fixture->source_route_first_record.pair.owner.slot_inode) ||
                (pair->owner.slot_device == fixture->source_route_first_record.pair.primary_slot_device &&
                 pair->owner.slot_inode == fixture->source_route_first_record.pair.primary_slot_inode) ||
                pidfd_pid(fixture->source_route_aborted_master_pidfd, &aborted_master) ||
                poll(&(struct pollfd){.fd = fixture->source_route_aborted_master_pidfd,
                    .events = POLLIN}, 1, 0) != 0) {
                status = -ESTALE; goto reject;
            }
        }
        if (pidfd_pid(rights[2], &master) || master != (pid_t)record.source_master_pid ||
            pidfd_pid(rights[0], &candidate) || candidate != (pid_t)pair->owner.owner_pid ||
            read_start_ticks(candidate, &candidate_start) ||
            candidate_start != pair->owner.owner_start_ticks ||
            read_parent_pid(candidate, &parent) || parent != master ||
            !process_thread_exists(candidate, pair->owner.owner_tid) ||
            read_start_ticks(master, &master_start) || master_start != record.source_master_start_ticks ||
            poll(pids, 2, 0) != 0 ||
            read_parent_pid(fixture->owner_pid, &current_parent) || current_parent != master ||
            getsockopt(rights[1], SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_SEQPACKET ||
            (size = sizeof(domain), getsockopt(rights[1], SOL_SOCKET, SO_DOMAIN, &domain, &size)) ||
            domain != AF_UNIX || setsockopt(rights[1], SOL_SOCKET, SO_PASSCRED,
                &enabled, sizeof(enabled))) goto reject;
        fixture->source_route_candidate_pidfd = rights[0];
        fixture->source_route_candidate_channel = rights[1];
        fixture->source_route_master_pidfd = rights[2];
        rights[0] = rights[1] = rights[2] = -1;
        fixture->source_route_record = record;
        if (record.source_epoch == KER_RX_OWNER_SOURCE_ROUTE_RETRY_EPOCH)
            fixture->source_route_retry_used = true;
        fixture->source_route_last_sequence = record.command_sequence;
        fixture->source_route_last_operation_id = record.operation_id;
        fixture->source_route_pending = true;
        fixture->source_route_candidate_authenticated = false;
        return 0;
    }
    if (rights_count) { status = -EPROTO; goto reject; }
    struct ker_rx_owner_peer_auth_record original_pair = record.pair;
    original_pair.owner.type = fixture->source_route_record.pair.owner.type;
    if (!fixture->source_route_pending || !fixture->source_route_candidate_authenticated ||
        record.operation_id != fixture->source_route_record.operation_id ||
        record.source_epoch != fixture->source_route_record.source_epoch ||
        record.source_master_pid != fixture->source_route_record.source_master_pid ||
        record.source_master_start_ticks != fixture->source_route_record.source_master_start_ticks ||
        memcmp(&original_pair, &fixture->source_route_record.pair, sizeof(record.pair))) {
        status = -ESTALE; goto reject;
    }
    fixture->source_route_last_sequence = record.command_sequence;
    if (pair->owner.type == KER_RX_OWNER_SOURCE_ROUTE_ABORT) {
        if (record.source_epoch == KER_RX_OWNER_SOURCE_ROUTE_EPOCH)
            abort_source_route_pending(fixture);
        else
            close_source_route_pending(fixture);
        return source_route_reply_record(&record, KER_RX_OWNER_SOURCE_ROUTE_ABORTED,
            record.command_sequence, 0);
    }
    if (pair->owner.type != KER_RX_OWNER_SOURCE_ROUTE_COMMIT &&
            pair->owner.type != KER_RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME) goto reject;
    return apply_source_route_commit(fixture, &record, true);
reject:
    for (size_t i = 0; i < rights_count; ++i) if (rights[i] >= 0) close(rights[i]);
    if (prepare) {
        if (have_credentials && credentials.pid == (pid_t)fixture->supervisor_pid &&
            record.operation_id > fixture->source_route_last_operation_id &&
            record.command_sequence > fixture->source_route_last_sequence) {
            fixture->source_route_last_operation_id = record.operation_id;
            fixture->source_route_last_sequence = record.command_sequence;
            fixture->source_route_rejected_operation_id = record.operation_id;
        }
        return source_route_reply_record(&record,
            KER_RX_OWNER_SOURCE_ROUTE_PREPARED, record.command_sequence, status);
    }
    return status;
}

static int authenticate_pending_source_candidate(struct fixture *fixture)
{
    if (!fixture->source_route_pending || fixture->source_route_candidate_authenticated)
        return 0;
    if (monotonic_ns() >= fixture->source_route_record.pair.authority_deadline_ns) {
        close_source_route_pending(fixture);
        return source_route_reply(fixture, KER_RX_OWNER_SOURCE_ROUTE_PREPARED,
            -ETIMEDOUT);
    }
    struct fixture candidate = {
        .relay_fd = fixture->source_route_candidate_channel,
        .owner_pidfd = fixture->source_route_candidate_pidfd,
        .owner_pid = (pid_t)fixture->source_route_record.pair.owner.owner_pid,
        .owner_tid = fixture->source_route_record.pair.owner.owner_tid,
        .owner_start = fixture->source_route_record.pair.owner.owner_start_ticks,
        .app_start = fixture->app_start,
        .supervisor_pid = fixture->supervisor_pid,
        .supervisor_start = fixture->supervisor_start,
        .epoch = fixture->epoch,
        .expected_owner_role = 1,
        .expected_owner_slot_device = fixture->source_route_record.pair.owner.slot_device,
        .expected_owner_slot_inode = fixture->source_route_record.pair.owner.slot_inode,
        .expected_owner_cookie = fixture->source_route_record.pair.owner.cookie,
        .owner_expected = true,
    };
    memcpy(candidate.nonce, fixture->nonce, sizeof(candidate.nonce));
    int result = receive_owner_auth(&candidate);
    if (result < 0) {
        close_source_route_pending(fixture);
        return source_route_reply(fixture, KER_RX_OWNER_SOURCE_ROUTE_PREPARED,
            result);
    }
    if (candidate.owner_authenticated) {
        fixture->source_route_candidate_authenticated = true;
        return source_route_reply(fixture, KER_RX_OWNER_SOURCE_ROUTE_PREPARED, 0);
    }
    return 0;
}

static bool peer_authority_live(const struct fixture *fixture)
{
    struct pollfd pfd = {.fd = fixture->peer.pidfd, .events = POLLIN};
    struct pollfd master = {.fd = fixture->source_master_pidfd, .events = POLLIN};
    return fixture->peer_authenticated && fixture->peer.fd >= 0 &&
        monotonic_ns() < fixture->peer_record.authority_deadline_ns &&
        supervisor_authority_live(fixture) && current_owner_live(fixture) &&
        poll(&pfd, 1, 0) == 0 &&
        (!fixture->source_route_active || (fixture->source_master_pidfd >= 0 &&
            poll(&master, 1, 0) == 0));
}

static int prepare_owner_loop(void *opaque)
{
    struct fixture *fixture = opaque;
    const char *decision_fd = getenv("KER_RX_DECISION_FD");
    char *end = NULL;
    errno = 0;
    long fd = decision_fd ? strtol(decision_fd, &end, 10) : -1;
    if (!decision_fd || errno || end == decision_fd || *end || fd < 0 || fd > INT32_MAX)
        return -EINVAL;
    return ker_posix_rx_decision_register((int)fd, relay_decision, fixture);
}

static int broker_run(struct fixture *fixture)
{
    fixture->broker_status = ker_socket_broker_server_run_with_test_hooks(
        fixture->broker, 0, prepare_owner_loop, app_loop, fixture);
    atomic_store_explicit(&fixture->broker_done, true, memory_order_release);
    return fixture->broker_status;
}

static int relay_decision(const struct ker_rx_decision_packet *packet, void *opaque)
{
    struct fixture *fixture = opaque;
    pthread_mutex_lock(&fixture->source_route_lock);
    if (!fixture->owner_authenticated || !supervisor_authority_live(fixture) ||
        !current_owner_live(fixture)) {
        fixture->startup_drops++;
        pthread_mutex_unlock(&fixture->source_route_lock);
        return KER_RX_DECISION_DROP;
    }
    if (!packet || !packet->full_frame || packet->full_frame_bytes != packet->packet_bytes ||
        packet->full_frame_bytes < 14 || packet->full_frame_bytes > KER_RX_OWNER_RELAY_MAX_FRAME ||
        packet->deadline_ns <= monotonic_ns() || fixture->packet_id) {
        pthread_mutex_unlock(&fixture->source_route_lock);
        return -EPROTO;
    }
    fixture->current_frame_hash = frame_hash32(packet->full_frame,
        packet->full_frame_bytes);
    memcpy(fixture->pending_frame, packet->full_frame, packet->full_frame_bytes);
    uint16_t probe_port = 0;
    fixture->pending_probe = !fixture->probe_packet_id &&
        (fixture->source_revoke_test ?
            frame_is_source_probe_syn(packet->full_frame, packet->full_frame_bytes,
                fixture->expected_probe_source_port,
                fixture->expected_probe_destination_port, &probe_port) :
            frame_is_probe(packet->full_frame, packet->full_frame_bytes,
                fixture->probe_token, fixture->expected_probe_destination_port,
                &probe_port));
    if (!fixture->pending_probe && fixture->expected_probe_source_port &&
        !fixture->probe_packet_id)
        fixture->pending_probe = frame_is_source_probe_ack(packet->full_frame,
            packet->full_frame_bytes, fixture->expected_probe_source_port,
            fixture->expected_probe_destination_port,
            &probe_port);
    uint16_t peer_port = 0;
    fixture->pending_peer_probe = fixture->expected_peer_source_port &&
        (!fixture->peer_packet_id || fixture->peer_auth_enabled) && frame_is_source_probe_ack(packet->full_frame,
            packet->full_frame_bytes, fixture->expected_peer_source_port,
            fixture->expected_probe_destination_port, &peer_port);
    if (fixture->pending_peer_probe) {
        fixture->peer_witnesses++;
        fixture->peer_packet_id = packet->packet_id;
        fixture->peer_source_port = peer_port;
    }
    if (fixture->pending_probe) {
        fixture->probe_witnesses++;
        fixture->probe_packet_id = packet->packet_id;
        fixture->probe_source_port = probe_port;
    }
    struct ker_rx_owner_relay_header header = {
        .magic = KER_RX_OWNER_RELAY_MAGIC,
        .version = KER_RX_OWNER_RELAY_VERSION,
        .type = KER_RX_OWNER_RELAY_REQUEST,
        .packet_id = packet->packet_id,
        .deadline_ns = packet->deadline_ns,
        .worker_epoch = fixture->epoch,
        .app_start_ticks = fixture->app_start,
        .owner_start_ticks = fixture->owner_start,
        .supervisor_start_ticks = fixture->supervisor_start,
        .app_pid = (uint32_t)getpid(),
        .owner_pid = (uint32_t)fixture->owner_pid,
        .owner_tid = fixture->owner_tid,
        .supervisor_pid = fixture->supervisor_pid,
        .frame_bytes = packet->full_frame_bytes,
        .queue_id = packet->queue_id,
        .queue_count = packet->queue_count,
        .vlan_tci = packet->vlan_tci,
        .vlan_stripped = (uint8_t)(packet->flags & 1U),
    };
    memcpy(header.run_nonce, fixture->nonce, sizeof(header.run_nonce));
    struct iovec vectors[] = {
        {.iov_base = &header, .iov_len = sizeof(header)},
        {.iov_base = (void *)packet->full_frame, .iov_len = packet->full_frame_bytes},
    };
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    ssize_t sent = sendmsg(fixture->relay_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != (ssize_t)(sizeof(header) + packet->full_frame_bytes)) {
        int status = sent < 0 ? -errno : -EIO;
        pthread_mutex_unlock(&fixture->source_route_lock);
        return status;
    }
    fixture->packet_id = packet->packet_id;
    fixture->deadline_ns = packet->deadline_ns;
    fixture->frame_bytes = packet->full_frame_bytes;
    fixture->queue_id = packet->queue_id;
    fixture->queue_count = packet->queue_count;
    fixture->vlan_tci = packet->vlan_tci;
    fixture->vlan_stripped = (uint8_t)(packet->flags & 1U);
    fixture->callbacks++;
    fixture->deferred++;
    pthread_mutex_unlock(&fixture->source_route_lock);
    return KER_RX_DECISION_DEFER;
}

typedef int (*owner_control_poll_hook)(void *context);

/* Source-route mode owns the shared supervisor control socket. Keep its
 * receiver and the legacy PEER_AUTH receiver in one handler so the unit
 * receiver exercises the same dispatch order as the live app loop. */
static int poll_owner_control(struct fixture *fixture,
    owner_control_poll_hook after_source_route_poll, void *context)
{
    if (fixture->owner_authenticated && fixture->source_route_enabled) {
        int status = receive_source_route_command(fixture);
        if (status) return status;
        if (fixture->source_route_cut_pending && !fixture->source_route_cut_reply_poll_traced)
            source_route_cut_trace(fixture, "app-control-complete",
                fixture->source_route_cut_record.command_deadline_ns, 0);
        status = authenticate_pending_source_candidate(fixture);
        if (status) return status;
        if (after_source_route_poll) {
            status = after_source_route_poll(context);
            if (status) return status;
        }
    }
    /* In source-route mode PREPARE/COMMIT and peer binding share AUTH_FD.
     * A second legacy recvmsg can consume a command queued after its empty
     * source-route poll. The source-route commit installs the peer binding. */
    if (fixture->owner_authenticated && fixture->peer_auth_enabled &&
        !fixture->source_route_enabled) {
        int status = receive_supervisor_peer_auth(fixture);
        if (!status) status = receive_peer_owner_auth(fixture);
        if (status) return status;
    }
    return 0;
}

static int app_loop(void *opaque)
{
    struct fixture *fixture = opaque;
    if (!fixture->ready && ker_posix_rx_decision_is_ready()) {
        const char *startup = getenv("KER_STARTUP_FD");
        char *end = NULL;
        errno = 0;
        long fd = startup ? strtol(startup, &end, 10) : -1;
        static const char marker[] = "KER_RX_DECISION_READY\n";
        if (!startup || errno || end == startup || *end || fd < 0 || fd > INT32_MAX ||
            syscall(SYS_write, (int)fd, marker, sizeof(marker) - 1) !=
                (long)(sizeof(marker) - 1)) return -EIO;
        fixture->ready = true;
        puts("RX_OWNER_RELAY_APP_READY");
        fflush(stdout);
    }
    if (!fixture->owner_expected) {
        int auth = receive_supervisor_owner_auth(fixture);
        if (auth) return auth;
    }
    if (!fixture->owner_authenticated && fixture->owner_expected) {
        int auth = receive_owner_auth(fixture);
        if (auth) return auth;
    }
    int control_status = poll_owner_control(fixture, NULL, NULL);
    if (control_status) return control_status;
    if (fixture->packet_id) {
        struct ker_rx_owner_relay_header reply = {0};
        uint8_t reply_buffer[sizeof(reply) + KER_RX_OWNER_RELAY_MAX_FRAME];
        char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))] = {0};
        struct iovec iov = {.iov_base = reply_buffer, .iov_len = sizeof(reply_buffer)};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control)};
        int action = KER_RX_DECISION_DROP;
        if (fixture->peer_forward_pending) {
            reply = fixture->peer_source_reply;
            goto poll_peer_reply;
        }
        bool trace_reply_poll = fixture->source_route_cut_pending && !fixture->source_route_cut_reply_poll_traced;
        if (trace_reply_poll) {
            fixture->source_route_cut_reply_poll_traced = true;
            source_route_cut_trace(fixture, "old-poll-enter", fixture->source_route_cut_record.command_deadline_ns, 0);
        }
        ssize_t received = recvmsg(fixture->relay_fd, &message,
            MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
        if (trace_reply_poll)
            source_route_cut_trace(fixture, "old-poll-return", fixture->source_route_cut_record.command_deadline_ns,
                received < 0 ? -errno : (int)received);
        if (received >= 0) {
            if ((size_t)received >= sizeof(reply))
                memcpy(&reply, reply_buffer, sizeof(reply));
            struct ucred credentials = {0};
            bool have_credentials = false;
            int received_fds[2] = {-1, -1};
            size_t received_fd_count = 0;
            int ancillary_status = parse_credentials(&message, &credentials,
                &have_credentials, received_fds, &received_fd_count);
            for (size_t i = 0; i < received_fd_count; ++i) close(received_fds[i]);
            struct pollfd owner_poll = {.fd = fixture->owner_pidfd,
                .events = POLLIN | POLLHUP | POLLERR};
            if ((size_t)received != sizeof(reply) + fixture->frame_bytes ||
                (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
                ancillary_status || received_fd_count || !have_credentials ||
                credentials.pid != fixture->owner_pid ||
                credentials.uid != getuid() || credentials.gid != getgid() ||
                poll(&owner_poll, 1, 0) != 0 ||
                reply.magic != KER_RX_OWNER_RELAY_MAGIC ||
                reply.version != KER_RX_OWNER_RELAY_VERSION ||
                reply.type != KER_RX_OWNER_RELAY_REPLY ||
                reply.packet_id != fixture->packet_id ||
                reply.deadline_ns != fixture->deadline_ns ||
                reply.worker_epoch != fixture->epoch ||
                reply.owner_pid != (uint32_t)fixture->owner_pid ||
                reply.owner_tid != fixture->owner_tid ||
                memcmp(reply.run_nonce, fixture->nonce, sizeof(reply.run_nonce)) ||
                reply.frame_bytes != fixture->frame_bytes ||
                reply.queue_id != fixture->queue_id ||
                reply.queue_count != fixture->queue_count ||
                reply.app_pid != (uint32_t)getpid() ||
                reply.app_start_ticks != fixture->app_start ||
                reply.owner_start_ticks != fixture->owner_start ||
                reply.supervisor_pid != fixture->supervisor_pid ||
                reply.supervisor_start_ticks != fixture->supervisor_start ||
                reply.action || reply.reserved ||
                reply.frame_hash32 != fixture->current_frame_hash ||
                memcmp(reply_buffer + sizeof(reply), fixture->pending_frame,
                    fixture->frame_bytes) ||
                reply.vlan_tci != fixture->vlan_tci ||
                reply.vlan_stripped != fixture->vlan_stripped ||
                reply.frame_unchanged > 1 || reply.dispatcher_result < -3 ||
                !supervisor_authority_live(fixture) || !current_owner_live(fixture)) return -EPROTO;
            const char *stop_marker = getenv("KER_RX_OWNER_RELAY_TEST_STOP_MARKER");
            if (stop_marker && fixture->pending_probe && !fixture->stop_requested_with_pending) {
                const char *release = getenv("KER_RX_OWNER_RELAY_TEST_STOP_RELEASE");
                if (!release) return -EINVAL;
                int marker_fd = open(stop_marker,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                if (marker_fd < 0) return -errno;
                int written = dprintf(marker_fd, "%llu %llu\n",
                    (unsigned long long)fixture->packet_id,
                    (unsigned long long)fixture->deadline_ns);
                int marker_errno = errno;
                close(marker_fd);
                if (written <= 0) return -(marker_errno ? marker_errno : EIO);
                fixture->stop_requested_with_pending = true;
                puts("RX_OWNER_RELAY_STOP_REQUEST pending=1");
                fflush(stdout);
                /* Request shutdown while the authenticated deferred lease is
                 * still live, then let the test release this exact callback
                 * only after the original lease deadline. */
                ker_posix_stop_run();
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
                for (unsigned attempt = 0; attempt < 3000; ++attempt) {
                    if (access(release, F_OK) == 0) break;
                    (void)nanosleep(&pause, NULL);
                }
                if (access(release, F_OK) != 0) return -ETIMEDOUT;
            }
            action = reply.dispatcher_result == fixture->queue_id &&
                reply.frame_unchanged == 1 ? KER_RX_DECISION_LOCAL : KER_RX_DECISION_DROP;
            if (reply.dispatcher_result == -3 && reply.frame_unchanged == 1 && peer_authority_live(fixture)) {
                int status = ker_rx_owner_relay_peer_begin(&fixture->peer,
                    &reply, fixture->pending_frame, fixture->frame_bytes);
                if (!status) {
                    fixture->peer_source_reply = reply;
                    fixture->peer_forward_pending = true;
                    /* Let the broker service the old worker's pending RPC
                     * before polling its relay. Do not renew the C31 lease. */
                    return 0;
                }
            }
            goto complete_reply;
poll_peer_reply:;
            int peer_action = KER_RX_DECISION_DROP;
            int peer_status = peer_authority_live(fixture) ?
                ker_rx_owner_relay_peer_poll(&fixture->peer, fixture->pending_frame,
                    fixture->frame_bytes, &peer_action) : -ESTALE;
            if (peer_status == -EAGAIN) return 0;
            fixture->peer_forward_pending = false;
            if (!peer_status && peer_authority_live(fixture)) {
                action = peer_action;
                printf("RX_OWNER_PEER_HANDOFF packet=%llu primary_pid=%u primary_tid=%u old_pid=%u old_tid=%u action=%d hash=%u bytes=%u\n",
                    (unsigned long long)reply.packet_id, reply.owner_pid, reply.owner_tid,
                    fixture->peer.identity.owner_pid, fixture->peer.identity.owner_tid,
                    action, reply.frame_hash32, fixture->frame_bytes);
                fflush(stdout);
            }
complete_reply:
            if (fixture->source_route_cut_pending)
                source_route_cut_trace(fixture, "old-reply", fixture->source_route_cut_record.command_deadline_ns, action);
            if (monotonic_ns() >= fixture->deadline_ns || !current_owner_live(fixture)) return -EPROTO;
            if (fixture->source_route_cut_pending)
                source_route_cut_trace(fixture, "native-complete-enter", fixture->source_route_cut_record.command_deadline_ns, action);
            int complete_status = ker_posix_rx_decision_complete(fixture->packet_id, action);
            uint64_t complete_ns = monotonic_ns();
            if (fixture->source_route_cut_pending)
                source_route_cut_trace(fixture, "native-complete-return", fixture->source_route_cut_record.command_deadline_ns, complete_status);
            if (complete_status) return -EPROTO;
            fixture->completed++;
            if (fixture->source_route_cut_pending) {
                fixture->source_route_cut_completed_id = fixture->packet_id;
                fixture->source_route_cut_completed_ns = complete_ns;
            }
            if (fixture->probe_packet_id == reply.packet_id) {
                fixture->probe_frame_hash = reply.frame_hash32;
                fixture->probe_dispatcher_result = reply.dispatcher_result;
            }
            if (fixture->peer_packet_id == reply.packet_id) {
                fixture->peer_frame_hash = reply.frame_hash32;
                fixture->peer_dispatcher_result = reply.dispatcher_result;
            }
            if (fixture->pending_probe) {
                static const char digits[] = "0123456789abcdef";
                char frame_hex[KER_RX_OWNER_RELAY_MAX_FRAME * 2 + 1];
                for (size_t i = 0; i < fixture->frame_bytes; ++i) {
                    frame_hex[i * 2] = digits[fixture->pending_frame[i] >> 4];
                    frame_hex[i * 2 + 1] = digits[fixture->pending_frame[i] & 0xf];
                }
                frame_hex[fixture->frame_bytes * 2] = 0;
                printf("RX_OWNER_RELAY_PROBE_FRAME packet_id=%llu bytes=%u monotonic_ns=%llu frame_hex=%s\n",
                    (unsigned long long)reply.packet_id, fixture->frame_bytes,
                    (unsigned long long)monotonic_ns(), frame_hex);
                fflush(stdout);
            }
            if (fixture->pending_peer_probe) {
                static const char digits[] = "0123456789abcdef";
                char frame_hex[KER_RX_OWNER_RELAY_MAX_FRAME * 2 + 1];
                for (size_t i = 0; i < fixture->frame_bytes; ++i) {
                    frame_hex[i * 2] = digits[fixture->pending_frame[i] >> 4];
                    frame_hex[i * 2 + 1] = digits[fixture->pending_frame[i] & 0xf];
                }
                frame_hex[fixture->frame_bytes * 2] = 0;
                printf("RX_OWNER_RELAY_PEER_FRAME packet_id=%llu source_port=%u dispatcher_result=%d frame_hash=%u bytes=%u monotonic_ns=%llu frame_hex=%s\n",
                    (unsigned long long)reply.packet_id, fixture->peer_source_port,
                    reply.dispatcher_result, reply.frame_hash32,
                    fixture->frame_bytes, (unsigned long long)monotonic_ns(), frame_hex);
                fflush(stdout);
            }
            fixture->packet_id = 0;
            fixture->pending_probe = false;
            fixture->pending_peer_probe = false;
            int cut_status = progress_source_route_cut(fixture);
            if (cut_status) return cut_status;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return -errno;
        }
    }
    if (atomic_load_explicit(&fixture->broker_done, memory_order_acquire)) {
        /* The C31 lease remains owned until its exact decision is completed.
         * Never report a healthy run stop while a relay response is pending. */
        if (fixture->packet_id) return -EBUSY;
        ker_posix_stop_run();
        return 0;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const char *fd_text = getenv("KER_BROKER_READINESS_FD");
    const char *nonce_text = getenv("KER_BROKER_RUN_NONCE");
    const char *epoch_text = getenv("KER_BROKER_WORKER_EPOCH");
    const char *relay_fd_text = getenv("KER_RX_OWNER_RELAY_FD");
    const char *relay_nonce = getenv("KER_RX_OWNER_RELAY_NONCE");
    const char *relay_epoch = getenv("KER_RX_OWNER_RELAY_EPOCH");
    const char *profile_text = getenv("KER_BROKER_WORKER_PROFILE_SHA256");
    const char *supervisor_start_text = getenv("KER_BROKER_SUPERVISOR_START_TICKS");
    const char *relay_supervisor_pid_text = getenv("KER_RX_OWNER_RELAY_SUPERVISOR_PID");
    const char *relay_supervisor_start_text = getenv("KER_RX_OWNER_RELAY_SUPERVISOR_START_TICKS");
    char *end = NULL;
    errno = 0;
    long control_fd = fd_text ? strtol(fd_text, &end, 10) : -1;
    if (!fd_text || errno || end == fd_text || *end || control_fd < 0) return 2;
    errno = 0;
    long relay_fd = relay_fd_text ? strtol(relay_fd_text, &end, 10) : -1;
    if (!relay_fd_text || errno || end == relay_fd_text || *end || relay_fd < 3) return 2;
    struct fixture fixture = {.relay_fd = (int)relay_fd, .owner_pidfd = -1,
        .supervisor_pidfd = -1, .source_master_pidfd = -1,
        .source_route_candidate_pidfd = -1, .source_route_candidate_channel = -1,
        .source_route_master_pidfd = -1, .source_route_aborted_candidate_pidfd = -1,
        .source_route_aborted_master_pidfd = -1,
        .peer = {.fd = -1, .pidfd = -1}};
    if (pthread_mutex_init(&fixture.source_route_lock, NULL)) return 2;
    const char *peer_auth_enabled = getenv("KER_RX_OWNER_PEER_AUTH_ENABLE");
    if (peer_auth_enabled && strcmp(peer_auth_enabled, "1")) return 2;
    fixture.peer_auth_enabled = peer_auth_enabled != NULL;
    const char *source_route_enabled = getenv("KER_RX_OWNER_SOURCE_ROUTE_ENABLE");
    if (source_route_enabled && strcmp(source_route_enabled, "1")) return 2;
    fixture.source_route_enabled = source_route_enabled != NULL;
    const char *source_admission_profile =
        getenv("KER_RX_OWNER_RELAY_SOURCE_ADMISSION_TEST");
    if (source_admission_profile && strcmp(source_admission_profile, "1") != 0)
        return 2;
    fixture.expected_owner_role = source_admission_profile ? 1 : 0;
    const char *source_revoke_test = getenv("KER_RX_OWNER_RELAY_SOURCE_REVOKE_TEST");
    if (source_revoke_test && strcmp(source_revoke_test, "1") != 0) return 2;
    fixture.source_revoke_test = source_revoke_test != NULL;
    if (fixture.source_revoke_test && !source_admission_profile) return 2;
    fixture.probe_token = getenv("KER_RX_OWNER_RELAY_PROBE_TOKEN");
    if (!fixture.probe_token || strlen(fixture.probe_token) != 24) return 2;
    fixture.expected_probe_destination_port = source_admission_profile ? 4108 : 80;
    if (getenv("KER_RX_OWNER_RELAY_SOURCE_FLOWMAP_TEST")) {
        const char *port_text = getenv("KER_RX_OWNER_RELAY_SOURCE_FLOWMAP_PORT");
        char *end = NULL;
        unsigned long port = port_text ? strtoul(port_text, &end, 10) : 0;
        if (!port_text || end == port_text || *end || !port || port > UINT16_MAX)
            return 2;
        fixture.expected_probe_source_port = (uint16_t)port;
    }
    if (getenv("KER_RX_OWNER_RELAY_SOURCE_PEER_TEST")) {
        const char *port_text = getenv("KER_RX_OWNER_RELAY_SOURCE_PEER_PORT");
        char *end = NULL;
        unsigned long port = port_text ? strtoul(port_text, &end, 10) : 0;
        if (!port_text || end == port_text || *end || !port || port > UINT16_MAX)
            return 2;
        fixture.expected_peer_source_port = (uint16_t)port;
    }
    if (decode_hex(nonce_text, fixture.broker_nonce, sizeof(fixture.broker_nonce)) ||
        decode_hex(profile_text, fixture.profile_hash, sizeof(fixture.profile_hash))) return 2;
    if (decode_hex(relay_nonce, fixture.nonce, sizeof(fixture.nonce))) return 2;
    errno = 0;
    unsigned long long epoch = relay_epoch ? strtoull(relay_epoch, &end, 10) : 0;
    if (!relay_epoch || errno || end == relay_epoch || *end || !epoch) return 2;
    fixture.epoch = (uint64_t)epoch;
    errno = 0;
    unsigned long long broker_epoch = epoch_text ? strtoull(epoch_text, &end, 10) : 0;
    if (!epoch_text || errno || end == epoch_text || *end || !broker_epoch) return 2;
    errno = 0;
    unsigned long long supervisor_start = supervisor_start_text ?
        strtoull(supervisor_start_text, &end, 10) : 0;
    if (!supervisor_start_text || errno || end == supervisor_start_text || *end ||
        !supervisor_start) return 2;
    errno = 0;
    unsigned long long relay_supervisor_start = relay_supervisor_start_text ?
        strtoull(relay_supervisor_start_text, &end, 10) : 0;
    if (!relay_supervisor_start_text || errno || end == relay_supervisor_start_text ||
        *end || !relay_supervisor_start) return 2;
    errno = 0;
    unsigned long relay_supervisor_pid = relay_supervisor_pid_text ?
        strtoul(relay_supervisor_pid_text, &end, 10) : 0;
    if (!relay_supervisor_pid_text || errno || end == relay_supervisor_pid_text ||
        *end || !relay_supervisor_pid || relay_supervisor_pid > UINT32_MAX) return 2;
    fixture.supervisor_pid = (uint32_t)relay_supervisor_pid;
    fixture.supervisor_start = (uint64_t)relay_supervisor_start;
    if (read_start_ticks(getpid(), &fixture.app_start)) return 2;
    struct ker_socket_broker_server *server = ker_socket_broker_server_create(argv[1]);
    if (!server) { fprintf(stderr, "RX_OWNER_RELAY stage=server-create errno=%d\n", errno); return 3; }
    if (ker_socket_broker_server_readiness_attach(server, (int)control_fd,
            fixture.broker_nonce, (uint64_t)broker_epoch, fixture.profile_hash,
            (uint64_t)supervisor_start) != 0) {
        fprintf(stderr, "RX_OWNER_RELAY stage=readiness-attach errno=%d\n", errno);
        return 4;
    }
    if (ker_socket_broker_server_bootstrap_complete_empty(server) != 0) { fprintf(stderr, "RX_OWNER_RELAY stage=bootstrap-empty errno=%d\n", errno); return 5; }
    fixture.broker = server;
    int run_result = broker_run(&fixture);
    int run_errno = errno;
    int broker_result = ker_socket_broker_server_destroy_checked(server);
    printf("RX_OWNER_RELAY_RESULT callbacks=%llu deferred=%llu completed=%llu startup_drops=%llu probe_witnesses=%llu probe_packet_id=%llu probe_source_port=%u probe_frame_hash=%u probe_dispatcher_result=%d peer_witnesses=%llu peer_packet_id=%llu peer_source_port=%u peer_frame_hash=%u peer_dispatcher_result=%d broker=%d run=%d\n",
        (unsigned long long)fixture.callbacks, (unsigned long long)fixture.deferred,
        (unsigned long long)fixture.completed,
        (unsigned long long)fixture.startup_drops,
        (unsigned long long)fixture.probe_witnesses,
        (unsigned long long)fixture.probe_packet_id, fixture.probe_source_port,
        fixture.probe_frame_hash, fixture.probe_dispatcher_result,
        (unsigned long long)fixture.peer_witnesses,
        (unsigned long long)fixture.peer_packet_id, fixture.peer_source_port,
        fixture.peer_frame_hash, fixture.peer_dispatcher_result,
        fixture.broker_status, run_result);
    fflush(stdout);
    if (!run_result && !fixture.broker_status && !broker_result &&
        fixture.callbacks > 0 && fixture.deferred == fixture.completed)
        puts("BROKER_DONE");
    fflush(stdout);
    if (fixture.owner_pidfd >= 0) close(fixture.owner_pidfd);
    if (fixture.supervisor_pidfd >= 0) close(fixture.supervisor_pidfd);
    if (fixture.source_route_aborted_candidate_pidfd >= 0)
        close(fixture.source_route_aborted_candidate_pidfd);
    if (fixture.source_route_aborted_master_pidfd >= 0)
        close(fixture.source_route_aborted_master_pidfd);
    if (fixture.peer.fd >= 0) close(fixture.peer.fd);
    if (fixture.peer.pidfd >= 0) close(fixture.peer.pidfd);
    if (run_result) errno = run_errno;
    return run_result || fixture.broker_status || broker_result ||
        fixture.callbacks == 0 || fixture.deferred != fixture.completed ? 1 : 0;
}
