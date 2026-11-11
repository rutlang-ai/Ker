#define _GNU_SOURCE
#include "rx-decision-consumer.h"
#include "rx-owner-relay-wire.h"
#include "rx-owner-auth-wire.h"
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
    int32_t probe_dispatcher_result;
    uint32_t current_frame_hash;
    const char *probe_token;
    bool pending_probe;
    uint8_t pending_frame[KER_RX_OWNER_RELAY_MAX_FRAME];
    uint64_t packet_id;
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
    const char *token, uint16_t *source_port)
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
    if (((uint16_t)frame[tcp + 2] << 8 | frame[tcp + 3]) != 80) return false;
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
    uint16_t expected_source_port, uint16_t *source_port)
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
    if (port != expected_source_port || destination != 80 ||
        !(flags & 0x10) || (flags & 0x02)) return false;
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
        record.owner_role != 0 || record.flags || !record.owner_pid ||
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
    if (!fixture->owner_authenticated || !supervisor_authority_live(fixture)) {
        fixture->startup_drops++;
        return KER_RX_DECISION_DROP;
    }
    if (!packet || !packet->full_frame || packet->full_frame_bytes != packet->packet_bytes ||
        packet->full_frame_bytes < 14 || packet->full_frame_bytes > KER_RX_OWNER_RELAY_MAX_FRAME ||
        packet->deadline_ns <= monotonic_ns() || fixture->packet_id) return -EPROTO;
    fixture->current_frame_hash = frame_hash32(packet->full_frame,
        packet->full_frame_bytes);
    memcpy(fixture->pending_frame, packet->full_frame, packet->full_frame_bytes);
    uint16_t probe_port = 0;
    fixture->pending_probe = !fixture->probe_packet_id &&
        frame_is_probe(packet->full_frame, packet->full_frame_bytes,
            fixture->probe_token, &probe_port);
    if (!fixture->pending_probe && fixture->expected_probe_source_port &&
        !fixture->probe_packet_id)
        fixture->pending_probe = frame_is_source_probe_ack(packet->full_frame,
            packet->full_frame_bytes, fixture->expected_probe_source_port,
            &probe_port);
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
    if (sent != (ssize_t)(sizeof(header) + packet->full_frame_bytes))
        return sent < 0 ? -errno : -EIO;
    fixture->packet_id = packet->packet_id;
    fixture->deadline_ns = packet->deadline_ns;
    fixture->frame_bytes = packet->full_frame_bytes;
    fixture->queue_id = packet->queue_id;
    fixture->queue_count = packet->queue_count;
    fixture->vlan_tci = packet->vlan_tci;
    fixture->vlan_stripped = (uint8_t)(packet->flags & 1U);
    fixture->callbacks++;
    fixture->deferred++;
    return KER_RX_DECISION_DEFER;
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
    if (fixture->packet_id) {
        struct ker_rx_owner_relay_header reply = {0};
        uint8_t reply_buffer[sizeof(reply) + KER_RX_OWNER_RELAY_MAX_FRAME];
        char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))] = {0};
        struct iovec iov = {.iov_base = reply_buffer, .iov_len = sizeof(reply_buffer)};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control)};
        ssize_t received = recvmsg(fixture->relay_fd, &message,
            MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
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
                !supervisor_authority_live(fixture)) return -EPROTO;
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
            if (monotonic_ns() >= fixture->deadline_ns ||
                ker_posix_rx_decision_complete(fixture->packet_id,
                    reply.dispatcher_result == fixture->queue_id &&
                        reply.frame_unchanged == 1 ? KER_RX_DECISION_LOCAL :
                        KER_RX_DECISION_DROP)) return -EPROTO;
            fixture->completed++;
            if (fixture->probe_packet_id == reply.packet_id) {
                fixture->probe_frame_hash = reply.frame_hash32;
                fixture->probe_dispatcher_result = reply.dispatcher_result;
            }
            if (fixture->pending_probe) {
                static const char digits[] = "0123456789abcdef";
                char frame_hex[KER_RX_OWNER_RELAY_MAX_FRAME * 2 + 1];
                for (size_t i = 0; i < fixture->frame_bytes; ++i) {
                    frame_hex[i * 2] = digits[fixture->pending_frame[i] >> 4];
                    frame_hex[i * 2 + 1] = digits[fixture->pending_frame[i] & 0xf];
                }
                frame_hex[fixture->frame_bytes * 2] = 0;
                printf("RX_OWNER_RELAY_PROBE_FRAME packet_id=%llu bytes=%u frame_hex=%s\n",
                    (unsigned long long)reply.packet_id, fixture->frame_bytes, frame_hex);
                fflush(stdout);
            }
            fixture->packet_id = 0;
            fixture->pending_probe = false;
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
        .supervisor_pidfd = -1};
    fixture.probe_token = getenv("KER_RX_OWNER_RELAY_PROBE_TOKEN");
    if (!fixture.probe_token || strlen(fixture.probe_token) != 24) return 2;
    if (getenv("KER_RX_OWNER_RELAY_SOURCE_FLOWMAP_TEST")) {
        const char *port_text = getenv("KER_RX_OWNER_RELAY_SOURCE_FLOWMAP_PORT");
        char *end = NULL;
        unsigned long port = port_text ? strtoul(port_text, &end, 10) : 0;
        if (!port_text || end == port_text || *end || !port || port > UINT16_MAX)
            return 2;
        fixture.expected_probe_source_port = (uint16_t)port;
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
    printf("RX_OWNER_RELAY_RESULT callbacks=%llu deferred=%llu completed=%llu startup_drops=%llu probe_witnesses=%llu probe_packet_id=%llu probe_source_port=%u probe_frame_hash=%u probe_dispatcher_result=%d broker=%d run=%d\n",
        (unsigned long long)fixture.callbacks, (unsigned long long)fixture.deferred,
        (unsigned long long)fixture.completed,
        (unsigned long long)fixture.startup_drops,
        (unsigned long long)fixture.probe_witnesses,
        (unsigned long long)fixture.probe_packet_id, fixture.probe_source_port,
        fixture.probe_frame_hash, fixture.probe_dispatcher_result,
        fixture.broker_status, run_result);
    fflush(stdout);
    if (!run_result && !fixture.broker_status && !broker_result &&
        fixture.callbacks > 0 && fixture.deferred == fixture.completed)
        puts("BROKER_DONE");
    fflush(stdout);
    if (fixture.owner_pidfd >= 0) close(fixture.owner_pidfd);
    if (fixture.supervisor_pidfd >= 0) close(fixture.supervisor_pidfd);
    if (run_result) errno = run_errno;
    return run_result || fixture.broker_status || broker_result ||
        fixture.callbacks == 0 || fixture.deferred != fixture.completed ? 1 : 0;
}
