/* Test-only coordinator. All TCP and cutover work remains in the broker. */
#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { perror(#x); return 1; } } while (0)

#define SOURCE_PROVIDER_MAGIC "KERSC22P"
#define SOURCE_PROVIDER_VERSION 1u
#define SOURCE_C28_MAGIC "KERSC28Q"
#define SOURCE_C28_VERSION 1u
#define SOURCE_C28_REQUEST_BYTES 148u
#define SOURCE_C28_REPLY_BYTES 180u
#define SOURCE_C28_HEADER_BYTES 40u
#define SOURCE_C28_PARK 1u
#define SOURCE_C28_COMMIT 2u
#define SOURCE_C28_ABORT 3u
#define SOURCE_C28_CURRENT_CENSUS 4u
#define SOURCE_C28_RETIRE_INITIAL_LISTENER 5u
#define SOURCE_C28_CLOSE 6u
#define SOURCE_C28_RETRY_ADOPT 7u
#define SOURCE_C28_RETRY_SLOT 8u
#define SOURCE_C28_ADOPT_SUCCESSOR 9u
#define SOURCE_C28_CUTOVER_BUDGET_NS UINT64_C(100000000)
#define SOURCE_C28_RECV_ALLOWED_FLAGS MSG_CMSG_CLOEXEC
struct source_provider_record {
    char magic[8];
    uint32_t version;
    uint32_t bytes;
    uint64_t source_epoch;
    uint64_t broker_epoch;
    uint8_t source_nonce[16];
    uint8_t broker_nonce[16];
    uint32_t address_ipv4;
    uint32_t port;
    uint32_t backlog;
    uint64_t slot0_device;
    uint64_t slot0_inode;
    uint64_t slot1_device;
    uint64_t slot1_inode;
} __attribute__((__packed__));

_Static_assert(sizeof(struct source_provider_record) == 108,
    "source provider record ABI changed");
_Static_assert(SOURCE_C28_HEADER_BYTES + sizeof(struct source_provider_record) ==
    SOURCE_C28_REQUEST_BYTES, "C28 request wire layout changed");
_Static_assert(SOURCE_C28_REPLY_BYTES - SOURCE_C28_REQUEST_BYTES == 32,
    "C28 result extension wire layout changed");

static uint64_t now_ns(void);
static int pidfd_matches(int pidfd, pid_t pid);
static int source_parent_live(int pidfd, pid_t pid, uint64_t expected_start);
static uint16_t source_get_le16(const uint8_t *p);
static uint32_t source_get_le32(const uint8_t *p);
static uint64_t source_get_le64(const uint8_t *p);

struct source_c28_received_credentials {
    struct ucred value;
    size_t count;
    int unexpected;
};

/* Walk ancillary data and close every delivered right before checking the
 * packet size or flags. Short and zero-length seqpackets can still carry
 * installed SCM_RIGHTS descriptors. */
static int source_c28_parse_received(ssize_t received_bytes,
    struct msghdr *message, uint8_t request[SOURCE_C28_REQUEST_BYTES],
    struct source_c28_received_credentials *credentials)
{
    memset(credentials, 0, sizeof(*credentials));
    for (struct cmsghdr *c = CMSG_FIRSTHDR(message); c;
            c = CMSG_NXTHDR(message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
                c->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
            memcpy(&credentials->value, CMSG_DATA(c), sizeof(credentials->value));
            ++credentials->count;
        } else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            size_t bytes = c->cmsg_len >= CMSG_LEN(0) ?
                c->cmsg_len - CMSG_LEN(0) : 0;
            int *fds = (int *)CMSG_DATA(c);
            for (size_t i = 0; i + sizeof(int) <= bytes; i += sizeof(int))
                (void)close(fds[i / sizeof(int)]);
            credentials->unexpected = 1;
        } else {
            credentials->unexpected = 1;
        }
    }
    if ((message->msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            (message->msg_flags & ~SOURCE_C28_RECV_ALLOWED_FLAGS)) {
        errno = EPROTO;
        return -1;
    }
    if (received_bytes != SOURCE_C28_REQUEST_BYTES) {
        errno = EPROTO;
        return -1;
    }
    memcpy(request, message->msg_iov[0].iov_base, SOURCE_C28_REQUEST_BYTES);
    if (credentials->unexpected || credentials->count != 1) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int source_c28_request_deadline_valid(const uint8_t request[SOURCE_C28_REQUEST_BYTES],
    uint64_t grant_deadline, uint64_t current_time)
{
    uint64_t request_deadline = source_get_le64(request + 24);
    return request_deadline && request_deadline <= grant_deadline &&
        current_time < request_deadline;
}

static int source_c28_validate_request(const uint8_t request[SOURCE_C28_REQUEST_BYTES],
    const struct source_provider_record *bundle,
    const struct source_c28_received_credentials *credentials,
    int parent_pidfd, pid_t parent_pid, uint64_t parent_start,
    uint64_t expected_sequence, uint64_t grant_deadline, uint64_t current_time,
    bool allow_retry, bool allow_successor)
{
    if (memcmp(request, SOURCE_C28_MAGIC, 8) ||
            source_get_le16(request + 8) != SOURCE_C28_VERSION ||
            source_get_le32(request + 12) != SOURCE_C28_REQUEST_BYTES ||
            source_get_le32(request + 32) || source_get_le32(request + 36) ||
            memcmp(request + SOURCE_C28_HEADER_BYTES, bundle, sizeof(*bundle)))
        return EPROTO;
    if (credentials->count != 1 || credentials->unexpected ||
            credentials->value.pid != parent_pid ||
            credentials->value.uid != getuid() || credentials->value.gid != getgid() ||
            !source_parent_live(parent_pidfd, parent_pid, parent_start)) return EACCES;
    uint64_t sequence = source_get_le64(request + 16);
    if (!sequence || sequence != expected_sequence) return EALREADY;
    if (!source_c28_request_deadline_valid(request, grant_deadline, current_time))
        return ETIMEDOUT;
    uint16_t operation = source_get_le16(request + 10);
    if (operation < SOURCE_C28_PARK || operation > SOURCE_C28_ADOPT_SUCCESSOR ||
            ((operation == SOURCE_C28_RETRY_ADOPT || operation == SOURCE_C28_RETRY_SLOT) &&
                !allow_retry) ||
            (operation == SOURCE_C28_ADOPT_SUCCESSOR && !allow_successor))
        return EOPNOTSUPP;
    uint64_t deadline = source_get_le64(request + 24);
    if (operation == SOURCE_C28_PARK &&
            deadline - current_time > SOURCE_C28_CUTOVER_BUDGET_NS) return ETIMEDOUT;
    return 0;
}

static uint16_t source_get_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t source_get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t source_get_le64(const uint8_t *p)
{
    return (uint64_t)source_get_le32(p) |
        ((uint64_t)source_get_le32(p + 4) << 32);
}

static void source_put_le32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (i * 8));
}

static void source_put_le64(uint8_t *p, uint64_t value)
{
    source_put_le32(p, (uint32_t)value);
    source_put_le32(p + 4, (uint32_t)(value >> 32));
}

static int source_parent_live(int pidfd, pid_t pid, uint64_t expected_start)
{
    struct pollfd pfd = {.fd = pidfd, .events = POLLIN | POLLHUP | POLLERR | POLLNVAL};
    if (poll(&pfd, 1, 0) != 0 || !pidfd_matches(pidfd, pid)) return 0;
    char path[64], line[4096];
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) <= 0) return 0;
    FILE *stream = fopen(path, "re");
    if (!stream) return 0;
    size_t n = fread(line, 1, sizeof(line) - 1, stream);
    int failed = ferror(stream);
    if (fclose(stream) || failed || !n) return 0;
    line[n] = '\0';
    char *field = strrchr(line, ')');
    if (!field) return 0;
    field += 2;
    for (unsigned index = 0; index < 19; ++index) {
        field = strchr(field, ' ');
        if (!field) return 0;
        while (*field == ' ') ++field;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long start = strtoull(field, &end, 10);
    return !errno && end != field && start == expected_start;
}

static int source_wait_fd(int fd, short events, int parent_pidfd, pid_t parent_pid,
    uint64_t parent_start, uint64_t deadline_ns)
{
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now >= deadline_ns) { errno = ETIMEDOUT; return -1; }
        if (!source_parent_live(parent_pidfd, parent_pid, parent_start)) {
            errno = ESRCH; return -1;
        }
        uint64_t remaining = deadline_ns - now;
        int timeout = (int)((remaining + UINT64_C(999999)) / UINT64_C(1000000));
        struct pollfd fds[2] = {
            {.fd = fd, .events = events | POLLERR | POLLHUP | POLLNVAL},
            {.fd = parent_pidfd, .events = POLLIN | POLLHUP | POLLERR | POLLNVAL},
        };
        int ready = poll(fds, 2, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { if (!ready) errno = ETIMEDOUT; return -1; }
        if (fds[1].revents) { errno = ESRCH; return -1; }
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) { errno = EPIPE; return -1; }
        if (fds[0].revents & events) return 0;
    }
}

static int source_c28_wait_request(int transfer, int parent_pidfd, pid_t parent_pid,
    uint64_t parent_start, uint64_t grant_deadline)
{
    uint64_t current = now_ns();
    if (!current || current >= grant_deadline) { errno = ETIMEDOUT; return -1; }
    if (!source_parent_live(parent_pidfd, parent_pid, parent_start)) {
        errno = ESRCH;
        return -1;
    }
    uint64_t remaining = grant_deadline - current;
    int timeout = (int)((remaining + UINT64_C(999999)) / UINT64_C(1000000));
    struct pollfd waits[2] = {
        {.fd = transfer, .events = POLLIN | POLLERR | POLLHUP | POLLNVAL},
        {.fd = parent_pidfd, .events = POLLIN | POLLHUP | POLLERR | POLLNVAL},
    };
    int ready;
    do { ready = poll(waits, 2, timeout); } while (ready < 0 && errno == EINTR &&
        now_ns() < grant_deadline);
    if (ready == 0 || (ready < 0 && errno == EINTR)) { errno = ETIMEDOUT; return -1; }
    if (ready < 0) return -1;
    if (waits[1].revents) { errno = ESRCH; return -1; }
    if (waits[0].revents & (POLLERR | POLLHUP | POLLNVAL)) { errno = EPIPE; return -1; }
    if (!(waits[0].revents & POLLIN)) { errno = EIO; return -1; }
    if (now_ns() >= grant_deadline) { errno = ETIMEDOUT; return -1; }
    return 0;
}

static int source_c28_reply(int transfer, const uint8_t request[SOURCE_C28_REQUEST_BYTES],
    int error, uint32_t phase, uint64_t lease, uint64_t listener_cookie,
    uint32_t received, uint32_t accepted, int parent_pidfd, pid_t parent_pid,
    uint64_t parent_start, uint64_t deadline_ns, const int *retry_fds)
{
    uint8_t reply[SOURCE_C28_REPLY_BYTES];
    memcpy(reply, request, SOURCE_C28_REQUEST_BYTES);
    source_put_le32(reply + SOURCE_C28_REQUEST_BYTES, (uint32_t)(int32_t)error);
    source_put_le32(reply + SOURCE_C28_REQUEST_BYTES + 4, phase);
    source_put_le64(reply + SOURCE_C28_REQUEST_BYTES + 8, lease);
    source_put_le64(reply + SOURCE_C28_REQUEST_BYTES + 16, listener_cookie);
    source_put_le32(reply + SOURCE_C28_REQUEST_BYTES + 24, received);
    source_put_le32(reply + SOURCE_C28_REQUEST_BYTES + 28, accepted);
    struct iovec iov = {.iov_base = reply, .iov_len = sizeof(reply)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(2 * sizeof(int))]; } control = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (!error && retry_fds) {
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(2 * sizeof(int));
        memcpy(CMSG_DATA(header), retry_fds, 2 * sizeof(int));
    }
    while (now_ns() < deadline_ns) {
        ssize_t n = sendmsg(transfer, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n == (ssize_t)sizeof(reply)) {
            if (now_ns() < deadline_ns) return 0;
            errno = ETIMEDOUT;
            return -1;
        }
        if (n >= 0) { errno = EIO; return -1; }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
        if (source_wait_fd(transfer, POLLOUT, parent_pidfd, parent_pid,
                parent_start, deadline_ns)) return -1;
    }
    errno = ETIMEDOUT;
    return -1;
}

static int source_c28_receive(int transfer, uint8_t request[SOURCE_C28_REQUEST_BYTES],
    struct source_c28_received_credentials *credentials,
    int parent_pidfd, pid_t parent_pid, uint64_t parent_start, uint64_t deadline)
{
    for (;;) {
        if (source_c28_wait_request(transfer, parent_pidfd, parent_pid,
                parent_start, deadline)) return -1;
        union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred)) +
            CMSG_SPACE(sizeof(int) * 16)]; } control = {0};
        struct iovec iov = {.iov_base = request, .iov_len = SOURCE_C28_REQUEST_BYTES};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
        ssize_t bytes = recvmsg(transfer, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (bytes < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        return source_c28_parse_received(bytes, &message, request, credentials);
    }
}

/* Freeze the retry's original listener before releasing the first master
 * barrier. The broker checks the aborted candidate's admission task and
 * adopts the same native listener; this code retains the resulting handles. */
struct source_retry_plan {
    int plan, group, census, watch, slot;
    uint64_t cookie;
    bool slot_attempted;
};

static int source_adopt_plan(struct ker_socket_client *client, int plan,
    int *cutover, int initial_census, uint64_t deadline, struct source_retry_plan *retry,
    int (*adopt)(struct ker_socket_client *, int))
{
    struct ker_socket_member_census_snapshot before, after, adopted;
    if (retry->plan >= 0 || *cutover < 0) { errno = EALREADY; return -1; }
    if (now_ns() >= deadline) { errno = ETIMEDOUT; return -1; }
    if (ker_socket_client_member_census_snapshot(client, initial_census, &before)) return -1;
    if (!before.listener_cookie || before.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1) {
        errno = EPROTO; return -1;
    }
    close(*cutover);
    *cutover = -1;
    while (now_ns() < deadline) {
        retry->plan = adopt(client, plan);
        if (retry->plan >= 0) break;
        if (errno != EAGAIN) return -1;
        struct timespec pause = {.tv_nsec = 100000};
        (void)nanosleep(&pause, NULL);
    }
    if (retry->plan < 0 || now_ns() >= deadline) { errno = ETIMEDOUT; return -1; }
    retry->group = ker_socket_client_owner_group_control(client, retry->plan);
    if (retry->group < 0) return -1;
    if (now_ns() >= deadline) { errno = ETIMEDOUT; return -1; }
    retry->census = ker_socket_client_member_census_create(client, retry->group, 0);
    if (retry->census < 0) return -1;
    if (now_ns() >= deadline) { errno = ETIMEDOUT; return -1; }
    if (ker_socket_client_member_census_snapshot(client, initial_census, &after) ||
            ker_socket_client_member_census_snapshot(client, retry->census, &adopted)) return -1;
    if (now_ns() >= deadline) { errno = ETIMEDOUT; return -1; }
    if (after.listener_cookie != before.listener_cookie ||
            adopted.listener_cookie != before.listener_cookie ||
            after.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1 ||
            adopted.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1) {
        errno = EPROTO; return -1;
    }
    retry->cookie = adopted.listener_cookie;
    return 0;
}

static int source_retry_slot(struct ker_socket_client *client,
    struct source_retry_plan *retry, uint64_t deadline)
{
    if (retry->slot_attempted) { errno = EALREADY; return -1; }
    if (!retry->cookie || retry->plan < 0) { errno = EINVAL; return -1; }
    if (now_ns() >= deadline) { errno = ETIMEDOUT; return -1; }
    retry->slot_attempted = true;
    retry->watch = ker_socket_client_owner_generation_watch_create(client, retry->plan);
    if (retry->watch < 0) return -1;
    while (now_ns() < deadline) {
        retry->slot = ker_socket_client_owner_group_slot(client, retry->plan, 1);
        if (retry->slot >= 0) {
            if (now_ns() < deadline) return 0;
            break;
        }
        if (errno != EAGAIN) return -1;
        struct timespec pause = {.tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int source_c28_wait_phase(struct ker_socket_client *client, int cutover,
    uint32_t target, int parent_pidfd, pid_t parent_pid, uint64_t parent_start,
    uint64_t deadline_ns, struct ker_socket_group_cutover_status *state)
{
    for (;;) {
        if (now_ns() >= deadline_ns) { errno = ETIMEDOUT; return -1; }
        if (!source_parent_live(parent_pidfd, parent_pid, parent_start)) {
            errno = ESRCH; return -1;
        }
        if (ker_socket_client_owner_group_cutover_poll(client, cutover, state)) return -1;
        if (state->phase == target) return 0;
        if (state->phase == KER_SOCKET_GROUP_CUTOVER_FAILED ||
                state->phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED ||
                state->phase == KER_SOCKET_GROUP_CUTOVER_ABORTED ||
                state->phase == KER_SOCKET_GROUP_CUTOVER_COMMITTED) {
            errno = state->result < 0 ? -state->result : EPROTO;
            return -1;
        }
        struct timespec pause = {.tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    }
}

static int source_c28_command_loop(int transfer, struct ker_socket_client *client,
    int plan, int group, int census, const struct source_provider_record *bundle,
    int parent_pidfd, pid_t parent_pid, uint64_t parent_start, uint64_t grant_deadline,
    bool allow_retry, bool allow_successor)
{
    const int initial_plan = plan;
    if (setsockopt(transfer, SOL_SOCKET, SO_PASSCRED, &(int){1}, sizeof(int))) return -1;
    uint64_t next_sequence = 1, park_deadline = 0;
    int cutover = -1, committed = 0, retired = 0;
    uint64_t park_lease = 0;
    uint32_t park_received = 0;
    int initial_census = -1;
    bool aborted = false, retry_delivered = false;
    const struct source_retry_plan empty_plan = {.plan = -1, .group = -1,
        .census = -1, .watch = -1, .slot = -1};
    struct source_retry_plan retry = empty_plan, successor = empty_plan;
    for (;;) {
        uint8_t request[SOURCE_C28_REQUEST_BYTES] = {0};
        struct source_c28_received_credentials credentials;
        if (source_c28_receive(transfer, request, &credentials, parent_pidfd,
                parent_pid, parent_start, grant_deadline)) return -1;
        uint64_t deadline = source_get_le64(request + 24);
        uint64_t sequence = source_get_le64(request + 16);
        uint16_t operation = source_get_le16(request + 10);
        int request_error = source_c28_validate_request(request, bundle,
            &credentials, parent_pidfd, parent_pid, parent_start, next_sequence,
            grant_deadline, now_ns(), allow_retry, allow_successor);
        if (!request_error && sequence == next_sequence) ++next_sequence;
        int action_error = request_error;
        uint32_t phase = 0, received = 0, accepted = 0;
        uint64_t lease = 0, listener_cookie = 0;
        int retry_fds[2] = {-1, -1};
        struct ker_socket_group_cutover_status state = {0};
        if (!action_error && operation == SOURCE_C28_PARK) {
            if (cutover >= 0 || (aborted && !retry_delivered)) action_error = EALREADY;
            else {
                if (group < 0) {
                    do {
                        group = ker_socket_client_owner_group_control(client, plan);
                        if (group >= 0 || (errno != EAGAIN && errno != EINTR)) break;
                        if (now_ns() >= deadline) { action_error = ETIMEDOUT; break; }
                        if (!source_parent_live(parent_pidfd, parent_pid, parent_start)) {
                            action_error = ESRCH; break;
                        }
                        struct timespec pause = {.tv_nsec = 1000000};
                        (void)nanosleep(&pause, NULL);
                    } while (now_ns() < deadline);
                    if (!action_error && group < 0 && now_ns() >= deadline)
                        action_error = ETIMEDOUT;
                    if (!action_error && group < 0) action_error = errno ? errno : EIO;
                }
                if (!action_error && now_ns() >= deadline) action_error = ETIMEDOUT;
                if (!action_error && now_ns() >= deadline) action_error = ETIMEDOUT;
            }
            if (!action_error) {
                park_deadline = deadline;
                if (allow_retry && !retry_delivered && initial_census < 0) {
                    initial_census = ker_socket_client_member_census_create(client, group, 0);
                    if (initial_census < 0) action_error = errno ? errno : EIO;
                }
            }
            if (!action_error) {
                do {
                    cutover = ker_socket_client_owner_group_cutover_begin(client, plan);
                    if (cutover >= 0 || (errno != EAGAIN && errno != EINTR)) break;
                    if (now_ns() >= park_deadline) { action_error = ETIMEDOUT; break; }
                    if (!source_parent_live(parent_pidfd, parent_pid, parent_start)) {
                        action_error = ESRCH; break;
                    }
                    struct timespec pause = {.tv_nsec = 1000000};
                    (void)nanosleep(&pause, NULL);
                } while (now_ns() < park_deadline);
                if (!action_error && cutover < 0 && now_ns() >= park_deadline)
                    action_error = ETIMEDOUT;
                if (!action_error && cutover < 0) action_error = errno ? errno : EIO;
                if (!action_error && source_c28_wait_phase(client, cutover,
                        KER_SOCKET_GROUP_CUTOVER_PREPARED, parent_pidfd, parent_pid,
                        parent_start, park_deadline, &state)) action_error = errno ? errno : EIO;
                if (!action_error && census < 0) {
                    do {
                        census = ker_socket_client_member_census_create(client, group, 1);
                        if (census >= 0 || (errno != EAGAIN && errno != EINTR)) break;
                        if (now_ns() >= park_deadline) { action_error = ETIMEDOUT; break; }
                        if (!source_parent_live(parent_pidfd, parent_pid, parent_start)) {
                            action_error = ESRCH; break;
                        }
                        struct timespec pause = {.tv_nsec = 1000000};
                        (void)nanosleep(&pause, NULL);
                    } while (now_ns() < park_deadline);
                    if (!action_error && census < 0 && now_ns() >= park_deadline)
                        action_error = ETIMEDOUT;
                    if (!action_error && census < 0) action_error = errno ? errno : EIO;
                }
                if (cutover >= 0) {
                    phase = state.phase; lease = state.lease;
                    received = state.received_packets; accepted = state.accepted_packets;
                    park_lease = lease;
                    park_received = received;
                    if (!action_error && (!park_lease || accepted))
                        action_error = EPROTO;
                }
            }
        } else if (!action_error && operation == SOURCE_C28_COMMIT) {
            if (cutover < 0 || !park_deadline || deadline != park_deadline || committed ||
                    !park_lease)
                action_error = EINVAL;
            else {
                int result;
                do {
                    result = ker_socket_client_owner_group_cutover_commit_before(
                        client, cutover, park_deadline);
                    if (!result || errno != EBUSY) break;
                    struct timespec pause = {.tv_nsec = 100000};
                    (void)nanosleep(&pause, NULL);
                } while (now_ns() < park_deadline);
                if (result) action_error = errno ? errno : EIO;
            }
            if (!action_error && source_c28_wait_phase(client, cutover,
                    KER_SOCKET_GROUP_CUTOVER_COMMITTED, parent_pidfd, parent_pid,
                    parent_start, park_deadline, &state)) action_error = errno ? errno : EIO;
            if (!action_error) {
                struct ker_socket_member_census_snapshot snapshot;
                if (now_ns() >= park_deadline ||
                        ker_socket_client_member_census_snapshot(client, census, &snapshot))
                    action_error = errno ? errno : ETIMEDOUT;
                else if (!snapshot.listener_cookie ||
                        snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1)
                    action_error = EPROTO;
                else { committed = 1; listener_cookie = snapshot.listener_cookie; }
                /* PREPARED observes a queue still receiving SYNs. The final
                 * receipt must account for every packet under the same lease. */
                if (!action_error && (state.lease != park_lease ||
                        state.received_packets < park_received ||
                        state.accepted_packets != state.received_packets)) action_error = EPROTO;
                phase = state.phase; lease = state.lease;
                received = state.received_packets; accepted = state.accepted_packets;
            }
        } else if (!action_error && operation == SOURCE_C28_ABORT) {
            if (cutover < 0 || !park_deadline || deadline != park_deadline ||
                    committed || !park_lease || aborted)
                action_error = EINVAL;
            else if (ker_socket_client_owner_group_cutover_abort_before(client,
                    cutover, park_deadline))
                action_error = errno ? errno : EIO;
            else if (source_c28_wait_phase(client, cutover,
                    KER_SOCKET_GROUP_CUTOVER_ABORTED, parent_pidfd, parent_pid,
                    parent_start, park_deadline, &state)) action_error = errno ? errno : EIO;
            if (!action_error && (state.lease != park_lease || state.result ||
                    state.received_packets < park_received ||
                    state.accepted_packets != state.received_packets))
                action_error = EPROTO;
            if (!action_error) aborted = true;
            phase = state.phase; lease = state.lease;
            received = state.received_packets; accepted = state.accepted_packets;
        } else if (!action_error && operation == SOURCE_C28_RETRY_ADOPT) {
            if (!aborted || retry_delivered || deadline != park_deadline ||
                    initial_census < 0) action_error = EINVAL;
            else if (source_adopt_plan(client, plan, &cutover, initial_census, deadline,
                    &retry, ker_socket_client_owner_group_retry_plan))
                action_error = errno ? errno : EIO;
            else {
                phase = KER_SOCKET_GROUP_CUTOVER_ABORTED;
                lease = park_lease;
                listener_cookie = retry.cookie;
            }
        } else if (!action_error && operation == SOURCE_C28_RETRY_SLOT) {
            if (retry_delivered) action_error = EALREADY;
            else if (source_retry_slot(client, &retry, deadline))
                action_error = errno ? errno : EIO;
            else {
                retry_fds[0] = retry.slot;
                retry_fds[1] = retry.watch;
                listener_cookie = retry.cookie;
            }
        } else if (!action_error && operation == SOURCE_C28_ADOPT_SUCCESSOR) {
            if (!committed || !retired || census < 0 || cutover < 0 || aborted)
                action_error = EINVAL;
            else if (source_adopt_plan(client, plan, &cutover, census, deadline,
                    &successor, ker_socket_client_owner_group_successor_plan) ||
                    source_retry_slot(client, &successor, deadline))
                action_error = errno ? errno : EIO;
            else {
                retry_fds[0] = successor.slot;
                retry_fds[1] = successor.watch;
                listener_cookie = successor.cookie;
            }
        } else if (!action_error && operation == SOURCE_C28_CURRENT_CENSUS) {
            struct ker_socket_member_census_snapshot snapshot;
            if (census < 0) action_error = EAGAIN;
            else if (ker_socket_client_member_census_snapshot(client, census, &snapshot))
                action_error = errno ? errno : EIO;
            else { listener_cookie = snapshot.listener_cookie;
                phase = cutover >= 0 ? state.phase : 0; }
        } else if (!action_error && operation == SOURCE_C28_RETIRE_INITIAL_LISTENER) {
            if (!committed || retired) action_error = EAGAIN;
            else if (ker_socket_client_owner_group_retire_initial_listener(client, plan))
                action_error = errno ? errno : EIO;
            else retired = 1;
        }
        if (!source_parent_live(parent_pidfd, parent_pid, parent_start) && !action_error)
            action_error = ESRCH;
        if (now_ns() >= deadline && !action_error) action_error = ETIMEDOUT;
        if (source_c28_reply(transfer, request, action_error, phase, lease,
                listener_cookie, received, accepted, parent_pidfd, parent_pid,
                parent_start, deadline, retry_fds[0] >= 0 ? retry_fds : NULL)) {
            /* A timed-out caller owns an unknown outcome; preserve all C28
             * capabilities and wait for an explicit later cleanup command. */
            if (errno != ETIMEDOUT) return -1;
            continue;
        }
        if (!action_error && operation == SOURCE_C28_RETRY_SLOT) {
            if (census >= 0) close(census);
            census = -1;
            plan = retry.plan;
            if (group >= 0) close(group);
            group = retry.group;
            park_deadline = park_lease = 0;
            park_received = 0;
            aborted = false;
            retry_delivered = true;
        }
        if (!action_error && operation == SOURCE_C28_ADOPT_SUCCESSOR) {
            if (census >= 0) close(census);
            if (group >= 0) close(group);
            if (plan != initial_plan) close(plan);
            close(successor.slot);
            close(successor.watch);
            close(successor.census);
            plan = successor.plan;
            group = successor.group;
            census = -1;
            successor = empty_plan;
            park_deadline = park_lease = 0;
            park_received = 0;
            committed = retired = 0;
        }
        if (!action_error && operation == SOURCE_C28_CLOSE) {
            if (initial_census >= 0) close(initial_census);
            if (census >= 0) close(census);
            if (cutover >= 0) close(cutover);
            if (retry.slot >= 0) close(retry.slot);
            if (retry.watch >= 0) close(retry.watch);
            if (retry.census >= 0) close(retry.census);
            if (retry.group >= 0) close(retry.group);
            if (retry.plan >= 0) close(retry.plan);
            if (group >= 0 && !retry_delivered) close(group);
            if (allow_successor && plan != initial_plan) close(plan);
            if (successor.slot >= 0) close(successor.slot);
            if (successor.watch >= 0) close(successor.watch);
            if (successor.census >= 0) close(successor.census);
            if (successor.group >= 0) close(successor.group);
            if (successor.plan >= 0) close(successor.plan);
            return 0;
        }
    }
}

static int parse_hex16(const char *text, uint8_t out[16])
{
    if (!text || strlen(text) != 32) return -1;
    for (size_t i = 0; i < 16; ++i) {
        char pair[3] = {text[i * 2], text[i * 2 + 1], '\0'};
        for (unsigned octet = 0; octet < 2; ++octet)
            if (!((pair[octet] >= '0' && pair[octet] <= '9') ||
                  (pair[octet] >= 'a' && pair[octet] <= 'f'))) return -1;
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(pair, &end, 16);
        if (errno || end != pair + 2 || value > UINT8_MAX) return -1;
        out[i] = (uint8_t)value;
    }
    return 0;
}

static int parse_decimal_u64(const char *text, uint64_t *value)
{
    if (!text || !*text || (text[0] == '0' && text[1])) return -1;
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || !end || *end || !parsed) return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int nonzero16(const uint8_t value[16])
{
    uint8_t combined = 0;
    for (size_t i = 0; i < 16; ++i) combined |= value[i];
    return combined != 0;
}

static int pidfd_matches(int pidfd, pid_t pid)
{
    char path[64], line[128];
    if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd) <= 0) return 0;
    FILE *stream = fopen(path, "re");
    if (!stream) return 0;
    int matches = 0;
    while (fgets(line, sizeof(line), stream)) {
        long value;
        if (sscanf(line, "Pid:\t%ld", &value) == 1) {
            matches = value == pid;
            break;
        }
    }
    if (fclose(stream)) return 0;
    return matches;
}

static int source_shell_provider(int argc, char **argv)
{
    /* broker, transfer-fd, mode, address, port, backlog, source nonce/epoch,
     * C34 readiness nonce/epoch, expected parent PID */
    CHECK(argc == 15);
    char *end = NULL;
    long transfer = strtol(argv[2], &end, 10);
    CHECK(argv[2][0] && !*end && transfer >= 0 && transfer <= INT32_MAX);
    bool allow_retry = !strcmp(argv[3], "--source-shell-abort-retry");
    bool allow_successor = !strcmp(argv[3], "--source-shell-successive");
    CHECK(allow_retry || allow_successor || !strcmp(argv[3], "--source-shell"));
    struct in_addr address;
    CHECK(inet_pton(AF_INET, argv[4], &address) == 1);
    uint64_t port, backlog, source_epoch, broker_epoch, expected_parent;
    uint64_t expected_parent_start, grant_deadline_ns, parent_pidfd_value;
    CHECK(!parse_decimal_u64(argv[5], &port) && port <= UINT16_MAX);
    CHECK(!parse_decimal_u64(argv[6], &backlog) && backlog <= 65535);
    CHECK(!parse_decimal_u64(argv[8], &source_epoch));
    CHECK(!parse_decimal_u64(argv[10], &broker_epoch));
    CHECK(!parse_decimal_u64(argv[11], &expected_parent) && expected_parent <= INT32_MAX);
    CHECK(!parse_decimal_u64(argv[12], &expected_parent_start));
    CHECK(!parse_decimal_u64(argv[13], &grant_deadline_ns));
    CHECK(!parse_decimal_u64(argv[14], &parent_pidfd_value) && parent_pidfd_value <= INT32_MAX);
    uint8_t source_nonce[16], broker_nonce[16];
    CHECK(!parse_hex16(argv[7], source_nonce) && nonzero16(source_nonce));
    CHECK(!parse_hex16(argv[9], broker_nonce) && nonzero16(broker_nonce));
    uint64_t initial_now = now_ns();
    CHECK(grant_deadline_ns && initial_now && initial_now < grant_deadline_ns);
    /* This C22 helper is narrowly for the actual pinned rt01 listener. */
    CHECK(address.s_addr == htonl(INADDR_ANY) && port == 80 && backlog == 511);
    struct ucred peer = {0};
    socklen_t peer_bytes = sizeof(peer);
    CHECK(!getsockopt((int)transfer, SOL_SOCKET, SO_PEERCRED, &peer, &peer_bytes));
    CHECK(peer_bytes == sizeof(peer) && peer.pid == (pid_t)expected_parent &&
        peer.uid == getuid() && peer.gid == getgid());
    CHECK(pidfd_matches((int)parent_pidfd_value, peer.pid));
    struct pollfd parent_liveness = {.fd = (int)parent_pidfd_value,
        .events = POLLIN | POLLHUP | POLLERR | POLLNVAL};
    CHECK(poll(&parent_liveness, 1, 0) == 0);
    char proc_path[64], proc_stat[4096];
    CHECK(snprintf(proc_path, sizeof(proc_path), "/proc/%llu/stat",
        (unsigned long long)expected_parent) > 0);
    FILE *proc = fopen(proc_path, "re");
    CHECK(proc != NULL);
    size_t proc_bytes = fread(proc_stat, 1, sizeof(proc_stat) - 1, proc);
    int proc_error = ferror(proc);
    CHECK(fclose(proc) == 0 && !proc_error && proc_bytes > 0);
    proc_stat[proc_bytes] = '\0';
    char *close_paren = strrchr(proc_stat, ')');
    CHECK(close_paren != NULL);
    char *field = close_paren + 2;
    for (unsigned index = 0; index < 19; ++index) {
        field = strchr(field, ' ');
        CHECK(field != NULL);
        while (*field == ' ') ++field;
    }
    char *start_end = NULL;
    errno = 0;
    unsigned long long parent_start = strtoull(field, &start_end, 10);
    CHECK(!errno && start_end != field && parent_start == expected_parent_start);

    struct ker_socket_client client;
    bool client_open = false;
    int plan = -1;
    int group = -1, census = -1;
    int slots[2] = {-1, -1};
    int watch = -1;
    const char *failure_stage = NULL;
    int failure_error = 0;
#define SOURCE_FAIL(stage, error) do { \
    failure_stage = (stage); failure_error = (error); errno = failure_error; goto failed; \
} while (0)
    if (ker_socket_client_open(&client, argv[1])) {
        int error = errno;
        (void)dprintf(STDERR_FILENO, "SOURCE_C22_BROKER_CONNECT_ERRNO=%d\n", error);
        errno = error;
        return 1;
    }
    client_open = true;
    if (now_ns() >= grant_deadline_ns)
        SOURCE_FAIL("post_connect_deadline", ETIMEDOUT);
    if (poll(&parent_liveness, 1, 0) != 0)
        SOURCE_FAIL("post_connect_parent_liveness", ESRCH);
    struct sockaddr_in tuple = {.sin_family = AF_INET,
        .sin_port = htons((uint16_t)port), .sin_addr = address};
    uint64_t before_plan = now_ns();
    if (!before_plan)
        SOURCE_FAIL("pre_plan_clock", errno ? errno : EIO);
    if (before_plan >= grant_deadline_ns)
        SOURCE_FAIL("pre_plan_deadline", ETIMEDOUT);
    if (poll(&parent_liveness, 1, 0) != 0)
        SOURCE_FAIL("pre_plan_parent_liveness", ESRCH);
    plan = ker_socket_client_owner_group_staged_plan(&client, &tuple,
        (int)backlog, KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    if (plan < 0) {
        int error = errno ? errno : EIO;
        (void)dprintf(STDERR_FILENO, "SOURCE_C22_PLAN_ERRNO=%d\n", error);
        SOURCE_FAIL("plan_create", error);
    }
    if (now_ns() >= grant_deadline_ns)
        SOURCE_FAIL("post_plan_deadline", ETIMEDOUT);
    if (poll(&parent_liveness, 1, 0) != 0)
        SOURCE_FAIL("post_plan_parent_liveness", ESRCH);
    slots[0] = ker_socket_client_owner_group_slot(&client, plan, 0);
    if (slots[0] < 0) SOURCE_FAIL("slot0_create", errno ? errno : EIO);
    if (now_ns() >= grant_deadline_ns) SOURCE_FAIL("slot0_deadline", ETIMEDOUT);
    if (poll(&parent_liveness, 1, 0) != 0) SOURCE_FAIL("slot0_parent_liveness", ESRCH);
    slots[1] = ker_socket_client_owner_group_slot(&client, plan, 1);
    if (slots[1] < 0) SOURCE_FAIL("slot1_create", errno ? errno : EIO);
    if (now_ns() >= grant_deadline_ns) SOURCE_FAIL("slot1_deadline", ETIMEDOUT);
    if (poll(&parent_liveness, 1, 0) != 0) SOURCE_FAIL("slot1_parent_liveness", ESRCH);
    /* The API/server grant a read-only watch; DESCRIBE below checks kind and
     * status flags only, not the broker's opaque logical-rights field. */
    watch = ker_socket_client_owner_generation_watch_create(&client, plan);
    if (watch < 0) SOURCE_FAIL("watch_create", errno ? errno : EIO);
    if (now_ns() >= grant_deadline_ns) SOURCE_FAIL("watch_deadline", ETIMEDOUT);
    if (poll(&parent_liveness, 1, 0) != 0) SOURCE_FAIL("watch_parent_liveness", ESRCH);
    for (unsigned i = 0; i < 2; ++i) {
        struct stat info;
        int status_flags = fcntl(slots[i], F_GETFL);
        int descriptor_flags = fcntl(slots[i], F_GETFD);
        if (fstat(slots[i], &info)) SOURCE_FAIL(i ? "slot1_fstat" : "slot0_fstat", errno);
        if (!S_ISFIFO(info.st_mode)) SOURCE_FAIL(i ? "slot1_type" : "slot0_type", EPROTO);
        if (status_flags < 0) SOURCE_FAIL(i ? "slot1_getfl" : "slot0_getfl", errno);
        if ((status_flags & O_ACCMODE) != O_WRONLY)
            SOURCE_FAIL(i ? "slot1_access_mode" : "slot0_access_mode", EPROTO);
        if (!(status_flags & O_NONBLOCK))
            SOURCE_FAIL(i ? "slot1_nonblock" : "slot0_nonblock", EPROTO);
        if (descriptor_flags < 0) SOURCE_FAIL(i ? "slot1_getfd" : "slot0_getfd", errno);
        if (!(descriptor_flags & FD_CLOEXEC))
            SOURCE_FAIL(i ? "slot1_cloexec" : "slot0_cloexec", EPROTO);
    }
    enum ker_socket_broker_kind kind = 0;
    int described_status_flags = -1;
    struct stat watch_info;
    int watch_status_flags = fcntl(watch, F_GETFL);
    int watch_descriptor_flags = fcntl(watch, F_GETFD);
    if (ker_socket_client_describe(&client, watch, &kind, &described_status_flags))
        SOURCE_FAIL("watch_describe", errno ? errno : EIO);
    if (kind != KER_SOCKET_BROKER_FF_OWNER_GENERATION_WATCH)
        SOURCE_FAIL("watch_kind", EPROTO);
    /* DESCRIBE reports host status flags, not opaque capability rights. */
    if (described_status_flags != 0) SOURCE_FAIL("watch_describe_status_flags", EPROTO);
    if (fstat(watch, &watch_info)) SOURCE_FAIL("watch_fstat", errno);
    if (!S_ISFIFO(watch_info.st_mode)) SOURCE_FAIL("watch_type", EPROTO);
    if (watch_info.st_uid != getuid()) SOURCE_FAIL("watch_owner", EPERM);
    if (watch_status_flags < 0) SOURCE_FAIL("watch_getfl", errno);
    if ((watch_status_flags & O_ACCMODE) != O_WRONLY)
        SOURCE_FAIL("watch_access_mode", EPROTO);
    if (!(watch_status_flags & O_NONBLOCK)) SOURCE_FAIL("watch_nonblock", EPROTO);
    if (watch_descriptor_flags < 0) SOURCE_FAIL("watch_getfd", errno);
    if (!(watch_descriptor_flags & FD_CLOEXEC)) SOURCE_FAIL("watch_cloexec", EPROTO);

    struct source_provider_record record = {0};
    memcpy(record.magic, SOURCE_PROVIDER_MAGIC, sizeof(record.magic));
    record.version = SOURCE_PROVIDER_VERSION;
    record.bytes = sizeof(record);
    record.source_epoch = source_epoch;
    record.broker_epoch = broker_epoch;
    memcpy(record.source_nonce, source_nonce, sizeof(source_nonce));
    memcpy(record.broker_nonce, broker_nonce, sizeof(broker_nonce));
    record.address_ipv4 = ntohl(address.s_addr);
    record.port = (uint32_t)port;
    record.backlog = (uint32_t)backlog;
    struct stat slot_info[2];
    if (fstat(slots[0], &slot_info[0])) SOURCE_FAIL("slot0_identity", errno);
    if (fstat(slots[1], &slot_info[1])) SOURCE_FAIL("slot1_identity", errno);
    record.slot0_device = (uint64_t)slot_info[0].st_dev;
    record.slot0_inode = (uint64_t)slot_info[0].st_ino;
    record.slot1_device = (uint64_t)slot_info[1].st_dev;
    record.slot1_inode = (uint64_t)slot_info[1].st_ino;
    int descriptors[3] = {slots[0], slots[1], watch};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(descriptors))]; } control = {0};
    struct iovec vector = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(descriptors));
    memcpy(CMSG_DATA(header), descriptors, sizeof(descriptors));
    for (;;) {
        uint64_t current_now = now_ns();
        if (!current_now) SOURCE_FAIL("transfer_clock", errno ? errno : EIO);
        if (current_now >= grant_deadline_ns) SOURCE_FAIL("transfer_deadline", ETIMEDOUT);
        if (poll(&parent_liveness, 1, 0) != 0)
            SOURCE_FAIL("transfer_parent_liveness", ESRCH);
        ssize_t sent = sendmsg((int)transfer, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent == (ssize_t)sizeof(record)) break;
        if (sent >= 0) SOURCE_FAIL("transfer_short_send", EIO);
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            SOURCE_FAIL("transfer_sendmsg", errno);
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) SOURCE_FAIL("transfer_clock_gettime", errno);
        uint64_t current = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
        int timeout = current >= grant_deadline_ns ? 0 :
            (int)((grant_deadline_ns - current + UINT64_C(999999)) / UINT64_C(1000000));
        struct pollfd waits[2] = {{.fd=(int)transfer, .events=POLLOUT}, parent_liveness};
        int ready = poll(waits, 2, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) SOURCE_FAIL("transfer_poll", errno);
        if (ready == 0) SOURCE_FAIL("transfer_deadline", ETIMEDOUT);
        if (waits[1].revents) SOURCE_FAIL("transfer_parent_liveness", ESRCH);
        if (waits[0].revents & (POLLERR | POLLHUP | POLLNVAL))
            SOURCE_FAIL("transfer_peer", EPIPE);
    }

    if (source_c28_command_loop((int)transfer, &client, plan, group, census,
            &record, (int)parent_pidfd_value, peer.pid, expected_parent_start,
            grant_deadline_ns, allow_retry, allow_successor))
        SOURCE_FAIL("command_loop", errno ? errno : EIO);
    close(watch);
    close(slots[0]); close(slots[1]); close(plan); close((int)transfer);
    ker_socket_client_close(&client);
    return 0;
failed:
    (void)dprintf(STDERR_FILENO, "SOURCE_C22_FAILURE_STAGE=%s ERRNO=%d\n",
        failure_stage ? failure_stage : "unknown", failure_error);
    if (watch >= 0) close(watch);
    if (census >= 0) close(census);
    if (group >= 0) close(group);
    for (unsigned i = 0; i < 2; ++i) if (slots[i] >= 0) close(slots[i]);
    if (plan >= 0) close(plan);
    close((int)transfer);
    if (client_open) ker_socket_client_close(&client);
#undef SOURCE_FAIL
    return 1;
}

static uint64_t now_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static int cutover_wait_until(struct ker_socket_client *client, int cap,
    uint32_t phase, int require_packet, uint64_t deadline)
{
    struct ker_socket_group_cutover_status state = {0};
    for (uint64_t current = now_ns(); current && current < deadline; current = now_ns()) {
        if (ker_socket_client_owner_group_cutover_poll(client, cap, &state)) {
            int error = errno;
            fprintf(stderr, "CUTOVER_WAIT poll_error=%d phase=%u result=%d received=%u accepted=%u lease=%llu\n",
                error, state.phase, state.result, state.received_packets,
                state.accepted_packets, (unsigned long long)state.lease);
            errno = error;
            return -1;
        }
        if (state.phase == phase && (!require_packet || state.received_packets)) {
            if (now_ns() >= deadline) break;
            printf("CUTOVER_STATE phase=%u received=%u accepted=%u\n",
                state.phase, state.received_packets, state.accepted_packets);
            fflush(stdout);
            return 0;
        }
        if (state.phase == KER_SOCKET_GROUP_CUTOVER_FAILED ||
            state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED) {
            fprintf(stderr, "CUTOVER_WAIT terminal phase=%u result=%d received=%u accepted=%u lease=%llu\n",
                state.phase, state.result, state.received_packets,
                state.accepted_packets, (unsigned long long)state.lease);
            errno = EPROTO; return -1;
        }
        struct timespec pause = {.tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    }
    fprintf(stderr, "CUTOVER_WAIT timeout phase=%u result=%d received=%u accepted=%u lease=%llu\n",
        state.phase, state.result, state.received_packets,
        state.accepted_packets, (unsigned long long)state.lease);
    errno = ETIMEDOUT;
    return -1;
}

static int cutover_wait(struct ker_socket_client *client, int cap,
    uint32_t phase, int require_packet)
{
    uint64_t start = now_ns();
    if (!start) return -1;
    return cutover_wait_until(client, cap, phase, require_packet,
        start + UINT64_C(10000000000));
}

int main(int argc, char **argv)
{
    bool retry_wire = argc == 6 && !strcmp(argv[3], "--source-retry-wire");
    int generation_watch = retry_wire || (argc == 4 &&
        !strcmp(argv[3], "--generation-watch-preclaim"));
    if (argc == 15 && (!strcmp(argv[3], "--source-shell") ||
            !strcmp(argv[3], "--source-shell-abort-retry") ||
            !strcmp(argv[3], "--source-shell-successive")))
        return source_shell_provider(argc, argv);
    CHECK(argc == 3 || generation_watch);
    char *end;
    long transfer = strtol(argv[2], &end, 10);
    CHECK(argv[2][0] && !*end && transfer >= 0 && transfer <= INT32_MAX);
    struct ker_socket_client client;
    CHECK(!ker_socket_client_open(&client, argv[1]));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4108)};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) == 1);
    int plan = ker_socket_client_owner_group_staged_plan(&client, &address, 16,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    CHECK(plan >= 0);
    int watch = generation_watch ?
        ker_socket_client_owner_generation_watch_create(&client, plan) : -1;
    CHECK(!generation_watch || watch >= 0);
    int retry_watch = -1;
    int slots[] = {ker_socket_client_owner_group_slot(&client, plan, 0),
        ker_socket_client_owner_group_slot(&client, plan, 1)};
    CHECK(slots[0] >= 0 && slots[1] >= 0);
    char byte = 'N';
    int transferred[3] = {slots[0], slots[1], watch};
    size_t transferred_count = generation_watch ? 3 : 2;
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(transferred))]; } control = {0};
    struct source_provider_record wire_bundle = {0};
    uint64_t wire_parent_fd = 0, wire_parent_start = 0, retry_sequence = 1;
    uint64_t wire_abort_deadline = 0;
    pid_t wire_parent = getppid();
    struct source_retry_plan wire_adopted = {.plan = -1, .group = -1, .census = -1,
        .watch = -1, .slot = -1};
    if (retry_wire) {
        CHECK(!parse_decimal_u64(argv[4], &wire_parent_start));
        CHECK(!parse_decimal_u64(argv[5], &wire_parent_fd) && wire_parent_fd <= INT32_MAX);
        CHECK(source_parent_live((int)wire_parent_fd, wire_parent, wire_parent_start));
        CHECK(!setsockopt((int)transfer, SOL_SOCKET, SO_PASSCRED, &(int){1}, sizeof(int)));
        memcpy(wire_bundle.magic, SOURCE_PROVIDER_MAGIC, sizeof(wire_bundle.magic));
        wire_bundle.version = SOURCE_PROVIDER_VERSION;
        wire_bundle.bytes = sizeof(wire_bundle);
        wire_bundle.port = 4108;
        wire_bundle.backlog = 16;
        struct stat ids[2];
        CHECK(!fstat(slots[0], &ids[0]) && !fstat(slots[1], &ids[1]));
        wire_bundle.slot0_device = ids[0].st_dev;
        wire_bundle.slot0_inode = ids[0].st_ino;
        wire_bundle.slot1_device = ids[1].st_dev;
        wire_bundle.slot1_inode = ids[1].st_ino;
    }
    struct iovec vector = {.iov_base = retry_wire ? (void *)&wire_bundle : (void *)&byte,
        .iov_len = retry_wire ? sizeof(wire_bundle) : 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(transferred_count * sizeof(transferred[0]));
    memcpy(CMSG_DATA(header), transferred, transferred_count * sizeof(transferred[0]));
    CHECK(sendmsg((int)transfer, &message, MSG_NOSIGNAL) == (ssize_t)vector.iov_len);
    vector = (struct iovec){&byte, 1};
    int previous_plan = -1, previous_group = -1, discarded_census = -1;
    int previous_aborted = 0, previous_abandoned = 0;
    int group = -1, census[2] = {-1, -1}, cutover = -1;
    uint64_t held_lease = 0;
    uint32_t held_phase = 0, held_received = 0, held_accepted = 0;
    uint64_t observed_listener_cookie = 0;
    char command[128];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "CONTROL\n")) {
            CHECK(group < 0);
            group = ker_socket_client_owner_group_control(&client, plan);
            CHECK(group >= 0);
        } else if (!strcmp(command, "CENSUS0\n") || !strcmp(command, "CENSUS1\n")) {
            unsigned index = command[6] - '0';
            CHECK(group >= 0 && census[index] < 0);
            census[index] = ker_socket_client_member_census_create(&client, group, index);
            struct ker_socket_member_census_snapshot state;
            CHECK(census[index] >= 0 && !ker_socket_client_member_census_snapshot(&client, census[index], &state));
            CHECK(state.listener_cookie && state.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1);
        } else if (!strcmp(command, "COOKIE0\n") || !strcmp(command, "COOKIE1\n")) {
            unsigned index = command[6] - '0';
            struct ker_socket_member_census_snapshot state;
            CHECK(census[index] >= 0 && !ker_socket_client_member_census_snapshot(
                &client, census[index], &state));
            CHECK(state.listener_cookie && state.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1);
            observed_listener_cookie = state.listener_cookie;
        } else if (!strcmp(command, "EARLY_NEXT\n")) {
            CHECK(ker_socket_client_owner_group_successor_plan(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "ABORT_NEXT\n")) {
            CHECK(ker_socket_client_owner_group_successor_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "WRONG_NEXT\n")) {
            CHECK(ker_socket_client_owner_group_successor_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
        } else if (!strcmp(command, "EARLY_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "COMMITTED_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "DEAD_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "WRONG_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
        } else if (!strcmp(command, "SOURCE_RETRY_WIRE\n")) {
            CHECK(retry_wire);
            uint64_t grant = now_ns() + UINT64_C(10000000000);
            uint8_t request[SOURCE_C28_REQUEST_BYTES] = {0};
            struct source_c28_received_credentials credentials;
            CHECK(!source_c28_receive((int)transfer, request, &credentials,
                (int)wire_parent_fd, wire_parent, wire_parent_start, grant));
            uint16_t operation = source_get_le16(request + 10);
            uint64_t deadline = source_get_le64(request + 24);
            int error = source_c28_validate_request(request, &wire_bundle,
                &credentials, (int)wire_parent_fd, wire_parent, wire_parent_start,
                retry_sequence, grant, now_ns(), true, false);
            if (!error) ++retry_sequence;
            uint64_t cookie = 0, lease = 0;
            uint32_t phase = 0;
            int *reply_fds = NULL;
            int retry_fds[2] = {-1, -1};
            if (!error && operation == SOURCE_C28_RETRY_ADOPT) {
                if (!wire_abort_deadline || deadline != wire_abort_deadline)
                    error = EINVAL;
                else if (source_adopt_plan(&client, plan, &cutover, census[0],
                        deadline, &wire_adopted,
                        ker_socket_client_owner_group_retry_plan)) error = errno ? errno : EIO;
                else {
                    previous_aborted = 1;
                    previous_plan = plan; plan = wire_adopted.plan;
                    previous_group = group; group = wire_adopted.group;
                    close(census[0]); census[0] = wire_adopted.census;
                    discarded_census = census[1]; census[1] = -1;
                    close(slots[0]); slots[0] = -1;
                    close(slots[1]); slots[1] = -1;
                    cookie = wire_adopted.cookie; lease = held_lease;
                    phase = KER_SOCKET_GROUP_CUTOVER_ABORTED;
                }
            } else if (!error && operation == SOURCE_C28_RETRY_SLOT) {
                if (source_retry_slot(&client, &wire_adopted, deadline))
                    error = errno ? errno : EIO;
                else {
                    slots[1] = retry_fds[0] = wire_adopted.slot;
                    retry_watch = retry_fds[1] = wire_adopted.watch;
                    reply_fds = retry_fds;
                    cookie = wire_adopted.cookie;
                }
            } else if (!error) error = EOPNOTSUPP;
            CHECK(!source_c28_reply((int)transfer, request, error, phase, lease,
                cookie, 0, 0, (int)wire_parent_fd, wire_parent, wire_parent_start,
                deadline, reply_fds));
        } else if (!strncmp(command, "SOURCE_RETRY_BEFORE ", 20)) {
            char *deadline_end = NULL;
            errno = 0;
            uint64_t deadline = strtoull(command + 20, &deadline_end, 10);
            CHECK(!errno && deadline && deadline_end != command + 20 &&
                !strcmp(deadline_end, "\n") && now_ns() < deadline);
            CHECK(previous_plan < 0 && previous_group < 0 && cutover >= 0);
            struct ker_socket_member_census_snapshot before, after, successor;
            CHECK(census[0] >= 0 && !ker_socket_client_member_census_snapshot(
                &client, census[0], &before));
            CHECK(before.listener_cookie && before.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1);
            printf("SOURCE_RETRY_BEFORE_BEGIN ns=%llu deadline=%llu cookie=%llu\n",
                (unsigned long long)now_ns(), (unsigned long long)deadline,
                (unsigned long long)before.listener_cookie);
            fflush(stdout);
            close(cutover); cutover = -1;
            CHECK(now_ns() < deadline);
            int next;
            do {
                next = ker_socket_client_owner_group_retry_plan(&client, plan);
                if (next >= 0 || errno != EAGAIN) break;
                CHECK(now_ns() < deadline);
                struct timespec pause = {.tv_nsec = 100000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(next >= 0 && now_ns() < deadline);
            int next_group = ker_socket_client_owner_group_control(&client, next);
            CHECK(next_group >= 0 && now_ns() < deadline);
            int next_census = ker_socket_client_member_census_create(&client, next_group, 0);
            CHECK(next_census >= 0 && now_ns() < deadline);
            CHECK(!ker_socket_client_member_census_snapshot(&client, census[0], &after));
            CHECK(!ker_socket_client_member_census_snapshot(&client, next_census, &successor));
            CHECK(now_ns() < deadline && after.listener_cookie == before.listener_cookie &&
                successor.listener_cookie == before.listener_cookie &&
                after.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1 &&
                successor.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1);
            printf("SUCCESSOR_COOKIE preserved=%llu\n",
                (unsigned long long)successor.listener_cookie);
            previous_aborted = 1; previous_abandoned = 0;
            previous_plan = plan; plan = next;
            previous_group = group; group = next_group;
            for (unsigned index = 0; index < 2; ++index) {
                if (slots[index] >= 0) { close(slots[index]); slots[index] = -1; }
                if (index == 1) {
                    if (discarded_census >= 0) close(discarded_census);
                    discarded_census = census[index];
                } else if (census[index] >= 0) close(census[index]);
                census[index] = -1;
            }
            census[0] = next_census;
            CHECK(now_ns() < deadline);
            printf("SOURCE_RETRY_BEFORE_COMPLETE ns=%llu deadline=%llu\n",
                (unsigned long long)now_ns(), (unsigned long long)deadline);
        } else if (!strcmp(command, "NEXT\n") || !strcmp(command, "RETRY\n") || !strcmp(command, "ABANDON\n") || !strcmp(command, "RECOVER\n")) {
            int recover = !strcmp(command, "RECOVER\n");
            int abandon = command[0] == 'A' || recover;
            int retry = command[0] == 'R' || abandon;
            int (*adopt)(struct ker_socket_client *, int) = recover ?
                ker_socket_client_owner_group_recover_dead_plan : abandon ?
                ker_socket_client_owner_group_abandon_plan : retry ?
                ker_socket_client_owner_group_retry_plan : ker_socket_client_owner_group_successor_plan;
            CHECK(previous_plan < 0 && previous_group < 0 && (abandon ? cutover < 0 : cutover >= 0));
            if (!abandon) {
                CHECK(adopt(&client, plan) == -1 && errno == EAGAIN);
                close(cutover); cutover = -1;
            }
            CHECK(ker_socket_client_owner_group_abandon_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
            uint64_t deadline = now_ns() + UINT64_C(10000000000);
            int next;
            do {
                next = adopt(&client, plan);
                if (next >= 0 || errno != EAGAIN) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(next >= 0);
            enum ker_socket_broker_kind kind;
            int flags = -1;
            CHECK(!ker_socket_client_describe(&client, next, &kind, &flags) &&
                kind == KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN && !flags);
            CHECK(adopt(&client, plan) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_slot(&client, next, 0) == -1 && errno == EALREADY);
            int next_group = ker_socket_client_owner_group_control(&client, next);
            CHECK(next_group >= 0);
            int next_census = ker_socket_client_member_census_create(&client, next_group, 0);
            struct ker_socket_member_census_snapshot before, after;
            CHECK(next_census >= 0 && !ker_socket_client_member_census_snapshot(&client, census[retry ? 0 : 1], &before));
            CHECK(!ker_socket_client_member_census_snapshot(&client, next_census, &after));
            CHECK(before.listener_cookie && before.listener_cookie == after.listener_cookie &&
                after.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1);
            printf("SUCCESSOR_COOKIE preserved=%llu\n", (unsigned long long)after.listener_cookie);
            previous_aborted = retry; previous_abandoned = abandon;
            previous_plan = plan; plan = next;
            previous_group = group; group = next_group;
            for (unsigned index = 0; index < 2; ++index) {
                close(slots[index]); slots[index] = -1;
                if (retry && index == 1) {
                    if (discarded_census >= 0) close(discarded_census);
                    discarded_census = census[index];
                } else close(census[index]);
                census[index] = -1;
            }
            census[0] = next_census;
            if (retry) {
                if (!recover) CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EAGAIN);
            } else {
                slots[1] = ker_socket_client_owner_group_slot(&client, plan, 1);
                CHECK(slots[1] >= 0);
            }
            if (!retry) {
                CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EALREADY);
                memcpy(CMSG_DATA(header), &slots[1], sizeof(slots[1]));
                header->cmsg_len = CMSG_LEN(sizeof(slots[1]));
                message.msg_controllen = CMSG_SPACE(sizeof(slots[1]));
                CHECK(sendmsg((int)transfer, &message, MSG_NOSIGNAL) == 1);
            }
        } else if (!strcmp(command, "SELECT_HISTORY\n")) {
            CHECK(!ker_socket_client_reuseport_group_select(&client, group, 1));
            CHECK(!ker_socket_client_reuseport_group_select(&client, group, 0));
        } else if (!strcmp(command, "HISTORY_REFUSED\n")) {
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "RECOVER_BLOCKED\n")) {
            uint64_t deadline = now_ns() + UINT64_C(200000000);
            do {
                CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == EAGAIN);
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
        } else if (!strcmp(command, "RETRY_SLOT_BLOCKED\n")) {
            uint64_t deadline = now_ns() + UINT64_C(200000000);
            do {
                CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EAGAIN);
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
        } else if (!strcmp(command, "RETRY_SLOT\n")) {
            if (generation_watch) {
                CHECK(previous_aborted && retry_watch < 0);
                retry_watch = ker_socket_client_owner_generation_watch_create(&client, plan);
                CHECK(retry_watch >= 0);
            }
            uint64_t deadline = now_ns() + UINT64_C(10000000000);
            do {
                slots[1] = ker_socket_client_owner_group_slot(&client, plan, 1);
                if (slots[1] >= 0 || errno != EAGAIN) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(slots[1] >= 0);
            CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EALREADY);
            int retry_descriptors[] = {slots[1], retry_watch};
            size_t retry_bytes = (generation_watch ? 2 : 1) * sizeof(int);
            memcpy(CMSG_DATA(header), retry_descriptors, retry_bytes);
            header->cmsg_len = CMSG_LEN(retry_bytes);
            message.msg_controllen = CMSG_SPACE(retry_bytes);
            CHECK(sendmsg((int)transfer, &message, MSG_NOSIGNAL) == 1);
        } else if (!strcmp(command, "CLOSED_REJECTED\n")) {
            struct ker_socket_member_census_snapshot state;
            CHECK(discarded_census >= 0 && !ker_socket_client_member_census_snapshot(&client, discarded_census, &state));
            CHECK(!state.state_counts[KER_SOCKET_TCP_STATE_LISTEN]);
        } else if (!strcmp(command, "OLD_CAPS\n")) {
            CHECK(previous_plan >= 0 && previous_group >= 0);
            /* Adoption transferred the watched initial listener out of the
             * predecessor, so that watch can no longer arm a cutover. */
            int expected_error = (previous_abandoned ||
                (generation_watch && previous_aborted)) ? EOPNOTSUPP : EALREADY;
            CHECK(ker_socket_client_owner_group_cutover_begin(&client,
                previous_plan) == -1 && errno == expected_error);
            CHECK(ker_socket_client_reuseport_group_select(&client, previous_group, previous_aborted ? 1 : 0) == -1 && errno == EOPNOTSUPP);
            CHECK(!ker_socket_client_reuseport_group_select(&client, previous_group, previous_aborted ? 0 : 1));
        } else if (!strcmp(command, "DROP_PARENT\n")) {
            CHECK(previous_plan >= 0 && previous_group >= 0);
            close(previous_plan); previous_plan = -1;
            close(previous_group); previous_group = -1;
        } else if (!strcmp(command, "EARLY_RETIRE\n")) {
            CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "ALIAS_RETIRE\n")) {
            uint64_t deadline = now_ns() + UINT64_C(200000000);
            unsigned attempts = 0;
            do {
                CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, plan) == -1 && errno == EAGAIN);
                ++attempts;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(attempts > 1);
        } else if (!strcmp(command, "WRONG_RETIRE\n")) {
            CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, slots[0]) == -1 && errno == ENOTSOCK);
        } else if (!strcmp(command, "RETIRE0\n")) {
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            int result;
            do {
                result = ker_socket_client_owner_group_retire_initial_listener(&client, plan);
                if (!result || errno != EAGAIN) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(!result);
            CHECK(!ker_socket_client_owner_group_retire_initial_listener(&client, plan));
        } else if (!strcmp(command, "STREAMS0\n") || !strcmp(command, "ACTIVE0\n")) {
            struct ker_socket_member_census_snapshot state;
            uint64_t deadline = now_ns() + UINT64_C(10000000000);
            do {
                CHECK(census[0] >= 0 && !ker_socket_client_member_census_snapshot(&client, census[0], &state));
                if (state.state_counts[KER_SOCKET_TCP_STATE_ESTABLISHED] >= 13) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(state.state_counts[KER_SOCKET_TCP_STATE_ESTABLISHED] >= 13);
            printf("SOURCE_STREAM_CENSUS established=%llu\n",
                (unsigned long long)state.state_counts[KER_SOCKET_TCP_STATE_ESTABLISHED]);
        } else if (!strcmp(command, "DRAINED0\n") || !strcmp(command, "DRAINED1\n")) {
            unsigned index = command[7] - '0';
            struct ker_socket_member_census_snapshot state;
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            uint64_t live;
            do {
                CHECK(census[index] >= 0 && !ker_socket_client_member_census_snapshot(&client, census[index], &state));
                live = 0;
                for (unsigned value = KER_SOCKET_TCP_STATE_ESTABLISHED;
                        value <= KER_SOCKET_TCP_STATE_BOUND_INACTIVE; ++value) {
                    if (value != KER_SOCKET_TCP_STATE_TIME_WAIT && value != KER_SOCKET_TCP_STATE_CLOSE &&
                            value != KER_SOCKET_TCP_STATE_LISTEN && value != KER_SOCKET_TCP_STATE_BOUND_INACTIVE)
                        live += state.state_counts[value];
                }
                if (!live) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(!live);
        } else if (!strcmp(command, "BEGIN\n")) {
            CHECK(cutover < 0);
            cutover = ker_socket_client_owner_group_cutover_begin(&client, plan);
            CHECK(cutover >= 0 && !cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_PREPARED, 0));
            CHECK(ker_socket_client_owner_group_abandon_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "QUEUED\n")) {
            CHECK(cutover >= 0 && !cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_PREPARED, 1));
        } else if (!strcmp(command, "HELD\n")) {
            struct ker_socket_group_cutover_status state;
            CHECK(cutover >= 0 &&
                !ker_socket_client_owner_group_cutover_poll(&client, cutover, &state));
            CHECK(state.phase == KER_SOCKET_GROUP_CUTOVER_PREPARED &&
                state.received_packets && !state.accepted_packets);
            held_lease = state.lease;
            held_phase = state.phase;
            held_received = state.received_packets;
            held_accepted = state.accepted_packets;
            printf("CUTOVER_HELD phase=%u received=%u accepted=%u\n",
                state.phase, state.received_packets, state.accepted_packets);
            fflush(stdout);
        } else if (!strcmp(command, "DEAD_BEGIN\n")) {
            CHECK(cutover < 0);
            CHECK(ker_socket_client_owner_group_cutover_begin(&client, plan) == -1);
            CHECK(errno == EAGAIN || errno == ESTALE || errno == ESRCH);
            printf("DEAD_OWNER_BEGIN_REJECTED errno=%d\n", errno);
            /* pidfd death can precede capability-HUP processing. Require a
             * bounded transition to permanent rejection, not event ordering. */
            int retry_error = 0;
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1);
                retry_error = errno;
                if (retry_error == EOPNOTSUPP) break;
                CHECK(retry_error == EAGAIN || retry_error == ESTALE || retry_error == ESRCH);
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(retry_error == EOPNOTSUPP);
            printf("DEAD_OWNER_PRE_CUTOVER_RETRY_REJECTED errno=%d\n", retry_error);
        } else if (!strcmp(command, "DEAD_CUTOVER\n")) {
            /* A request can race autonomous quarantine. API success only
             * acknowledges the request; it must never certify commitment. */
            int requested = ker_socket_client_owner_group_cutover_commit(&client, cutover);
            CHECK(requested == 0 || (requested == -1 && errno == EALREADY));
            printf("DEAD_OWNER_COMMIT_REQUEST result=%d error=%d\n",
                requested, requested ? errno : 0);
            struct ker_socket_group_cutover_status state;
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(!ker_socket_client_owner_group_cutover_poll(&client, cutover, &state));
                CHECK(state.phase != KER_SOCKET_GROUP_CUTOVER_COMMITTED &&
                    state.phase != KER_SOCKET_GROUP_CUTOVER_ABORTED && !state.accepted_packets);
                if (state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED &&
                state.result < 0 && state.received_packets && !state.accepted_packets);
            printf("DEAD_OWNER_QUARANTINED phase=%u result=%d received=%u accepted=%u\n",
                state.phase, state.result, state.received_packets, state.accepted_packets);
            CHECK(ker_socket_client_owner_group_cutover_commit(&client, cutover) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_cutover_abort(&client, cutover) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == ECANCELED);
            CHECK(ker_socket_client_owner_group_abandon_plan(&client, plan) == -1 && errno == ECANCELED);
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == ECANCELED);
        } else if (!strncmp(command, "COMMIT_BEFORE ", 14)) {
            char *deadline_end = NULL;
            errno = 0;
            unsigned long long deadline = strtoull(command + 14, &deadline_end, 10);
            CHECK(!errno && deadline && deadline_end != command + 14 &&
                !strcmp(deadline_end, "\n"));
            uint64_t request_started = now_ns();
            fprintf(stderr, "COMMIT_BEFORE_REQUEST begin_ns=%llu deadline_ns=%llu cap=%d\n",
                (unsigned long long)request_started, deadline, cutover);
            fflush(stderr);
            int request_result = ker_socket_client_owner_group_cutover_commit_before(
                &client, cutover, deadline);
            int request_error = request_result ? errno : 0;
            fprintf(stderr, "COMMIT_BEFORE_REQUEST end_ns=%llu result=%d error=%d\n",
                (unsigned long long)now_ns(), request_result, request_error);
            fflush(stderr);
            if (request_result) { errno = request_error; CHECK(!request_result); }
            CHECK(!cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_COMMITTED, 0));
        } else if (!strncmp(command, "COMMIT_BEFORE_QUARANTINE ", 25)) {
            char *deadline_end = NULL;
            errno = 0;
            unsigned long long deadline = strtoull(command + 25, &deadline_end, 10);
            CHECK(!errno && deadline && deadline_end != command + 25 &&
                !strcmp(deadline_end, "\n"));
            CHECK(!ker_socket_client_owner_group_cutover_commit_before(&client,
                cutover, deadline));
            struct ker_socket_group_cutover_status state = {0};
            uint64_t poll_deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(!ker_socket_client_owner_group_cutover_poll(&client,
                    cutover, &state));
                CHECK(state.phase != KER_SOCKET_GROUP_CUTOVER_COMMITTED &&
                    state.phase != KER_SOCKET_GROUP_CUTOVER_ABORTED &&
                    !state.accepted_packets);
                if (state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < poll_deadline);
            CHECK(state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED &&
                state.result == -ETIMEDOUT && state.received_packets == 1 &&
                !state.accepted_packets);
            CHECK(ker_socket_client_owner_group_cutover_commit(&client,
                cutover) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_cutover_abort(&client,
                cutover) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 &&
                errno == ECANCELED);
            printf("C28_ASYNC_ACCEPT_QUARANTINED phase=%u result=%d received=%u accepted=%u\n",
                state.phase, state.result, state.received_packets,
                state.accepted_packets);
            fflush(stdout);
            fprintf(stderr, "C28_ASYNC_ACCEPT_QUARANTINED phase=%u result=%d received=%u accepted=%u monotonic_ns=%llu\n",
                state.phase, state.result, state.received_packets,
                state.accepted_packets, (unsigned long long)now_ns());
            fflush(stderr);
        } else if (!strcmp(command, "QUARANTINED\n")) {
            struct ker_socket_group_cutover_status state;
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(cutover >= 0 && !ker_socket_client_owner_group_cutover_poll(
                    &client, cutover, &state));
                CHECK(state.phase != KER_SOCKET_GROUP_CUTOVER_COMMITTED);
                if (state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED &&
                !state.accepted_packets);
            printf("SOURCE_EXPIRED_QUARANTINED phase=%u result=%d received=%u accepted=%u\n",
                state.phase, state.result, state.received_packets, state.accepted_packets);
        } else if (!strcmp(command, "COMMIT\n")) {
            CHECK(!ker_socket_client_owner_group_cutover_commit(&client, cutover));
            CHECK(!cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_COMMITTED, 0));
        } else if (!strncmp(command, "ABORT_BEFORE ", 13)) {
            char *end;
            errno = 0;
            uint64_t deadline = strtoull(command + 13, &end, 10);
            CHECK(!errno && deadline && end != command + 13 && !strcmp(end, "\n"));
            CHECK(!ker_socket_client_owner_group_cutover_abort_before(
                &client, cutover, deadline));
            CHECK(!cutover_wait_until(&client, cutover,
                KER_SOCKET_GROUP_CUTOVER_ABORTED, 0, deadline));
            wire_abort_deadline = deadline;
        } else if (!strcmp(command, "ABORT\n")) {
            CHECK(!ker_socket_client_owner_group_cutover_abort(&client, cutover));
            CHECK(!cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_ABORTED, 0));
        } else if (!strcmp(command, "RELEASE\n")) {
            if (cutover >= 0) { close(cutover); cutover = -1; }
            if (group >= 0) { close(group); group = -1; }
            if (plan >= 0) { close(plan); plan = -1; }
            for (unsigned index = 0; index < 2; ++index) {
                if (slots[index] >= 0) { close(slots[index]); slots[index] = -1; }
            }
        } else if (!strcmp(command, "CLOSED0\n") || !strcmp(command, "CLOSED1\n")) {
            unsigned index = command[6] - '0';
            struct ker_socket_member_census_snapshot state;
            CHECK(census[index] >= 0);
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(!ker_socket_client_member_census_snapshot(&client, census[index], &state));
                if (!state.state_counts[KER_SOCKET_TCP_STATE_LISTEN]) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(!state.state_counts[KER_SOCKET_TCP_STATE_LISTEN]);
        } else if (!strcmp(command, "STOP\n")) break;
        else { errno = EINVAL; CHECK(0); }
        if (!strcmp(command, "HELD\n")) {
            printf("OWNER_GROUP_OK HELD lease=%llu phase=%u received=%u accepted=%u\n",
                (unsigned long long)held_lease, held_phase, held_received, held_accepted);
        } else if (!strcmp(command, "COOKIE0\n") || !strcmp(command, "COOKIE1\n")) {
            printf("OWNER_GROUP_OK %.*s cookie=%llu\n", 7, command,
                (unsigned long long)observed_listener_cookie);
        } else {
            printf("OWNER_GROUP_OK %s", command);
        }
        fflush(stdout);
    }
    if (cutover >= 0) close(cutover);
    for (unsigned index = 0; index < 2; ++index) {
        if (census[index] >= 0) close(census[index]);
        if (slots[index] >= 0) close(slots[index]);
    }
    if (group >= 0) close(group);
    if (plan >= 0) close(plan);
    if (watch >= 0) close(watch);
    if (retry_watch >= 0) close(retry_watch);
    if (discarded_census >= 0) close(discarded_census);
    if (previous_plan >= 0) close(previous_plan);
    if (previous_group >= 0) close(previous_group);
    close((int)transfer);
    ker_socket_client_close(&client);
    return 0;
}
