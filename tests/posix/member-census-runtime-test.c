#define _GNU_SOURCE
#include "member-census-runtime.h"
#include "tcp-payload-snapshot.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "member census runtime:%d: %s (errno=%d: %s)\n", \
            __LINE__, #condition, errno, strerror(errno)); \
        return 1; \
    } \
} while (0)

#define QUERY_DEADLINE_NS UINT64_C(5000000000)
#define QUERY_POLL_NS UINT64_C(1000000)

/* Exported only by the separate, noninstalled test-runtime DSO. These helpers
 * change the actual current LKL task credentials and never exist in ker-posix. */
extern int ker_member_census_test_clear_net_admin(void);
extern int ker_member_census_test_restore_capabilities(void);
extern int ker_member_census_test_runtime_map_counts(unsigned *test_runtime,
    unsigned *production_runtime);

static uint64_t monotonic_ns(void)
{
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static void pause_briefly(void)
{
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = (long)QUERY_POLL_NS};
    while (nanosleep(&pause, NULL) && errno == EINTR) { }
}

static int payload_wire_command(const char *prefix, const char *expected)
{
    char command_path[512];
    uint64_t start = monotonic_ns();
    if (!start || snprintf(command_path, sizeof(command_path), "%s.command", prefix) >=
            (int)sizeof(command_path)) return -EINVAL;
    for (;;) {
        FILE *file = fopen(command_path, "r");
        if (file) {
            char command[64] = {0};
            int read_ok = fscanf(file, "%63s", command) == 1;
            fclose(file);
            if (read_ok && !strcmp(command, expected)) {
                unlink(command_path);
                return 0;
            }
        }
        uint64_t now = monotonic_ns();
        if (!now || now < start || now - start >= QUERY_DEADLINE_NS) return -ETIMEDOUT;
        pause_briefly();
    }
}

static int payload_wire_state(const char *prefix, const char *state,
    const struct ker_socket_member_payload_snapshot *snapshot)
{
    char state_path[512];
    if (snprintf(state_path, sizeof(state_path), "%s.state", prefix) >=
            (int)sizeof(state_path)) return -EINVAL;
    FILE *file = fopen(state_path, "w");
    if (!file) return -errno;
    int result = fprintf(file, "%s bytes=%llu sockets=%llu\n", state,
        (unsigned long long)snapshot->payload_bytes,
        (unsigned long long)snapshot->sampled_sockets) < 0 ? -EIO : 0;
    if (fclose(file) && !result) result = -errno;
    return result;
}

static int payload_wire_probe(uint32_t mark, const char *prefix, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0) return -errno;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
        int error = errno; close(fd); return -error;
    }
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(port)};
    peer.sin_addr.s_addr = htonl(UINT32_C(0xc6120001)); /* 198.18.0.1 */
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
        int error = errno; close(fd); return -error;
    }
    uint8_t payload[1200];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i * 17u + 3u);
    size_t sent = 0;
    while (sent < sizeof(payload)) {
        ssize_t count = send(fd, payload + sent, sizeof(payload) - sent, 0);
        if (count < 0) { int error = errno; close(fd); return -error; }
        if (!count) { close(fd); return -EIO; }
        sent += (size_t)count;
    }
    /* Drop the last application descriptor while the peer suppresses ACKs.
     * The snapshot must find this original-Linux orphan by the authenticated
     * member mark, not by a retained adapter descriptor. */
    if (close(fd)) return -errno;
    struct ker_socket_member_payload_snapshot snapshot = {0};
    int result = payload_wire_state(prefix, "READY", &snapshot);
    if (result) return result;
    result = payload_wire_command(prefix, "PARTIAL");
    if (result) return result;
    result = ker_native_tcp_payload_snapshot_test_limit(mark, 4096, &snapshot);
    if (result) return result;
    result = payload_wire_state(prefix, "PARTIAL", &snapshot);
    if (result) return result;
    result = payload_wire_command(prefix, "FULL");
    if (result) return result;
    result = ker_native_tcp_payload_snapshot_test_limit(mark, 4096, &snapshot);
    if (result) return result;
    if (snapshot.payload_bytes != 0) return -EPROTO;
    result = payload_wire_state(prefix, "FULL", &snapshot);
    if (result) return result;
    /* Keep FIN outstanding during the zero-payload sample. */
    return payload_wire_command(prefix, "FINACK");
}

static int payload_wire_sack_probe(uint32_t mark, const char *prefix, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0) return -errno;
    int mss = 512;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) ||
        setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss))) {
        int error = errno; close(fd); return -error;
    }
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(port)};
    peer.sin_addr.s_addr = htonl(UINT32_C(0xc6120001));
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
        int error = errno; close(fd); return -error;
    }
    uint8_t payload[1200];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i * 29u + 11u);
    size_t sent = 0;
    while (sent < sizeof(payload)) {
        ssize_t count = send(fd, payload + sent, sizeof(payload) - sent, 0);
        if (count < 0) { int error = errno; close(fd); return -error; }
        if (!count) { close(fd); return -EIO; }
        sent += (size_t)count;
    }
    struct ker_socket_member_payload_snapshot snapshot = {0};
    int result = payload_wire_state(prefix, "SACK_READY", &snapshot);
    if (result) { close(fd); return result; }
    result = payload_wire_command(prefix, "SACK");
    if (result) { fprintf(stderr, "SACK command timeout\\n"); close(fd); return result; }
    struct tcp_info info;
    socklen_t info_length = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_length)) {
        int error = errno; close(fd); return -error;
    }
    result = ker_native_tcp_payload_snapshot_test_limit(mark, 4096, &snapshot);
    if (result) { close(fd); return result; }
    if (info.tcpi_sacked == 0 || snapshot.payload_bytes != sizeof(payload) ||
        snapshot.sampled_sockets != 1) {
        close(fd);
        return -EPROTO;
    }
    char state_path[512];
    if (snprintf(state_path, sizeof(state_path), "%s.state", prefix) >=
            (int)sizeof(state_path)) { close(fd); return -EINVAL; }
    FILE *state = fopen(state_path, "w");
    if (!state) { int error = errno; close(fd); return -error; }
    result = fprintf(state, "SACK bytes=%llu sockets=%llu sacked=%u unacked=%u\n",
        (unsigned long long)snapshot.payload_bytes,
        (unsigned long long)snapshot.sampled_sockets, info.tcpi_sacked,
        info.tcpi_unacked) < 0 ? -EIO : 0;
    if (fclose(state) && !result) result = -errno;
    if (result) { close(fd); return result; }
    result = payload_wire_command(prefix, "SACK_FULL");
    if (result) { fprintf(stderr, "SACK_FULL command timeout\\n"); close(fd); return result; }
    result = ker_native_tcp_payload_snapshot_test_limit(mark, 4096, &snapshot);
    if (result || snapshot.payload_bytes) { close(fd); return result ? result : -EPROTO; }
    if (close(fd)) return -errno;
    result = payload_wire_state(prefix, "SACK_FULL", &snapshot);
    if (result) return result;
    result = payload_wire_command(prefix, "FINACK2");
    if (result) fprintf(stderr, "SACK FINACK2 command timeout\\n");
    return result;
}

static int create_marked_listener(uint32_t mark, int *fd_out,
    struct ker_member_census_identity *identity)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0) return -errno;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
        int error = errno; close(fd); return -error;
    }
    struct sockaddr_in address = {.sin_family = AF_INET};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 32)) {
        int error = errno; close(fd); return -error;
    }
    socklen_t address_length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &address_length) ||
        address_length != sizeof(address) || !ntohs(address.sin_port)) {
        int error = errno ? errno : EPROTO; close(fd); return -error;
    }
    uint64_t cookie = 0;
    socklen_t cookie_length = sizeof(cookie);
    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &cookie_length) ||
        cookie_length != sizeof(cookie) || !cookie) {
        int error = errno ? errno : EPROTO; close(fd); return -error;
    }
    *identity = (struct ker_member_census_identity){
        .mark = mark, .local_port = ntohs(address.sin_port),
        .listener_cookie = cookie};
    *fd_out = fd;
    return 0;
}

static int create_marked_connections(uint32_t mark, uint16_t port,
    int *listener_out, int clients[2], int accepted[2])
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (listener < 0) return -errno;
    if (setsockopt(listener, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 8)) {
        int error = errno; close(listener); return -error;
    }
    socklen_t length = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &length) ||
        length != sizeof(address)) {
        int error = errno ? errno : EPROTO; close(listener); return -error;
    }
    clients[0] = clients[1] = accepted[0] = accepted[1] = -1;
    for (size_t i = 0; i < 2; ++i) {
        clients[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (clients[i] < 0 || setsockopt(clients[i], SOL_SOCKET, SO_MARK,
                &mark, sizeof(mark)) ||
            connect(clients[i], (struct sockaddr *)&address, sizeof(address))) {
            int error = errno;
            for (size_t j = 0; j <= i; ++j) if (clients[j] >= 0) close(clients[j]);
            close(listener);
            return -error;
        }
        accepted[i] = accept(listener, NULL, NULL);
        if (accepted[i] < 0) {
            int error = errno;
            for (size_t j = 0; j <= i; ++j) {
                close(clients[j]);
                if (accepted[j] >= 0) close(accepted[j]);
            }
            close(listener);
            return -error;
        }
    }
    *listener_out = listener;
    return 0;
}

static int create_marked_ipv6_connections(uint32_t mark, int fds[3])
{
    fds[0] = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    fds[1] = fds[2] = -1;
    if (fds[0] < 0) return -errno;
    if (setsockopt(fds[0], SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
        int error = errno; close(fds[0]); return -error;
    }
    struct sockaddr_in6 address = {.sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    if (bind(fds[0], (struct sockaddr *)&address, sizeof(address)) || listen(fds[0], 4)) {
        int error = errno; close(fds[0]); return -error;
    }
    socklen_t length = sizeof(address);
    if (getsockname(fds[0], (struct sockaddr *)&address, &length) ||
        length != sizeof(address) || !address.sin6_port) {
        int error = errno ? errno : EPROTO; close(fds[0]); return -error;
    }
    fds[1] = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fds[1] < 0 || setsockopt(fds[1], SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) ||
        connect(fds[1], (struct sockaddr *)&address, sizeof(address))) {
        int error = errno;
        if (fds[1] >= 0) close(fds[1]);
        close(fds[0]);
        return -error;
    }
    fds[2] = accept(fds[0], NULL, NULL);
    if (fds[2] < 0) {
        int error = errno; close(fds[1]); close(fds[0]); return -error;
    }
    return 0;
}

static bool snapshot_matches_listener(
    const struct ker_socket_member_census_snapshot *snapshot, uint64_t cookie)
{
    return snapshot->total == 1 &&
        snapshot->state_counts[KER_MEMBER_CENSUS_TCP_LISTEN] == 1 &&
        snapshot->listener_cookie == cookie;
}

static bool snapshot_unchanged(const struct ker_socket_member_census_snapshot *actual,
    const struct ker_socket_member_census_snapshot *expected)
{
    return memcmp(actual, expected, sizeof(*actual)) == 0;
}

static bool payload_snapshot_unchanged(
    const struct ker_socket_member_payload_snapshot *actual,
    const struct ker_socket_member_payload_snapshot *expected)
{
    return memcmp(actual, expected, sizeof(*actual)) == 0;
}

static int poll_payload_until_done(uint64_t ticket, uint64_t minimum_sockets,
    uint64_t maximum_sockets, struct ker_socket_member_payload_snapshot *snapshot)
{
    uint64_t start = monotonic_ns();
    if (!start) return -EIO;
    for (;;) {
        int status = 0x5a5a;
        struct ker_socket_member_payload_snapshot sentinel;
        memset(&sentinel, 0xa5, sizeof(sentinel));
        const struct ker_socket_member_payload_snapshot before = sentinel;
        int polled = ker_member_payload_query_poll(ticket, &status, &sentinel);
        if (polled == 1) {
            if (status) return status;
            if (sentinel.sampled_sockets < minimum_sockets ||
                sentinel.sampled_sockets > maximum_sockets) return -EPROTO;
            *snapshot = sentinel;
            return 0;
        }
        if (polled < 0) return polled;
        if (status != 0x5a5a || !payload_snapshot_unchanged(&sentinel, &before))
            return -EPROTO;
        uint64_t now = monotonic_ns();
        if (!now || now < start || now - start >= QUERY_DEADLINE_NS) return -ETIMEDOUT;
        pause_briefly();
    }
}

static int netlink_denial(int protocol, const void *request, size_t request_length)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
    if (fd < 0) return -errno;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t sent = sendto(fd, request, request_length, 0,
        (struct sockaddr *)&kernel, sizeof(kernel));
    if (sent < 0) {
        int error = errno;
        close(fd);
        return error == EPERM ? 0 : -error;
    }
    if ((size_t)sent != request_length) { close(fd); return -EIO; }
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    int polled;
    do { polled = poll(&ready, 1, 1000); } while (polled < 0 && errno == EINTR);
    if (polled <= 0) {
        int error = polled == 0 ? ETIMEDOUT : errno;
        close(fd);
        return -error;
    }
    uint8_t response[256];
    ssize_t received = recv(fd, response, sizeof(response), 0);
    int receive_error = errno;
    close(fd);
    if (received < (ssize_t)(sizeof(struct ker_member_census_nlmsghdr) +
            sizeof(struct ker_member_census_nlmsgerr)))
        return received < 0 ? -receive_error : -EPROTO;
    struct ker_member_census_nlmsghdr header;
    memcpy(&header, response, sizeof(header));
    if (header.type != KER_MEMBER_CENSUS_NLMSG_ERROR ||
        header.length > (uint32_t)received ||
        header.length < sizeof(header) + sizeof(struct ker_member_census_nlmsgerr))
        return -EPROTO;
    int32_t error;
    memcpy(&error, response + sizeof(header), sizeof(error));
    return error == -EPERM ? 0 : (error < 0 ? error : -EPROTO);
}

static int public_netlink_guards(const struct ker_member_census_identity *identity)
{
    struct ker_member_census_diag_request diag = {
        .header = {.length = sizeof(diag),
            .type = KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST,
            .flags = KER_MEMBER_CENSUS_NLM_F_REQUEST | KER_MEMBER_CENSUS_NLM_F_DUMP,
            .sequence = 0xc641, .port_id = 0},
        .request = {.family = AF_INET, .protocol = IPPROTO_TCP,
            .states = UINT32_MAX,
            .id = {.source_port = htons(identity->local_port)}},
        .bytecode_attribute = {.length = sizeof(struct ker_member_census_nlattr) +
            4u + 8u, .type = KER_MEMBER_CENSUS_IN_DIAG_REQ_BYTECODE},
        .mark_instruction = {.code = KER_MEMBER_CENSUS_IN_DIAG_BC_MARK_COND,
            .yes = 12, .no = 16},
        .condition = {.mark = identity->mark, .mask = UINT32_MAX}};
    int result = netlink_denial(KER_MEMBER_CENSUS_NETLINK_PROTOCOL,
        &diag, sizeof(diag));
    if (result) return result;

    struct {
        struct ker_member_census_nlmsghdr header;
        struct ifinfomsg information;
    } __attribute__((packed)) setlink = {
        .header = {.length = sizeof(setlink), .type = RTM_SETLINK,
            .flags = KER_MEMBER_CENSUS_NLM_F_REQUEST | 0x04u,
            .sequence = 0xc642, .port_id = 0},
        .information = {.ifi_family = AF_UNSPEC, .ifi_index = 1,
            .ifi_flags = IFF_UP, .ifi_change = IFF_UP}};
    return netlink_denial(NETLINK_ROUTE, &setlink, sizeof(setlink));
}

static int restricted_submitter_guard(const struct ker_member_census_identity *identity)
{
    int result = 0;
    uint64_t ticket = UINT64_C(0xfeedface);
    int dropped = ker_member_census_test_clear_net_admin();
    if (dropped) return dropped;
    if (ker_member_census_diag_require_net_admin() != -EPERM) result = -EPROTO;
    if (!result && (ker_member_census_query_submit(identity, &ticket) != -EPERM ||
            ticket != UINT64_C(0xfeedface))) result = -EPROTO;
    if (!result) {
        int denied = ker_member_payload_query_submit(identity->mark, &ticket);
        if (denied != -EPERM || ticket != UINT64_C(0xfeedface)) {
            fprintf(stderr, "payload query authority: result=%d ticket=%llx\n",
                denied, (unsigned long long)ticket);
            result = -EPROTO;
        }
    }
    if (!result) {
        struct ker_socket_member_payload_snapshot sentinel = {
            .payload_bytes = UINT64_C(0xfeedfacecafebeef),
            .sampled_sockets = UINT64_C(0xdecafbadc001d00d)};
        struct ker_socket_member_payload_snapshot before = sentinel;
        int denied = ker_native_tcp_payload_snapshot_test_limit(identity->mark, 1, &sentinel);
        if (denied != -EPERM || !payload_snapshot_unchanged(&sentinel, &before)) {
            fprintf(stderr, "payload ioctl authority: result=%d bytes=%llx sockets=%llx\n",
                denied, (unsigned long long)sentinel.payload_bytes,
                (unsigned long long)sentinel.sampled_sockets);
            result = -EPROTO;
        }
    }
    int restored = ker_member_census_test_restore_capabilities();
    return result ? result : restored;
}

static int poll_until_done(uint64_t ticket, uint64_t cookie, bool *saw_pending)
{
    uint64_t start = monotonic_ns();
    if (!start) return -EIO;
    for (;;) {
        int query_status = 0x5a5a;
        struct ker_socket_member_census_snapshot sentinel;
        memset(&sentinel, 0xa5, sizeof(sentinel));
        const struct ker_socket_member_census_snapshot before = sentinel;
        int polled = ker_member_census_query_poll(ticket, &query_status, &sentinel);
        if (polled == 1) {
            if (query_status) return query_status;
            return snapshot_matches_listener(&sentinel, cookie) ? 0 : -EPROTO;
        }
        if (polled < 0) return polled;
        if (query_status != 0x5a5a || !snapshot_unchanged(&sentinel, &before))
            return -EPROTO;
        if (saw_pending) *saw_pending = true;
        uint64_t now = monotonic_ns();
        if (!now || now < start || now - start >= QUERY_DEADLINE_NS) return -ETIMEDOUT;
        pause_briefly();
    }
}

int main(void)
{
    unsigned test_runtime_maps = 0, production_runtime_maps = 0;
    REQUIRE(ker_member_census_test_runtime_map_counts(&test_runtime_maps,
        &production_runtime_maps) == 0);
    REQUIRE(test_runtime_maps == 1 && production_runtime_maps == 0);
    uint32_t first_mark = 0, mark = 0;
    REQUIRE(ker_member_census_mark_allocate(&first_mark) == 0 && first_mark != 0);

    uint64_t first_lease = 0, rejected_lease = UINT64_C(0xfeedface), next_lease = 0;
    REQUIRE(ker_member_census_server_claim(&first_lease) == 0 && first_lease != 0);
    REQUIRE(ker_member_census_server_claim(&rejected_lease) == -EBUSY &&
        rejected_lease == UINT64_C(0xfeedface));
    REQUIRE(ker_member_census_mark_allocate(&mark) == 0 && mark > first_mark);
    REQUIRE(ker_member_census_server_release(first_lease) == 0);
    REQUIRE(ker_member_census_server_release(first_lease) == -ESTALE);
    REQUIRE(ker_member_census_server_claim(&next_lease) == 0 && next_lease > first_lease);
    REQUIRE(ker_member_census_server_release(next_lease) == 0);
    uint32_t after_release_mark = 0;
    REQUIRE(ker_member_census_mark_allocate(&after_release_mark) == 0 &&
        after_release_mark > mark);

    int listener = -1;
    struct ker_member_census_identity identity = {0};
    int created = create_marked_listener(after_release_mark, &listener, &identity);
    REQUIRE(created == 0);

    uint64_t tickets[4] = {0};
    for (size_t i = 0; i < 4; ++i)
        REQUIRE(ker_member_census_query_submit(&identity, &tickets[i]) == 0 && tickets[i]);

    uint64_t fifth_ticket = UINT64_C(0xfacefeed);
    REQUIRE(ker_member_census_query_submit(&identity, &fifth_ticket) == -EAGAIN &&
        fifth_ticket == UINT64_C(0xfacefeed));

    /* Any queued/running slot leaves both poll outputs untouched. */
    bool saw_pending = false;
    bool completed[4] = {false};
    for (size_t i = 1; i < 4; ++i) {
        int status = 0x5a5a;
        struct ker_socket_member_census_snapshot sentinel;
        memset(&sentinel, 0xa5, sizeof(sentinel));
        const struct ker_socket_member_census_snapshot before = sentinel;
        int polled = ker_member_census_query_poll(tickets[i], &status, &sentinel);
        if (polled == 0) {
            saw_pending = true;
            REQUIRE(status == 0x5a5a && snapshot_unchanged(&sentinel, &before));
        } else if (polled == 1) {
            REQUIRE(status == 0 && snapshot_matches_listener(&sentinel,
                identity.listener_cookie));
            completed[i] = true;
        } else {
            REQUIRE(false);
        }
    }

    REQUIRE(ker_member_census_query_cancel(tickets[0]) == 0);
    uint64_t replacement_ticket = 0;
    uint64_t recovery_start = monotonic_ns();
    REQUIRE(recovery_start != 0);
    for (;;) {
        int submitted = ker_member_census_query_submit(&identity, &replacement_ticket);
        if (!submitted) break;
        REQUIRE(submitted == -EAGAIN);
        uint64_t now = monotonic_ns();
        REQUIRE(now && now >= recovery_start &&
            now - recovery_start < QUERY_DEADLINE_NS);
        pause_briefly();
    }
    REQUIRE(replacement_ticket && replacement_ticket != tickets[0]);
    REQUIRE(ker_member_census_query_poll(tickets[0], &(int){0},
        &(struct ker_socket_member_census_snapshot){0}) == -ENOENT);

    /* Jobs which were not consumed by an earlier readiness poll remain valid. */
    for (size_t i = 1; i < 4; ++i) {
        if (completed[i]) continue;
        int result = poll_until_done(tickets[i], identity.listener_cookie, &saw_pending);
        REQUIRE(result == 0);
    }
    REQUIRE(poll_until_done(replacement_ticket, identity.listener_cookie, &saw_pending) == 0);
    /* The worker has successfully queried with its own credentials. A
     * restricted submitter must still be denied before it can enqueue work. */
    REQUIRE(public_netlink_guards(&identity) == 0);
    REQUIRE(restricted_submitter_guard(&identity) == 0);
    REQUIRE(public_netlink_guards(&identity) == 0);

    REQUIRE(close(listener) == 0);
    listener = -1;

    /* A metadata identity remains queryable after its original TCP fd closes. */
    uint64_t empty_ticket = 0;
    REQUIRE(ker_member_census_query_submit(&identity, &empty_ticket) == 0 && empty_ticket);
    uint64_t empty_start = monotonic_ns();
    REQUIRE(empty_start != 0);
    for (;;) {
        int status = 0x5a5a;
        struct ker_socket_member_census_snapshot snapshot;
        memset(&snapshot, 0xa5, sizeof(snapshot));
        int polled = ker_member_census_query_poll(empty_ticket, &status, &snapshot);
        if (polled == 1) {
            REQUIRE(status == 0 && snapshot.total == 0 &&
                snapshot.listener_cookie == identity.listener_cookie);
            break;
        }
        REQUIRE(polled == 0 && status == 0x5a5a);
        uint64_t now = monotonic_ns();
        REQUIRE(now && now >= empty_start && now - empty_start < QUERY_DEADLINE_NS);
        pause_briefly();
    }

    int payload_listener = -1;
    int payload_clients[2] = {-1, -1}, payload_accepted[2] = {-1, -1};
    REQUIRE(create_marked_connections(identity.mark, 0, &payload_listener,
        payload_clients, payload_accepted) == 0);
    struct ker_socket_member_payload_snapshot payload = {0};
    int payload_result = ker_native_tcp_payload_snapshot_test_limit(identity.mark,
        4096, &payload);
    if (payload_result || payload.sampled_sockets < 2 || payload.sampled_sockets > 4096)
        fprintf(stderr, "payload positive sample result=%d bytes=%llu sockets=%llu\n",
            payload_result, (unsigned long long)payload.payload_bytes,
            (unsigned long long)payload.sampled_sockets);
    REQUIRE(payload_result == 0 && payload.sampled_sockets >= 2 &&
        payload.sampled_sockets <= 4096);
    struct ker_socket_member_payload_snapshot unchanged = {
        .payload_bytes = UINT64_C(0xfeedfacecafebeef),
        .sampled_sockets = UINT64_C(0xdecafbadc001d00d)};
    struct ker_socket_member_payload_snapshot before = unchanged;
    REQUIRE(ker_native_tcp_payload_snapshot_test_limit(identity.mark, 1,
        &unchanged) == -EOVERFLOW && payload_snapshot_unchanged(&unchanged, &before));

    uint64_t payload_ticket = 0;
    REQUIRE(ker_member_payload_query_submit(identity.mark, &payload_ticket) == 0 &&
        payload_ticket != 0);
    REQUIRE(poll_payload_until_done(payload_ticket, 2, 4096, &payload) == 0);
    for (size_t i = 0; i < 2; ++i) {
        REQUIRE(close(payload_clients[i]) == 0);
        REQUIRE(close(payload_accepted[i]) == 0);
    }
    REQUIRE(close(payload_listener) == 0);
    payload_ticket = 0;
    REQUIRE(ker_member_payload_query_submit(identity.mark, &payload_ticket) == 0 &&
        payload_ticket != 0);
    REQUIRE(poll_payload_until_done(payload_ticket, 0, 0, &payload) == 0 &&
        payload.payload_bytes == 0 && payload.sampled_sockets == 0);

    int ipv6_fds[3] = {-1, -1, -1};
    REQUIRE(create_marked_ipv6_connections(identity.mark, ipv6_fds) == 0);
    payload_result = ker_native_tcp_payload_snapshot_test_limit(identity.mark, 4096, &payload);
    REQUIRE(payload_result == 0 && payload.sampled_sockets == 2 && payload.payload_bytes == 0);
    for (size_t i = 0; i < 3; ++i) REQUIRE(close(ipv6_fds[i]) == 0);
    payload_ticket = 0;
    REQUIRE(ker_member_payload_query_submit(identity.mark, &payload_ticket) == 0 &&
        payload_ticket != 0);
    REQUIRE(poll_payload_until_done(payload_ticket, 0, 0, &payload) == 0 &&
        payload.payload_bytes == 0 && payload.sampled_sockets == 0);

    const char *wire_prefix = getenv("KER_C9_PAYLOAD_CONTROL");
    if (wire_prefix) {
        const char *port_text = getenv("KER_C9_PAYLOAD_PORT");
        const char *sack_port_text = getenv("KER_C9_PAYLOAD_SACK_PORT");
        char *end = NULL;
        unsigned long port = port_text ? strtoul(port_text, &end, 10) : 0;
        REQUIRE(port_text && end && *end == '\0' && port > 0 && port <= UINT16_MAX);
        int wire_result = payload_wire_probe(identity.mark, wire_prefix, (uint16_t)port);
        REQUIRE(wire_result == 0);
        end = NULL;
        unsigned long sack_port = sack_port_text ? strtoul(sack_port_text, &end, 10) : 0;
        REQUIRE(sack_port_text && end && *end == '\0' && sack_port > 0 &&
            sack_port <= UINT16_MAX);
        wire_result = payload_wire_sack_probe(identity.mark, wire_prefix, (uint16_t)sack_port);
        if (wire_result) fprintf(stderr, "SACK payload probe failed: %d\n", wire_result);
        REQUIRE(wire_result == 0);
        printf("C9_PAYLOAD_PARTIAL_ACK_ORPHAN_OK\n");
    }

    /* Leave work owned by the runtime for ker-posix finalization to cancel and join. */
    for (size_t i = 0; i < 4; ++i) {
        uint64_t shutdown_ticket = 0;
        REQUIRE(ker_member_census_query_submit(&identity, &shutdown_ticket) == 0 &&
            shutdown_ticket);
    }
    printf("MEMBER_CENSUS_RUNTIME_OK lease_marks=monotonic slots=4 cancel=recovered "
        "listen=1 empty_after_close=1 shutdown=queued pending_observed=%u\n",
        saw_pending ? 1u : 0u);
    return 0;
}
