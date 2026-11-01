#define _GNU_SOURCE
#include "member-census-runtime.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
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
