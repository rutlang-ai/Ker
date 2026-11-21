// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "source-network-readback.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <lkl.h>
#include <lkl/asm/fcntl.h>
#include <lkl/asm-generic/poll.h>
#include <lkl/linux/if.h>
#include <lkl/linux/in.h>
#include <lkl/linux/netlink.h>
#include <lkl/linux/rtnetlink.h>
#include <lkl/linux/sockios.h>

static int parse_u64(const char *text, uint64_t *value)
{
    if (!text || !*text || !value || (text[0] == '0' && text[1])) return -EINVAL;
    uint64_t parsed = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return -EINVAL;
        unsigned digit = *p - '0';
        if (parsed > (UINT64_MAX - digit) / 10) return -ERANGE;
        parsed = parsed * 10 + digit;
    }
    *value = parsed;
    return 0;
}

static int parse_prefix(const char *text, unsigned *prefix)
{
    uint64_t value;
    int result = parse_u64(text, &value);
    if (result) return result;
    if (value < 1 || value > 30) return -ERANGE;
    *prefix = (unsigned)value;
    return 0;
}

static int parse_canonical_ipv4(const char *text, struct in_addr *address)
{
    char canonical[INET_ADDRSTRLEN];
    if (!text || !*text || inet_pton(AF_INET, text, address) != 1 ||
        !inet_ntop(AF_INET, address, canonical, sizeof(canonical)) ||
        strcmp(text, canonical))
        return -EINVAL;
    return 0;
}

static bool unicast_host_address(struct in_addr address, uint32_t mask)
{
    uint32_t host = ntohl(address.s_addr);
    uint32_t hostmask = ~ntohl(mask);
    uint32_t first = host >> 24;
    return host && host != UINT32_MAX && first != 0 && first != 127 &&
        first < 224 && first != 255 && (host & hostmask) != 0 &&
        (host & hostmask) != hostmask;
}

int ker_source_network_parse_expectation(const char *record,
    const char *setter_address, const char *setter_prefix,
    const char *setter_gateway, const char *bootstrap_deadline,
    uint64_t now_ns, struct ker_source_network_expectation *out)
{
    if (!record || !setter_address || !setter_prefix || !setter_gateway ||
        !bootstrap_deadline || !out)
        return -EINVAL;
    size_t record_length = strnlen(record, KER_SOURCE_NETWORK_READBACK_MAX_RECORD + 1U);
    if (!record_length || record_length > KER_SOURCE_NETWORK_READBACK_MAX_RECORD)
        return -E2BIG;
    char copy[KER_SOURCE_NETWORK_READBACK_MAX_RECORD + 1U];
    memcpy(copy, record, record_length + 1);
    char *fields[7];
    char *cursor = copy;
    for (size_t i = 0; i < 7; ++i) {
        fields[i] = cursor;
        char *separator = strchr(cursor, '|');
        if (i == 6) {
            if (separator) return -EINVAL;
        } else {
            if (!separator) return -EINVAL;
            *separator = '\0';
            cursor = separator + 1;
        }
        if (!*fields[i]) return -EINVAL;
    }
    if (strcmp(fields[0], "v1") != 0 || strlen(fields[1]) != 64) return -EPROTO;
    for (size_t i = 0; i < 64; ++i)
        if (!((fields[1][i] >= '0' && fields[1][i] <= '9') ||
              (fields[1][i] >= 'a' && fields[1][i] <= 'f')))
            return -EINVAL;

    struct ker_source_network_expectation parsed = {.version = KER_SOURCE_NETWORK_READBACK_VERSION};
    memcpy(parsed.template_sha256, fields[1], 64);
    parsed.template_sha256[64] = '\0';
    unsigned prefix;
    int result = parse_canonical_ipv4(fields[2], &parsed.address);
    if (result) return result;
    result = parse_canonical_ipv4(fields[3], &parsed.netmask);
    if (result) return result;
    result = parse_canonical_ipv4(fields[4], &parsed.broadcast);
    if (result) return result;
    result = parse_canonical_ipv4(fields[5], &parsed.gateway);
    if (result) return result;
    result = parse_prefix(setter_prefix, &prefix);
    if (result) return result;
    uint32_t mask = htonl(UINT32_MAX << (32U - prefix));
    uint32_t address_host = ntohl(parsed.address.s_addr);
    uint32_t expected_broadcast = (address_host & ntohl(mask)) | ~ntohl(mask);
    if (parsed.netmask.s_addr != mask ||
        ntohl(parsed.broadcast.s_addr) != expected_broadcast ||
        !unicast_host_address(parsed.address, mask) ||
        !unicast_host_address(parsed.gateway, mask) ||
        (ntohl(parsed.gateway.s_addr) & ntohl(mask)) != (address_host & ntohl(mask)) ||
        parsed.gateway.s_addr == parsed.address.s_addr)
        return -EINVAL;

    struct in_addr configured_address, configured_gateway;
    result = parse_canonical_ipv4(setter_address, &configured_address);
    if (result) return result;
    result = parse_canonical_ipv4(setter_gateway, &configured_gateway);
    if (result) return result;
    if (configured_address.s_addr != parsed.address.s_addr ||
        configured_gateway.s_addr != parsed.gateway.s_addr)
        return -EADDRNOTAVAIL;

    uint64_t record_deadline, launch_deadline;
    result = parse_u64(fields[6], &record_deadline);
    if (result) return result;
    result = parse_u64(bootstrap_deadline, &launch_deadline);
    if (result) return result;
    if (!record_deadline || record_deadline != launch_deadline) return -EPROTO;
    if (record_deadline <= now_ns) return -ETIMEDOUT;
    if (record_deadline - now_ns > KER_SOURCE_NETWORK_READBACK_MAX_DEADLINE_AHEAD_NS)
        return -ERANGE;
    parsed.deadline_ns = record_deadline;
    *out = parsed;
    return 0;
}

void ker_source_network_route_scan_init(struct ker_source_network_route_scan *scan,
    uint32_t sequence, uint32_t expected_reply_pid, uint32_t expected_ifindex,
    struct in_addr expected_gateway)
{
    if (!scan) return;
    memset(scan, 0, sizeof(*scan));
    scan->sequence = sequence;
    scan->expected_reply_pid = expected_reply_pid;
    scan->expected_ifindex = expected_ifindex;
    scan->expected_gateway = expected_gateway;
}

static int parse_route_message(struct ker_source_network_route_scan *scan,
    const struct lkl_nlmsghdr *header)
{
    if (header->nlmsg_len < LKL_NLMSG_LENGTH(sizeof(struct lkl_rtmsg))) return -EPROTO;
    const struct lkl_rtmsg *route = LKL_NLMSG_DATA(header);
    size_t remaining = header->nlmsg_len - LKL_NLMSG_LENGTH(sizeof(*route));
    const unsigned char *cursor = (const unsigned char *)route +
        ((sizeof(*route) + LKL_NLMSG_ALIGNTO - 1U) & ~(LKL_NLMSG_ALIGNTO - 1U));
    uint32_t table_override = 0, oif = 0;
    struct in_addr gateway = {0}, destination = {0};
    bool have_table = false, have_oif = false, have_gateway = false, have_destination = false;
    bool multipath = false, unsupported = false;
    while (remaining) {
        if (remaining < sizeof(struct lkl_rtattr)) return -EPROTO;
        const struct lkl_rtattr *attribute = (const void *)cursor;
        size_t attribute_length = attribute->rta_len;
        if (attribute_length < sizeof(*attribute) || attribute_length > remaining) return -EPROTO;
        size_t aligned_length = (attribute_length + LKL_RTA_ALIGNTO - 1U) &
            ~(LKL_RTA_ALIGNTO - 1U);
        if (aligned_length > remaining) {
            if (attribute_length != remaining) return -EPROTO;
            aligned_length = remaining;
        }
        size_t length = attribute_length - LKL_RTA_LENGTH(0);
        switch (attribute->rta_type) {
        case LKL_RTA_TABLE:
            if (have_table || length != sizeof(table_override)) return -EPROTO;
            memcpy(&table_override, LKL_RTA_DATA(attribute), sizeof(table_override));
            have_table = true;
            break;
        case LKL_RTA_OIF:
            if (have_oif || length != sizeof(oif)) return -EPROTO;
            memcpy(&oif, LKL_RTA_DATA(attribute), sizeof(oif));
            have_oif = true;
            break;
        case LKL_RTA_GATEWAY:
            if (have_gateway || length != sizeof(gateway)) return -EPROTO;
            memcpy(&gateway, LKL_RTA_DATA(attribute), sizeof(gateway));
            have_gateway = true;
            break;
        case LKL_RTA_DST:
            if (have_destination || length != sizeof(destination)) return -EPROTO;
            memcpy(&destination, LKL_RTA_DATA(attribute), sizeof(destination));
            have_destination = true;
            break;
        case LKL_RTA_MULTIPATH:
            multipath = true;
            break;
        default:
            unsupported = true;
            break;
        }
        cursor += aligned_length;
        remaining -= aligned_length;
    }
    uint32_t table = have_table ? table_override : route->rtm_table;
    if (table != LKL_RT_TABLE_MAIN || route->rtm_dst_len != 0) return 0;
    if (++scan->default_count != 1) return -EEXIST;
    if (route->rtm_family != LKL_AF_INET || route->rtm_src_len != 0 || route->rtm_tos != 0 ||
        route->rtm_type != LKL_RTN_UNICAST || route->rtm_scope != LKL_RT_SCOPE_UNIVERSE ||
        route->rtm_flags != 0 || multipath || unsupported)
        return -EOPNOTSUPP;
    if (have_destination && destination.s_addr != 0) return -EPROTO;
    if (!have_oif || !have_gateway || !oif) return -ENODATA;
    if (oif != scan->expected_ifindex || gateway.s_addr != scan->expected_gateway.s_addr)
        return -EADDRNOTAVAIL;
    scan->observed_table = table;
    scan->observed_oif = oif;
    scan->observed_gateway = gateway;
    return 0;
}

int ker_source_network_route_feed(struct ker_source_network_route_scan *scan,
    const void *datagram, size_t datagram_length,
    const struct lkl_sockaddr_nl *sender, size_t sender_length)
{
    if (!scan || !datagram || !sender || !scan->sequence || scan->done ||
        !datagram_length || datagram_length > KER_SOURCE_NETWORK_READBACK_MAX_DATAGRAM ||
        datagram_length > INT_MAX || sender_length != sizeof(*sender) ||
        sender->nl_family != LKL_AF_NETLINK || sender->nl_pid != 0 || sender->nl_groups != 0)
        return -EPROTO;
    const unsigned char *cursor = datagram;
    size_t remaining = datagram_length;
    while (remaining) {
        if (remaining < sizeof(struct lkl_nlmsghdr)) return -EPROTO;
        const struct lkl_nlmsghdr *header = (const void *)cursor;
        size_t message_length = header->nlmsg_len;
        if (message_length < LKL_NLMSG_HDRLEN || message_length > remaining) return -EPROTO;
        size_t aligned_length = (message_length + LKL_NLMSG_ALIGNTO - 1U) &
            ~(LKL_NLMSG_ALIGNTO - 1U);
        if (aligned_length > remaining) {
            if (message_length != remaining) return -EPROTO;
            aligned_length = remaining;
        }
        if (header->nlmsg_seq != scan->sequence ||
            header->nlmsg_pid != scan->expected_reply_pid)
            return -EPROTO;
        if (header->nlmsg_flags & LKL_NLM_F_DUMP_INTR) return -EAGAIN;
        if (scan->done) return -EPROTO;
        if (header->nlmsg_type == LKL_NLMSG_DONE) {
            size_t payload = message_length - LKL_NLMSG_HDRLEN;
            int status = 0;
            if (payload == sizeof(status)) memcpy(&status, LKL_NLMSG_DATA(header), sizeof(status));
            else if (payload != 0) return -EPROTO;
            if (status > 0) return -EPROTO;
            if (status < 0) return status;
            scan->done = 1;
        } else if (header->nlmsg_type == LKL_NLMSG_ERROR) {
            if (header->nlmsg_len != LKL_NLMSG_LENGTH(sizeof(struct lkl_nlmsgerr))) return -EPROTO;
            const struct lkl_nlmsgerr *error = LKL_NLMSG_DATA(header);
            return error->error < 0 ? error->error : -EPROTO;
        } else if (header->nlmsg_type == LKL_RTM_NEWROUTE) {
            int result = parse_route_message(scan, header);
            if (result) return result;
        } else {
            return -EPROTO;
        }
        cursor += aligned_length;
        remaining -= aligned_length;
    }
    return 0;
}

int ker_source_network_route_finish(const struct ker_source_network_route_scan *scan)
{
    if (!scan || !scan->done) return -EPROTO;
    if (scan->default_count != 1 || scan->observed_table != LKL_RT_TABLE_MAIN ||
        scan->observed_oif != scan->expected_ifindex ||
        scan->observed_gateway.s_addr != scan->expected_gateway.s_addr)
        return -ENETUNREACH;
    return 0;
}

static int host_monotonic_ns(uint64_t *result)
{
    struct timespec now;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) < 0) return -errno;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) / 1000000000ULL)
        return -EOVERFLOW;
    *result = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
    return 0;
}

static int check_deadline(uint64_t deadline_ns)
{
    uint64_t now;
    int result = host_monotonic_ns(&now);
    if (result) return result;
    return now < deadline_ns ? 0 : -ETIMEDOUT;
}

static const char *readback_error_name(int result)
{
    if (result == -EADDRNOTAVAIL) return "EADDRNOTAVAIL";
    if (result == -ENETUNREACH) return "ENETUNREACH";
    if (result == -ETIMEDOUT) return "ETIMEDOUT";
    if (result == -EPROTO) return "EPROTO";
    return "errno";
}

enum readback_known_fields {
    READBACK_KNOWN_ADDRESS = 1U << 0,
    READBACK_KNOWN_NETMASK = 1U << 1,
    READBACK_KNOWN_BROADCAST = 1U << 2,
    READBACK_KNOWN_ROUTE = 1U << 3,
};

static void report_readback_failure(const char *stage, int result,
    const struct ker_source_network_expectation *expected,
    const struct ker_source_network_observation *actual, unsigned known)
{
    int saved_errno = errno;
    char ea[INET_ADDRSTRLEN], aa[INET_ADDRSTRLEN];
    char em[INET_ADDRSTRLEN], am[INET_ADDRSTRLEN];
    char eb[INET_ADDRSTRLEN], ab[INET_ADDRSTRLEN];
    char eg[INET_ADDRSTRLEN], ag[INET_ADDRSTRLEN];
#define FORMAT_IP(buffer, value, valid) do { \
    if (!(valid)) memcpy((buffer), "unknown", sizeof("unknown")); \
    else if (!inet_ntop(AF_INET, &(value), (buffer), sizeof(buffer))) \
        memcpy((buffer), "?", 2); \
} while (0)
#define FORMAT_EXPECTED(buffer, value) do { \
    if (!inet_ntop(AF_INET, &(value), (buffer), sizeof(buffer))) \
        memcpy((buffer), "?", 2); \
} while (0)
    FORMAT_EXPECTED(ea, expected->address); FORMAT_IP(aa, actual->address, known & READBACK_KNOWN_ADDRESS);
    FORMAT_EXPECTED(em, expected->netmask); FORMAT_IP(am, actual->netmask, known & READBACK_KNOWN_NETMASK);
    FORMAT_EXPECTED(eb, expected->broadcast); FORMAT_IP(ab, actual->broadcast, known & READBACK_KNOWN_BROADCAST);
    FORMAT_EXPECTED(eg, expected->gateway); FORMAT_IP(ag, actual->gateway, known & READBACK_KNOWN_ROUTE);
#undef FORMAT_IP
#undef FORMAT_EXPECTED
    char message[768];
    int length = snprintf(message, sizeof(message),
        "ker source network readback diagnostic: stage=%s error=%d name=%s "
        "ifindex_requested=%u address_expected=%s address_observed=%s "
        "netmask_expected=%s netmask_observed=%s "
        "broadcast_expected=%s broadcast_observed=%s "
        "gateway_expected=%s gateway_observed=%s route_table=%s%u route_oif=%s%u deadline_ns=%llu\n",
        stage, result, readback_error_name(result), actual->ifindex,
        ea, aa, em, am, eb, ab, eg, ag,
        known & READBACK_KNOWN_ROUTE ? "" : "unknown/", actual->route_table,
        known & READBACK_KNOWN_ROUTE ? "" : "unknown/", actual->route_oif,
        (unsigned long long)expected->deadline_ns);
    if (length > 0) {
        size_t bytes = (size_t)length < sizeof(message) ?
            (size_t)length : sizeof(message) - 1;
        (void)syscall(SYS_write, STDERR_FILENO, message, bytes);
    }
    errno = saved_errno;
}

static int wait_lkl_fd(int fd, short events, uint64_t deadline_ns)
{
    for (;;) {
        uint64_t now;
        int result = host_monotonic_ns(&now);
        if (result) return result;
        if (now >= deadline_ns) return -ETIMEDOUT;
        uint64_t remaining = deadline_ns - now;
        uint64_t ms = (remaining + 999999ULL) / 1000000ULL;
        if (ms > INT_MAX) ms = INT_MAX;
        struct lkl_pollfd pollfd = {.fd = fd, .events = events};
        long polled = lkl_sys_poll(&pollfd, 1, (int)ms);
        if (polled == -LKL_EINTR) continue;
        if (polled < 0) return (int)polled;
        if (polled == 0) continue;
        if (pollfd.revents & (LKL_POLLERR | LKL_POLLHUP | LKL_POLLNVAL)) return -EIO;
        if (pollfd.revents == events || (pollfd.revents & events)) return 0;
        return -EPROTO;
    }
}

static int read_interface_address(int fd, const char *name, unsigned long operation,
    struct in_addr *address, unsigned *known, unsigned known_field,
    const char **failed_stage)
{
    struct lkl_ifreq request = {0};
    size_t name_length = strnlen(name, LKL_IFNAMSIZ);
    if (!name_length || name_length >= LKL_IFNAMSIZ) return -ENAMETOOLONG;
    memcpy(request.lkl_ifr_name, name, name_length + 1);
    if (failed_stage) {
        if (operation == LKL_SIOCGIFADDR) *failed_stage = "SIOCGIFADDR ioctl";
        else if (operation == LKL_SIOCGIFNETMASK) *failed_stage = "SIOCGIFNETMASK ioctl";
        else if (operation == LKL_SIOCGIFBRDADDR) *failed_stage = "SIOCGIFBRDADDR ioctl";
        else *failed_stage = "interface address ioctl";
    }
    long result = lkl_sys_ioctl(fd, operation, (unsigned long)&request);
    if (result < 0) return (int)result;
    const struct lkl_sockaddr_in *value = (const struct lkl_sockaddr_in *)&request.lkl_ifr_addr;
    if (value->sin_family != LKL_AF_INET) return -EPROTO;
    memcpy(&address->s_addr, &value->sin_addr, sizeof(address->s_addr));
    if (known) *known |= known_field;
    return 0;
}

static int read_interface(int ifindex, const struct ker_source_network_expectation *expected,
    struct ker_source_network_observation *observed, unsigned *known,
    const char **failed_stage)
{
    if (failed_stage) *failed_stage = "AF_INET datagram socket";
    int fd = (int)lkl_sys_socket(LKL_AF_INET, LKL_SOCK_DGRAM, 0);
    if (fd < 0) return fd;
    if (failed_stage) *failed_stage = "deadline before SIOCGIFNAME";
    int result = check_deadline(expected->deadline_ns);
    struct lkl_ifreq request = {0};
    if (!result) {
        if (failed_stage) *failed_stage = "SIOCGIFNAME ioctl";
        request.lkl_ifr_ifindex = ifindex;
        long query = lkl_sys_ioctl(fd, LKL_SIOCGIFNAME, (unsigned long)&request);
        if (query < 0) result = (int)query;
    }
    char name[LKL_IFNAMSIZ];
    if (!result) {
        if (failed_stage) *failed_stage = "SIOCGIFNAME result validation";
        const char *end = memchr(request.lkl_ifr_name, '\0', sizeof(request.lkl_ifr_name));
        if (!end || end == request.lkl_ifr_name) result = -EPROTO;
        else memcpy(name, request.lkl_ifr_name, (size_t)(end - request.lkl_ifr_name) + 1);
    }
    if (!result) {
        if (failed_stage) *failed_stage = "deadline before SIOCGIFADDR";
        result = check_deadline(expected->deadline_ns);
    }
    if (!result) result = read_interface_address(fd, name, LKL_SIOCGIFADDR,
        &observed->address, known, READBACK_KNOWN_ADDRESS, failed_stage);
    if (!result) {
        if (failed_stage) *failed_stage = "deadline before SIOCGIFNETMASK";
        result = check_deadline(expected->deadline_ns);
    }
    if (!result) result = read_interface_address(fd, name, LKL_SIOCGIFNETMASK,
        &observed->netmask, known, READBACK_KNOWN_NETMASK, failed_stage);
    if (!result) {
        if (failed_stage) *failed_stage = "deadline before SIOCGIFBRDADDR";
        result = check_deadline(expected->deadline_ns);
    }
    if (!result) result = read_interface_address(fd, name, LKL_SIOCGIFBRDADDR,
        &observed->broadcast, known, READBACK_KNOWN_BROADCAST, failed_stage);
    if (!result) {
        if (failed_stage) *failed_stage = "deadline after interface ioctls";
        result = check_deadline(expected->deadline_ns);
    }
    long closed = lkl_sys_close(fd);
    result = ker_source_network_finish_close(result, closed, failed_stage,
        "AF_INET datagram socket close");
    if (result) return result;
    if (failed_stage) *failed_stage = "interface tuple comparison";
    if (observed->address.s_addr != expected->address.s_addr ||
        observed->netmask.s_addr != expected->netmask.s_addr ||
        observed->broadcast.s_addr != expected->broadcast.s_addr)
        return -EADDRNOTAVAIL;
    return 0;
}

static int send_request(int fd, const void *request, size_t length,
    const struct lkl_sockaddr_nl *destination, uint64_t deadline_ns)
{
    for (;;) {
        int result = check_deadline(deadline_ns);
        if (result) return result;
        long sent = lkl_sys_sendto(fd, (void *)request, length, 0,
            (void *)destination, sizeof(*destination));
        if (sent == (long)length) return 0;
        if (sent == -LKL_EINTR) continue;
        if (sent == -LKL_EAGAIN) {
            result = wait_lkl_fd(fd, LKL_POLLOUT, deadline_ns);
            if (result) return result;
            continue;
        }
        return sent < 0 ? (int)sent : -EIO;
    }
}

static int receive_routes(int fd,
    const struct ker_source_network_expectation *expected,
    struct ker_source_network_route_scan *scan)
{
    union {
        max_align_t alignment;
        unsigned char bytes[KER_SOURCE_NETWORK_READBACK_MAX_DATAGRAM];
    } buffer;
    size_t total = 0;
    unsigned datagrams = 0;
    while (!scan->done) {
        int result = check_deadline(expected->deadline_ns);
        if (result) return result;
        long needed = lkl_sys_recvfrom(fd, NULL, 0, MSG_PEEK | LKL_MSG_TRUNC, NULL, NULL);
        if (needed == -LKL_EINTR) continue;
        if (needed == -LKL_EAGAIN) {
            result = wait_lkl_fd(fd, LKL_POLLIN, expected->deadline_ns);
            if (result) return result;
            continue;
        }
        if (needed <= 0) return needed < 0 ? (int)needed : -EPROTO;
        if ((unsigned long)needed > sizeof(buffer.bytes) ||
            (size_t)needed > KER_SOURCE_NETWORK_READBACK_MAX_TOTAL_BYTES - total ||
            datagrams == KER_SOURCE_NETWORK_READBACK_MAX_DATAGRAMS)
            return -E2BIG;
        struct lkl_sockaddr_nl sender = {0};
        int sender_length = sizeof(sender);
        long received = lkl_sys_recvfrom(fd, buffer.bytes, (size_t)needed, 0,
            (void *)&sender, &sender_length);
        if (received == -LKL_EINTR) continue;
        if (received == -LKL_EAGAIN) continue;
        if (received != needed) return received < 0 ? (int)received : -EPROTO;
        result = ker_source_network_route_feed(scan, buffer.bytes, (size_t)received,
            &sender, (size_t)sender_length);
        if (result) return result;
        total += (size_t)received;
        ++datagrams;
        result = check_deadline(expected->deadline_ns);
        if (result) return result;
    }
    return ker_source_network_route_finish(scan);
}

static int read_default_route(int ifindex,
    const struct ker_source_network_expectation *expected,
    struct ker_source_network_observation *observed, unsigned *known,
    const char **failed_stage)
{
    const uint32_t sequence = 0x4b535201U;
    if (failed_stage) *failed_stage = "RTM_GETROUTE netlink socket";
    int fd = (int)lkl_sys_socket(LKL_AF_NETLINK,
        LKL_SOCK_RAW | LKL_O_NONBLOCK | LKL_O_CLOEXEC, LKL_NETLINK_ROUTE);
    if (fd < 0) return fd;
    if (failed_stage) *failed_stage = "deadline before RTM_GETROUTE bind";
    int result = check_deadline(expected->deadline_ns);
    struct lkl_sockaddr_nl local = {.nl_family = LKL_AF_NETLINK};
    if (!result) {
        if (failed_stage) *failed_stage = "RTM_GETROUTE netlink bind";
        long bound = lkl_sys_bind(fd, (void *)&local, sizeof(local));
        if (bound < 0) result = (int)bound;
    }
    if (!result) {
        if (failed_stage) *failed_stage = "RTM_GETROUTE getsockname";
        int local_length = sizeof(local);
        long named = lkl_sys_getsockname(fd, (void *)&local, &local_length);
        if (named < 0) result = (int)named;
        else if (local_length != (int)sizeof(local) ||
            local.nl_family != LKL_AF_NETLINK || !local.nl_pid || local.nl_groups)
            result = -EPROTO;
    }
    struct {
        struct lkl_nlmsghdr header;
        struct lkl_rtmsg route;
    } request = {
        .header = {.nlmsg_len = LKL_NLMSG_LENGTH(sizeof(struct lkl_rtmsg)),
            .nlmsg_type = LKL_RTM_GETROUTE,
            .nlmsg_flags = LKL_NLM_F_REQUEST | LKL_NLM_F_DUMP,
            .nlmsg_seq = sequence},
        .route = {.rtm_family = LKL_AF_INET},
    };
    struct lkl_sockaddr_nl kernel = {.nl_family = LKL_AF_NETLINK};
    if (!result) {
        if (failed_stage) *failed_stage = "RTM_GETROUTE request send";
        result = send_request(fd, &request, request.header.nlmsg_len,
            &kernel, expected->deadline_ns);
    }
    struct ker_source_network_route_scan scan;
    ker_source_network_route_scan_init(&scan, sequence, local.nl_pid,
        (uint32_t)ifindex, expected->gateway);
    if (!result) {
        if (failed_stage) *failed_stage = "RTM_GETROUTE response validation";
        result = receive_routes(fd, expected, &scan);
        if (result == -EADDRNOTAVAIL && failed_stage)
            *failed_stage = "RTM_GETROUTE expected default route mismatch";
        else if (result == -ENETUNREACH && failed_stage)
            *failed_stage = "RTM_GETROUTE no matching main-table default";
    }
    long closed = lkl_sys_close(fd);
    result = ker_source_network_finish_close(result, closed, failed_stage,
        "RTM_GETROUTE netlink socket close");
    if (scan.observed_table) {
        observed->route_table = scan.observed_table;
        observed->route_oif = scan.observed_oif;
        observed->gateway = scan.observed_gateway;
        if (known) *known |= READBACK_KNOWN_ROUTE;
    }
    if (result) return result;
    return 0;
}

int ker_source_network_readback(int ifindex,
    const struct ker_source_network_expectation *expected,
    struct ker_source_network_observation *observed)
{
    if (ifindex <= 0 || !expected || !observed ||
        expected->version != KER_SOURCE_NETWORK_READBACK_VERSION ||
        !expected->deadline_ns)
        return -EINVAL;
    struct ker_source_network_observation actual = {
        .version = KER_SOURCE_NETWORK_READBACK_VERSION,
        .ifindex = (uint32_t)ifindex,
        .deadline_ns = expected->deadline_ns,
    };
    memcpy(actual.template_sha256, expected->template_sha256,
        sizeof(actual.template_sha256));
    unsigned known = 0;
    const char *failed_stage = "initial deadline";
    int result = check_deadline(expected->deadline_ns);
    if (!result) result = read_interface(ifindex, expected, &actual, &known, &failed_stage);
    if (!result) result = read_default_route(ifindex, expected, &actual, &known, &failed_stage);
    if (!result) {
        failed_stage = "deadline after all readbacks";
        result = check_deadline(expected->deadline_ns);
    }
    if (!result && (actual.route_oif != actual.ifindex ||
        actual.gateway.s_addr != expected->gateway.s_addr)) {
        failed_stage = "final route tuple comparison";
        result = -EADDRNOTAVAIL;
    }
    if (result) report_readback_failure(failed_stage, result, expected, &actual, known);
    if (!result) *observed = actual;
    return result;
}

int ker_source_network_format_proof(const struct ker_source_network_observation *observed,
    char *buffer, size_t capacity)
{
    if (!observed || !buffer || !capacity ||
        observed->version != KER_SOURCE_NETWORK_READBACK_VERSION ||
        !observed->ifindex || observed->route_table != LKL_RT_TABLE_MAIN ||
        observed->route_oif != observed->ifindex || !observed->deadline_ns ||
        strnlen(observed->template_sha256, sizeof(observed->template_sha256)) != 64)
        return -EINVAL;
    for (size_t i = 0; i < 64; ++i)
        if (!((observed->template_sha256[i] >= '0' && observed->template_sha256[i] <= '9') ||
              (observed->template_sha256[i] >= 'a' && observed->template_sha256[i] <= 'f')))
            return -EINVAL;
    char address[INET_ADDRSTRLEN], netmask[INET_ADDRSTRLEN];
    char broadcast[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &observed->address, address, sizeof(address)) ||
        !inet_ntop(AF_INET, &observed->netmask, netmask, sizeof(netmask)) ||
        !inet_ntop(AF_INET, &observed->broadcast, broadcast, sizeof(broadcast)) ||
        !inet_ntop(AF_INET, &observed->gateway, gateway, sizeof(gateway)))
        return -EINVAL;
    int length = snprintf(buffer, capacity,
        "KER_SOURCE_NETWORK_READBACK_V1 template_sha256=%s ifindex=%u address=%s "
        "netmask=%s broadcast=%s gateway=%s route_oif=%u route_table=%u deadline_ns=%llu\n",
        observed->template_sha256, observed->ifindex, address, netmask, broadcast,
        gateway, observed->route_oif, observed->route_table,
        (unsigned long long)observed->deadline_ns);
    return length < 0 || (size_t)length >= capacity ? -ENOSPC : length;
}

int ker_source_network_write_startup_with_ops(int fd,
    const struct ker_source_network_observation *observed,
    const struct ker_source_network_startup_ops *ops)
{
    if (fd < 0 || !observed || !ops || !ops->validate_pipe ||
        !ops->monotonic_now || !ops->write_record || !ops->wait_writable)
        return -EINVAL;
    int result = ops->validate_pipe(fd);
    if (result) return result;
    char proof[512];
    int proof_length = ker_source_network_format_proof(observed, proof, sizeof(proof));
    if (proof_length < 0) return proof_length;
    static const char ready[] = "KER_NATIVE_READY\n";
    char record[PIPE_BUF];
    const size_t ready_length = sizeof(ready) - 1;
    size_t total = ready_length + (size_t)proof_length;
    if (total > sizeof(record) || total > PIPE_BUF) return -E2BIG;
    memcpy(record, ready, ready_length);
    memcpy(record + ready_length, proof, (size_t)proof_length);

    for (;;) {
        uint64_t now;
        result = ops->monotonic_now(&now);
        if (result) return result;
        if (now >= observed->deadline_ns) return -ETIMEDOUT;
        ssize_t written = ops->write_record(fd, record, total);
        if (written == (ssize_t)total) {
            result = ops->monotonic_now(&now);
            if (result) return result;
            return now < observed->deadline_ns ? 0 : -ETIMEDOUT;
        }
        if (written == -EAGAIN) {
            result = ops->wait_writable(fd, observed->deadline_ns);
            if (result) return result;
            continue;
        }
        /* EINTR and short writes are ambiguous; never emit a second success. */
        return written < 0 ? (int)written : -EIO;
    }
}

static int startup_pipe_validate(int fd)
{
    struct stat status;
    if (syscall(SYS_fstat, fd, &status) < 0) return -errno;
    if (!S_ISFIFO(status.st_mode)) return -ENOTSUP;
    long flags = syscall(SYS_fcntl, fd, F_GETFL, 0);
    if (flags < 0) return -errno;
    if ((flags & O_ACCMODE) != O_WRONLY) return -EBADF;
    if (!(flags & O_NONBLOCK) && syscall(SYS_fcntl, fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -errno;
    return 0;
}

static ssize_t startup_pipe_write(int fd, const void *record, size_t length)
{
    long written = syscall(SYS_write, fd, record, length);
    return written < 0 ? -errno : (ssize_t)written;
}

static int startup_pipe_wait_writable(int fd, uint64_t deadline_ns)
{
    for (;;) {
        uint64_t now;
        int result = host_monotonic_ns(&now);
        if (result) return result;
        if (now >= deadline_ns) return -ETIMEDOUT;
        uint64_t remaining = deadline_ns - now;
        uint64_t timeout_ms = (remaining + 999999ULL) / 1000000ULL;
        if (timeout_ms > INT_MAX) timeout_ms = INT_MAX;
        struct pollfd descriptor = {.fd = fd, .events = POLLOUT};
        struct timespec timeout = {
            .tv_sec = (time_t)(timeout_ms / 1000U),
            .tv_nsec = (long)(timeout_ms % 1000U) * 1000000L,
        };
        long polled = syscall(SYS_ppoll, &descriptor, 1, &timeout, NULL, sizeof(uint64_t));
        if (polled < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (polled == 0) continue;
        if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) return -EIO;
        if (descriptor.revents & POLLOUT) return 0;
        return -EPROTO;
    }
}

int ker_source_network_write_startup(int fd,
    const struct ker_source_network_observation *observed)
{
    const struct ker_source_network_startup_ops ops = {
        .validate_pipe = startup_pipe_validate,
        .monotonic_now = host_monotonic_ns,
        .write_record = startup_pipe_write,
        .wait_writable = startup_pipe_wait_writable,
    };
    return ker_source_network_write_startup_with_ops(fd, observed, &ops);
}
