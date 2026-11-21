/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_SOURCE_NETWORK_READBACK_H
#define KER_SOURCE_NETWORK_READBACK_H

#include <netinet/in.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <lkl/linux/netlink.h>
#include <lkl/linux/rtnetlink.h>

#define KER_SOURCE_NETWORK_READBACK_ENV "KER_SOURCE_NETWORK_READBACK"
#define KER_SOURCE_NETWORK_READBACK_VERSION 1U
#define KER_SOURCE_NETWORK_READBACK_MAX_RECORD 256U
#define KER_SOURCE_NETWORK_READBACK_MAX_DATAGRAM 65536U
#define KER_SOURCE_NETWORK_READBACK_MAX_DATAGRAMS 32U
#define KER_SOURCE_NETWORK_READBACK_MAX_TOTAL_BYTES (256U * 1024U)
#define KER_SOURCE_NETWORK_READBACK_MAX_DEADLINE_AHEAD_NS (300ULL * 1000000000ULL)

/* Private controller-supplied expectation; not a readback result. */
struct ker_source_network_expectation {
    uint32_t version;
    char template_sha256[65];
    struct in_addr address;
    struct in_addr netmask;
    struct in_addr broadcast;
    struct in_addr gateway;
    uint64_t deadline_ns;
};

/* Values sampled from the initialized original LKL Linux network stack. */
struct ker_source_network_observation {
    uint32_t version;
    uint32_t ifindex;
    uint32_t route_table;
    uint32_t route_oif;
    struct in_addr address;
    struct in_addr netmask;
    struct in_addr broadcast;
    struct in_addr gateway;
    char template_sha256[65];
    uint64_t deadline_ns;
};

struct ker_source_network_route_scan {
    uint32_t sequence;
    uint32_t expected_reply_pid;
    uint32_t expected_ifindex;
    struct in_addr expected_gateway;
    uint32_t default_count;
    uint32_t observed_table;
    uint32_t observed_oif;
    struct in_addr observed_gateway;
    int done;
};

/* Preserve the first readback error while still recording close-only failures. */
static inline int ker_source_network_finish_close(int result, long close_result,
    const char **failed_stage, const char *close_stage)
{
    if (result) return result;
    if (close_result < 0) {
        if (failed_stage) *failed_stage = close_stage;
        return (int)close_result;
    }
    return 0;
}

/* Pure validation helpers are shared with malformed-input unit controls. */
int ker_source_network_parse_expectation(const char *record,
    const char *setter_address, const char *setter_prefix,
    const char *setter_gateway, const char *bootstrap_deadline,
    uint64_t now_ns, struct ker_source_network_expectation *out);
void ker_source_network_route_scan_init(struct ker_source_network_route_scan *scan,
    uint32_t sequence, uint32_t expected_reply_pid, uint32_t expected_ifindex,
    struct in_addr expected_gateway);
int ker_source_network_route_feed(struct ker_source_network_route_scan *scan,
    const void *datagram, size_t datagram_length,
    const struct lkl_sockaddr_nl *sender, size_t sender_length);
int ker_source_network_route_finish(const struct ker_source_network_route_scan *scan);

/* Uses only original LKL ioctl/netlink interfaces; caller supplies the one
 * immutable host CLOCK_MONOTONIC deadline and keeps the result private. */
int ker_source_network_readback(int ifindex,
    const struct ker_source_network_expectation *expected,
    struct ker_source_network_observation *observed);
int ker_source_network_format_proof(const struct ker_source_network_observation *observed,
    char *buffer, size_t capacity);
int ker_source_network_write_startup(int fd,
    const struct ker_source_network_observation *observed);
struct ker_source_network_startup_ops {
    int (*validate_pipe)(int fd);
    int (*monotonic_now)(uint64_t *now_ns);
    ssize_t (*write_record)(int fd, const void *buffer, size_t length);
    int (*wait_writable)(int fd, uint64_t deadline_ns);
};
int ker_source_network_write_startup_with_ops(int fd,
    const struct ker_source_network_observation *observed,
    const struct ker_source_network_startup_ops *ops);

#endif
