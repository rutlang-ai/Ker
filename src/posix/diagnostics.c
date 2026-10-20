#define _GNU_SOURCE
#include "diagnostics.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <lkl.h>

static int read_file(const char *path, char *buffer, size_t capacity)
{
    long fd = lkl_sys_open(path, LKL_O_RDONLY, 0);
    if (fd < 0) return (int)fd;
    size_t used = 0;
    int result = 0;
    for (;;) {
        if (used + 1 == capacity) { result = -ENOSPC; break; }
        long count = lkl_sys_read(fd, buffer + used, capacity - used - 1);
        if (count < 0) { result = (int)count; break; }
        if (!count) break;
        used += (size_t)count;
    }
    buffer[used] = 0;
    lkl_sys_close(fd);
    return result;
}
struct field { const char *name; uint64_t *value; };
static int counters(const char *path, const char *prefix, struct field *fields, size_t count)
{
    char buffer[16384];
    int result = read_file(path, buffer, sizeof(buffer));
    if (result) return result;
    char *line_state = NULL, *header = strtok_r(buffer, "\n", &line_state);
    while (header && strncmp(header, prefix, strlen(prefix))) header = strtok_r(NULL, "\n", &line_state);
    if (!header) return -ENOENT;
    char *values = strtok_r(NULL, "\n", &line_state);
    if (!values || strncmp(values, prefix, strlen(prefix))) return -EINVAL;
    char *header_state = NULL, *value_state = NULL;
    char *name = strtok_r(header, " ", &header_state), *value = strtok_r(values, " ", &value_state);
    size_t found = 0;
    while (name && value) {
        for (size_t i = 0; i < count; ++i) {
            if (!strcmp(name, fields[i].name)) {
                char *end;
                errno = 0;
                unsigned long long parsed = strtoull(value, &end, 10);
                if (errno || *end || !*value) return -EINVAL;
                *fields[i].value = parsed;
                found++;
            }
        }
        name = strtok_r(NULL, " ", &header_state);
        value = strtok_r(NULL, " ", &value_state);
    }
    return found == count ? 0 : -ENOENT;
}
/* /proc/net/snmp6 uses one name/value per line, unlike paired IPv4 tables. */
static int counters6(struct field *fields, size_t count)
{
    char buffer[16384];
    int result = read_file("/proc/net/snmp6", buffer, sizeof(buffer));
    if (result) return result;
    size_t found = 0;
    char *state = NULL;
    for (char *line = strtok_r(buffer, "\n", &state); line; line = strtok_r(NULL, "\n", &state)) {
        char *columns = NULL;
        char *name = strtok_r(line, " \t", &columns);
        char *text = strtok_r(NULL, " \t", &columns);
        if (!name) continue;
        for (size_t i = 0; i < count; i++) if (!strcmp(name, fields[i].name)) {
            if (!text) return -EINVAL;
            char *end;
            errno = 0;
            unsigned long long value = strtoull(text, &end, 10);
            if (errno || *end || !*text) return -EINVAL;
            *fields[i].value = value;
            found++;
        }
    }
    return found == count ? 0 : -ENOENT;
}
int ker_native_counters(struct ker_native_counters *out)
{
    struct ker_native_counters value = {0};
    struct field basic[] = {{"ActiveOpens", &value.active_opens}, {"PassiveOpens", &value.passive_opens},
        {"RetransSegs", &value.retransmitted_segments}};
    int result = counters("/proc/net/snmp", "Tcp:", basic, sizeof(basic) / sizeof(basic[0]));
    if (result) return result;
    struct field extended[] = {{"TCPWinProbe", &value.zero_window_probes}, {"TCPOFOQueue", &value.out_of_order_queued}};
    result = counters("/proc/net/netstat", "TcpExt:", extended, sizeof(extended) / sizeof(extended[0]));
    if (result) return result;
    struct field udp[] = {{"InDatagrams", &value.udp_in_datagrams},
        {"OutDatagrams", &value.udp_out_datagrams}, {"InErrors", &value.udp_in_errors},
        {"NoPorts", &value.udp_no_ports}};
    result = counters("/proc/net/snmp", "Udp:", udp, sizeof(udp) / sizeof(udp[0]));
    if (result) return result;
    struct field ip[] = {{"FragOKs", &value.ip_frag_ok}, {"FragCreates", &value.ip_frag_creates},
        {"ReasmOKs", &value.ip_reasm_ok}, {"ReasmFails", &value.ip_reasm_fails}};
    result = counters("/proc/net/snmp", "Ip:", ip, sizeof(ip) / sizeof(ip[0]));
    if (result) return result;
    struct field ipv6[] = {{"Udp6InDatagrams", &value.udp6_in_datagrams},
        {"Udp6OutDatagrams", &value.udp6_out_datagrams}, {"Udp6InErrors", &value.udp6_in_errors},
        {"Udp6NoPorts", &value.udp6_no_ports}, {"Ip6FragOKs", &value.ip6_frag_ok},
        {"Ip6FragCreates", &value.ip6_frag_creates}, {"Ip6ReasmOKs", &value.ip6_reasm_ok},
        {"Ip6ReasmFails", &value.ip6_reasm_fails}, {"Ip6ReasmTimeout", &value.ip6_reasm_timeouts}};
    result = counters6(ipv6, sizeof(ipv6) / sizeof(ipv6[0]));
    if (result) return result;
    char policy[16];
    result = read_file("/proc/sys/net/ipv4/tcp_ecn", policy, sizeof(policy));
    if (result) return result;
    if (strlen(policy) != 2 || policy[0] < '0' || policy[0] > '2' || policy[1] != '\n')
        return -EINVAL;
    value.tcp_ecn = (uint64_t)(policy[0] - '0');
    *out = value;
    return 0;
}
