/* Header geometry comes from original DPDK; this adapter only selects owners.
 * Original Linux remains responsible for protocol validation and state. */
#include "worker-exception-filter.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <rte_net.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
static int ports(unsigned char *bits, const char *text)
{
    if (!text || !*text) return 0;
    if (strlen(text) > 4096) return -E2BIG;
    while (*text) {
        if (*text < '0' || *text > '9') return -EINVAL;
        char *end; errno = 0;
        unsigned long first = strtoul(text, &end, 10), last = first;
        if (errno || first > 65535) return -EINVAL;
        if (*end == '-') {
            text = end + 1;
            if (*text < '0' || *text > '9') return -EINVAL;
            errno = 0; last = strtoul(text, &end, 10);
            if (errno || last > 65535 || last < first) return -EINVAL;
        }
        for (unsigned long value = first; value <= last; value++) bits[value / 8] |= (unsigned char)(1U << (value % 8));
        if (!*end) return 0;
        if (*end != ',' || !end[1]) return -EINVAL;
        text = end + 1;
    }
    return 0;
}
int ker_exception_filter_init(struct ker_exception_filter *filter, const char *tcp, const char *udp)
{
    if (!filter) return -EINVAL;
    struct ker_exception_filter candidate = {0};
    int result = ports(candidate.tcp, tcp);
    if (!result) result = ports(candidate.udp, udp);
    if (!result) *filter = candidate;
    return result;
}
bool ker_exception_arp(const struct rte_mbuf *packet)
{
    if (!packet) return false;
    struct rte_net_hdr_lens lengths = {0};
    uint32_t l2_type = rte_net_get_ptype(packet, &lengths, RTE_PTYPE_L2_MASK) & RTE_PTYPE_L2_MASK;
    if (l2_type != RTE_PTYPE_L2_ETHER && l2_type != RTE_PTYPE_L2_ETHER_VLAN && l2_type != RTE_PTYPE_L2_ETHER_QINQ) return false;
    if (lengths.l2_len < 14) return false;
    rte_be16_t temporary;
    const rte_be16_t *type = rte_pktmbuf_read(packet, lengths.l2_len - 2, 2, &temporary);
    return type && rte_be_to_cpu_16(*type) == RTE_ETHER_TYPE_ARP;
}
enum ker_exception_class ker_exception_classify(const struct ker_exception_filter *filter, const struct rte_mbuf *packet)
{
    if (!packet) return KER_EXCEPTION_UNKNOWN;
    struct rte_net_hdr_lens lengths = {0};
    uint32_t type = rte_net_get_ptype(packet, &lengths, RTE_PTYPE_ALL_MASK);
    if ((type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_FRAG ||
        (type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_FRAG) return KER_EXCEPTION_FRAGMENT;
    unsigned l3 = lengths.l2_len, l3_size = lengths.l3_len;
    unsigned family = type & RTE_PTYPE_L3_MASK;
    bool ipv4 = family == RTE_PTYPE_L3_IPV4 || family == RTE_PTYPE_L3_IPV4_EXT;
    bool ipv6 = family == RTE_PTYPE_L3_IPV6 || family == RTE_PTYPE_L3_IPV6_EXT;
    /* Only original DPDK's actual IP-in-IP geometry selects inner services.
     * UDP tunnels keep their outer destination port, as in the source filter. */
    if ((type & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_IP) {
        l3 += lengths.l3_len + lengths.tunnel_len + lengths.inner_l2_len;
        l3_size = lengths.inner_l3_len;
        family = type & RTE_PTYPE_INNER_L3_MASK;
        ipv4 = family == RTE_PTYPE_INNER_L3_IPV4 || family == RTE_PTYPE_INNER_L3_IPV4_EXT;
        ipv6 = family == RTE_PTYPE_INNER_L3_IPV6 || family == RTE_PTYPE_INNER_L3_IPV6_EXT;
    }
    uint32_t offset = l3 + l3_size;
    int protocol;
    if (ipv4) {
        struct rte_ipv4_hdr temporary;
        const struct rte_ipv4_hdr *ip = rte_pktmbuf_read(packet, l3, sizeof(temporary), &temporary);
        if (!ip || l3_size < sizeof(temporary) || offset > packet->pkt_len) return KER_EXCEPTION_UNKNOWN;
        protocol = ip->next_proto_id;
    } else if (ipv6) {
        struct rte_ipv6_hdr temporary;
        const struct rte_ipv6_hdr *ip = rte_pktmbuf_read(packet, l3, sizeof(temporary), &temporary);
        if (!ip || (rte_be_to_cpu_32(ip->vtc_flow) >> 28) != 6 || l3_size < sizeof(temporary)) return KER_EXCEPTION_UNKNOWN;
        uint32_t parsed = l3 + sizeof(temporary); int fragment;
        protocol = rte_net_skip_ip6_ext(ip->proto, packet, &parsed, &fragment);
        if (fragment) return KER_EXCEPTION_FRAGMENT;
        if (protocol < 0 || parsed > packet->pkt_len || parsed != offset) return KER_EXCEPTION_UNKNOWN;
    } else return KER_EXCEPTION_UNKNOWN;
    if (protocol == 89) return KER_EXCEPTION_OSPF;
    if (ipv6 && protocol == IPPROTO_ICMPV6) {
        unsigned char temporary[8];
        const unsigned char *icmp = rte_pktmbuf_read(packet, offset, sizeof(temporary), temporary);
        return icmp && icmp[0] >= 133 && icmp[0] <= 137 ? KER_EXCEPTION_NDP : KER_EXCEPTION_UNKNOWN;
    }
    if (!filter) return KER_EXCEPTION_UNKNOWN;
    const unsigned char *bitmap;
    uint16_t destination;
    if (protocol == IPPROTO_TCP) {
        struct rte_tcp_hdr temporary;
        const struct rte_tcp_hdr *tcp = rte_pktmbuf_read(packet, offset, sizeof(temporary), &temporary);
        if (!tcp) return KER_EXCEPTION_UNKNOWN;
        destination = rte_be_to_cpu_16(tcp->dst_port); bitmap = filter->tcp;
    } else if (protocol == IPPROTO_UDP) {
        struct rte_udp_hdr temporary;
        const struct rte_udp_hdr *udp = rte_pktmbuf_read(packet, offset, sizeof(temporary), &temporary);
        if (!udp) return KER_EXCEPTION_UNKNOWN;
        destination = rte_be_to_cpu_16(udp->dst_port); bitmap = filter->udp;
    } else return KER_EXCEPTION_UNKNOWN;
    return bitmap[destination / 8] & (1U << (destination % 8)) ? KER_EXCEPTION_SERVICE : KER_EXCEPTION_UNKNOWN;
}
