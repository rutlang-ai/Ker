#define _GNU_SOURCE
/* Translate original Linux virtio metadata; packet processing/segmentation and
 * checksum arithmetic belong to original Linux and original DPDK APIs. */
#include "worker-offload.h"
#include <errno.h>
#include <dlfcn.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <rte_dev.h>
#include <rte_ip.h>
#include <rte_net.h>
#include <rte_tcp.h>
#include <rte_udp.h>

static bool same_file(const char *left, const char *right)
{
    struct stat left_stat, right_stat;
    return left && right && !stat(left, &left_stat) && !stat(right, &right_stat) &&
        left_stat.st_dev == right_stat.st_dev && left_stat.st_ino == right_stat.st_ino;
}

static void *loaded_driver_symbol(const struct rte_driver *driver, const char *name)
{
    Dl_info module_info;
    if (!driver || !dladdr(driver, &module_info) || !module_info.dli_fname) return NULL;
    bool main_executable = same_file(module_info.dli_fname, "/proc/self/exe");
    if (main_executable) {
        void *symbol = dlsym(RTLD_DEFAULT, name);
        Dl_info symbol_info;
        return symbol && dladdr(symbol, &symbol_info) &&
            same_file(symbol_info.dli_fname, module_info.dli_fname) ? symbol : NULL;
    }
    void *handle = dlopen(module_info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
    if (!handle) return NULL;
    void *symbol = dlsym(handle, name);
    Dl_info symbol_info;
    bool owned = symbol && dladdr(symbol, &symbol_info) &&
        same_file(symbol_info.dli_fname, module_info.dli_fname);
    dlclose(handle);
    return owned ? symbol : NULL;
}

uint32_t ker_worker_offload_feature_mask(int mode, bool tap)
{
    if (mode <= 0 || mode > 2) return 0;
    /* Original TAP software GSO cannot run IPv6 TSO; other qualified PMDs can. */
    return 1U | (mode == 2 ? (1U << 11) | (tap ? 0U : (1U << 12)) : 0U);
}

int ker_worker_offload_prepare(uint16_t port, int mode, struct rte_eth_conf *config,
    struct ker_worker_offload *state)
{
    memset(state, 0, sizeof(*state));
    if (!mode) return 0;
    if (mode < 0 || mode > 2) return -EINVAL;
    struct rte_eth_dev_info info;
    int error = rte_eth_dev_info_get(port, &info);
    if (error) return error;
    /* Bond capabilities cannot describe member-specific IPv6 GSO/retry
     * restrictions (notably original TAP). Qualify that composition before
     * advertising original Linux features for it. Default off is unchanged. */
    if (info.driver_name && !strcmp(info.driver_name, "net_bonding")) return -EOPNOTSUPP;
    uint64_t required = RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    if (mode == 2) required |= RTE_ETH_TX_OFFLOAD_TCP_TSO | RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    if ((info.tx_offload_capa & required) != required) return -EOPNOTSUPP;
    state->mode = mode;
    state->flags = required | (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM);
    state->segment_limit = info.tx_desc_lim.nb_seg_max;
    state->tap = info.driver_name && !strcmp(info.driver_name, "net_tap");
    if (state->tap) {
        /* Only the isolated, qualified TAP ownership patch may opt into
         * retries. Unmodified PMDs keep the fail-closed boundary. */
        /* EAL loads PMDs RTLD_LOCAL. Resolve only the driver library owning
         * this selected port, using its public device/driver information. */
        int (*retry_abi)(uint16_t) = loaded_driver_symbol(
            rte_dev_driver(info.device), "ker_dpdk_tap_tx_retry_abi");
        state->tap_retry_safe = retry_abi && retry_abi(port) == 1;
    }
    /* Map only features fully implemented by the translator. */
    state->features = ker_worker_offload_feature_mask(mode, state->tap);
    config->txmode.offloads |= state->flags;
    return 0;
}

int ker_worker_offload_apply(const struct ker_worker_offload *state,
    const struct ker_packet_header *header, struct rte_mbuf *packet, unsigned mtu,
    struct ker_worker_offload_result *result)
{
    memset(result, 0, sizeof(*result));
    if (header->flags & ~1U) return -EOPNOTSUPP;
    if (!header->flags) {
        if (header->gso_type || header->gso_size || header->header_length ||
            header->checksum_start || header->checksum_offset) return -EINVAL;
        return packet->pkt_len <= mtu + 18 ? 0 : -EMSGSIZE;
    }
    if (!state->mode || (state->segment_limit && packet->nb_segs > state->segment_limit))
        return -EOPNOTSUPP;
    unsigned location = (unsigned)header->checksum_start + header->checksum_offset;
    if (location + 2 > packet->pkt_len || location + 2 > packet->data_len) return -EINVAL;
    struct rte_net_hdr_lens lengths = {0};
    uint32_t type = rte_net_get_ptype(packet, &lengths, RTE_PTYPE_ALL_MASK);
    unsigned l3 = type & RTE_PTYPE_L3_MASK, l4 = type & RTE_PTYPE_L4_MASK;
    bool ipv4 = l3 == RTE_PTYPE_L3_IPV4 || l3 == RTE_PTYPE_L3_IPV4_EXT;
    bool ipv6 = l3 == RTE_PTYPE_L3_IPV6 || l3 == RTE_PTYPE_L3_IPV6_EXT;
    unsigned start = lengths.l2_len + lengths.l3_len;
    bool tcp = l4 == RTE_PTYPE_L4_TCP, udp = l4 == RTE_PTYPE_L4_UDP;
    bool tap_ipv6_extensions = state->tap && l3 == RTE_PTYPE_L3_IPV6_EXT;
    if (!header->gso_type && ((!ipv4 && !ipv6) || (!tcp && !udp) ||
            tap_ipv6_extensions)) {
        /* Generic virtio CHECKSUM_PARTIAL (ICMP, extension headers, tunnels)
         * cannot always be expressed by an ethdev TCP/UDP flag. Its offsets
         * and pseudo-header seed come from original Linux. Complete only the
         * requested byte range with the original DPDK raw checksum helper. */
        if (header->gso_size || header->header_length || header->checksum_start < 14 ||
            packet->pkt_len > mtu + 18) return -EINVAL;
        uint16_t sum;
        if (rte_raw_cksum_mbuf(packet, header->checksum_start,
                packet->pkt_len - header->checksum_start, &sum)) return -EINVAL;
        sum = (uint16_t)~sum;
        /* Match original Linux skb_checksum_help() for CHECKSUM_PARTIAL. */
        if (!sum) sum = 0xffffU;
        unsigned char *data = rte_pktmbuf_mtod(packet, unsigned char *);
        memcpy(data + location, &sum, sizeof(sum));
        result->fallback = 1;
        return 0;
    }
    if (!ipv4 && !ipv6) return -EOPNOTSUPP;
    if (lengths.l2_len != 14 && lengths.l2_len != 18) return -EOPNOTSUPP;
    if (header->checksum_start != start) return -EINVAL;
    bool tso = header->gso_type != 0;
    unsigned total_headers = start + lengths.l4_len;
    if (tso) {
        if (state->mode != 2 || !tcp || !header->gso_size ||
            header->header_length < total_headers || header->header_length > packet->pkt_len ||
            (ipv4 ? header->gso_type != 1 : (header->gso_type != 4 || !(state->features & (1U << 12)))))
            return -EOPNOTSUPP;
        if ((unsigned)header->gso_size + lengths.l3_len + lengths.l4_len > mtu) return -EMSGSIZE;
    } else if (header->gso_size || header->header_length || packet->pkt_len > mtu + lengths.l2_len)
        return -EMSGSIZE;
    unsigned char *bytes = rte_pktmbuf_mtod(packet, unsigned char *);
    if (total_headers > packet->data_len ||
        header->checksum_offset != (tcp ? offsetof(struct rte_tcp_hdr, cksum) : offsetof(struct rte_udp_hdr, dgram_cksum)))
        return -EINVAL;
    packet->l2_len = lengths.l2_len;
    packet->l3_len = lengths.l3_len;
    packet->l4_len = lengths.l4_len;
    packet->ol_flags |= (ipv4 ? RTE_MBUF_F_TX_IPV4 : RTE_MBUF_F_TX_IPV6) |
        (tcp ? RTE_MBUF_F_TX_TCP_CKSUM : RTE_MBUF_F_TX_UDP_CKSUM);
    if (tso) {
        packet->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
        unsigned maximum = mtu - lengths.l3_len - lengths.l4_len;
        /* Pinned TAP bounds GSO's complete Ethernet segment by its MTU.
         * Use a smaller legal segment maximum; original DPDK does all actual
         * segmentation. Linux still owns TCP sequence/ACK/retransmit state. */
        if (state->tap) maximum -= lengths.l2_len;
        packet->tso_segsz = RTE_MIN(header->gso_size, maximum);
        if (!packet->tso_segsz) return -EMSGSIZE;
        if (ipv4) result->tso4 = 1; else result->tso6 = 1;
    }
    uint16_t seed;
    if (ipv4) {
        struct rte_ipv4_hdr *ip = (void *)(bytes + lengths.l2_len);
        if (state->flags & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
            packet->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
            ip->hdr_checksum = 0;
            result->ip = 1;
        }
        seed = rte_ipv4_phdr_cksum(ip, packet->ol_flags);
    } else {
        struct rte_ipv6_hdr pseudo = *(struct rte_ipv6_hdr *)(bytes + lengths.l2_len);
        pseudo.proto = tcp ? IPPROTO_TCP : IPPROTO_UDP;
        if (!tso) {
            unsigned extension_length = lengths.l3_len - sizeof(pseudo);
            uint16_t payload_length = rte_be_to_cpu_16(pseudo.payload_len);
            if (extension_length > payload_length) return -EINVAL;
            pseudo.payload_len = rte_cpu_to_be_16(payload_length - extension_length);
        }
        seed = rte_ipv6_phdr_cksum(&pseudo, packet->ol_flags);
    }
    memcpy(bytes + location, &seed, sizeof(seed));
    result->tcp = tcp;
    result->udp = udp;
    return 0;
}
