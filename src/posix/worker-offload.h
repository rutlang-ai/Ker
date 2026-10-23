#ifndef KER_WORKER_OFFLOAD_H
#define KER_WORKER_OFFLOAD_H
#include "packet-channel.h"
#include <rte_ethdev.h>
#include <rte_mbuf.h>
struct ker_worker_offload {
    uint64_t flags;
    unsigned features;
    uint16_t segment_limit;
    int mode;
    bool tap;
    bool tap_retry_safe;
};
struct ker_worker_offload_result { unsigned tcp, udp, ip, tso4, tso6, fallback; };
uint32_t ker_worker_offload_feature_mask(int mode);
int ker_worker_offload_prepare(uint16_t port, int mode, struct rte_eth_conf *config,
    struct ker_worker_offload *state);
int ker_worker_offload_apply(const struct ker_worker_offload *state,
    const struct ker_packet_header *header, struct rte_mbuf *packet, unsigned mtu,
    struct ker_worker_offload_result *result);
#endif
