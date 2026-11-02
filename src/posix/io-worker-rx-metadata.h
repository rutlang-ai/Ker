#ifndef KER_IO_WORKER_RX_METADATA_H
#define KER_IO_WORKER_RX_METADATA_H

#include "worker-exception.h"

/* Metadata accepted by the existing RX extraction and exception-routing
 * path. Keep RSS and other already-supported routing metadata here. */
static inline bool ker_io_worker_metadata_supported(const struct rte_mbuf *packet)
{
    const uint64_t changed = RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_QINQ_STRIPPED |
        RTE_MBUF_F_RX_LRO | RTE_MBUF_F_RX_SEC_OFFLOAD | RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED;
    return !(packet->ol_flags & changed) &&
        (packet->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) != RTE_MBUF_F_RX_IP_CKSUM_NONE &&
        (packet->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) != RTE_MBUF_F_RX_L4_CKSUM_NONE;
}

/* The decision wire has a narrower metadata contract than the worker's
 * original exception path. Apply it only to frames already classified for
 * native Linux injection. */
static inline bool ker_io_worker_rx_decision_metadata_supported(
    const struct rte_mbuf *packet)
{
    const uint64_t allowed = RTE_MBUF_F_RX_IP_CKSUM_MASK | RTE_MBUF_F_RX_L4_CKSUM_MASK;
    const uint64_t ip = packet->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK;
    const uint64_t l4 = packet->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK;
    return !(packet->ol_flags & ~allowed) &&
        (!ip || ip == RTE_MBUF_F_RX_IP_CKSUM_GOOD) &&
        (!l4 || l4 == RTE_MBUF_F_RX_L4_CKSUM_GOOD) && !packet->vlan_tci;
}

static inline bool ker_io_worker_route_metadata_supported(const struct rte_mbuf *packet,
    enum ker_exception_route route, bool rx_decision_enabled)
{
    return !rx_decision_enabled || route != KER_EXCEPTION_NATIVE ||
        ker_io_worker_rx_decision_metadata_supported(packet);
}

#endif
