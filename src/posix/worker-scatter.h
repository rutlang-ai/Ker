/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef KER_WORKER_SCATTER_H
#define KER_WORKER_SCATTER_H
#include <stdbool.h>
#include <stdint.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

static inline uint16_t ker_worker_scatter_required_segments(uint32_t mtu)
{
    const uint32_t payload = RTE_MBUF_DEFAULT_BUF_SIZE - RTE_PKTMBUF_HEADROOM;
    uint64_t frame_length = (uint64_t)mtu + RTE_ETHER_HDR_LEN;
    uint64_t segments = frame_length / payload + (frame_length % payload != 0);
    return segments <= UINT16_MAX ? (uint16_t)segments : 0;
}

static inline bool ker_worker_scatter_limits_support(uint16_t required,
    uint16_t total_limit, uint16_t mtu_limit)
{
    return required && (!total_limit || total_limit >= required) &&
        (!mtu_limit || mtu_limit >= required);
}

static inline uint32_t ker_worker_rx_eth_overhead(const struct rte_eth_dev_info *info)
{
    const uint32_t minimum = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
    if (info->max_mtu != UINT16_MAX && info->max_rx_pktlen > info->max_mtu) {
        uint32_t reported = info->max_rx_pktlen - info->max_mtu;
        return reported < minimum ? minimum : reported;
    }
    return minimum;
}

static inline uint64_t ker_worker_rx_required_segments(uint32_t mtu, uint32_t overhead)
{
    const uint32_t payload = RTE_MBUF_DEFAULT_BUF_SIZE - RTE_PKTMBUF_HEADROOM;
    uint64_t frame_length = (uint64_t)mtu + overhead;
    return frame_length / payload + (frame_length % payload != 0);
}

static inline bool ker_worker_rx_limits_support(uint64_t required, uint16_t mtu_limit)
{
    return required && (!mtu_limit || mtu_limit == UINT16_MAX || required <= mtu_limit);
}
#endif
