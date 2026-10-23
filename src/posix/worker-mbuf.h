/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef KER_WORKER_MBUF_H
#define KER_WORKER_MBUF_H
#include <rte_mbuf.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
/* Add one actual queue owner's RX/TX descriptors to the aggregate budget. */
static inline int ker_worker_mbuf_budget_add(uint32_t *rx_total,
    uint32_t *tx_total, uint32_t rx_descriptors, uint32_t tx_descriptors)
{
    if (!rx_total || !tx_total) return -EINVAL;
    if (*rx_total > UINT32_MAX - rx_descriptors ||
        *tx_total > UINT32_MAX - tx_descriptors) return -EOVERFLOW;
    *rx_total += rx_descriptors;
    *tx_total += tx_descriptors;
    return 0;
}
/* Add one ethdev's per-queue descriptor requirement for every active queue. */
static inline int ker_worker_mbuf_budget_add_queues(uint32_t *rx_total,
    uint32_t *tx_total, uint32_t queues, uint32_t rx_per_queue,
    uint32_t tx_per_queue)
{
    if (!queues) return -EINVAL;
    for (uint32_t queue = 0; queue < queues; queue++) {
        int result = ker_worker_mbuf_budget_add(rx_total, tx_total,
            rx_per_queue, tx_per_queue);
        if (result) return result;
    }
    return 0;
}
/* Reserve one mbuf per configured RX and TX descriptor, two worker bursts,
 * and a small refill/scheduling margin. */
static inline int ker_worker_mbuf_pool_count(uint32_t rx_descriptors,
    uint32_t tx_descriptors, uint32_t *count)
{
    const uint32_t margin = 256;
    const uint32_t bursts = 2 * 32;
    if (rx_descriptors > UINT32_MAX - tx_descriptors) return -EOVERFLOW;
    uint32_t descriptors = rx_descriptors + tx_descriptors;
    if (!count) return -EINVAL;
    if (descriptors > UINT32_MAX - bursts - margin) return -EOVERFLOW;
    uint32_t needed = descriptors + bursts + margin;
    *count = needed < 4095 ? 4095 : needed;
    return 0;
}
/* Copy one complete Ethernet frame into a pool-sized mbuf chain. On failure,
 * reclaim every allocated segment. The caller owns the returned chain. */
struct rte_mbuf *ker_worker_mbuf_from_bytes(struct rte_mempool *pool,
                                           const void *bytes, size_t length);
#endif
