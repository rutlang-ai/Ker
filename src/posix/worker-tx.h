/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_WORKER_TX_H
#define KER_WORKER_TX_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <rte_mbuf.h>
#define KER_WORKER_TX_CAPACITY 32
struct ker_worker_tx {
    struct rte_mbuf *packets[KER_WORKER_TX_CAPACITY];
    uint32_t lengths[KER_WORKER_TX_CAPACITY];
    bool multiseg[KER_WORKER_TX_CAPACITY];
    uint16_t count;
    int64_t first_ns;
    bool retrying;
};
struct ker_worker_tx_result { uint16_t packets; uint64_t bytes, multiseg; };
typedef uint16_t (*ker_worker_tx_burst)(void *, struct rte_mbuf **, uint16_t);
static inline bool ker_worker_tx_append(struct ker_worker_tx *queue,
    struct rte_mbuf *packet, int64_t now)
{
    if (queue->count == KER_WORKER_TX_CAPACITY) return false;
    if (!queue->count) queue->first_ns = now;
    uint16_t i = queue->count++;
    queue->packets[i] = packet;
    queue->lengths[i] = packet->pkt_len;
    queue->multiseg[i] = packet->nb_segs > 1;
    return true;
}
/* Ceil to microseconds; the first retained packet fixes the batch deadline. */
static inline int ker_worker_tx_wait_us(const struct ker_worker_tx *queue,
    int delay_us, int64_t now)
{
    if (!queue->count || queue->retrying || queue->count == KER_WORKER_TX_CAPACITY)
        return 0;
    int64_t elapsed = now >= queue->first_ns ? now - queue->first_ns : 0;
    int64_t remaining = (int64_t)delay_us * 1000 - elapsed;
    return remaining > 0 ? (int)((remaining + 999) / 1000) : 0;
}
static inline struct ker_worker_tx_result ker_worker_tx_flush(struct ker_worker_tx *queue,
    ker_worker_tx_burst burst, void *context)
{
    struct ker_worker_tx_result result = {0};
    if (!queue->count) return result;
    result.packets = burst(context, queue->packets, queue->count);
    /* Read saved metadata: the PMD may already have freed accepted mbufs. */
    for (uint16_t i = 0; i < result.packets; ++i) {
        result.bytes += queue->lengths[i];
        result.multiseg += queue->multiseg[i];
    }
    queue->count -= result.packets;
    memmove(queue->packets, queue->packets + result.packets,
        queue->count * sizeof(queue->packets[0]));
    memmove(queue->lengths, queue->lengths + result.packets,
        queue->count * sizeof(queue->lengths[0]));
    memmove(queue->multiseg, queue->multiseg + result.packets,
        queue->count * sizeof(queue->multiseg[0]));
    queue->retrying = queue->count != 0;
    if (!queue->count) queue->first_ns = 0;
    return result;
}
static inline void ker_worker_tx_discard(struct ker_worker_tx *queue)
{
    for (uint16_t i = 0; i < queue->count; ++i) rte_pktmbuf_free(queue->packets[i]);
    memset(queue, 0, sizeof(*queue));
}
#endif
