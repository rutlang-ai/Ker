#ifndef KER_WORKER_RX_DRAIN_H
#define KER_WORKER_RX_DRAIN_H

#include <stdint.h>
#include <rte_mbuf.h>

typedef uint16_t (*ker_worker_rx_burst_fn)(void *context,
    struct rte_mbuf **packets, uint16_t capacity);
typedef void (*ker_worker_rx_free_fn)(void *context, struct rte_mbuf *packet);

/* Discard startup RX backlog until an empty burst proves the queue is clear.
 * The finite budget bounds startup work; excess backlog fails closed. */
int ker_worker_rx_drain(ker_worker_rx_burst_fn burst,
    ker_worker_rx_free_fn free_packet, void *context, uint16_t packet_budget,
    uint64_t *discarded);

#endif
