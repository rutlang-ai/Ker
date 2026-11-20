#ifndef EXAMPLE_OWNED_FRAME_SEND_H
#define EXAMPLE_OWNED_FRAME_SEND_H
#include <stdint.h>
struct rte_mempool;
struct rte_mbuf;
struct example_owned_sender;
struct example_owned_send_stats {
    uint64_t dropped_segments, copies, copy_failures, inputs_freed, accepted;
};
/* Primary EAL lcore only. The caller owns and keeps the started port/pool alive.
 * No checksum/TSO metadata, parked generations or page-array mode is supported. */
struct example_owned_sender *example_owned_sender_new(struct rte_mempool *pool,
    uint16_t port, uint16_t queue);
void example_owned_sender_delete(struct example_owned_sender *sender);
/* Consume a sole-owned original DPDK packet on every result, including a NULL
 * sender. total specifies bytes to copy; short input fails in the original body.
 * Zero means accepted by the PMD; -1 means rejected/dropped. */
int example_owned_send(struct example_owned_sender *sender, struct rte_mbuf *packet, int total);
void example_owned_send_snapshot(struct example_owned_send_stats *stats);
#endif
