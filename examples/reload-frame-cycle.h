#ifndef EXAMPLE_RELOAD_FRAME_CYCLE_H
#define EXAMPLE_RELOAD_FRAME_CYCLE_H
#include <stdint.h>
struct example_reload_cycle;
struct ker_reload_tx;
struct rte_mbuf;
struct rte_mempool;
/* One caller-owned primary EAL port and serialized two-generation event loop.
 * This is isolated from authenticated resident sessions and FreeBSD veth ABI. */
int example_reload_cycle_open(struct example_reload_cycle **out);
struct ker_reload_tx *example_reload_cycle_register(struct example_reload_cycle *cycle);
int example_reload_cycle_start(struct example_reload_cycle *cycle);
int example_reload_cycle_ready(const struct example_reload_cycle *cycle);
unsigned example_reload_cycle_hooks(const struct example_reload_cycle *cycle);
uint64_t example_reload_cycle_tx_calls(const struct example_reload_cycle *cycle);
uint64_t example_reload_cycle_tx_packets(const struct example_reload_cycle *cycle);
uint16_t example_reload_cycle_port(const struct example_reload_cycle *cycle);
struct rte_mempool *example_reload_cycle_pool(struct example_reload_cycle *cycle);
/* Exercise both RX rings, both parked TX rings and two owner handovers.
 * Enqueue consumes/NULLs input. Later errors may leave queue-owned packets;
 * close then refuses with EBUSY. Caller serializes every operation. */
int example_reload_cycle_transfer(struct example_reload_cycle *, struct rte_mbuf **input,
    struct rte_mbuf **output);
/* Empty-only: staged, queued or caller-held mbufs keep all resources alive. */
int example_reload_cycle_close(struct example_reload_cycle **cycle);
#endif
