/* Private test boundary for the unchanged original drain-ring implementation.
 * Packet parsing/stack dispatch is outside this fixture. */
#ifndef KER_TEST_FSTACK_DRAIN_DPDK_IF_H
#define KER_TEST_FSTACK_DRAIN_DPDK_IF_H

#include <stdint.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include "ff_config.h"
#include "ff_memory.h"

struct rte_ring;
struct rte_mbuf;
struct ff_dpdk_if_context;

struct rte_ring *create_ring(const char *name, unsigned count, int socket_id,
    unsigned flags);
void ff_dpdk_process_packets(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **bufs, uint16_t count, struct ff_dpdk_if_context *ctx,
    int pkts_from_ring);

#endif
