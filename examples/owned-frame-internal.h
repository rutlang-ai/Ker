#ifndef EXAMPLE_OWNED_FRAME_INTERNAL_H
#define EXAMPLE_OWNED_FRAME_INTERNAL_H
#include <stdio.h>
#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include "ff_config.h"
#define ff_global_cfg example_owned_configuration
extern struct ff_config example_owned_configuration;
#define lcore_conf example_owned_lcores
#define ff_app_mbuf_pool example_owned_pool
#include "ff_memory.h"
#include "offload.inc"
#include "owned-frame-send.h"
struct example_owned_sender {
    struct ff_dpdk_if_context context;
    struct lcore_conf conf;
    struct rte_mempool *pool;
    unsigned lcore;
    uint16_t queue;
};
extern _Thread_local struct example_owned_sender *example_owned_active;
extern _Thread_local struct example_owned_send_stats example_owned_counts;
/* Checked by the caller API before the unchanged original body is entered. */
int example_owned_no_hw(void);
int example_owned_copydata(void *packet, void *output, int offset, int length);
void example_owned_input_free(void *packet);
void example_owned_offload(void *packet, struct ff_tx_offload *metadata);
void example_owned_divert(uint16_t port, uint16_t queue, struct rte_mbuf *packet);
int example_owned_transmit(struct rte_mbuf *packet, uint16_t port);
int example_owned_upstream_send(struct ff_dpdk_if_context *context, void *packet, int total);
#endif
