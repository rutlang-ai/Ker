#ifndef EXAMPLE_RSS_TABLE_POLICY_H
#define EXAMPLE_RSS_TABLE_POLICY_H
#include <stdint.h>
#include "ff_config.h"
struct rte_mbuf;
struct rte_ring;
/* Single-threaded caller policy. Software hash model only; does not configure
 * a device RETA or select ports for Linux sockets. Rules are copied. */
int example_rss_configure(const struct ff_rss_check_cfg *rules, uint16_t queues,
    uint16_t own_queue, uint16_t reta_size, uint16_t first, uint16_t last);
void example_rss_reset(void);
/* Caller explicitly registers this callback with ker::packet_dispatcher. */
int example_rss_dispatch(void *data, uint16_t *length, uint16_t queue, uint16_t queues);
/* Borrowed packet, transfers to caller's selected ring only on success. */
int example_rss_route(struct rte_mbuf *packet, struct rte_ring *local,
    struct rte_ring *other);
#endif
