#ifndef EXAMPLE_RSS_TABLE_POLICY_H
#define EXAMPLE_RSS_TABLE_POLICY_H
#include <stddef.h>
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
/* Caller-only advisory tuple helpers. They do not allocate Linux socket ports. */
int example_rss_advisory_configure(uint16_t queues, uint16_t own_queue, uint16_t reta_size);
int example_rss_advisory_ready(int ipv6);
int example_rss_advisory_enable(int enabled, int recheck);
int example_rss_advisory_suggest4(uint32_t remote, uint32_t local, uint16_t remote_port,
    uint16_t *candidate, uint16_t first, uint16_t last);
int example_rss_advisory_suggest6(const uint8_t remote[16], const uint8_t local[16],
    uint16_t remote_port, uint16_t *candidate, uint16_t first, uint16_t last);
int example_rss_advisory_is_owner4(uint32_t remote, uint32_t local,
    uint16_t remote_port, uint16_t local_port);
int example_rss_advisory_is_owner6(const uint8_t remote[16], const uint8_t local[16],
    uint16_t remote_port, uint16_t local_port);
const uint8_t *example_rss_advisory_key(size_t *length);
uint16_t example_rss_advisory_reta_size(void);
uint16_t example_rss_advisory_queue_count(void);
uint16_t example_rss_advisory_own_queue(void);
#endif
