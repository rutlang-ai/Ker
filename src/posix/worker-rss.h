#ifndef KER_WORKER_RSS_H
#define KER_WORKER_RSS_H
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <rte_ethdev.h>

/* Public ethdev API state only; this does not predict or steer socket tuples. */
struct ker_worker_rss {
    uint16_t reta_size;
    uint8_t key_length;
    uint8_t key[64];
    uint64_t types;
    bool key_captured;
};
int ker_worker_rss_prepare(uint16_t port, uint16_t queues,
    struct rte_eth_conf *config, struct ker_worker_rss *state);
int ker_worker_rss_apply(uint16_t port, uint16_t queues,
    struct ker_worker_rss *state);
#endif
