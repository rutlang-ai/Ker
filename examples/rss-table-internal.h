#ifndef EXAMPLE_RSS_TABLE_INTERNAL_H
#define EXAMPLE_RSS_TABLE_INTERNAL_H
#include <stdint.h>
#include <stdio.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include "ff_config.h"
#define ff_global_cfg example_rss_configuration
#define lcore_conf example_rss_lcores
extern struct ff_config example_rss_configuration;
#include "ff_memory.h"
/* Source names are private to this caller library, never Ker exports. */
#define ff_rss_tbl_init example_rss_tbl_init
#define ff_rss_tbl_set_portrange example_rss_tbl_set_portrange
#define ff_rss_tbl_get_portrange example_rss_tbl_get_portrange
#define ff_rss_check example_rss_check
#define ff_rss_check6 example_rss_check6
#define ff_rss_reta_log2 example_rss_reta_log2
#define ff_rss_thash_build_key example_rss_thash_build_key
#define ff_rss_thash_ctx_init example_rss_thash_ctx_init
#define ff_rss_adjust_sport example_rss_adjust_sport
#define ff_rss_adjust_sport6 example_rss_adjust_sport6
#define ff_rss_tbl6_init example_rss_tbl6_init
#define ff_rss_tbl6_set_portrange example_rss_tbl6_set_portrange
#define ff_rss_tbl6_get_portrange example_rss_tbl6_get_portrange
#define ff_veth_get_softc example_rss_context_new
void *example_rss_context_new(struct ff_dpdk_if_context *context);
void example_rss_context_cleanup(void);
int ff_rss_tbl_init(void);
int ff_rss_tbl_set_portrange(uint16_t first, uint16_t last);
int ff_rss_tbl_get_portrange(uint32_t saddr, uint32_t daddr, uint16_t sport,
    uint16_t *first, uint16_t *last, uint16_t **ports);
int ff_rss_check(void *context, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport);
int ff_rss_check6(void *context, const uint8_t *saddr, const uint8_t *daddr,
    uint16_t sport, uint16_t dport);
int ff_rss_thash_ctx_init(void);
int ff_rss_thash_build_key(uint16_t port_id, uint16_t reta_size);
int ff_rss_adjust_sport(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t dport, uint16_t *out_sport, uint16_t first, uint16_t last);
int ff_rss_adjust_sport6(void *softc, const uint8_t *saddr6, const uint8_t *daddr6,
    uint16_t dport, uint16_t *out_sport, uint16_t first, uint16_t last);
int ff_rss_tbl6_init(void);
int ff_rss_tbl6_set_portrange(uint16_t first, uint16_t last);
int ff_rss_tbl6_get_portrange(const uint8_t *saddr, const uint8_t *daddr,
    uint16_t sport, uint16_t *first, uint16_t *last, uint16_t **ports);
#endif
