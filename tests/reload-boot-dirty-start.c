#define _DEFAULT_SOURCE
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "reload-frame-cycle.h"
int __real_example_reload_cycle_start(struct example_reload_cycle *cycle);
int __wrap_example_reload_cycle_start(struct example_reload_cycle *cycle)
{
    int result = __real_example_reload_cycle_start(cycle);
    if (result) return result;
    struct rte_mbuf *packet = rte_pktmbuf_alloc(example_reload_cycle_pool(cycle));
    if (!packet) abort();
    void *bytes = rte_pktmbuf_append(packet, 64); if (!bytes) abort(); memset(bytes, 0x44, 64);
    if (rte_eth_tx_burst(example_reload_cycle_port(cycle), 0, &packet, 1) != 1) abort();
    fputs("RELOAD_BOOT_PREMATURE_TX\n", stderr);
    return 0;
}
