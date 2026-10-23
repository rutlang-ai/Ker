/* Corrupt one successful original RETA readback to exercise fail-closed RSS. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <rte_ethdev.h>
int rte_eth_dev_rss_reta_query(uint16_t port,
    struct rte_eth_rss_reta_entry64 *table, uint16_t size)
{
    typedef int (*query_fn)(uint16_t, struct rte_eth_rss_reta_entry64 *, uint16_t);
    query_fn original = (query_fn)dlsym(RTLD_NEXT, "rte_eth_dev_rss_reta_query");
    if (!original) return -ENOTSUP;
    int result = original(port, table, size);
    if (!result && size) {
        table[0].reta[0] = UINT16_MAX;
        fputs("INJECT: successful original RETA readback corrupted\n", stderr);
    }
    return result;
}
