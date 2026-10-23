/* Corrupt one successful original RETA readback to exercise fail-closed RSS. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_ethdev.h>

int rte_eth_dev_rss_hash_conf_get(uint16_t port, struct rte_eth_rss_conf *conf)
{
    typedef int (*get_fn)(uint16_t, struct rte_eth_rss_conf *);
    static unsigned calls;
    get_fn original = (get_fn)dlsym(RTLD_NEXT, "rte_eth_dev_rss_hash_conf_get");
    if (!original) return -ENOTSUP;
    int result = original(port, conf);
    const char *mode = getenv("KER_TEST_RSS_FAILURE");
    if (!result && mode && !strcmp(mode, "key-change") && ++calls == 4 &&
        conf->rss_key && conf->rss_key_len) {
        conf->rss_key[0] ^= 0xff;
        fputs("INJECT: successful original RSS key readback changed\n", stderr);
    }
    return result;
}

int rte_eth_dev_rss_reta_query(uint16_t port,
    struct rte_eth_rss_reta_entry64 *table, uint16_t size)
{
    typedef int (*query_fn)(uint16_t, struct rte_eth_rss_reta_entry64 *, uint16_t);
    query_fn original = (query_fn)dlsym(RTLD_NEXT, "rte_eth_dev_rss_reta_query");
    if (!original) return -ENOTSUP;
    int result = original(port, table, size);
    const char *mode = getenv("KER_TEST_RSS_FAILURE");
    if (!result && size && mode && !strcmp(mode, "reta-mismatch")) {
        table[0].reta[0] = UINT16_MAX;
        fputs("INJECT: successful original RETA readback corrupted\n", stderr);
    }
    return result;
}
