/* Control-plane qualification of real DPDK APIs, not flow/RSS landing evidence. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "worker-rss.h"

int main(int argc, char **argv)
{
    if (rte_eal_init(argc, argv) < 0) return 1;
    uint16_t port;
    int status = 1;
    bool configured = false, started = false;
    struct rte_mempool *pool = NULL;
    if (rte_eth_dev_get_port_by_name("net_null0", &port)) goto done;
    struct rte_eth_conf config = {0};
    struct ker_worker_rss rss = {0};
    if (!ker_worker_rss_prepare(port, 1, &config, &rss) ||
        ker_worker_rss_prepare(port, 2, &config, &rss)) goto done;
    if (rte_eth_dev_configure(port, 2, 2, &config)) goto done;
    configured = true;
    pool = rte_pktmbuf_pool_create("rss_control", 1023, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) goto done;
    for (uint16_t queue = 0; queue < 2; queue++)
        if (rte_eth_rx_queue_setup(port, queue, 128, rte_socket_id(), NULL, pool) ||
            rte_eth_tx_queue_setup(port, queue, 128, rte_socket_id(), NULL)) goto done;
    if (rte_eth_dev_start(port)) goto done;
    started = true;
    uint8_t before[64] = {0};
    struct rte_eth_rss_conf actual = {.rss_key = before, .rss_key_len = rss.key_length};
    if (rte_eth_dev_rss_hash_conf_get(port, &actual) || ker_worker_rss_apply(port, 2, &rss) ||
        memcmp(before, rss.key, rss.key_length) || rss.reta_size != 128) goto done;
    struct rte_eth_rss_reta_entry64 table[2] = {{.mask = UINT64_MAX}, {.mask = UINT64_MAX}};
    /* Poison the device table independently; the production adapter must
     * replace all entries and verify their original API readback. */
    for (unsigned index = 0; index < 128; index++) table[index / 64].reta[index % 64] = 1;
    if (rte_eth_dev_rss_reta_update(port, table, 128) || ker_worker_rss_apply(port, 2, &rss)) goto done;
    memset(table[0].reta, 0xff, sizeof(table[0].reta));
    memset(table[1].reta, 0xff, sizeof(table[1].reta));
    if (rte_eth_dev_rss_reta_query(port, table, 128)) goto done;
    for (unsigned index = 0; index < 128; index++)
        if (table[index / 64].reta[index % 64] != index % 2) goto done;
    if (rte_eth_dev_stop(port)) goto done;
    started = false;
    if (rte_eth_dev_start(port)) goto done;
    started = true;
    if (ker_worker_rss_apply(port, 2, &rss) || memcmp(before, rss.key, rss.key_length)) goto done;
    puts("PASS: real null PMD key preserved and all 128 RETA entries restored/read back; no packet landing claimed");
    status = 0;
done:
    if (started && rte_eth_dev_stop(port)) status = 1;
    if (configured && rte_eth_dev_close(port)) status = 1;
    unsigned outstanding = pool ? rte_mempool_in_use_count(pool) : 0;
    if (outstanding) status = 1;
    else if (pool) rte_mempool_free(pool);
    if (rte_eal_cleanup()) status = 1;
    return status;
}
