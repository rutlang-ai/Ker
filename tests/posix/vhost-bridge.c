/* Test-only Ethernet transport between original DPDK vhost and TAP PMDs. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int signal) { (void)signal; stopping = 1; }
int main(int argc, char **argv)
{
    if (rte_eal_init(argc, argv) < 0) return 1;
    struct rte_mempool *pool = rte_pktmbuf_pool_create("vhost_peer", 4095, 0, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    uint16_t ports[2]; bool configured[2] = {0}, started[2] = {0};
    int result = 1;
    uint64_t forwarded[2] = {0}, dropped = 0;
    if (!pool || rte_eth_dev_get_port_by_name("net_vhost0", &ports[0]) ||
        rte_eth_dev_get_port_by_name("net_tap0", &ports[1])) goto done;
    for (unsigned side = 0; side < 2; side++) {
        struct rte_eth_conf config = {0};
        uint16_t queues = side == 0 ? 2 : 1;
        if (rte_eth_dev_configure(ports[side], queues, queues, &config)) goto done;
        configured[side] = true;
        for (uint16_t queue = 0; queue < queues; queue++)
            if (rte_eth_rx_queue_setup(ports[side], queue, 512, rte_socket_id(), NULL, pool) ||
                rte_eth_tx_queue_setup(ports[side], queue, 512, rte_socket_id(), NULL)) goto done;
        if (rte_eth_dev_start(ports[side])) goto done;
        started[side] = true;
        if (rte_eth_promiscuous_enable(ports[side]) || rte_eth_allmulticast_enable(ports[side])) goto done;
    }
    signal(SIGTERM, stop); signal(SIGINT, stop);
    puts("READY"); fflush(stdout);
    while (!stopping) {
        bool progress = false;
        for (unsigned side = 0; side < 2; side++) {
            uint16_t queues = side == 0 ? 2 : 1;
            for (uint16_t queue = 0; queue < queues; queue++) {
                struct rte_mbuf *packets[32];
                uint16_t count = rte_eth_rx_burst(ports[side], queue, packets, 32);
                if (!count) continue;
                progress = true;
                uint16_t sent = rte_eth_tx_burst(ports[1 - side], 0, packets, count);
                forwarded[side] += sent; dropped += count - sent;
                for (uint16_t index = sent; index < count; index++) rte_pktmbuf_free(packets[index]);
            }
        }
        if (!progress) usleep(100);
    }
    result = 0;
done:
    for (unsigned side = 0; side < 2; side++) {
        if (started[side] && rte_eth_dev_stop(ports[side])) result = 1;
        if (configured[side] && rte_eth_dev_close(ports[side])) result = 1;
    }
    unsigned outstanding = pool ? rte_mempool_in_use_count(pool) : 0;
    printf("BRIDGE {\"to_host\":%llu,\"to_native\":%llu,\"dropped\":%llu,\"outstanding\":%u}\n",
        (unsigned long long)forwarded[0], (unsigned long long)forwarded[1],
        (unsigned long long)dropped, outstanding);
    if (outstanding) result = 1;
    else if (pool) rte_mempool_free(pool);
    if (rte_eal_cleanup()) result = 1;
    return result;
}
