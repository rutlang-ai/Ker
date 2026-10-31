#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_bus_vdev.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "kni-bridge-internal.h"
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "kni host caller: %s errno=%d\n", #x, errno); return 1; } } while (0)
static int64_t now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
int main(int argc, char **argv)
{
    REQUIRE(rte_eal_init(argc, argv) >= 0 && example_kni_prepare() == 0);
    struct rte_mempool *pool = rte_pktmbuf_pool_create("kni_bridge_pool", 2047, 0, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY); REQUIRE(pool);
    struct rte_eth_conf config = {0};
    REQUIRE(rte_eth_dev_configure(0, 1, 1, &config) == 0);
    REQUIRE(rte_eth_rx_queue_setup(0, 0, 256, SOCKET_ID_ANY, NULL, pool) == 0);
    REQUIRE(rte_eth_tx_queue_setup(0, 0, 256, SOCKET_ID_ANY, NULL) == 0 && rte_eth_dev_start(0) == 0);
    ff_kni_init(1, NULL, NULL);
    REQUIRE(kni_stat && !kni_stat[0]);
    ff_kni_alloc(0, 0, 0, 256);
    REQUIRE(kni_stat[0] && kni_stat[0]->port_id == 1 && rte_eth_dev_count_avail() == 2);
    uint16_t paired; REQUIRE(rte_eth_dev_get_port_by_name("virtio_user0", &paired) == 0 && paired == kni_stat[0]->port_id);
    REQUIRE(rte_eth_dev_configure(paired, 1, 1, &config) == 0);
    REQUIRE(rte_eth_rx_queue_setup(paired, 0, 256, SOCKET_ID_ANY, NULL, pool) == 0);
    REQUIRE(rte_eth_tx_queue_setup(paired, 0, 256, SOCKET_ID_ANY, NULL) == 0 && rte_eth_dev_start(paired) == 0);
    REQUIRE(ff_kni_is_owner_thread() && ff_kni_is_runtime_owner());
    REQUIRE(!kni_stat[0]->rx_packets && !kni_stat[0]->tx_packets && !kni_stat[0]->rx_dropped && !kni_stat[0]->tx_dropped);
    puts("READY_KNI_HOST_BRIDGE ports=2 rings=2 stats=live"); fflush(stdout);
    int64_t deadline = now_ms() + 20000;
    for (;;) {
        REQUIRE(now_ms() < deadline);
        struct rte_mbuf *packets[32];
        uint16_t count = rte_eth_rx_burst(0, 0, packets, 32);
        for (unsigned i = 0; i < count; ++i) REQUIRE(ff_kni_enqueue(FILTER_UNKNOWN, 0, packets[i]) == 0);
        ff_kni_process(0, 0, packets, 32);
        struct pollfd control = {.fd = STDIN_FILENO, .events = POLLIN};
        REQUIRE(poll(&control, 1, 0) >= 0);
        if (control.revents & POLLIN) {
            char command; REQUIRE(read(STDIN_FILENO, &command, 1) == 1 && command == 'x');
            break;
        }
        REQUIRE(!(control.revents & (POLLERR | POLLHUP | POLLNVAL)));
        struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
    }
    REQUIRE(kni_stat[0]->rx_packets == 1 && kni_stat[0]->tx_packets == 1 &&
        !kni_stat[0]->rx_dropped && !kni_stat[0]->tx_dropped);
    REQUIRE(rte_ring_empty(kni_rp[0]) && rte_ring_empty(kni_inject_rp[0]));
    REQUIRE(rte_eth_dev_stop(paired) == 0 && rte_vdev_uninit("virtio_user0") == 0);
    REQUIRE(rte_eth_dev_stop(0) == 0 && rte_vdev_uninit("net_tap0") == 0);
    REQUIRE(rte_eth_dev_count_avail() == 0 && rte_mempool_avail_count(pool) == 2047);
    REQUIRE(example_kni_reset() == 0);
    rte_mempool_free(pool); REQUIRE(rte_eal_cleanup() == 0);
    puts("KNI_HOST_BRIDGE rx=1 tx=1 dropped=0 pool=2047 ports=0");
    return 0;
}
