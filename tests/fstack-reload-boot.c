#define _GNU_SOURCE
#include <ker/reload.h>
#include <ker/reload-tx.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <string.h>
#include "eal.h"
#include "ff_config.h"
#include "reload-frame-cycle.h"
#include "worker-mbuf.h"
static struct example_reload_cycle *cycle;
static struct ker_reload_tx *g_ctx;
static struct ff_config source_configuration;
#define ff_global_cfg source_configuration
static struct ff_port_cfg port_config;
#define IT_PORT_ID 0
#define SKIP_IF_NO_INIT() CHECK(cycle && rte_eal_process_type() == RTE_PROC_PRIMARY)
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_non_null(p) CHECK((p) != NULL)
static int source_attached(void)
{
    struct ker_reload_runtime view; CHECK(ker_reload_runtime_view(&view) == 0); return view.attached;
}
static void *source_register(void *sc, void *ifp, struct ff_port_cfg *config)
{
    CHECK(sc && ifp && config == &port_config && config->port_id == example_reload_cycle_port(cycle));
    return example_reload_cycle_register(cycle);
}
static int source_start(void) { return example_reload_cycle_start(cycle); }
#define ff_reload_state_attached source_attached
#define ff_reload_rx_owner_gen ker_reload_rx_owner
#define ff_no_hw_mode() (!ker_reload_rx_allowed())
#define ff_drain_ring_ready() example_reload_cycle_ready(cycle)
#define nb_dev_ports rte_eth_dev_count_avail()
#define ff_dpdk_register_if source_register
#define ff_dpdk_if_up source_start
#define g_nb_tx_hooks ((int)example_reload_cycle_hooks(cycle))
#define hw_tx_calls() example_reload_cycle_tx_calls(cycle)
#define hw_tx_pkts() example_reload_cycle_tx_packets(cycle)
#include "fstack-reload-boot-source.inc"
int main(void)
{
    ker_test_eal_init();
    for (unsigned attempt = 0; attempt < 5; ++attempt) {
        int opened = example_reload_cycle_open(&cycle);
        if (opened) fprintf(stderr, "boot open attempt=%u result=%d rte_errno=%d errno=%d\n", attempt, opened, rte_errno, errno);
        CHECK(opened == 0);
        port_config.port_id = example_reload_cycle_port(cycle);
        ff_global_cfg.dpdk.port_cfgs = &port_config;
        ff_global_cfg.dpdk.nb_ports = rte_eth_dev_count_avail();
        test_it_a09_boot_state(NULL);
        CHECK(g_ctx && example_reload_cycle_hooks(cycle) == 1);
        struct rte_eth_link link; CHECK(rte_eth_link_get_nowait(port_config.port_id, &link) == 0 && link.link_status);
        struct rte_eth_stats stats; CHECK(rte_eth_stats_get(port_config.port_id, &stats) == 0);
        CHECK(stats.opackets == 0 && stats.ipackets == 0);
        unsigned char bytes[64], scratch[64]; memset(bytes, (int)(attempt + 0x71), sizeof(bytes));
        struct rte_mbuf *input = ker_worker_mbuf_from_bytes(example_reload_cycle_pool(cycle), bytes, sizeof(bytes));
        struct rte_mbuf *output = NULL, *original = input; CHECK(input);
        CHECK(example_reload_cycle_transfer(cycle, &input, &output) == 0 && !input && output == original && rte_mbuf_refcnt_read(output) == 1);
        const void *received = rte_pktmbuf_read(output, 0, sizeof(bytes), scratch);
        CHECK(received && output->pkt_len == sizeof(bytes) && memcmp(received, bytes, sizeof(bytes)) == 0);
        rte_pktmbuf_free(output);
        CHECK(example_reload_cycle_tx_calls(cycle) == 2 && example_reload_cycle_tx_packets(cycle) == 2);
        CHECK(rte_eth_stats_get(port_config.port_id, &stats) == 0 && stats.opackets == 2 && stats.ipackets == 3);
        CHECK(rte_mempool_avail_count(example_reload_cycle_pool(cycle)) == 511);
        CHECK(example_reload_cycle_close(&cycle) == 0 && !cycle);
        g_ctx = NULL;
        CHECK(rte_eth_dev_count_avail() == 0 && !rte_ring_lookup("drain_rx_p0_q0_g0") &&
            !rte_ring_lookup("drain_rx_p0_q0_g1") && !rte_ring_lookup("drain_tx_p0_q0_g0") &&
            !rte_ring_lookup("drain_tx_p0_q0_g1"));
        struct ker_reload_runtime view; CHECK(ker_reload_runtime_view(&view) == 0 && !view.attached);
    }
    CHECK(rte_eal_cleanup() == 0);
    puts("RELOAD_BOOT_SOURCE test_it_a09_boot_state cycles=5 boot_tx=0 hooks=1 transfer_tx=2 transfer_rx=3 pool=511");
    return 0;
}
