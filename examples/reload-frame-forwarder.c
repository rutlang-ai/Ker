#define _DEFAULT_SOURCE
#include <ker/reload.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "reload-frame-cycle.h"
#include "worker-mbuf.h"
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "reload-frame caller: %s\n", #x); return 1; } } while (0)
int main(int argc, char **argv)
{
    int used = rte_eal_init(argc, argv); REQUIRE(used >= 0); argc -= used; argv += used;
    REQUIRE(argc == 3);
    unsigned char bytes[65536], scratch[65536];
    FILE *source = fopen(argv[1], "rb"); REQUIRE(source);
    size_t length = fread(bytes, 1, sizeof(bytes), source);
    REQUIRE(!ferror(source) && feof(source) && length >= 14 && length <= UINT16_MAX && fclose(source) == 0);
    struct example_reload_cycle *cycle = NULL;
    REQUIRE(example_reload_cycle_open(&cycle) == 0 && example_reload_cycle_ready(cycle));
    struct ker_reload_runtime view; REQUIRE(ker_reload_runtime_view(&view) == 0);
    REQUIRE(view.attached && view.rx_owner == 0 && !view.rx_stopped && ker_reload_rx_allowed());
    REQUIRE(example_reload_cycle_register(cycle) && example_reload_cycle_start(cycle) == 0);
    struct rte_eth_stats stats;
    REQUIRE(rte_eth_stats_get(example_reload_cycle_port(cycle), &stats) == 0 && !stats.opackets && !stats.ipackets);
    REQUIRE(example_reload_cycle_hooks(cycle) == 1 && !example_reload_cycle_tx_calls(cycle) && !example_reload_cycle_tx_packets(cycle));
    puts("RELOAD_BOOT_READY attached=1 owner=0 ports=1 rings=4 hooks=1 tx=0");
    struct rte_mbuf *input = ker_worker_mbuf_from_bytes(example_reload_cycle_pool(cycle), bytes, length), *output = NULL;
    struct rte_mbuf *original = input;
    REQUIRE(input && example_reload_cycle_transfer(cycle, &input, &output) == 0 && !input && output == original && rte_mbuf_refcnt_read(output) == 1);
    const void *received = rte_pktmbuf_read(output, 0, length, scratch);
    REQUIRE(received && output->pkt_len == length && memcmp(received, bytes, length) == 0);
    FILE *file = fopen(argv[2], "wb"); REQUIRE(file);
    REQUIRE(fwrite(received, 1, length, file) == length && fclose(file) == 0);
    unsigned segments = output->nb_segs;
    rte_pktmbuf_free(output);
    REQUIRE(example_reload_cycle_tx_calls(cycle) == 2 && example_reload_cycle_tx_packets(cycle) == 2);
    REQUIRE(rte_eth_stats_get(example_reload_cycle_port(cycle), &stats) == 0 && stats.opackets == 2 && stats.ipackets == 3);
    REQUIRE(example_reload_cycle_close(&cycle) == 0 && !cycle && rte_eal_cleanup() == 0);
    printf("RELOAD_FRAME_CYCLE bytes=%zu segments=%u rings=4 handovers=2 tx=2 rx=3 pool=511\n", length, segments);
    return 0;
}
