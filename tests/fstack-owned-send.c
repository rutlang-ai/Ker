#define _GNU_SOURCE
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <string.h>
#include "eal.h"
#include "owned-frame-port.h"
static struct example_frame_port fixture;
static int g_copydata_fail;
static void ff_test_reset_send_ctl(void) { g_copydata_fail = 0; }
static void *ff_test_register(unsigned port)
{
    CHECK(port == 0 && fixture.port == 0); return fixture.sender;
}
static void ff_dpdk_deregister_if(void *ctx) { CHECK(ctx == fixture.sender); }
static int source_send(void *ctx, void *opaque, int total)
{
    CHECK(opaque && (total == 100 || total == 128));
    unsigned char bytes[128]; memset(bytes, 0x5a, sizeof(bytes));
    struct rte_mbuf *packet = example_frame_from_bytes(fixture.pool, bytes,
        (unsigned)total - (g_copydata_fail ? 1u : 0u));
    CHECK(packet);
    return example_owned_send(ctx, packet, total);
}
#define ff_dpdk_if_send source_send
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_non_null(x) CHECK((x) != NULL)
#define SKIP_IF_NO_INIT() CHECK(fixture.sender != NULL)
#include "fstack-owned-send-null-source.inc"
#include "fstack-owned-send-copy-source.inc"
static void conservation(void)
{
    CHECK(rte_mempool_avail_count(fixture.pool) == 511);
    CHECK(rte_ring_count(fixture.wire) == 0);
    struct rte_eth_stats stats; CHECK(rte_eth_stats_get(fixture.port, &stats) == 0);
    CHECK(stats.opackets == 0 && stats.ipackets == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    int copy = strcmp(argv[1], "copy") == 0;
    CHECK(copy || strcmp(argv[1], "null") == 0);
    ker_test_eal_init(); CHECK(example_frame_port_open(&fixture) == 0);
    CHECK(rte_eth_dev_count_avail() == 1);
    conservation();
    for (unsigned i = 0; i < 5; ++i) {
        if (copy) test_ff_dpdk_if_send_copydata_fail(NULL);
        else test_ff_dpdk_if_send_null_ctx_with_mbuf(NULL);
        conservation();
    }
    struct example_owned_send_stats stats; example_owned_send_snapshot(&stats);
    CHECK(stats.inputs_freed == 5 && stats.dropped_segments == 5 && stats.accepted == 0);
    CHECK(stats.copies == (copy ? 5u : 0u) && stats.copy_failures == (copy ? 5u : 0u));
    if (copy) {
        unsigned char bytes[1024]; memset(bytes, 0x39, sizeof(bytes));
        struct rte_mbuf *input = example_frame_from_bytes(fixture.pool, bytes, sizeof(bytes)); CHECK(input);
        CHECK(example_owned_send(fixture.sender, input, 1536) == -1);
        conservation(); example_owned_send_snapshot(&stats);
        CHECK(stats.copies == 8 && stats.copy_failures == 6 && stats.inputs_freed == 6 && stats.dropped_segments == 8);
    }
    unsigned char unsupported[64] = {0};
    struct rte_mbuf *tagged = example_frame_from_bytes(fixture.pool, unsupported, sizeof(unsupported)); CHECK(tagged);
    tagged->ol_flags = RTE_MBUF_F_TX_IP_CKSUM;
    errno = 0;
    CHECK(example_owned_send(fixture.sender, tagged, sizeof(unsupported)) == -1 && errno == ENOTSUP);
    conservation();
    /* Recover using the same sender, pool and live PMD after all failures. */
    unsigned char recovery[128], output[128]; memset(recovery, 0xa7, sizeof(recovery));
    struct rte_mbuf *input = example_frame_from_bytes(fixture.pool, recovery, sizeof(recovery)); CHECK(input);
    CHECK(example_owned_send(fixture.sender, input, sizeof(recovery)) == 0);
    struct rte_mbuf *received = NULL;
    CHECK(rte_eth_rx_burst(fixture.port, 0, &received, 1) == 1 && received->pkt_len == sizeof(recovery));
    const void *bytes = rte_pktmbuf_read(received, 0, sizeof(recovery), output);
    CHECK(bytes && memcmp(bytes, recovery, sizeof(recovery)) == 0);
    rte_pktmbuf_free(received);
    struct rte_eth_stats recovered; CHECK(rte_eth_stats_get(fixture.port, &recovered) == 0);
    CHECK(recovered.opackets == 1 && recovered.ipackets == 1);
    /* Count restoration must represent distinct real objects, not double frees. */
    struct rte_mbuf *all[511];
    for (unsigned i = 0; i < 511; ++i) {
        all[i] = rte_pktmbuf_alloc(fixture.pool); CHECK(all[i]);
        for (unsigned j = 0; j < i; ++j) CHECK(all[i] != all[j]);
    }
    CHECK(rte_pktmbuf_alloc(fixture.pool) == NULL);
    for (unsigned i = 0; i < 511; ++i) rte_pktmbuf_free(all[i]);
    CHECK(rte_mempool_avail_count(fixture.pool) == 511);
    CHECK(example_frame_port_close(&fixture) == 0); CHECK(rte_eal_cleanup() == 0);
    printf("OWNED_SOURCE_CASE %s exact_cleanup=true failure_tx=0 failure_rx=0 recovery_tx=1 recovery_rx=1 unique_pool=511\n", copy ?
        "test_ff_dpdk_if_send_copydata_fail" : "test_ff_dpdk_if_send_null_ctx_with_mbuf");
    return 0;
}
