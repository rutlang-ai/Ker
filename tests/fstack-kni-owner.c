#define _GNU_SOURCE
#include "eal.h"
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_eth_ring.h>
#include "check.h"
#include "kni-bridge-internal.h"
#include "ff_reload.h"

#define KNI_TEST_POOL_SZ 64
static int eal_initialized = 1;
static struct rte_mempool *test_pool;
static struct rte_ring *sink_rx, *sink_tx;
static uint16_t sink_port;
static int seed_full_ring_packets;
static unsigned full_ring_seed_count;
static struct rte_mbuf *full_ring_seeded[16];
static unsigned char full_ring_payloads[16][32];
static struct rte_mbuf *source_pktmbuf_alloc(struct rte_mempool *pool);
#define rte_pktmbuf_alloc source_pktmbuf_alloc

#define assert_true(x) CHECK((x) != 0)
#define assert_null(x) CHECK((x) == NULL)
#define assert_non_null(x) CHECK((x) != NULL)
#define assert_int_equal(a,b) CHECK((a) == (b))
#define assert_ptr_equal(a,b) CHECK((a) == (b))
#define mock_assert(expression, message, file, line) \
    do { (void)(message); (void)(file); (void)(line); CHECK(expression); } while (0)

extern void *__real_rte_zmalloc(const char *, size_t, unsigned);

#include "fstack-kni-owner-source.inc"
#undef rte_pktmbuf_alloc

static struct rte_mbuf *source_pktmbuf_alloc(struct rte_mempool *pool)
{
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
    if (seed_full_ring_packets && packet && p1_rx &&
        rte_ring_count(p1_rx) < rte_ring_get_capacity(p1_rx)) {
        CHECK(full_ring_seed_count < sizeof(full_ring_seeded) / sizeof(full_ring_seeded[0]));
        unsigned index = full_ring_seed_count++;
        unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(packet,
            sizeof(full_ring_payloads[index]));
        CHECK(bytes);
        full_ring_seeded[index] = packet;
        for (unsigned j = 0; j < sizeof(full_ring_payloads[index]); ++j)
            full_ring_payloads[index][j] = bytes[j] = (unsigned char)(0x31 + 13 * index + j);
    }
    return packet;
}

static void exercise_real_short_tx_sink(void);
static void exercise_real_full_ring_drain(void);
static void exercise_real_owner_gate(void)
{
    rte_eth_fp_ops[0] = p1_saved_ops;
    struct rte_mbuf *packet = rte_pktmbuf_alloc(test_pool);
    CHECK(packet);
    char *bytes = rte_pktmbuf_append(packet, 32);
    CHECK(bytes);
    memset(bytes, 0x5a, 32);
    CHECK(!rte_ring_enqueue(p1_inject, packet));

    struct rte_mbuf *burst[1], *received = NULL;
    ff_reload_set_gen(0);
    CHECK(!example_kni_owner_ready());
    example_kni_poll_inject(0, 0, burst, 1);
    CHECK(rte_ring_count(p1_inject) == 1 && rte_ring_empty(sink_tx));

    ff_reload_set_gen(1);
    CHECK(example_kni_owner_ready());
    example_kni_poll_inject(0, 0, burst, 1);
    CHECK(rte_ring_empty(p1_inject) && !rte_ring_dequeue(sink_tx, (void **)&received));
    CHECK(received == packet && received->pkt_len == 32);
    for (unsigned i = 0; i < 32; ++i)
        CHECK(rte_pktmbuf_mtod(received, const unsigned char *)[i] == 0x5a);
    rte_pktmbuf_free(received);
    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ);
}

static void run_case(void (*test)(void **), int expected_limit, int exercise_sink)
{
    void *state = NULL;
    CHECK(!ff_reload_state_attached());
    CHECK(example_kni_prepare() == 0);
    CHECK(p1_cold_setup(&state) == 0);
    CHECK(!ff_reload_kni_owner_match());
    seed_full_ring_packets = exercise_sink == 2;
    full_ring_seed_count = 0;
    test(&state);
    seed_full_ring_packets = 0;
    if (expected_limit >= 0) {
        CHECK(ff_reload_kni_owner_match());
        CHECK(p1_tx_calls == 1 && p1_tx_limit == (unsigned)expected_limit);
    }
    if (exercise_sink == 1) exercise_real_short_tx_sink();
    if (exercise_sink == 2) exercise_real_full_ring_drain();
    if (exercise_sink == 3) exercise_real_owner_gate();
    CHECK(p1_cold_teardown(&state) == 0);
    CHECK(!ff_reload_state_attached());
}

static void verify_payload(struct rte_mbuf *packet, const unsigned char expected[32])
{
    CHECK(packet && rte_pktmbuf_pkt_len(packet) == 32);
    CHECK(memcmp(rte_pktmbuf_mtod(packet, const void *), expected, 32) == 0);
}
static void exercise_real_full_ring_drain(void)
{
    struct rte_mbuf *burst[1], *received;
    const unsigned capacity = rte_ring_get_capacity(p1_rx);
    CHECK(capacity == 15 && full_ring_seed_count == capacity);
    CHECK(rte_ring_count(p1_rx) == capacity && rte_ring_free_count(p1_rx) == 0);
    CHECK(kni_stat[0]->rx_dropped == 1 && kni_stat[0]->rx_packets == 0);
    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ - capacity);

    /* The rejected allocation leaves every admitted object in source FIFO order. */
    for (unsigned i = 0; i < capacity; ++i) {
        CHECK(rte_ring_dequeue(p1_rx, (void **)&received) == 0 && received == full_ring_seeded[i]);
        verify_payload(received, full_ring_payloads[i]);
        CHECK(rte_ring_enqueue(p1_rx, received) == 0);
    }
    CHECK(rte_ring_count(p1_rx) == capacity && rte_ring_free_count(p1_rx) == 0);

    /* The original KNI drain transmits through the real capacity-one net_ring PMD. */
    rte_eth_fp_ops[0] = p1_saved_ops;
    kni_stat[0]->port_id = sink_port;
    CHECK(rte_ring_count(p1_rx) == capacity);
    ff_kni_process(0, 0, burst, 1);
    CHECK(kni_stat[0]->rx_packets == 1 && kni_stat[0]->rx_dropped == 1);
    CHECK(rte_ring_dequeue(sink_tx, (void **)&received) == 0 &&
        received == full_ring_seeded[0]);
    verify_payload(received, full_ring_payloads[0]);
    rte_pktmbuf_free(received);
    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ - capacity + 1);
    CHECK(rte_ring_free_count(p1_rx) == 1);

    struct rte_mbuf *retry = rte_pktmbuf_alloc(test_pool);
    CHECK(retry && full_ring_seed_count == capacity);
    unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(retry, sizeof(full_ring_payloads[capacity]));
    CHECK(bytes);
    full_ring_seeded[capacity] = retry;
    for (unsigned j = 0; j < sizeof(full_ring_payloads[capacity]); ++j)
        full_ring_payloads[capacity][j] = bytes[j] = (unsigned char)(0xe1 + j);
    full_ring_seed_count++;
    CHECK(ff_kni_enqueue(FILTER_ARP, 0, retry) == 0);
    CHECK(rte_ring_count(p1_rx) == capacity && kni_stat[0]->rx_dropped == 1);

    for (unsigned i = 1; i <= capacity; ++i) {
        CHECK(rte_ring_count(p1_rx) == capacity - i + 1);
        ff_kni_process(0, 0, burst, 1);
        CHECK(kni_stat[0]->rx_packets == i + 1 && kni_stat[0]->rx_dropped == 1);
        CHECK(rte_ring_dequeue(sink_tx, (void **)&received) == 0 &&
            received == full_ring_seeded[i]);
        verify_payload(received, full_ring_payloads[i]);
        rte_pktmbuf_free(received);
    }
    CHECK(rte_ring_empty(p1_rx) && rte_ring_empty(sink_tx) &&
        rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ);
    CHECK(kni_stat[0]->rx_packets == capacity + 1 && kni_stat[0]->rx_dropped == 1 &&
        kni_stat[0]->tx_packets == 0 && kni_stat[0]->tx_dropped == 0);
}
static void exercise_real_short_tx_sink(void)
{
    struct rte_mbuf *burst[3], *received;
    unsigned char expected[3][32];
    uint64_t tx_before, dropped_before;
    CHECK(rte_ring_get_capacity(sink_tx) == 1);
    CHECK(p1_tx_calls == 1 && p1_tx_limit == 1 && kni_stat[0]->tx_packets == 1 &&
        kni_stat[0]->tx_dropped == 2);
    rte_eth_fp_ops[0] = p1_saved_ops;
    tx_before = kni_stat[0]->tx_packets;
    dropped_before = kni_stat[0]->tx_dropped;
    for (unsigned i = 0; i < 3; ++i) {
        burst[i] = rte_pktmbuf_alloc(test_pool);
        CHECK(burst[i]);
        unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(burst[i], sizeof(expected[i]));
        CHECK(bytes);
        for (unsigned j = 0; j < sizeof(expected[i]); ++j)
            expected[i][j] = bytes[j] = (unsigned char)(0x20 + 17 * i + j);
        CHECK(rte_ring_enqueue(p1_inject, burst[i]) == 0);
    }
    example_kni_poll_inject(0, 0, burst, 3);
    CHECK(kni_stat[0]->tx_packets == tx_before + 1 &&
        kni_stat[0]->tx_dropped == dropped_before + 2);
    CHECK(rte_ring_count(sink_tx) == 1 &&
        rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ - 1);
    CHECK(rte_ring_dequeue(sink_tx, (void **)&received) == 0 && received == burst[0]);
    verify_payload(received, expected[0]);
    rte_pktmbuf_free(received);
    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ);

    burst[0] = rte_pktmbuf_alloc(test_pool);
    CHECK(burst[0]);
    unsigned char *retry = (unsigned char *)rte_pktmbuf_append(burst[0], sizeof(expected[0]));
    CHECK(retry);
    for (unsigned j = 0; j < sizeof(expected[0]); ++j)
        expected[0][j] = retry[j] = (unsigned char)(0xc0 + j);
    CHECK(rte_ring_enqueue(p1_inject, burst[0]) == 0);
    example_kni_poll_inject(0, 0, burst, 1);
    CHECK(kni_stat[0]->tx_packets == tx_before + 2 &&
        kni_stat[0]->tx_dropped == dropped_before + 2 && rte_ring_count(sink_tx) == 1);
    CHECK(rte_ring_dequeue(sink_tx, (void **)&received) == 0 && received == burst[0]);
    verify_payload(received, expected[0]);
    rte_pktmbuf_free(received);
    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ &&
        rte_ring_empty(p1_inject) && rte_ring_empty(sink_tx));
}

int main(int argc, char **argv)
{
    const int short_tx = argc == 2 && !strcmp(argv[1], "short-tx");
    const int full_ring = argc == 2 && !strcmp(argv[1], "full-ring");
    const int owner = argc == 2 && !strcmp(argv[1], "owner");
    const int nonowner = argc == 2 && !strcmp(argv[1], "nonowner");
    CHECK(owner || nonowner || short_tx || full_ring);
    ker_test_eal_init();
    test_pool = rte_pktmbuf_pool_create("kni_owner_source_pool", KNI_TEST_POOL_SZ,
        0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(test_pool);
    sink_rx = rte_ring_create("kni_short_sink_rx", 2, SOCKET_ID_ANY,
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    sink_tx = rte_ring_create("kni_short_sink_tx", 2, SOCKET_ID_ANY,
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    CHECK(sink_rx && sink_tx);
    int created = rte_eth_from_rings("kni_owner_sink", &sink_rx, 1,
        &sink_tx, 1, SOCKET_ID_ANY);
    CHECK(created == 0);
    sink_port = (uint16_t)created;
    struct rte_eth_conf config = {0};
    CHECK(rte_eth_dev_configure(sink_port, 1, 1, &config) == 0);
    CHECK(rte_eth_rx_queue_setup(sink_port, 0, 2, SOCKET_ID_ANY, NULL, test_pool) == 0);
    CHECK(rte_eth_tx_queue_setup(sink_port, 0, 2, SOCKET_ID_ANY, NULL) == 0);
    CHECK(rte_eth_dev_start(sink_port) == 0);

    if (short_tx) {
        run_case(test_p1_future_kni_short_tx, 1, 1);
    } else if (full_ring) {
        run_case(test_p1_future_kni_full_ring, -1, 2);
    } else if (owner) {
        run_case(test_p1_future_kni_owner, 3, 3);
    } else {
        run_case(test_p1_kni_nonowner, -1, 0);
    }

    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ);
    CHECK(rte_eth_dev_stop(sink_port) == 0 && rte_eth_dev_close(sink_port) == 0);
    CHECK(rte_vdev_uninit("net_ring_kni_owner_sink") == 0);
    rte_ring_free(sink_rx); rte_ring_free(sink_tx);
    rte_mempool_free(test_pool);
    CHECK(rte_eal_cleanup() == 0);
    puts(short_tx ? "PASS: original KNI short-TX contract and real net_ring sink recovery" :
        full_ring ? "PASS: original KNI full-ring contract and real net_ring FIFO drain" :
        owner ? "PASS: original KNI owner with a real held and released packet" :
        "PASS: original KNI nonowner shared ring lookup");
    return 0;
}
