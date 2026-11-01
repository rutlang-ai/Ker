#define _GNU_SOURCE
#include <ker/reload.h>
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
static uint32_t fixture_epoch;
static int fixture_generation;
static struct rte_ring *sink_rx, *sink_tx;
static uint16_t sink_port;

static void init_eal(void)
{
    cpu_set_t allowed;
    CHECK(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
    int cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); ++cpu) {}
    CHECK(cpu < CPU_SETSIZE);
    char mapping[64], prefix[64];
    snprintf(mapping, sizeof(mapping), "--lcores=0@%d", cpu);
    snprintf(prefix, sizeof(prefix), "--file-prefix=ker-kni-owner-%ld", (long)getpid());
    char *args[] = {"ker-kni-owner-test", mapping, prefix, "--no-huge", "--no-pci",
        "--no-shconf", "--iova-mode=va", "--no-telemetry", "-m", "64"};
    CHECK(rte_eal_init((int)(sizeof(args) / sizeof(args[0])), args) >= 0);
}

#define assert_true(x) CHECK((x) != 0)
#define assert_null(x) CHECK((x) == NULL)
#define assert_non_null(x) CHECK((x) != NULL)
#define assert_int_equal(a,b) CHECK((a) == (b))
#define assert_ptr_equal(a,b) CHECK((a) == (b))
#define mock_assert(expression, message, file, line) \
    do { (void)(message); (void)(file); (void)(line); CHECK(expression); } while (0)

extern void *__real_rte_zmalloc(const char *, size_t, unsigned);

int ff_reload_state_attached(void)
{
    return example_kni_reload_state_attached();
}
int ff_reload_kni_owner_match(void)
{
    return example_kni_reload_owner_matches();
}
void ff_reload_set_epoch(uint32_t epoch)
{
    fixture_epoch = epoch;
}
void ff_reload_set_gen(int generation)
{
    fixture_generation = generation;
    if (example_kni_reload_state_attached())
        CHECK(ker_reload_worker_select(generation, 0) == 0);
}
void ff_reload_attach_state(void *state)
{
    if (!state) {
        example_kni_unbind_reload();
        return;
    }
    CHECK(example_kni_bind_reload(state, sizeof(struct ff_reload_state),
        fixture_epoch, fixture_generation) == 0);
}
void ff_reload_dir_sync_enable(int enable)
{
    /* The retained source fixture explicitly uses the supported no-directory scope. */
    CHECK(enable == 0);
}
int ff_reload_gendir_install(void *directory, size_t size)
{
    CHECK(directory == NULL && size == 0);
    return 0;
}
void ff_reload_master_complete(void)
{
    CHECK(example_kni_reload_owner_matches() == 0);
    CHECK(example_kni_activate_reload_owner() == 0);
    CHECK(example_kni_reload_owner_matches() == 1);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" /* exact source cases land in the next stacked tranche */
#include "fstack-kni-owner-source.inc"
#pragma GCC diagnostic pop

static void exercise_real_short_tx_sink(void);
static void run_case(void (*test)(void **), int expected_limit, int exercise_sink)
{
    void *state = NULL;
    CHECK(ker_reload_kni_owner_matches() == -ENOTCONN);
    CHECK(example_kni_prepare() == 0);
    CHECK(p1_cold_setup(&state) == 0);
    CHECK(ker_reload_kni_owner_matches() == 0);
    test(&state);
    if (expected_limit >= 0) {
        CHECK(example_kni_reload_owner_matches() == 1);
        CHECK(p1_tx_calls == 1 && p1_tx_limit == (unsigned)expected_limit);
    }
    if (exercise_sink) exercise_real_short_tx_sink();
    CHECK(p1_cold_teardown(&state) == 0);
    CHECK(ker_reload_kni_owner_matches() == -ENOTCONN);
}

static void verify_payload(struct rte_mbuf *packet, const unsigned char expected[32])
{
    CHECK(packet && rte_pktmbuf_pkt_len(packet) == 32);
    CHECK(memcmp(rte_pktmbuf_mtod(packet, const void *), expected, 32) == 0);
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
    CHECK(argc == 1 || short_tx);
    init_eal();
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
    } else {
        run_case(test_p1_future_kni_owner, 3, 0);
        run_case(test_p1_kni_nonowner, -1, 0);
    }

    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ);
    CHECK(rte_eth_dev_stop(sink_port) == 0 && rte_eth_dev_close(sink_port) == 0);
    CHECK(rte_vdev_uninit("net_ring_kni_owner_sink") == 0);
    rte_ring_free(sink_rx); rte_ring_free(sink_tx);
    rte_mempool_free(test_pool);
    CHECK(rte_eal_cleanup() == 0);
    puts(short_tx ? "PASS: original KNI short-TX contract and real net_ring sink recovery" :
        "PASS: original KNI future owner activation and nonowner contracts");
    return 0;
}
