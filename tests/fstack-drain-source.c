/* Original reload directory and drain-ring contracts over DPDK EAL. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <stdarg.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_log.h>
#include <rte_bus_vdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "check.h"
#include "eal.h"
#include "ff_config.h"
#include "ff_memory.h"
#include "ff_reload.h"

/* The source directory fixtures switch roles within one EAL process. Lookup,
 * allocation, queue operations, PID checks and clock reads still use the
 * original libraries. Only the missing-directory case suppresses lookup. */
static int p1_process_type = -1;
static pid_t p1_parent;
static int p1_missing_directory;
static jmp_buf fatal;
static int expecting_fatal;
static unsigned fatal_count;

enum rte_proc_type_t __real_rte_eal_process_type(void);
enum rte_proc_type_t __wrap_rte_eal_process_type(void)
{
    if (p1_process_type >= 0) return (enum rte_proc_type_t)p1_process_type;
    return __real_rte_eal_process_type();
}

const struct rte_memzone *__real_rte_memzone_lookup(const char *);
const struct rte_memzone *__wrap_rte_memzone_lookup(const char *name)
{
    if (p1_missing_directory && !strcmp(name, FF_RELOAD_GENDIR_NAME))
        return NULL;
    return __real_rte_memzone_lookup(name);
}

void __real_rte_exit(int status, const char *format, ...) __attribute__((noreturn));
void __wrap_rte_exit(int status, const char *format, ...)
{
    if (expecting_fatal) {
        CHECK(status == EXIT_FAILURE && strstr(format, "cross-master epoch isolation"));
        ++fatal_count;
        longjmp(fatal, 1);
    }
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    __real_rte_exit(status, "%s", message);
}

struct ff_config ff_global_cfg;
#include "../third_party/fstack-reload/ff_reload.c"
#include "../third_party/fstack-reload/ff_reload_gendir.c"
#include "../third_party/fstack-reload/ff_drain_ring.c"

int ff_log(uint32_t level, uint32_t type, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = rte_vlog(level, type, format, args);
    va_end(args);
    return result;
}

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

#define __real_getppid getppid
#define assert_int_equal(left, right) CHECK((uintmax_t)(left) == (uintmax_t)(right))
#define assert_int_not_equal(left, right) CHECK((uintmax_t)(left) != (uintmax_t)(right))
#define assert_memory_equal(left, right, size) CHECK(!memcmp((left), (right), (size)))
#define assert_true(value) CHECK(value)
#define assert_non_null(value) CHECK((value) != NULL)
#define assert_ptr_equal(left, right) CHECK((left) == (right))
#define skip() CHECK(0)
/* Keep setjmp in this fixture so the original loop variables stay ordinary C
 * locals, even when the compiler inlines the upstream test cases. */
static void expect_failure_ff_reload_gendir_attach(void)
{
    expecting_fatal = 1;
    if (!setjmp(fatal)) {
        ff_reload_gendir_attach();
        CHECK(0);
    }
    expecting_fatal = 0;
}

#define expect_assert_failure(call) expect_failure_ ## call

static int equiv_eal_init_once(void)
{
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);
    return 1;
}

#include "fstack-drain-create-ring.inc"
#include "fstack-drain-source.inc"

void ff_dpdk_process_packets(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **bufs, uint16_t count, struct ff_dpdk_if_context *ctx,
    int pkts_from_ring)
{
    (void)port_id; (void)queue_id; (void)bufs; (void)count;
    (void)ctx; (void)pkts_from_ring;
    fputs("unsupported: drain fixture reached FreeBSD stack packet processing\n", stderr);
    abort();
}

static uint16_t sink_port;
static struct rte_ring *sink_rx;
static struct rte_ring *sink_tx[2];

/* The original drain routine intentionally has no ownership test; its
 * main-loop caller gates it on the original no-hardware-owner predicate. */
static unsigned drain_tx_if_hardware_owner(uint16_t port, uint16_t queue,
    struct rte_mbuf **burst, unsigned count)
{
    if (ff_no_hw_mode()) return 0;
    return ff_drain_ring_tx_drain(port, queue, burst, count);
}

static void make_sink(void)
{
    sink_rx = rte_ring_create("drain_foreign_sink_rx", 8, SOCKET_ID_ANY,
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    sink_tx[0] = rte_ring_create("drain_foreign_sink_tx0", 8, SOCKET_ID_ANY,
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    sink_tx[1] = rte_ring_create("drain_foreign_sink_tx1", 8, SOCKET_ID_ANY,
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    CHECK(sink_rx && sink_tx[0] && sink_tx[1]);
    int port = rte_eth_from_rings("drain_sink", &sink_rx, 1,
        sink_tx, 2, SOCKET_ID_ANY);
    if (port < 0) fprintf(stderr, "rte_eth_from_rings failed: %s (%d)\n",
        rte_strerror(rte_errno), rte_errno);
    CHECK(port >= 0);
    sink_port = (uint16_t)port;
    struct rte_eth_conf config = {0};
    CHECK(!rte_eth_dev_configure(sink_port, 1, 2, &config));
    CHECK(!rte_eth_rx_queue_setup(sink_port, 0, 8, SOCKET_ID_ANY, NULL,
        p1_pool));
    CHECK(!rte_eth_tx_queue_setup(sink_port, 0, 8, SOCKET_ID_ANY, NULL));
    CHECK(!rte_eth_tx_queue_setup(sink_port, 1, 8, SOCKET_ID_ANY, NULL));
    CHECK(!rte_eth_dev_start(sink_port));
}

static void consume_retained_foreign_tx(void)
{
    static const unsigned char payload[] = {
        0x46, 0x45, 0x2d, 0x54, 0x58, 0x2d, 0x65, 0x31, 0x2d, 0x67, 0x30
    };
    struct rte_mbuf *packet = NULL, *received = NULL;
    struct rte_mbuf *burst[1];
    unsigned char *bytes;

    make_sink();
    CHECK(ff_no_hw_mode());
    CHECK(drain_tx_if_hardware_owner(sink_port, 1, burst, 1) == 0);
    CHECK(rte_ring_count(p1_rings[1][1][0]) == 1);
    CHECK(rte_ring_count(sink_tx[1]) == 0);
    CHECK(rte_ring_dequeue(p1_rings[1][1][0], (void **)&packet) == 0);
    bytes = (unsigned char *)rte_pktmbuf_append(packet, sizeof(payload));
    CHECK(bytes);
    memcpy(bytes, payload, sizeof(payload));
    CHECK(rte_ring_enqueue(p1_rings[1][1][0], packet) == 0);

    /* A second real directory identity owns the hardware. The original drain
     * implementation selects the foreign epoch's peer TX ring for that owner. */
    p1_dir->slot[1] = (struct ff_reload_epoch_slot){
        .epoch = 1, .gen = 0, .state = FF_RELOAD_SLOT_LIVE,
        .master_pid = (uint32_t)getpid(),
    };
    p1_dir->slot[2] = (struct ff_reload_epoch_slot){
        .epoch = 2, .gen = 0, .state = FF_RELOAD_SLOT_LIVE,
        .master_pid = (uint32_t)getpid(),
    };
    p1_dir->active_word = (uint64_t)2 << 32;
    p1_dir->rx_owner_word = (uint64_t)2 << 32;
    p1_dir->kni_owner_word = (uint64_t)2 << 32;
    p1_reload.rx_owner_gen = 0;

    ff_drain_ring_unregist();
    ff_reload_set_epoch(2);
    ff_reload_set_gen(0);
    CHECK(ff_drain_ring_init() == 0);
    CHECK(rte_ring_count(p1_rings[1][1][0]) == 1);
    CHECK(!ff_no_hw_mode());
    CHECK(drain_tx_if_hardware_owner(sink_port, 1, burst, 1) == 1);
    CHECK(rte_ring_dequeue(sink_tx[1], (void **)&received) == 0);
    CHECK(received == packet && received->pkt_len == sizeof(payload));
    CHECK(!memcmp(rte_pktmbuf_mtod(received, const void *), payload,
        sizeof(payload)));
    rte_pktmbuf_free(received);
    CHECK(rte_mempool_avail_count(p1_pool) == 58);

    CHECK(!rte_eth_dev_stop(sink_port));
    CHECK(!rte_eth_dev_close(sink_port));
    CHECK(!rte_vdev_uninit("net_ring_drain_sink"));
    rte_ring_free(sink_rx);
    rte_ring_free(sink_tx[0]);
    rte_ring_free(sink_tx[1]);
    sink_rx = NULL;
    sink_tx[0] = sink_tx[1] = NULL;
}

static void release_full_ring_fixture(void)
{
    void *packet;
    struct rte_ring *tx = rte_ring_lookup("drain_tx_p0_q0_g0");
    struct rte_mempool *pool = rte_mempool_lookup("ut_f_m4_1_pool");
    CHECK(tx && pool);
    while (!rte_ring_dequeue(tx, &packet))
        rte_pktmbuf_free(packet);
    CHECK(rte_mempool_avail_count(pool) == 512);
    rte_mempool_free(pool);
    for (unsigned gen = 0; gen < FF_RELOAD_GEN_MAX; ++gen) {
        char name[RTE_RING_NAMESIZE];
        snprintf(name, sizeof(name), "drain_tx_p0_q0_g%u", gen);
        rte_ring_free(rte_ring_lookup(name));
        snprintf(name, sizeof(name), "drain_rx_p0_q0_g%u", gen);
        rte_ring_free(rte_ring_lookup(name));
    }
}

int main(int argc, char **argv)
{
    const struct {
        const char *name;
        void (*run)(void **);
        unsigned fatal_attempts;
    } cases[] = {
        {"drain-owner", test_p1_drain_queue_ownership, 0},
        {"drain-nonowner", test_p1_drain_nonowner_tx, 0},
        {"drain-peer", test_p1_drain_peer_tx, 0},
        {"drain-foreign", test_p1_drain_foreign_epoch_tx, 0},
        {"drain-empty", test_p1_drain_empty_qconf, 0},
        {"directory-live", test_p1_directory_live_slot, 2},
        {"directory-full", test_p1_directory_full, 2},
        {"directory-missing", test_p1_directory_missing, 1},
        {"directory-invalid", test_p1_directory_invalid, 1},
        {"directory-success", test_p1_directory_success, 0},
        {"directory-primary-busy", test_p1_directory_primary_slot_busy, 1},
        {"slot-window", test_p2_slot_transient_window, 0},
        {"slot-exhausted", test_p2_slot_transient_exhausted, 1},
    };

    CHECK(argc == 2);
    ker_test_eal_init();
    if (!strcmp(argv[1], "drain-full-ring")) {
        test_f_m4_1_drain_ring_full_visible(NULL);
        release_full_ring_fixture();
    } else {
        size_t i = 0;
        while (i < sizeof(cases) / sizeof(cases[0]) && strcmp(argv[1], cases[i].name))
            ++i;
        CHECK(i < sizeof(cases) / sizeof(cases[0]));
        CHECK(!p1_setup(NULL));
        cases[i].run(NULL);
        CHECK(fatal_count == cases[i].fatal_attempts);
        if (cases[i].run == test_p1_drain_foreign_epoch_tx)
            consume_retained_foreign_tx();
        CHECK(!p1_teardown(NULL));
        for (unsigned tx = 0; tx < 2; ++tx)
            for (unsigned q = 0; q < 2; ++q)
                for (unsigned gen = 0; gen < 2; ++gen)
                    rte_ring_free(p1_rings[tx][q][gen]);
        const struct rte_memzone *zone = rte_memzone_lookup(FF_RELOAD_GENDIR_NAME);
        CHECK(zone && !rte_memzone_free(zone));
    }
    CHECK(!rte_eal_cleanup());
    printf("PASS: exact F-Stack source case %s\n", argv[1]);
    return 0;
}
