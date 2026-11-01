/* Original foreign-epoch drain contract plus real EAL/PMD consumption.
 * The source helpers/assertions are imported verbatim; the only local
 * boundary is an explicit abort if the out-of-scope FreeBSD stack callback
 * is ever reached. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_bus_vdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "check.h"
#include "eal.h"
#include "ff_config.h"
#include "ff_memory.h"
#include "ff_reload.h"

/* p1_setup/teardown are unchanged source helpers. These values belonged to
 * source-only wrappers used by other cases; this fixture leaves EAL truthful. */
int p1_process_type = -1;
pid_t p1_parent;
int p1_missing_directory;

#include "../src/compat/reload.c"
#include "../third_party/fstack-reload/ff_drain_ring.c"

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

#define assert_int_equal(left, right) CHECK((left) == (right))
#define assert_true(value) CHECK(value)
#define assert_non_null(value) CHECK((value) != NULL)
#define assert_ptr_equal(left, right) CHECK((left) == (right))
#define skip() CHECK(0)

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

int main(void)
{
    ker_test_eal_init();
    p1_setup(NULL);
    test_p1_drain_foreign_epoch_tx(NULL);
    consume_retained_foreign_tx();
    p1_teardown(NULL);
    CHECK(!rte_eal_cleanup());
    puts("PASS: exact foreign-epoch drain assertions and original drain-ring PMD handoff");
    return 0;
}
