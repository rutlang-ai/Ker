/* Exact RX-15 orphan-purge source contract in an isolated one-queue EAL.
 * The upstream source case and helpers are imported verbatim. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "check.h"
#include "eal.h"
#include "ff_config.h"
#include "ff_memory.h"
#include "ff_reload.h"

#include "../src/compat/reload.c"
#include "../third_party/fstack-reload/ff_drain_ring.c"

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

#define assert_int_equal(left, right) CHECK((left) == (right))
#define assert_true(value) CHECK(value)
#define assert_non_null(value) CHECK((value) != NULL)
#define skip() CHECK(0)

static int
equiv_eal_init_once(void)
{
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);
    return 1;
}

#include "fstack-drain-create-ring.inc"
#include "fstack-drain-orphans-source.inc"

void
ff_dpdk_process_packets(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **bufs, uint16_t count, struct ff_dpdk_if_context *ctx,
    int pkts_from_ring)
{
    (void)port_id;
    (void)queue_id;
    (void)bufs;
    (void)count;
    (void)ctx;
    (void)pkts_from_ring;
    fputs("unsupported: RX-15 fixture reached stack packet processing\n",
        stderr);
    abort();
}

int
main(void)
{
    struct rte_mempool *pool;

    ker_test_eal_init();
    test_rx15_primary_purges_orphaned_rings(NULL);
    pool = rte_mempool_lookup("ut_rx15_pool");
    CHECK(pool != NULL);
    CHECK(rte_mempool_avail_count(pool) == 64);
    rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    puts("PASS: exact RX-15 orphan-purge assertions against original drain rings");
    return 0;
}
