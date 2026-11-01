/* Exact source contracts plus the real caller-only context lifecycle. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_thash.h>
#include <stdio.h>
#include <string.h>
#include "check.h"
#include "eal.h"
#include "../examples/rss-table-internal.h"
#include "../examples/rss-table-policy.h"
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_true(value) CHECK((value) != 0)
#define assert_non_null(value) CHECK((value) != NULL)
#define skip() CHECK(0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "fstack-rss-source-helpers.inc"
#include "fstack-rss-adjust-source.inc"
#pragma GCC diagnostic pop

int main(void)
{
    ker_test_eal_init();
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);

    /* Preserve the original unit setup: default key, RETA BSS=0, no contexts. */
    example_rss_reset();
    test_ff_rss_adjust_sport_thash_adjust_off(NULL);
    test_ff_rss_adjust_sport6_thash_adjust_off(NULL);
    test_ff_rss_thash_ctx_init_thash_adjust_off(NULL);
    test_ff_rss_adjust_sport_null(NULL);
    test_ff_rss_adjust_sport_degraded(NULL);
    test_ff_rss_adjust_sport_single_queue(NULL);
    test_ff_rss_adjust_sport6_guard(NULL);
    test_ff_rss_adjust_sport_range_params(NULL);
    test_ff_rss_adjust_sport6_range_params(NULL);
    CHECK(!example_rss_advisory_ready(0) && !example_rss_advisory_ready(1));

    /* Then run those exact bodies with genuine ready original DPDK contexts. */
    CHECK(example_rss_advisory_configure(2, 1, 128) == 0);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));
    test_ff_rss_adjust_sport_thash_adjust_off(NULL);
    test_ff_rss_adjust_sport6_thash_adjust_off(NULL);
    test_ff_rss_thash_ctx_init_thash_adjust_off(NULL);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));

    /* The exact range/single-queue source bodies above use BSS RETA=0 and
     * return at readiness. Recreate valid source configuration and contexts,
     * explicitly enable adjustment, then prove those later branches decline
     * without altering the caller's output. */
    CHECK(example_rss_advisory_configure(2, 1, 128) == 0);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));
    CHECK(test_rss_build_table(0x01020304, 0x05060708, htons(53)) == 0);
    g_rss_cfg.thash_adjust = 1;
    g_rss_cfg.recheck = 0;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;
    void *softc = test_rss_softc(TEST_RSS_PORT);
    uint16_t out = 0x5A5A;
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = 1;
    lcore_conf[0].tx_queue_id[TEST_RSS_PORT] = 0;
    CHECK(example_rss_adjust_sport(softc, 0x01020304, 0x05060708,
        htons(53), &out, 10000, 65535) == -1 && out == 0x5A5A);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    lcore_conf[0].tx_queue_id[TEST_RSS_PORT] = TEST_RSS_QID;
    const uint16_t firsts[] = {60000, 1024};
    const uint16_t lasts[] = {1024, 1025};
    for (unsigned i = 0; i < sizeof(firsts) / sizeof(firsts[0]); ++i) {
        out = 0x5A5A;
        CHECK(example_rss_adjust_sport(softc, 0x01020304, 0x05060708,
            htons(53), &out, firsts[i], lasts[i]) == -1 && out == 0x5A5A);
        out = 0x5A5A;
        CHECK(example_rss_adjust_sport6(softc, test_saddr6, test_daddr6,
            htons(53), &out, firsts[i], lasts[i]) == -1 && out == 0x5A5A);
    }
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
    example_rss_reset();
    CHECK(!example_rss_advisory_ready(0) && !example_rss_advisory_ready(1));
    CHECK(!rte_thash_find_existing("ff_rss_thash_0"));
    CHECK(!rte_thash_find_existing("ff_rss_thash6_0"));
    CHECK(example_rss_advisory_configure(2, 1, 128) == 0);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));
    example_rss_reset();
    CHECK(!example_rss_advisory_ready(0) && !example_rss_advisory_ready(1));
    CHECK(!rte_thash_find_existing("ff_rss_thash_0"));
    CHECK(!rte_thash_find_existing("ff_rss_thash6_0"));
    CHECK(rte_eal_cleanup() == 0);
    puts("PASS: unchanged RSS adjustment source assertions; BSS guards and ready single-queue/range declines; contexts reset");
    return 0;
}
