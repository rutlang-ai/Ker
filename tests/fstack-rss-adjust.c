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
    CHECK(!example_rss_advisory_ready(0) && !example_rss_advisory_ready(1));

    /* Then run those exact bodies with genuine ready original DPDK contexts. */
    CHECK(example_rss_advisory_configure(2, 1, 128) == 0);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));
    test_ff_rss_adjust_sport_thash_adjust_off(NULL);
    test_ff_rss_adjust_sport6_thash_adjust_off(NULL);
    test_ff_rss_thash_ctx_init_thash_adjust_off(NULL);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));
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
    puts("PASS: unchanged RSS disabled source assertions in BSS and ready-context profiles; original contexts reset");
    return 0;
}
