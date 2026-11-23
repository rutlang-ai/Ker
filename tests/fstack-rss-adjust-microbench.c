/* Original source timing contract plus explicit BSS control and ready fixture. */
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
static int microbench_skip_observed;
static int ready_fixture;
#define skip() do { microbench_skip_observed = 1; return; } while (0)
/* Keep the original helper intact, then adapt only the ready fixture's switch. */
#define test_rss_build_table test_rss_build_table_original
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "fstack-rss-source-helpers.inc"
#pragma GCC diagnostic pop
#undef test_rss_build_table
static int
test_rss_build_table(uint32_t saddr, uint32_t daddr, uint16_t sport)
{
    int result = test_rss_build_table_original(saddr, daddr, sport);
    if (result == 0 && ready_fixture)
        g_rss_cfg.thash_adjust = 1; /* ready-fixture adaptation, absent in source setup */
    return result;
}
#include "fstack-rss-microbench-source.inc"

static uint32_t
independent_toeplitz(const uint8_t *key, size_t key_length,
    const uint8_t *tuple, size_t tuple_length)
{
    uint32_t hash = 0;
    for (size_t bit = 0; bit < tuple_length * 8; ++bit) {
        if (!(tuple[bit / 8] & (0x80u >> (bit % 8))))
            continue;
        uint32_t window = 0;
        for (size_t k = 0; k < 32; ++k) {
            size_t index = bit + k;
            CHECK(index < key_length * 8);
            window = (window << 1) |
                ((key[index / 8] >> (7 - index % 8)) & 1u);
        }
        hash ^= window;
    }
    return hash;
}

static void
validate_original_candidates(void)
{
    const uint32_t saddr = 0x01020304, daddr = 0x05060708;
    const uint16_t first = TEST_RSS_FIRST, last = TEST_RSS_LAST;
    size_t key_length = 0;
    const uint8_t *key = example_rss_advisory_key(&key_length);
    CHECK(key && key_length == sizeof(test_rsskey_40));
    const uint16_t reta_size = example_rss_advisory_reta_size();
    CHECK(reta_size == 128);
    for (int recheck = 0; recheck <= 1; ++recheck) {
        CHECK(example_rss_advisory_enable(1, recheck) == 0);
        for (unsigned i = 0; i < 64; ++i) {
            uint16_t remote_port = htons((uint16_t)(1024 + i));
            uint16_t candidate = 0;
            CHECK(example_rss_advisory_suggest4(saddr, daddr, remote_port,
                &candidate, first, last) == 0);
            CHECK(candidate >= first && candidate <= last);
            uint8_t tuple[12];
            memcpy(tuple, &saddr, 4);
            memcpy(tuple + 4, &daddr, 4);
            memcpy(tuple + 8, &remote_port, 2);
            uint16_t local_port = htons(candidate);
            memcpy(tuple + 10, &local_port, 2);
            uint32_t hash = independent_toeplitz(key, key_length, tuple, sizeof(tuple));
            CHECK(((hash & (reta_size - 1)) % TEST_RSS_NBQ) == TEST_RSS_QID);
            CHECK(example_rss_advisory_is_owner4(saddr, daddr, remote_port,
                htons(candidate)) == 1);
        }
    }
}

int
main(void)
{
    ker_test_eal_init();
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);

    /* Original builder leaves thash_adjust=0; this profile is skip control only. */
    example_rss_reset();
    ready_fixture = 0;
    microbench_skip_observed = 0;
    test_ff_rss_adjust_microbench(NULL);
    CHECK(microbench_skip_observed == 1);
    CHECK(g_rss_cfg.thash_adjust == 0);
    puts("CONTROL_EXPECTED_SKIP: original BSS profile is not a compatibility pass or timing result");

    /* Use the original caller library's real DPDK thash contexts and exact key/RETA. */
    example_rss_reset();
    CHECK(example_rss_advisory_configure(TEST_RSS_NBQ, TEST_RSS_QID, 128) == 0);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));
    CHECK(example_rss_advisory_reta_size() == 128);
    ready_fixture = 1;
    CHECK(test_rss_build_table(0x01020304, 0x05060708, htons(1000)) == 0);
    CHECK(g_rss_cfg.thash_adjust == 1);
    validate_original_candidates();

    /* This invokes the byte-audited source body, with the original strict timing assertion. */
    microbench_skip_observed = 0;
    test_ff_rss_adjust_microbench(NULL);
    CHECK(microbench_skip_observed == 0);
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
    example_rss_reset();
    CHECK(!example_rss_advisory_ready(0) && !example_rss_advisory_ready(1));
    CHECK(!rte_thash_find_existing("ff_rss_thash_0"));
    CHECK(!rte_thash_find_existing("ff_rss_thash6_0"));
    CHECK(rte_eal_cleanup() == 0);
    puts("PASS: ready original RSS microbenchmark; candidate oracles and DPDK contexts cleaned up");
    return 0;
}
