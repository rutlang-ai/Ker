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
#define __real_ff_rss_check example_rss_check
#define __real_ff_rss_check6 example_rss_check6
#undef ff_rss_check
#undef ff_rss_check6
#define ff_rss_check __wrap_ff_rss_check
#define ff_rss_check6 __wrap_ff_rss_check6
#include "fstack-rss-recheck-wrappers.inc"
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_true(value) CHECK((value) != 0)
#define assert_non_null(value) CHECK((value) != NULL)
#define skip() CHECK(0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "fstack-rss-source-helpers.inc"
#include "fstack-rss-adjust-source.inc"
#pragma GCC diagnostic pop

static uint32_t ready_toeplitz(const uint8_t *key, size_t key_length,
    const uint8_t *tuple, size_t tuple_length)
{
    uint32_t hash = 0;
    for (size_t bit = 0; bit < tuple_length * 8; ++bit) {
        if (!(tuple[bit / 8] & (0x80u >> (bit % 8)))) continue;
        uint32_t window = 0;
        for (size_t k = 0; k < 32; ++k) {
            size_t index = bit + k;
            CHECK(index < key_length * 8);
            window = (window << 1) | ((key[index / 8] >> (7 - index % 8)) & 1u);
        }
        hash ^= window;
    }
    return hash;
}

static void verify_ready_tuple4(void *softc, uint32_t remote, uint32_t local,
    uint16_t remote_port, uint16_t local_port)
{
    uint8_t tuple[12];
    memcpy(tuple, &remote, 4); memcpy(tuple + 4, &local, 4);
    memcpy(tuple + 8, &remote_port, 2); memcpy(tuple + 10, &local_port, 2);
    size_t key_length;
    const uint8_t *key = example_rss_advisory_key(&key_length);
    CHECK(key && key_length == sizeof(test_rsskey_40));
    uint16_t queue = (uint16_t)((ready_toeplitz(key, key_length, tuple, sizeof(tuple)) & 127) % TEST_RSS_NBQ);
    CHECK(queue == TEST_RSS_QID);
    CHECK(example_rss_check(softc, remote, local, remote_port, local_port) == 1);
}

static void verify_ready_tuple6(void *softc, const uint8_t remote[16],
    const uint8_t local[16], uint16_t remote_port, uint16_t local_port)
{
    uint8_t tuple[36];
    memcpy(tuple, remote, 16); memcpy(tuple + 16, local, 16);
    memcpy(tuple + 32, &remote_port, 2); memcpy(tuple + 34, &local_port, 2);
    size_t key_length;
    const uint8_t *key = example_rss_advisory_key(&key_length);
    CHECK(key && key_length == sizeof(test_rsskey_40));
    uint16_t queue = (uint16_t)((ready_toeplitz(key, key_length, tuple, sizeof(tuple)) & 127) % TEST_RSS_NBQ);
    CHECK(queue == TEST_RSS_QID);
    CHECK(example_rss_check6(softc, remote, local, remote_port, local_port) == 1);
}

static void ready_recheck_controls(void)
{
    const uint32_t remote4 = 0x01020304, local4 = 0x05060708;
    const uint16_t first = 10000, last = 65535;
    CHECK(example_rss_advisory_configure(TEST_RSS_NBQ, TEST_RSS_QID, 128) == 0);
    CHECK(example_rss_advisory_ready(0) && example_rss_advisory_ready(1));
    CHECK(test_rss_build_table(remote4, local4, htons(80)) == 0);
    g_rss_cfg.thash_adjust = 1;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;
    void *softc = test_rss_softc(TEST_RSS_PORT);
    unsigned accepted4[2] = {0, 0}, accepted6[2] = {0, 0};
    uint64_t calls4[2] = {0, 0}, calls6[2] = {0, 0};
    const uint8_t *key = example_rss_advisory_key(NULL);
    CHECK(key && example_rss_advisory_ready(0) && example_rss_advisory_ready(1));

    for (unsigned mode = 0; mode < 2; ++mode) {
        g_rss_cfg.recheck = (int)mode;
        for (unsigned i = 0; i < 64; ++i) {
            uint16_t remote_port = htons((uint16_t)(1024 + i));
            uint16_t out = 0xA55A;
            uint64_t before = g_ff_rss_check_calls;
            int result = example_rss_adjust_sport(softc, remote4, local4,
                remote_port, &out, first, last);
            calls4[mode] += g_ff_rss_check_calls - before;
            CHECK(result == 0 || result == -1);
            if (result == 0) {
                CHECK(out >= first && out <= last);
                ++accepted4[mode];
                verify_ready_tuple4(softc, remote4, local4, remote_port, htons(out));
            } else CHECK(out == 0xA55A);
        }
        for (unsigned i = 0; i < 64; ++i) {
            uint16_t remote_port = htons((uint16_t)(1024 + i));
            uint16_t out = 0xA55A;
            uint64_t before = g_ff_rss_check6_calls;
            int result = example_rss_adjust_sport6(softc, test_saddr6,
                test_daddr6, remote_port, &out, first, last);
            calls6[mode] += g_ff_rss_check6_calls - before;
            CHECK(result == 0 || result == -1);
            if (result == 0) {
                CHECK(out >= first && out <= last);
                ++accepted6[mode];
                verify_ready_tuple6(softc, test_saddr6, test_daddr6,
                    remote_port, htons(out));
            } else CHECK(out == 0xA55A);
        }
    }
    CHECK(accepted4[0] > 0 && accepted4[1] > 0);
    CHECK(accepted6[0] > 0 && accepted6[1] > 0);
    CHECK(calls4[0] == 0 && calls6[0] == 0);
    CHECK(calls4[1] >= accepted4[1] && calls4[1] > 0);
    CHECK(calls6[1] >= accepted6[1] && calls6[1] > 0);
    printf("RSS ready recheck: v4 accepted off/on=%u/%u checks=%llu/%llu; v6 accepted off/on=%u/%u checks=%llu/%llu\n",
        accepted4[0], accepted4[1], (unsigned long long)calls4[0],
        (unsigned long long)calls4[1], accepted6[0], accepted6[1],
        (unsigned long long)calls6[0], (unsigned long long)calls6[1]);
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
    example_rss_reset();
    CHECK(!example_rss_advisory_ready(0) && !example_rss_advisory_ready(1));
}

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
    test_ff_rss_adjust_sport_recheck_off(NULL);
    test_ff_rss_adjust_sport_recheck_on(NULL);
    test_ff_rss_adjust_sport6_recheck_off(NULL);
    test_ff_rss_adjust_sport6_recheck_on(NULL);
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
    ready_recheck_controls();
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
