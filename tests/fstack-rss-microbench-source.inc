#include <time.h>

#ifndef FF_RSS_RECHECK_MICROBENCH_N
#define FF_RSS_RECHECK_MICROBENCH_N 10000
#endif

static uint64_t
rd_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void
test_ff_rss_adjust_microbench(void **state)          /* TC-U-RSS-04-05 */
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr_base = 0x05060708;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss_build_table(saddr, daddr_base, sport_seed), 0);
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;

    /* Pre-flight: confirm ctx readiness state. In unit env reta=0 -> unready
     * -> both off/on take the same early-return path; per spec 07 §1.4 note,
     * print "skipped: thash ctx not ready" and PASS (real data via spec 08). */
    uint16_t out_probe = 0;
    int probe = ff_rss_adjust_sport(sc, saddr, daddr_base, htons(1024), &out_probe,
                                   TEST_RSS_FIRST, TEST_RSS_LAST);
    if (probe < 0) {
        printf("\n[R-D 0.4 MICROBENCH] thash ctx not ready in unit env "
               "(rss_reta_size[]=0); skipping microbench. Real off-vs-on "
               "timing covered by spec 08 (example/rss_ct.c).\n");
        ff_global_cfg.dpdk.rss_check_cfgs = NULL;
        skip();
        return;
    }

    const int N = FF_RSS_RECHECK_MICROBENCH_N;
    uint64_t t_off, t_on;
    uint16_t out;

    g_rss_cfg.recheck = 0;
    t_off = rd_now_ns();
    for (int i = 0; i < N; i++) {
        out = 0;
        (void)ff_rss_adjust_sport(sc, saddr, daddr_base + (i & 0xFFFF),
                                  htons((uint16_t)(1024 + (i & 0x3FFF))),
                                  &out,
                                  TEST_RSS_FIRST, TEST_RSS_LAST);
    }
    t_off = rd_now_ns() - t_off;

    g_rss_cfg.recheck = 1;
    t_on = rd_now_ns();
    for (int i = 0; i < N; i++) {
        out = 0;
        (void)ff_rss_adjust_sport(sc, saddr, daddr_base + (i & 0xFFFF),
                                  htons((uint16_t)(1024 + (i & 0x3FFF))),
                                  &out,
                                  TEST_RSS_FIRST, TEST_RSS_LAST);
    }
    t_on = rd_now_ns() - t_on;

    printf("\n[R-D 0.4 MICROBENCH] N=%d v4 recheck off=%lu ns (%.1f ns/call), "
           "on=%lu ns (%.1f ns/call), on/off=%.2fx\n",
           N, (unsigned long)t_off, (double)t_off / N,
           (unsigned long)t_on, (double)t_on / N,
           t_off > 0 ? (double)t_on / (double)t_off : 0.0);
    assert_true(t_off < t_on);   /* recheck=0 strictly faster */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
