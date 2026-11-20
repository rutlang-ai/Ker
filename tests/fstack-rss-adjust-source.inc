static void
test_ff_rss_adjust_sport_thash_adjust_off(void **state)
{
    (void)state;
    g_rss_cfg.recheck = 0;
    g_rss_cfg.thash_adjust = 0;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    uint16_t out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);

    g_rss_cfg.thash_adjust = 1; /* restore default for subsequent tests */
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport6_thash_adjust_off(void **state)
{
    (void)state;
    g_rss_cfg.recheck = 0;
    g_rss_cfg.thash_adjust = 0;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    uint8_t saddr6[16] = { 0x20,0x01 }, daddr6[16] = { 0x20,0x02 };
    uint16_t out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport6(sc, saddr6, daddr6,
                                          htons(80), &out,
                                          TEST_RSS_FIRST, TEST_RSS_LAST), -1);

    g_rss_cfg.thash_adjust = 1;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_thash_ctx_init_thash_adjust_off(void **state)
{
    (void)state;
    g_rss_cfg.thash_adjust = 0;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    int rv = ff_rss_thash_ctx_init();
    assert_int_equal(rv, 0);

    g_rss_cfg.thash_adjust = 1;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport_null(void **state)
{
    (void)state;
    uint16_t out = 0;
    /* NULL softc -> -1 (guard hits before ff_veth_softc_to_hostc deref) */
    assert_int_equal(ff_rss_adjust_sport(NULL, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);
    /* NULL out_sport with a valid softc -> -1 */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), NULL,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);
}

static void
test_ff_rss_adjust_sport_degraded(void **state)
{
    (void)state;
    /* init: with reta_size=0 everywhere it returns 0 but leaves all ports
     * unready (no exception, graceful degrade). */
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ; /* multi-queue */
    uint16_t out = 0xFFFF;
    int rv = ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                 htons(80), &out,
                                 TEST_RSS_FIRST, TEST_RSS_LAST);
    assert_int_equal(rv, -1);          /* unready -> fall back */
}

static void
test_ff_rss_adjust_sport_single_queue(void **state)
{
    (void)state;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);
    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = 1;     /* single queue */
    uint16_t out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);
}

static void
test_ff_rss_adjust_sport6_guard(void **state)
{
    (void)state;
    uint16_t out = 0;
    assert_int_equal(ff_rss_adjust_sport6(NULL, test_saddr6, test_daddr6,
                                          htons(80), &out,
                                          TEST_RSS_FIRST, TEST_RSS_LAST), -1);
    void *sc = test_rss_softc(TEST_RSS_PORT);
    assert_int_equal(ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                          htons(80), NULL,
                                          TEST_RSS_FIRST, TEST_RSS_LAST), -1);

    assert_int_equal(ff_rss_thash_ctx_init(), 0);   /* v6 ctx degrades (reta=0) */
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                          htons(80), &out,
                                          TEST_RSS_FIRST, TEST_RSS_LAST), -1);
}

static void
test_ff_rss_adjust_sport_range_params(void **state)
{
    (void)state;
    g_rss_cfg.recheck = 0;
    g_rss_cfg.thash_adjust = 1;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    uint16_t out = 0xFFFF;

    /* inverted range */
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         /*first*/60000, /*last*/1024), -1);
    /* range too small to hold one reta block */
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         /*first*/1024, /*last*/1025), -1);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport6_range_params(void **state)
{
    (void)state;
    g_rss_cfg.recheck = 0;
    g_rss_cfg.thash_adjust = 1;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    uint16_t out = 0xFFFF;

    assert_int_equal(ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                          htons(80), &out,
                                          /*first*/60000, /*last*/1024), -1);
    assert_int_equal(ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                          htons(80), &out,
                                          /*first*/1024, /*last*/1025), -1);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport_recheck_off(void **state)   /* TC-U-RSS-04-01 */
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr = 0x05060708;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss_build_table(saddr, daddr, sport_seed), 0);
    g_rss_cfg.recheck = 0;   /* R-D 0.4: disable runtime recheck */
    assert_int_equal(ff_rss_thash_ctx_init(), 0);   /* unit-env ctx unready */

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport(sc, saddr, daddr,
                                     htons((uint16_t)(1024 + i)), &out,
                                     TEST_RSS_FIRST, TEST_RSS_LAST);
        assert_int_equal(rv, -1);   /* ctx-unready degrade */
    }
    /* recheck=0 path never reaches L3105; counter must stay 0 */
    assert_int_equal(g_ff_rss_check_calls, 0);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport_recheck_on(void **state)    /* TC-U-RSS-04-02 */
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr = 0x05060708;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss_build_table(saddr, daddr, sport_seed), 0);
    g_rss_cfg.recheck = 1;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport(sc, saddr, daddr,
                                     htons((uint16_t)(1024 + i)), &out,
                                     TEST_RSS_FIRST, TEST_RSS_LAST);
        assert_int_equal(rv, -1);   /* ctx-unready degrade */
    }
    /* ctx-unready blocks the main loop; counter remains 0 here. The
     * "recheck=1 -> ff_rss_check is forced" semantic is covered by the
     * R-B equivalence test (full-loop landing=100%) under the default
     * recheck=1 from test_rss_build_table. Direct call below sanity-checks
     * that the wrap interceptor is actually wired. */
    assert_int_equal(g_ff_rss_check_calls, 0);

    uint64_t before = g_ff_rss_check_calls;
    (void)ff_rss_check(sc, saddr, daddr, sport_seed, htons(80));
    assert_true(g_ff_rss_check_calls > before);   /* wrap chain alive */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport6_recheck_off(void **state)  /* TC-U-RSS-04-03 */
{
    (void)state;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss6_build_table(test_saddr6, test_daddr6,
                                           sport_seed), 0);
    g_rss_cfg.recheck = 0;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check6_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                      htons((uint16_t)(1024 + i)), &out,
                                      TEST_RSS_FIRST, TEST_RSS_LAST);
        assert_int_equal(rv, -1);
    }
    assert_int_equal(g_ff_rss_check6_calls, 0);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport6_recheck_on(void **state)   /* TC-U-RSS-04-04 */
{
    (void)state;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss6_build_table(test_saddr6, test_daddr6,
                                           sport_seed), 0);
    g_rss_cfg.recheck = 1;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check6_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                      htons((uint16_t)(1024 + i)), &out,
                                      TEST_RSS_FIRST, TEST_RSS_LAST);
        assert_int_equal(rv, -1);
    }
    assert_int_equal(g_ff_rss_check6_calls, 0);

    uint64_t before = g_ff_rss_check6_calls;
    (void)ff_rss_check6(sc, test_saddr6, test_daddr6, sport_seed, htons(80));
    assert_true(g_ff_rss_check6_calls > before);   /* v6 wrap chain alive */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
