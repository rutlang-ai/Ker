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
