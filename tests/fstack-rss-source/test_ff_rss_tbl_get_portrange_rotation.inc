static void
test_ff_rss_tbl_get_portrange_rotation(void **state)
{
    (void)state;
    const uint32_t saddr = 0x0A0B0C0D, daddr = 0x11121314;
    const uint16_t sport = htons(2000);

    assert_int_equal(test_rss_build_table(saddr, daddr, sport), 0);

    uint16_t f1 = 0, l1 = 0, f2 = 0, l2 = 0;
    uint16_t *pr1 = NULL, *pr2 = NULL;
    assert_int_equal(ff_rss_tbl_get_portrange(saddr, daddr, sport, &f1, &l1, &pr1), 0);
    assert_int_equal(ff_rss_tbl_get_portrange(saddr, daddr, sport, &f2, &l2, &pr2), 0);

    /* Stable: consecutive lookups return the same idx range + buffer. */
    assert_int_equal(f1, f2);
    assert_int_equal(l1, l2);
    assert_ptr_equal(pr1, pr2);

    /* Caller-side rotation: walking the index window yields distinct ports,
     * each of which (per build口径) lands on the owning queue. */
    assert_true(l1 > f1);                     /* >1 candidate so rotation matters */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    uint16_t p_first = pr1[f1];
    uint16_t p_next  = pr1[f1 + 1];
    assert_int_not_equal(p_first, p_next);    /* rotation visits a different port */
    assert_int_equal(ff_rss_check(sc, saddr, daddr, sport, htons(p_first)), 1);
    assert_int_equal(ff_rss_check(sc, saddr, daddr, sport, htons(p_next)), 1);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
