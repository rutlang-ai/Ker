static void
test_ff_rss_tbl6_set_get(void **state)
{
    (void)state;
    assert_int_equal(test_rss6_build_table(test_saddr6, test_daddr6,
                                           htons(1000)), 0);

    /* Hit: same v6 3-tuple used to build the table. */
    uint16_t first = 0, last = 0;
    uint16_t *pr = NULL;
    int rv = ff_rss_tbl6_get_portrange(test_saddr6, test_daddr6, htons(1000),
                                       &first, &last, &pr);
    assert_int_equal(rv, 0);                  /* hit => 0 (ff_dpdk_if.c:3349) */
    assert_non_null(pr);
    assert_true(first >= 1);
    assert_true(last >= first);

    /* Each port in [first,last] must self-consistently re-check to 1 (lands). */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    int checked = 0;
    for (uint16_t k = first; k <= last && checked < 128; k++, checked++) {
        assert_int_equal(ff_rss_check6(sc, test_saddr6, test_daddr6,
                                       htons(1000), htons(pr[k])), 1);
        if (k == last) break;
    }
    assert_true(checked > 0);

    /* Miss: a different saddr6 (flip last byte) => -ENOENT. */
    uint8_t other_saddr6[16];
    memcpy(other_saddr6, test_saddr6, 16);
    other_saddr6[15] = 0xEE;
    uint16_t f2 = 0, l2 = 0; uint16_t *pr2 = NULL;
    int rv2 = ff_rss_tbl6_get_portrange(other_saddr6, test_daddr6, htons(1000),
                                        &f2, &l2, &pr2);
    assert_int_equal(rv2, -ENOENT);
    assert_null(pr2);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
