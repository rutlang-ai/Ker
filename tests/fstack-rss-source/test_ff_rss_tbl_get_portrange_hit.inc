static void
test_ff_rss_tbl_get_portrange_hit(void **state)
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr = 0x05060708;
    const uint16_t sport = htons(1000);

    assert_int_equal(test_rss_build_table(saddr, daddr, sport), 0);

    uint16_t first = 0, last = 0;
    uint16_t *pr = NULL;
    int rv = ff_rss_tbl_get_portrange(saddr, daddr, sport, &first, &last, &pr);

    assert_int_equal(rv, 0);                 /* hit => 0 (ff_dpdk_if.c:2827) */
    assert_non_null(pr);
    assert_true(first >= 1);                  /* idx 0 is the "last selected" slot */
    assert_true(last >= first);

    /* Every port in [first,last] must land on our queue. Cross-check the lib's
     * ff_rss_check against the independent replica, and assert self-consistency
     * (lib returns 1). Sample to bound runtime over a potentially large set. */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    int checked = 0;
    for (uint16_t k = first; k <= last && checked < 256; k++, checked++) {
        uint16_t dport = pr[k];
        uint16_t dport_n = htons(dport);
        int lib = ff_rss_check(sc, saddr, daddr, sport, dport_n);
        int exp = test_expected_rss_check(saddr, daddr, sport, dport_n,
                                          TEST_RSS_NBQ, TEST_RSS_RETA, TEST_RSS_QID);
        assert_int_equal(lib, exp);           /* hit correctness (07 §0.4) */
        assert_int_equal(lib, 1);             /* self-consistency: lands on queue */
        if (k == last) break;                 /* avoid uint16_t wrap when last==0xFFFF */
    }
    assert_true(checked > 0);                 /* non-empty port set */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
