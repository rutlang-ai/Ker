static void
test_ff_rss_tbl_get_portrange_miss(void **state)
{
    (void)state;
    const uint32_t saddr = 0x21222324, daddr = 0x31323334;
    const uint16_t sport = htons(3000);

    assert_int_equal(test_rss_build_table(saddr, daddr, sport), 0);

    /* Query a 3-tuple NOT in the table (different saddr). */
    uint16_t first = 0, last = 0;
    uint16_t *pr = NULL;
    int rv = ff_rss_tbl_get_portrange(0x41424344 /*other saddr*/, daddr, sport,
                                      &first, &last, &pr);
    assert_int_equal(rv, -ENOENT);
    assert_null(pr);                          /* not filled on miss */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
