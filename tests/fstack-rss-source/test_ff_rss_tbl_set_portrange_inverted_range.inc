static void
test_ff_rss_tbl_set_portrange_inverted_range(void **state)
{
    (void)state;
    struct ff_rss_check_cfg dummy = { .enable = 1 };
    ff_global_cfg.dpdk.rss_check_cfgs = &dummy;
    int rv = ff_rss_tbl_set_portrange(/*first*/2048, /*last*/1024);
    assert_int_equal(rv, -1);
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
