static void
test_ff_rss_tbl_set_portrange_disabled(void **state)
{
    (void)state;
    struct ff_rss_check_cfg dummy = { .enable = 0 };
    ff_global_cfg.dpdk.rss_check_cfgs = &dummy;
    int rv = ff_rss_tbl_set_portrange(1024, 2048);
    assert_int_equal(rv, -1);
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
