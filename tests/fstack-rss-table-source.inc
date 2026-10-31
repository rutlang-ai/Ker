static void
test_ff_rss_tbl_set_portrange_no_cfg(void **state)
{
    (void)state;
    /* Ensure clean state. */
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
    int rv = ff_rss_tbl_set_portrange(1024, 2048);
    assert_int_equal(rv, -1);
}
