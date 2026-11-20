static void
test_rss_check_thash_adjust_off_parses(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_rss_check_thash_adjust_off.ini"));
    assert_int_equal(rv, 0);
    assert_non_null(ff_global_cfg.dpdk.rss_check_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->enable,        1);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->thash_adjust,  0);
}
