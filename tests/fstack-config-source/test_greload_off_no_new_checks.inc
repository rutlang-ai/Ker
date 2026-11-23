static void
test_greload_off_no_new_checks(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_full.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.graceful_reload, 0);
    assert_int_equal(ff_global_cfg.dpdk.primary_slim, 0);
}
