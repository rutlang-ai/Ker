static void
test_graceful_reload_default_off(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_full.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.graceful_reload, 0);
}
