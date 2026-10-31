static void
test_greload_bad_value_atoi(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_greload_bad_value.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.graceful_reload, 0);
}
