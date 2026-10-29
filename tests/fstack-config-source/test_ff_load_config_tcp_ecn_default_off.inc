static void
test_ff_load_config_tcp_ecn_default_off(void **state)
{
    (void)state;
    /* valid_minimal.ini has [freebsd.boot] but NO tcp_ecn key. */
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.freebsd.tcp_ecn, 0);
}
