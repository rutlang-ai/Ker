static void
test_ff_load_config_inet6_fixture_ignored(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_inet6.ini"));
    assert_int_equal(rv, 0);
    /* INET4 portions still parse correctly. */
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].addr,    "192.168.1.10");
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].netmask, "255.255.255.0");
}
