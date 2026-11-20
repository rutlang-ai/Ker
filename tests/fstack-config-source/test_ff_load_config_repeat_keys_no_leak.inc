static void
test_ff_load_config_repeat_keys_no_leak(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_repeat_keys.ini"));
    assert_int_equal(rv, 0);
    /* Last value of each repeated key wins. */
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].addr,    "192.168.1.30");
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].netmask, "255.255.0.0");
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].gateway, "192.168.1.254");
}
