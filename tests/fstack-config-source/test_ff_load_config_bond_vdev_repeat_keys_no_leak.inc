static void
test_ff_load_config_bond_vdev_repeat_keys_no_leak(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_bond_vdev_repeat.ini"));
    assert_int_equal(rv, 0);
    /* Last value of each repeated key wins. */
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].iface, "net_pcap_b");
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].path,  "/tmp/b");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].slave,       "eth0,eth1");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].primary,     "eth1");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].xmit_policy, "l34");
}
