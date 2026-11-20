static void
test_ff_load_config_bond_full(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_bond.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 1);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].mode, 4);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].slave, "0,1");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].primary, "0");
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].socket_id, 0);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].bond_mac, "AA:BB:CC:DD:EE:FF");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].xmit_policy, "l34");
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].lsc_poll_period_ms, 100);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].up_delay, 100);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].down_delay, 200);
}
