static void
test_ff_load_config_dpdk_extra_keys(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_extra_keys.ini"));
    assert_int_equal(rv, 0);
    assert_string_equal(ff_global_cfg.dpdk.base_virtaddr, "0x200000000");
    assert_string_equal(ff_global_cfg.dpdk.file_prefix,   "mytest");
    assert_int_equal(ff_global_cfg.dpdk.nb_vdev, 1);
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].nb_cq, 1);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].down_delay, 300);
}
