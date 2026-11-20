static void
test_ff_load_config_vdev_full(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_vdev.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_vdev, 1);
    assert_non_null(ff_global_cfg.dpdk.vdev_cfgs);
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].iface, "eth0");
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].path, "/var/run/usvhost");
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].nb_queues, 2);
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].queue_size, 512);
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].mac, "00:11:22:33:44:55");
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].nb_cq, 1);
}
