static void
test_ff_unload_config_zeroes_state(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    (void)rv;
    /* After load: at minimum proc_lcore + filename are non-NULL. */
    assert_non_null(ff_global_cfg.dpdk.proc_lcore);
    assert_non_null(ff_global_cfg.filename);

    ff_unload_config();

    /* All ownership pointers must be NULL'd (defense-in-depth: a future
     * caller that re-uses ff_global_cfg without re-loading must not see
     * dangling pointers). */
    assert_null(ff_global_cfg.dpdk.proc_lcore);
    assert_null(ff_global_cfg.dpdk.port_cfgs);
    assert_null(ff_global_cfg.dpdk.vlan_cfgs);
    assert_null(ff_global_cfg.dpdk.bond_cfgs);
    assert_null(ff_global_cfg.dpdk.vdev_cfgs);
    assert_null(ff_global_cfg.dpdk.rss_check_cfgs);
    assert_null(ff_global_cfg.dpdk.portid_list);
    assert_null(ff_global_cfg.filename);
    assert_null(ff_global_cfg.dpdk.lcore_mask);
    assert_null(ff_global_cfg.freebsd.boot);
    assert_null(ff_global_cfg.freebsd.sysctl);
    /* Idempotent: a second call on already-unloaded state is a no-op. */
    ff_unload_config();
    assert_null(ff_global_cfg.filename);
}
