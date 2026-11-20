static void
test_vlan_cfg_handler_id_not_in_filter_returns_one(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_vlan_id_not_in_filter.ini"));
    /* Load itself succeeds (rv=0); the handler simply ignores the orphan
     * [vlan99] section so vlan_cfgs[0] (slot for vlan_filter[0]=10) stays
     * un-named. */
    assert_int_equal(rv, 0);
    assert_non_null(ff_global_cfg.dpdk.vlan_cfgs);
    /* slot 0 was allocated but no [vlanN] matched filter[0]=10, so name is NULL */
    assert_null(ff_global_cfg.dpdk.vlan_cfgs[0].name);
}
