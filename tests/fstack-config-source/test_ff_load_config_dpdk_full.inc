static void
test_ff_load_config_dpdk_full(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_full.ini"));
    (void)rv;
    /* lcore_mask=0xF -> 4 lcores; proc_lcore allocated, nb_procs >= 1 */
    assert_non_null(ff_global_cfg.dpdk.proc_lcore);
    /* port_list=0-1 -> nb_ports = 2 */
    assert_int_equal(ff_global_cfg.dpdk.nb_ports, 2);
    /* bond enabled, nb_bond=1, bond_cfgs allocated */
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 1);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs);
    /* bond0 fields: mode=4, slave="eth0,eth1", primary="eth0" */
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].mode, 4);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].slave);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].slave, "eth0,eth1");
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].primary);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].primary, "eth0");
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].bond_mac);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].xmit_policy);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].lsc_poll_period_ms, 100);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].up_delay,           200);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].down_delay,         200);
    /* rss_check + rss_tbl: 2 entries (port 0 + port 1) */
    assert_non_null(ff_global_cfg.dpdk.rss_check_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->enable, 1);
    /* R-F: thash_adjust defaults to 1 when omitted. */
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->thash_adjust, 1);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->nb_rss_tbl, 2);
    /* port0 entry: port_id=0, sport=80 (htons applied internally) */
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->rss_tbl_cfgs[0].port_id, 0);
    /* port1 entry: port_id=1, sport=443 */
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->rss_tbl_cfgs[1].port_id, 1);
    /* port0 lcore_list parsed as 0,1 */
    assert_non_null(ff_global_cfg.dpdk.port_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[0].nb_lcores, 2);
    /* port0 nb_vip = 3 */
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[0].nb_vip, 3);
    /* port0 nb_vip6 = 2 (only when INET6 is enabled in lib build) */
#ifdef INET6
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[0].nb_vip6, 2);
#endif
    /* port1 lcore_list=2-3 -> nb_lcores=2 */
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[1].nb_lcores, 2);
}
