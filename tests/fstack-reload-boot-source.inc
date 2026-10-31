static void
test_it_a09_boot_state(void **state)
{
    static int sc = 1, ifp = 2;

    (void)state;
    SKIP_IF_NO_INIT();

    assert_int_equal(ff_reload_state_attached(), 1);
    assert_int_equal(ff_reload_rx_owner_gen(), 0);
    assert_int_equal(ff_no_hw_mode(), 0);          /* owner == our gen */
    assert_int_equal(ff_drain_ring_ready(), 1);
    assert_non_null(rte_ring_lookup("drain_tx_p0_q0_g0"));
    assert_non_null(rte_ring_lookup("drain_tx_p0_q0_g1"));
    assert_non_null(rte_ring_lookup("drain_rx_p0_q0_g0"));
    assert_non_null(rte_ring_lookup("drain_rx_p0_q0_g1"));
    assert_int_equal((int)nb_dev_ports, 1);

    g_ctx = ff_dpdk_register_if(&sc, &ifp,
        &ff_global_cfg.dpdk.port_cfgs[IT_PORT_ID]);
    assert_non_null(g_ctx);
    assert_int_equal(ff_dpdk_if_up(), 0);          /* veth ctx for main_loop */

    /* the tx counter must be live on every data port, else the RV11
     * assertions below would silently degrade to tautologies */
    assert_int_equal(g_nb_tx_hooks, (int)ff_global_cfg.dpdk.nb_ports);

    /* nothing transmitted during init: clean RV11 baseline */
    assert_int_equal(hw_tx_calls(), 0);
    assert_int_equal(hw_tx_pkts(), 0);
}
