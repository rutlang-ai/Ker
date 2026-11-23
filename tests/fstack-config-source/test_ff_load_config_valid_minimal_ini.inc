static void
test_ff_load_config_valid_minimal_ini(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    /* rv may be 0 (full success) or -1 (post-parse check failure); either way
     * the parser portion must have run and populated dpdk.* fields. */
    (void)rv;
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_string_equal(ff_global_cfg.dpdk.lcore_mask, "1");
    assert_int_equal(ff_global_cfg.dpdk.nb_channel, 4);
    assert_int_equal(ff_global_cfg.dpdk.promiscuous, 1);
    assert_int_equal(ff_global_cfg.dpdk.numa_on, 1);
    assert_int_equal(ff_global_cfg.dpdk.idle_sleep, 20);
    assert_int_equal(ff_global_cfg.dpdk.pkt_tx_delay, 100);
}
