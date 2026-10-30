static void
test_ff_load_config_thread_mode_default_off(void **state)
{
    (void)state;
    /* valid_dpdk_full.ini has lcore_mask=0xF and NO thread_mode key. */
    int rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_full.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.dpdk.thread_mode, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_threads, 0);
    /* Multi-process semantics unchanged: nb_procs == lcore_mask bit count. */
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 4);
}
