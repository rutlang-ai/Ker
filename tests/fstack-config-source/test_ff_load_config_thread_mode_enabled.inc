static void
test_ff_load_config_thread_mode_enabled(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_thread_mode.ini"));
    assert_int_equal(rv, 0);
    /* thread_mode flag parsed from [dpdk] thread_mode=1. */
    assert_int_equal(ff_global_cfg.dpdk.thread_mode, 1);
    /* nb_threads = original bit-count of lcore_mask (0xf -> 4). */
    assert_int_equal(ff_global_cfg.dpdk.nb_threads, 4);
    /* Collapsed to a single process. */
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 1);
    /* proc_type forced to primary. */
    assert_non_null(ff_global_cfg.dpdk.proc_type);
    assert_string_equal(ff_global_cfg.dpdk.proc_type, "primary");
    /* proc_mask overwritten with the full lcore_mask ("0xf"). */
    assert_non_null(ff_global_cfg.dpdk.proc_mask);
    assert_string_equal(ff_global_cfg.dpdk.proc_mask, "0xf");
}
