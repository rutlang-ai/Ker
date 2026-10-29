static void
test_ff_load_config_unknown_section(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_with_unknown.ini"));
    (void)rv;
    /* Even with [unknown_section] present, dpdk.lcore_mask must still parse */
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_string_equal(ff_global_cfg.dpdk.lcore_mask, "1");
    /* And [kni] section should populate kni.enable / kni.method */
    assert_int_equal(ff_global_cfg.kni.enable, 1);
    assert_non_null(ff_global_cfg.kni.method);
    assert_string_equal(ff_global_cfg.kni.method, "accept");
}
