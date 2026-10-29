static void
test_port_cfg_handler_id_over_max_returns_one(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_port_id_over_max.ini"));
    /* Load succeeds; [port200] section is silently ignored. */
    assert_int_equal(rv, 0);
    /* Only port0 should have a name */
    assert_non_null(ff_global_cfg.dpdk.port_cfgs);
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].name, "port0");
}
