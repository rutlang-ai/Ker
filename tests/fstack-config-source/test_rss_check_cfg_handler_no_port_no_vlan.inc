static void
test_rss_check_cfg_handler_no_port_no_vlan(void **state)
{
    (void)state;
    /* Note: [rss_check] section appears BEFORE [portN] in the fixture so
     * port_cfgs is still NULL when rss_check_cfg_handler is invoked. */
    int rv = load_with_fixture(FIXTURE_PATH("invalid_rss_check_no_port.ini"));
    (void)rv;
    assert_null(ff_global_cfg.dpdk.rss_check_cfgs);
}
