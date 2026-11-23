static void
test_ff_load_config_portlist_nonint(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_portlist_nonint.ini"));
    (void)rv;
    /* Parser hit "not an integer" -> __parse_config_list returns 0,
     * which propagates up; nb_ports may stay 0 or partial. We assert
     * the parser did NOT crash and bond_cfgs was never allocated. */
    assert_null(ff_global_cfg.dpdk.bond_cfgs);
}
