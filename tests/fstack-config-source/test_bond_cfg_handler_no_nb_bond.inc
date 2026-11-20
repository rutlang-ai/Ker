static void
test_bond_cfg_handler_no_nb_bond(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_bond_no_nb_bond.ini"));
    (void)rv;
    /* bond_cfg_handler returned 0 -> ini_parse stops with error; in either
     * case bond_cfgs was never allocated (the early-return "must config
     * dpdk.nb_bond first" branch). */
    assert_null(ff_global_cfg.dpdk.bond_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 0);
}
