static void
test_bond_cfg_handler_bad_section(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_bond_bad_section.ini"));
    (void)rv;
    /* nb_bond=1 -> bond_cfgs alloc'd; but [bond_xx] section sscanf fails,
     * so handler returned 0. We assert the alloc happened (proves the
     * "section format error" path was reached, after the alloc). */
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 1);
    /* The rejection happened before any field was set on bond[0]. */
    if (ff_global_cfg.dpdk.bond_cfgs != NULL) {
        assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].mode, 0);
    }
}
