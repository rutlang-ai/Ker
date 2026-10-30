static void
test_rss_tbl_cfg_handler_bad_tuple(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_rss_tbl_bad_tuple.ini"));
    (void)rv;
    /* rss_check_cfgs allocated (port_cfgs was set up by [port0]); but the
     * 3-token rss_tbl entry caused per-entry error, so nb_rss_tbl stays 0
     * (or rss_tbl_cfgs[0] left at default zero values). */
    if (ff_global_cfg.dpdk.rss_check_cfgs != NULL) {
        /* Either the malformed entry was rejected outright (nb_rss_tbl=0),
         * or it was partially parsed (port_id=0, daddr/saddr empty). */
        assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->nb_rss_tbl, 0);
    }
}
