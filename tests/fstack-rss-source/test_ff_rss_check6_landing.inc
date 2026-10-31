static void
test_ff_rss_check6_landing(void **state)
{
    (void)state;
    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    lcore_conf[0].tx_queue_id[TEST_RSS_PORT]   = TEST_RSS_QID;

    /* Probe several dports; for each, the lib verdict must equal the replica
     * (mask 0xFFFF here), and whenever it lands it must land on our queue. */
    int landed = 0;
    for (uint16_t j = 0; j < 64; j++) {
        uint16_t dport = htons((uint16_t)(2000 + j));
        int lib = ff_rss_check6(sc, test_saddr6, test_daddr6, htons(1000), dport);
        int exp = test_expected_rss_check6(test_saddr6, test_daddr6,
                                           htons(1000), dport,
                                           TEST_RSS_NBQ, TEST_RSS_RETA, TEST_RSS_QID);
        assert_int_equal(lib, exp);          /* v6 hit correctness */
        if (lib) {
            landed++;
            /* zero false positive: replica must independently agree it lands. */
            assert_int_equal(exp, 1);
        }
    }
    assert_true(landed > 0);                  /* some dport lands on our queue */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
