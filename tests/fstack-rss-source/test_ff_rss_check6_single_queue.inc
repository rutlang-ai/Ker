static void
test_ff_rss_check6_single_queue(void **state)
{
    (void)state;
    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = 1;     /* single queue */
    assert_int_equal(ff_rss_check6(sc, test_saddr6, test_daddr6,
                                   htons(1000), htons(80)), 1);
}
