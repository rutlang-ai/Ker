static void
test_ut_nr_18_gen_pool_config(void **state)
{
    (void)state;
    char name[64];

    /* gen 0/1 pool names: mbuf_pool_<socket>_gen<gen> */
    assert_int_equal(ff_mbuf_gen_pool_name(name, sizeof(name), 0, 0), 0);
    assert_string_equal(name, "mbuf_pool_0_gen0");
    assert_int_equal(ff_mbuf_gen_pool_name(name, sizeof(name), 3, 1), 0);
    assert_string_equal(name, "mbuf_pool_3_gen1");

    /* out-of-range generation indices are rejected */
    assert_int_equal(ff_mbuf_gen_pool_name(name, sizeof(name), 0, -1), -1);
    assert_int_equal(ff_mbuf_gen_pool_name(name, sizeof(name), 0,
                                           FF_MBUF_GEN_MAX), -1);
    /* truncated buffer is rejected (full name needs 18 bytes incl NUL) */
    char small[8];
    assert_int_equal(ff_mbuf_gen_pool_name(small, sizeof(small), 0, 0), -1);

    /* ping-pong pair is exactly gen0/gen1 */
    assert_int_equal(FF_MBUF_GEN_MAX, 2);

    /* ff_app_mbuf_pool boundary: =0 falls back to the shared pool,
     * =1 returns the (here uncreated, thus NULL) generation pool. */
    static struct rte_mempool sentinel;
    pktmbuf_pool[0] = &sentinel;
    ff_global_cfg.dpdk.graceful_reload = 0;
    assert_ptr_equal(ff_app_mbuf_pool(0), &sentinel);
    ff_global_cfg.dpdk.graceful_reload = 1;
    assert_null(ff_app_mbuf_pool(0));
    /* set_gen switches the selection; invalid gen is ignored */
    ff_app_mbuf_set_gen(1);
    assert_null(ff_app_mbuf_pool(0));       /* gen1 slot, also uncreated */
    ff_app_mbuf_set_gen(FF_MBUF_GEN_MAX);   /* out of range: ignored */
    assert_null(ff_app_mbuf_pool(0));
    ff_app_mbuf_set_gen(0);                 /* restore for later tests */
    ff_global_cfg.dpdk.graceful_reload = 0;
    pktmbuf_pool[0] = NULL;
}

static void
test_ut_nr_21_shared_pool_cache_size(void **state)
{
    (void)state;
    /* P1: RX-bound pktmbuf_pool — legacy MEMPOOL_CACHE_SIZE */
    assert_int_equal(ff_shared_pool_cache_size(1, MEMPOOL_CACHE_SIZE), 0);
    assert_int_equal(ff_shared_pool_cache_size(0, MEMPOOL_CACHE_SIZE),
                     MEMPOOL_CACHE_SIZE);
    /* P2: message_pool — legacy MSG_RING_SIZE / 2 */
    assert_int_equal(ff_shared_pool_cache_size(1, MSG_RING_SIZE / 2), 0);
    assert_int_equal(ff_shared_pool_cache_size(0, MSG_RING_SIZE / 2),
                     MSG_RING_SIZE / 2);
    assert_int_equal(MSG_RING_SIZE / 2, 16);
    /* P3: ff_ref_pool (PA builds) — legacy MEMPOOL_CACHE_SIZE */
    assert_int_equal(ff_shared_pool_cache_size(1, MEMPOOL_CACHE_SIZE), 0);
    assert_int_equal(ff_shared_pool_cache_size(0, MEMPOOL_CACHE_SIZE),
                     MEMPOOL_CACHE_SIZE);
    /* M-B fallback ring capacity is reserved as a constant */
    assert_true(FREE_RING_SIZE > 0);
}
