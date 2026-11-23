static void
test_ut_nr_25_drain_ring_size_config(void **state)
{
    (void)state;

    /* explicit value */
    assert_int_equal(load_with_proc(
        FIXTURE_PATH("valid_drain_ring_size.ini"), "secondary", "0"), 0);
    assert_int_equal(ff_global_cfg.dpdk.drain_ring_size, 4096);

    /* negative value remapped to the default (never reaches unsigned) */
    assert_int_equal(load_with_proc(
        FIXTURE_PATH("valid_drain_ring_size_neg.ini"), "secondary", "0"), 0);
    assert_int_equal(ff_global_cfg.dpdk.drain_ring_size,
                     FF_DRAIN_RING_SIZE_DEFAULT);

    /* non-power-of-two rejected */
    assert_int_equal(load_with_proc(
        FIXTURE_PATH("invalid_drain_ring_size_pow2.ini"), "secondary", "0"),
        -1);

    /* the default itself is a power of two and sane */
    assert_int_equal(FF_DRAIN_RING_SIZE_DEFAULT, 2048u);
    assert_int_equal(FF_DRAIN_RING_SIZE_DEFAULT &
                     (FF_DRAIN_RING_SIZE_DEFAULT - 1), 0u);
}
