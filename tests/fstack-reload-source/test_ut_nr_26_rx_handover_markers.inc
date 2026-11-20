static void
test_ut_nr_26_rx_handover_markers(void **state)
{
    (void)state;
    struct ff_reload_state st;

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);

    /* not attached: everything degrades, ff_no_hw_mode() must stay 0 so a
     * legacy (graceful_reload=0) process is never parked */
    ff_reload_attach_state(NULL);
    ff_global_cfg.dpdk.graceful_reload = 1;
    assert_int_equal(ff_reload_rx_owner_gen(), -1);
    assert_int_equal(ff_reload_rx_stopped(), 0);
    assert_int_equal(ff_no_hw_mode(), 0);
    assert_int_equal(ff_queue_handover_mutex(0, 0, 0, 1, 10),
                     FF_RELOAD_HANDOVER_INVAL);

    ff_reload_attach_state(&st);
    ff_reload_set_gen(0);
    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);

    /* gen0 owns the hardware: it is allowed on the hardware, gen1 is not */
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_reload_set_gen(1);
    assert_int_equal(ff_no_hw_mode(), 1);
    ff_reload_set_gen(0);

    /* bad arguments */
    assert_int_equal(ff_queue_handover_mutex(0, 0, 0, 0, 10),
                     FF_RELOAD_HANDOVER_INVAL);
    assert_int_equal(ff_queue_handover_mutex(0, 0, 0, FF_RELOAD_GEN_MAX, 10),
                     FF_RELOAD_HANDOVER_INVAL);
    assert_int_equal(ff_reload_rx_release(FF_RELOAD_GEN_MAX),
                     FF_RELOAD_HANDOVER_INVAL);

    /* gen1 asks for the hardware while gen0 still holds it and never parks:
     * bounded wait, then timeout (no stealing, no hang) */
    assert_int_equal(ff_queue_handover_mutex(0, 0, 0, 1, 60),
                     FF_RELOAD_HANDOVER_TIMEOUT);
    assert_int_equal(ff_reload_rx_owner_gen(), 0);

    /* gen0 parks and hands over */
    ff_reload_set_gen(0);
    assert_int_equal(ff_reload_rx_release(1), FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_rx_stopped(), 1);
    assert_int_equal(ff_reload_rx_owner_gen(), 1);
    /* parked owner is off the hardware too */
    assert_int_equal(ff_no_hw_mode(), 1);

    /* gen1 acquires; the parked flag clears so its main_loop resumes */
    ff_reload_set_gen(1);
    assert_int_equal(ff_queue_handover_mutex(0, 0, 0, 1, 100),
                     FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_rx_stopped(), 0);
    assert_int_equal(ff_no_hw_mode(), 0);
    /* gen0 is now the parked side */
    ff_reload_set_gen(0);
    assert_int_equal(ff_no_hw_mode(), 1);

    /* re-acquiring is idempotent (the drain confirmation can be delivered
     * more than once across a round) */
    ff_reload_set_gen(1);
    assert_int_equal(ff_queue_handover_mutex(0, 0, 0, 1, 10),
                     FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_rx_stopped(), 0);
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_reload_set_gen(0);

    /* H-12: hand rx back to gen0 — the markers are fully reversible */
    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_reload_set_gen(1);
    assert_int_equal(ff_no_hw_mode(), 1);

    /* graceful_reload=0 never parks anything, whatever the markers say */
    ff_global_cfg.dpdk.graceful_reload = 0;
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_reload_set_gen(0);
    assert_int_equal(ff_no_hw_mode(), 0);

    ff_reload_attach_state(NULL);
}
