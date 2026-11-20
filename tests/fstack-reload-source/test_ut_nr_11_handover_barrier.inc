static void
test_ut_nr_11_handover_barrier(void **state)
{
    (void)state;
    struct ff_reload_state st;
    uint32_t e1, e2;

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    ff_reload_attach_state(&st);
    ff_global_cfg.dpdk.graceful_reload = 1;

    /* no slot registered (primary / helper): ack is a no-op */
    ff_reload_set_slot(FF_RELOAD_MAX_PROCS);    /* out of range: ignored */
    ff_reload_handover_ack();
    ff_reload_handover_arm(&e1);
    assert_int_equal(e1, 1);
    assert_int_equal(ff_reload_handover_parked(0, e1), 0);

    /* armed, nobody acked yet: the wait must not proceed */
    assert_int_equal(ff_reload_handover_parked(1, e1), 0);

    /* slot 0 acks: parked for this epoch only */
    ff_reload_set_slot(0);
    ff_reload_handover_ack();
    assert_int_equal(ff_reload_handover_parked(0, e1), 1);
    assert_int_equal(ff_reload_handover_parked(1, e1), 0);      /* other slot */
    assert_int_equal(ff_reload_handover_parked(0, e1 + 1), 0);  /* other epoch */

    /* a fresh round: the wait predicate is the NEW epoch. The stale word
     * from e1 may keep matching an e1 query — harmless, epochs are
     * monotonic and the master never asks about a past epoch again. */
    ff_reload_handover_arm(&e2);
    assert_int_equal(e2, 2);
    assert_int_equal(ff_reload_handover_parked(0, e2), 0);
    ff_reload_handover_ack();
    assert_int_equal(ff_reload_handover_parked(0, e2), 1);

    /* out-of-range slot on the master side */
    assert_int_equal(ff_reload_handover_parked(FF_RELOAD_MAX_PROCS, e2), 0);

    /* the UT-NR-11 judgement, marker-level: replay the master sequence
     * and assert at every step that not both generations are unparked. */
    ff_reload_set_gen(0);
    ff_reload_set_slot(1);
    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 0);       /* G_old owns and polls */
    ff_reload_set_gen(1);
    assert_int_equal(ff_no_hw_mode(), 1);       /* G_new parked from birth */

    ff_reload_rx_stopped_set(1);               /* park order */
    ff_reload_set_gen(0);
    assert_int_equal(ff_no_hw_mode(), 1);       /* G_old parks by order */
    ff_reload_set_gen(1);
    assert_int_equal(ff_no_hw_mode(), 1);       /* G_new still parked */
    ff_reload_handover_ack();                  /* G_new worker acks too: inert */

    assert_int_equal(ff_reload_rx_release(1), FF_RELOAD_HANDOVER_OK);
    ff_reload_set_gen(0);
    assert_int_equal(ff_no_hw_mode(), 1);       /* G_old definitively off */
    ff_reload_set_gen(1);
    assert_int_equal(ff_no_hw_mode(), 1);       /* ...until stopped clears */

    assert_int_equal(ff_queue_handover_mutex(0, 0, 0, 1, 10),
                     FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_rx_stopped(), 0);
    assert_int_equal(ff_no_hw_mode(), 0);       /* G_new polls, alone */
    ff_reload_set_gen(0);
    assert_int_equal(ff_no_hw_mode(), 1);       /* G_old parked, alone */

    /* H-12 reversal (rx return): the markers flip back in one write pair */
    ff_reload_set_gen(0);
    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_reload_set_gen(1);
    assert_int_equal(ff_no_hw_mode(), 1);

    ff_reload_attach_state(NULL);
    ff_global_cfg.dpdk.graceful_reload = 0;
}
