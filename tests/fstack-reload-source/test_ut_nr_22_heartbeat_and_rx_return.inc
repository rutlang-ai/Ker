static void
test_ut_nr_22_heartbeat_and_rx_return(void **state)
{
    (void)state;
    struct ff_reload_state st;
    uint64_t last = 900;
    uint32_t epoch = 0, target = 0;

    /* ---- pure evaluation ---- */
    /* counter advanced -> alive, baseline refreshed */
    assert_int_equal(ff_reload_heartbeat_eval(5, 6, 1000, &last, 100), 1);
    assert_int_equal(last, 1000);
    /* not advanced, within window -> alive */
    assert_int_equal(ff_reload_heartbeat_eval(5, 5, 1099, &last, 100), 1);
    /* boundary: exactly timeout -> stalled */
    assert_int_equal(ff_reload_heartbeat_eval(5, 5, 1100, &last, 100), 0);
    /* timeout disabled -> never stalls */
    assert_int_equal(ff_reload_heartbeat_eval(5, 5, 99999, &last, 0), 1);
    /* clock went backwards -> treated as alive */
    assert_int_equal(ff_reload_heartbeat_eval(5, 5, 500, &last, 100), 1);
    /* invalid args */
    assert_int_equal(ff_reload_heartbeat_eval(5, 5, 1000, NULL, 100), -1);

    /* ---- shared block validation ---- */
    assert_int_equal(ff_reload_state_valid(NULL, sizeof(st)), 0);
    assert_int_equal(ff_reload_state_valid(&st, 8), 0);
    memset(&st, 0, sizeof(st));
    assert_int_equal(ff_reload_state_valid(&st, sizeof(st)), 0);
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    assert_int_equal(ff_reload_state_valid(&st, sizeof(st)), 1);
    st.len = 4;
    assert_int_equal(ff_reload_state_valid(&st, sizeof(st)), 0);
    st.len = (uint32_t)sizeof(st);

    /* ---- attached-state flow ---- */
    ff_reload_attach_state(&st);
    assert_int_equal(ff_reload_state_attached(), 1);

    /* steady state: worker gen follows active (0) */
    ff_reload_set_gen(0);
    assert_int_equal(ff_reload_worker_gen(), 0);

    /* open the window: epoch 1, target gen 1 */
    ff_reload_master_begin(&epoch, &target);
    assert_int_equal(epoch, 1);
    assert_int_equal(target, 1);
    assert_int_equal(ff_reload_hw_locked(), 1);         /* ENV-1 armed */
    assert_int_equal(ff_reload_worker_gen(), 1);

    /* rx-owner generation (gen == target) ticks each loop pass */
    ff_reload_set_gen(1);
    ff_reload_heartbeat_set_timeout(1000);
    ff_reload_heartbeat_tick();
    ff_reload_heartbeat_tick();
    assert_int_equal(ff_reload_heartbeat_counter(), 2);

    /* non-owner (G_old, gen 0) samples: no stall while ticks flow */
    ff_reload_set_gen(0);
    assert_int_equal(ff_reload_heartbeat_sample(2000), 0);  /* baseline */
    assert_int_equal(ff_reload_heartbeat_sample(2050), 0);  /* alive */
    ff_reload_set_gen(1);
    ff_reload_heartbeat_tick();
    ff_reload_set_gen(0);
    assert_int_equal(ff_reload_heartbeat_sample(2100), 0);  /* advanced */

    /* owner dies: no further ticks -> stall detected once, then rebased */
    assert_int_equal(ff_reload_heartbeat_sample(3100), 1);  /* 1000 stall */
    assert_int_equal(st.heartbeat_stalls, 1);
    assert_int_equal(ff_reload_heartbeat_sample(3150), 0);  /* rebased */

    /* READY bookkeeping: epoch+pid correlation */
    ff_reload_publish_ready(3, 4242);
    assert_int_equal(ff_reload_ready_matches(3, 4242, epoch), 1);
    assert_int_equal(ff_reload_ready_matches(3, 9999, epoch), 0);
    assert_int_equal(ff_reload_ready_matches(3, 4242, epoch + 1), 0);
    assert_int_equal(ff_reload_ready_matches(200, 4242, epoch), 0);

    /* window closed with flip: active = target, KNI owner follows */
    ff_reload_master_complete();
    assert_int_equal(ff_reload_hw_locked(), 0);
    assert_int_equal(ff_reload_active_gen(), 1);
    assert_int_equal(ff_reload_kni_owner_gen(), 1);
    assert_int_equal(ff_reload_worker_gen(), 1);        /* active now */

    /* heartbeat stops once the window is closed (flow_map died) */
    ff_reload_set_gen(1);
    ff_reload_heartbeat_tick();
    assert_int_equal(ff_reload_heartbeat_counter(), 3); /* unchanged */

    /* abort path: window closes without flipping */
    ff_reload_master_begin(&epoch, &target);
    ff_reload_master_abort();
    assert_int_equal(ff_reload_hw_locked(), 0);
    assert_int_equal(ff_reload_active_gen(), 1);        /* no flip */

    /* detach restores the not-attached baseline */
    ff_reload_attach_state(NULL);
    assert_int_equal(ff_reload_state_attached(), 0);
    assert_int_equal(ff_reload_active_gen(), 0);
    assert_int_equal(ff_reload_hw_locked(), 0);
}
