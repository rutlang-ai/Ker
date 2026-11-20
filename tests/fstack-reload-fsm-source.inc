/* UT-NR-10: legal chain T0->T1->T2->T3->T4->T5->T0 passes; illegal
 * transitions (T5+HUP re-entry, T0->T4 jump, T3->T1) are rejected. */
static void
test_ut_nr_10_reload_fsm_transitions(void **state)
{
    (void)state;
    int st, expect[] = {
        NGX_FF_RELOAD_T1_GNEW_SPAWN,
        NGX_FF_RELOAD_T2_HANDOVER,
        NGX_FF_RELOAD_T3_DRAIN,
        NGX_FF_RELOAD_T4_DRAIN_DONE,
        NGX_FF_RELOAD_T5_GOLD_QUIT,
        NGX_FF_RELOAD_T0_IDLE,
    };
    int ev[] = {
        NGX_FF_RELOAD_EV_HUP,
        NGX_FF_RELOAD_EV_ALL_READY,
        NGX_FF_RELOAD_EV_HANDOVER_DONE,
        NGX_FF_RELOAD_EV_DRAIN_DONE,
        NGX_FF_RELOAD_EV_QUIT_GOLD,
        NGX_FF_RELOAD_EV_GOLD_EXITED,
    };
    int i;

    st = NGX_FF_RELOAD_T0_IDLE;
    for (i = 0; i < 6; i++) {
        st = ngx_ff_reload_fsm_next(st, ev[i]);
        assert_int_equal(st, expect[i]);
    }

    /* re-entry protection (semantics 6): HUP is only legal in T0 */
    st = NGX_FF_RELOAD_T5_GOLD_QUIT;
    assert_int_equal(ngx_ff_reload_fsm_next(st, NGX_FF_RELOAD_EV_HUP),
                     NGX_FF_RELOAD_T_MAX);
    st = NGX_FF_RELOAD_T1_GNEW_SPAWN;
    assert_int_equal(ngx_ff_reload_fsm_next(st, NGX_FF_RELOAD_EV_HUP),
                     NGX_FF_RELOAD_T_MAX);

    /* illegal jumps */
    assert_int_equal(ngx_ff_reload_fsm_next(NGX_FF_RELOAD_T0_IDLE,
                     NGX_FF_RELOAD_EV_QUIT_GOLD), NGX_FF_RELOAD_T_MAX);
    assert_int_equal(ngx_ff_reload_fsm_next(NGX_FF_RELOAD_T3_DRAIN,
                     NGX_FF_RELOAD_EV_ALL_READY), NGX_FF_RELOAD_T_MAX);
    assert_int_equal(ngx_ff_reload_fsm_next(NGX_FF_RELOAD_T0_IDLE,
                     NGX_FF_RELOAD_EV_GOLD_EXITED), NGX_FF_RELOAD_T_MAX);

    /* failure paths: T1 -> T_ERROR -> T0 */
    assert_int_equal(ngx_ff_reload_fsm_next(NGX_FF_RELOAD_T1_GNEW_SPAWN,
                     NGX_FF_RELOAD_EV_GNEW_DIED), NGX_FF_RELOAD_T_ERROR);
    assert_int_equal(ngx_ff_reload_fsm_next(NGX_FF_RELOAD_T1_GNEW_SPAWN,
                     NGX_FF_RELOAD_EV_READY_TIMEOUT), NGX_FF_RELOAD_T_ERROR);
    assert_int_equal(ngx_ff_reload_fsm_next(NGX_FF_RELOAD_T_ERROR,
                     NGX_FF_RELOAD_EV_RESET), NGX_FF_RELOAD_T0_IDLE);

    /* state names resolve for every valid state */
    for (i = 0; i < NGX_FF_RELOAD_T_MAX; i++) {
        assert_non_null(ngx_ff_reload_fsm_state_name(i));
    }
    assert_string_equal(ngx_ff_reload_fsm_state_name(NGX_FF_RELOAD_T0_IDLE),
                        "T0_IDLE");
}

/* UT-NR-10 (M4 Batch C completion): the authoritative legal-transition
 * table, kept in one place so the exhaustive sweep below and the legal-path
 * walk stay in sync with ngx_ff_reload_fsm.h by construction. */
struct ut_nr10_trans {
    int state, event, next;
};

static const struct ut_nr10_trans ut_nr10_legal[] = {
    { NGX_FF_RELOAD_T0_IDLE,       NGX_FF_RELOAD_EV_HUP,           NGX_FF_RELOAD_T1_GNEW_SPAWN },
    { NGX_FF_RELOAD_T1_GNEW_SPAWN, NGX_FF_RELOAD_EV_ALL_READY,     NGX_FF_RELOAD_T2_HANDOVER },
    { NGX_FF_RELOAD_T1_GNEW_SPAWN, NGX_FF_RELOAD_EV_READY_TIMEOUT, NGX_FF_RELOAD_T_ERROR },
    { NGX_FF_RELOAD_T1_GNEW_SPAWN, NGX_FF_RELOAD_EV_GNEW_DIED,     NGX_FF_RELOAD_T_ERROR },
    { NGX_FF_RELOAD_T2_HANDOVER,   NGX_FF_RELOAD_EV_HANDOVER_DONE, NGX_FF_RELOAD_T3_DRAIN },
    { NGX_FF_RELOAD_T2_HANDOVER,   NGX_FF_RELOAD_EV_ABORT,         NGX_FF_RELOAD_T_ERROR },
    { NGX_FF_RELOAD_T3_DRAIN,      NGX_FF_RELOAD_EV_DRAIN_DONE,    NGX_FF_RELOAD_T4_DRAIN_DONE },
    { NGX_FF_RELOAD_T3_DRAIN,      NGX_FF_RELOAD_EV_ABORT,         NGX_FF_RELOAD_T_ERROR },
    { NGX_FF_RELOAD_T4_DRAIN_DONE, NGX_FF_RELOAD_EV_QUIT_GOLD,     NGX_FF_RELOAD_T5_GOLD_QUIT },
    { NGX_FF_RELOAD_T4_DRAIN_DONE, NGX_FF_RELOAD_EV_ABORT,         NGX_FF_RELOAD_T_ERROR },
    { NGX_FF_RELOAD_T5_GOLD_QUIT,  NGX_FF_RELOAD_EV_GOLD_EXITED,   NGX_FF_RELOAD_T0_IDLE },
    { NGX_FF_RELOAD_T_ERROR,       NGX_FF_RELOAD_EV_RESET,         NGX_FF_RELOAD_T0_IDLE },
};

/* UT-NR-10a: every legal transition, driven one by one from T0 (including
 * the ones the happy-path test above does not reach: each ABORT entry and
 * both T1 failure events), then two consecutive full rounds to prove the
 * FSM returns to a fully reusable T0 after T5 and after RESET. */
static void
test_ut_nr_10_all_legal_transitions(void **state)
{
    unsigned i;
    int round;

    (void)state;

    for (i = 0; i < sizeof(ut_nr10_legal) / sizeof(ut_nr10_legal[0]); i++) {
        assert_int_equal(ngx_ff_reload_fsm_next(ut_nr10_legal[i].state,
                                                ut_nr10_legal[i].event),
                         ut_nr10_legal[i].next);
    }

    /* two full rounds back to back: T0 must be indistinguishable after a
     * completed round (re-entry protection must reset with the state) */
    for (round = 0; round < 2; round++) {
        int st = NGX_FF_RELOAD_T0_IDLE;
        int ev[] = {
            NGX_FF_RELOAD_EV_HUP,
            NGX_FF_RELOAD_EV_ALL_READY,
            NGX_FF_RELOAD_EV_HANDOVER_DONE,
            NGX_FF_RELOAD_EV_DRAIN_DONE,
            NGX_FF_RELOAD_EV_QUIT_GOLD,
            NGX_FF_RELOAD_EV_GOLD_EXITED,
        };
        int expect[] = {
            NGX_FF_RELOAD_T1_GNEW_SPAWN,
            NGX_FF_RELOAD_T2_HANDOVER,
            NGX_FF_RELOAD_T3_DRAIN,
            NGX_FF_RELOAD_T4_DRAIN_DONE,
            NGX_FF_RELOAD_T5_GOLD_QUIT,
            NGX_FF_RELOAD_T0_IDLE,
        };
        unsigned k;

        for (k = 0; k < sizeof(ev) / sizeof(ev[0]); k++) {
            st = ngx_ff_reload_fsm_next(st, ev[k]);
            assert_int_equal(st, expect[k]);
        }
    }
}

/* UT-NR-10b: exhaustive 7-state x 11-event sweep. Every (state, event)
 * pair outside the legal table above must be refused with T_MAX — no
 * undocumented transition, no fallback to a "nearest" state, and EV_NONE
 * is never accepted anywhere. */
static void
test_ut_nr_10_illegal_combinations_exhaustive(void **state)
{
    int s, e;
    unsigned i;

    (void)state;

    assert_int_equal(NGX_FF_RELOAD_T_MAX, 7);    /* sweep assumptions */
    assert_int_equal(NGX_FF_RELOAD_EV_MAX, 11);

    for (s = 0; s < NGX_FF_RELOAD_T_MAX; s++) {
        for (e = 0; e < NGX_FF_RELOAD_EV_MAX; e++) {
            int legal = 0;
            int next = ngx_ff_reload_fsm_next(s, e);

            for (i = 0; i < sizeof(ut_nr10_legal) / sizeof(ut_nr10_legal[0]); i++) {
                if (ut_nr10_legal[i].state == s
                    && ut_nr10_legal[i].event == e) {
                    legal = 1;
                    assert_int_equal(next, ut_nr10_legal[i].next);
                    break;
                }
            }

            if (!legal) {
                assert_int_equal(next, NGX_FF_RELOAD_T_MAX);
            }
        }
    }

    /* out-of-range states are refused for every event (EV_NONE included) */
    {
        int bad_states[] = { NGX_FF_RELOAD_T_MAX, -1, 99 };
        unsigned b;

        for (b = 0; b < sizeof(bad_states) / sizeof(bad_states[0]); b++) {
            for (e = 0; e < NGX_FF_RELOAD_EV_MAX; e++) {
                assert_int_equal(
                    ngx_ff_reload_fsm_next(bad_states[b], e),
                    NGX_FF_RELOAD_T_MAX);
            }
        }
    }
}

/* UT-NR-10c: T_ERROR recovery from every failure entry. Each state that
 * can enter T_ERROR must do so via its own event, RESET must be the only
 * way out, and after recovery a fresh legal round must complete — the
 * abort paths of C-NR-404 (READY timeout / G_new death / handover park
 * timeout / DR6 reclaim during drain) all land in this shared pattern. */
static void
test_ut_nr_10_error_recovery_and_abort(void **state)
{
    struct {
        int from_state, event;
    } failure_entries[] = {
        { NGX_FF_RELOAD_T1_GNEW_SPAWN, NGX_FF_RELOAD_EV_READY_TIMEOUT },
        { NGX_FF_RELOAD_T1_GNEW_SPAWN, NGX_FF_RELOAD_EV_GNEW_DIED },
        { NGX_FF_RELOAD_T2_HANDOVER,   NGX_FF_RELOAD_EV_ABORT },
        { NGX_FF_RELOAD_T3_DRAIN,      NGX_FF_RELOAD_EV_ABORT },
        { NGX_FF_RELOAD_T4_DRAIN_DONE, NGX_FF_RELOAD_EV_ABORT },
    };
    unsigned i, k;
    int ev_round[] = {
        NGX_FF_RELOAD_EV_HUP,
        NGX_FF_RELOAD_EV_ALL_READY,
        NGX_FF_RELOAD_EV_HANDOVER_DONE,
        NGX_FF_RELOAD_EV_DRAIN_DONE,
        NGX_FF_RELOAD_EV_QUIT_GOLD,
        NGX_FF_RELOAD_EV_GOLD_EXITED,
    };
    int expect_round[] = {
        NGX_FF_RELOAD_T1_GNEW_SPAWN,
        NGX_FF_RELOAD_T2_HANDOVER,
        NGX_FF_RELOAD_T3_DRAIN,
        NGX_FF_RELOAD_T4_DRAIN_DONE,
        NGX_FF_RELOAD_T5_GOLD_QUIT,
        NGX_FF_RELOAD_T0_IDLE,
    };

    (void)state;

    for (i = 0; i < sizeof(failure_entries) / sizeof(failure_entries[0]); i++) {
        int st = ngx_ff_reload_fsm_next(failure_entries[i].from_state,
                                        failure_entries[i].event);

        assert_int_equal(st, NGX_FF_RELOAD_T_ERROR);

        /* RESET is the only exit; everything else is refused */
        assert_int_equal(
            ngx_ff_reload_fsm_next(st, NGX_FF_RELOAD_EV_RESET),
            NGX_FF_RELOAD_T0_IDLE);
        assert_int_equal(
            ngx_ff_reload_fsm_next(st, NGX_FF_RELOAD_EV_HUP),
            NGX_FF_RELOAD_T_MAX);
        assert_int_equal(
            ngx_ff_reload_fsm_next(st, NGX_FF_RELOAD_EV_GOLD_EXITED),
            NGX_FF_RELOAD_T_MAX);

        /* a fresh full round must succeed right after recovery */
        st = NGX_FF_RELOAD_T0_IDLE;
        for (k = 0; k < sizeof(ev_round) / sizeof(ev_round[0]); k++) {
            st = ngx_ff_reload_fsm_next(st, ev_round[k]);
            assert_int_equal(st, expect_round[k]);
        }
    }
}
