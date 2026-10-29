/* P2 (C-P2-6a): a reaped child is a pid that is certainly gone. */
static uint32_t
p1_dead_pid(void)
{
    pid_t child = fork();
    int wstatus = 0;

    assert_true(child >= 0);
    if (child == 0)
        _exit(0);
    assert_int_equal(waitpid(child, &wstatus, 0), child);
    return (uint32_t)child;
}

static uint32_t
p1_now_ms(void)
{
    struct timespec ts;

    assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &ts), 0);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u
        + (uint64_t)(ts.tv_nsec / 1000000));
}

/* Set up "old master gone, its workers still refreshing the stamp" on the
 * slot this process would mint (epoch 1 -> slot 1). */
static void
p1_orphan_slot(uint32_t dead)
{
    p1_process_type = RTE_PROC_SECONDARY;
    p1_parent = (uint32_t)__real_getppid();
    p1_dir->next_epoch = 0;
    p1_dir->slot[1].epoch = 1;
    p1_dir->slot[1].gen = 0;
    p1_dir->slot[1].state = FF_RELOAD_SLOT_LIVE;
    p1_dir->slot[1].master_pid = dead;
    p1_dir->slot[1].pad = p1_now_ms();
}

/* C-P2-6a: the window right after an old master quit must NOT kill the new
 * generation — the slot is only temporarily unavailable. */
static void
test_p2_slot_transient_window(void **state)
{
    uint32_t dead = p1_dead_pid();

    (void)state;
    p1_orphan_slot(dead);
    /* Budget above the stamp window: the retry has to be able to wait for
     * the orphan workers' stamp to go stale. */
    ff_reload_reclaim_timeout_set(FF_RELOAD_SLOT_STALE_MS + 500u);

    {
        uint32_t t0 = p1_now_ms();

        ff_reload_gendir_attach();
        /* The slot was held by a dead master with a fresh stamp: taking it
         * immediately would mean the orphan workers were never waited for,
         * so the attach must have waited for the stamp to go stale. */
        assert_true((uint32_t)(p1_now_ms() - t0) >= FF_RELOAD_SLOT_STALE_MS);
    }
    ff_reload_reclaim_timeout_set(0);

    assert_int_equal(ff_reload_gendir_present(), 1);
    assert_int_equal(ff_reload_epoch(), 1);
    assert_int_equal(p1_dir->slot[1].master_pid, p1_parent);
    /* R-16: no hopping to a neighbouring slot */
    assert_int_equal(p1_dir->slot[2].master_pid, 0);
    assert_int_equal(p1_dir->slot[3].master_pid, 0);
    assert_int_equal(p1_dir->reclaim_refused, 0);
}

/* C-P2-6a: once that budget is exhausted, refusing is the answer — and it
 * is counted, not taken silently. */
static void
test_p2_slot_transient_exhausted(void **state)
{
    uint32_t dead = p1_dead_pid();

    (void)state;
    p1_orphan_slot(dead);
    ff_reload_reclaim_timeout_set(50);

    expect_assert_failure(ff_reload_gendir_attach());
    ff_reload_reclaim_timeout_set(0);

    assert_int_equal(ff_reload_gendir_present(), 0);
    assert_int_equal(p1_dir->slot[1].master_pid, dead);
    assert_int_equal(p1_dir->slot[2].master_pid, 0);
    assert_int_equal(p1_dir->slot[3].master_pid, 0);
    assert_int_equal(p1_dir->reclaim_refused, 1);
}
