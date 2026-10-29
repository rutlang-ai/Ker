/* ---- P2 (B01-1 / B02-1): takeover proof -------------------------------- */

static uint32_t
p2_dead_pid(void)
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
p2_now_ms(void)
{
    struct timespec ts;

    assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &ts), 0);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u
        + (uint64_t)(ts.tv_nsec / 1000000));
}

static void
p2_gendir_init(struct ff_reload_gendir *gd)
{
    memset(gd, 0, sizeof(*gd));
    gd->magic = FF_RELOAD_GENDIR_MAGIC;
    gd->version = FF_RELOAD_GENDIR_VERSION;
    gd->len = (uint32_t)sizeof(*gd);
    gd->slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    gd->gen_max = FF_RELOAD_GEN_MAX;
    gd->active_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd->rx_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd->kni_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    assert_int_equal(ff_reload_gendir_install(gd, sizeof(*gd)), 0);
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_reload_gendir_reclaim_counters_reset();
}

/* C-P2-1/2: the hardware-user table is what a takeover consults. */
static void
test_p2_hw_user_proof(void **state)
{
    struct ff_reload_gendir gd;
    uint32_t dead = p2_dead_pid();

    (void)state;
    p2_gendir_init(&gd);
    ff_reload_set_epoch(1);
    ff_reload_set_gen(0);

    /* no users: nothing to prove, nothing blocks */
    assert_int_equal(ff_reload_gendir_users_clear(1, 0), 1);
    assert_int_equal(ff_reload_gendir_users_active(1, 0), 0);

    /* a live peer user blocks, a dead one does not (exit proof) */
    gd.user[0].epoch = 1;
    gd.user[0].gen = 0;
    gd.user[0].pid = (uint32_t)getppid();
    gd.user[0].state = FF_RELOAD_USER_ACTIVE;
    gd.user[1].epoch = 1;
    gd.user[1].gen = 0;
    gd.user[1].pid = dead;
    gd.user[1].state = FF_RELOAD_USER_ACTIVE;
    assert_int_equal(ff_reload_gendir_users_active(1, 0), 1);
    assert_int_equal(ff_reload_gendir_users_clear(1, 0), 0);
    assert_int_equal(ff_reload_gendir_epoch_users_clear(1), 0);

    /* registration is idempotent: two adds leave exactly one own entry */
    assert_int_equal(ff_reload_gendir_user_add(1, 0), 0);
    assert_int_equal(ff_reload_gendir_user_add(1, 0), 0);
    assert_int_equal(ff_reload_gendir_users_active(1, 0), 2);

    /* our own ack is a STOPPED entry, not a disappearance */
    ff_reload_gendir_user_stop(1, 0);
    assert_int_equal(ff_reload_gendir_users_active(1, 0), 1);
    assert_int_equal(ff_reload_gendir_users_clear(1, 0), 0);

    /* the peer's ack clears the coordinate; another coordinate is untouched */
    gd.user[0].state = FF_RELOAD_USER_STOPPED;
    assert_int_equal(ff_reload_gendir_users_clear(1, 0), 1);
    gd.user[2].epoch = 2;
    gd.user[2].gen = 1;
    gd.user[2].pid = (uint32_t)getppid();
    gd.user[2].state = FF_RELOAD_USER_ACTIVE;
    assert_int_equal(ff_reload_gendir_users_clear(2, 1), 0);
    assert_int_equal(ff_reload_gendir_users_clear(1, 0), 1);

    ff_reload_gendir_user_release(1, 0);
    assert_int_equal(ff_reload_gendir_users_active(1, 0), 0);
    ff_reload_gendir_install(NULL, 0);
}

/* C-P2-3: a dead master is not a proof — the displaced coordinate's users
 * must have confirmed they stopped. */
static void
test_p2_reclaim_needs_user_proof(void **state)
{
    struct ff_reload_gendir gd;
    uint32_t dead = p2_dead_pid(), oe = 0, og = 0, stopped = 0;

    (void)state;
    p2_gendir_init(&gd);
    ff_reload_set_epoch(2);
    ff_reload_set_gen(1);

    /* owner epoch 1/gen 0: master dead and stamp stale (no orphan refresh) */
    gd.slot[1].epoch = 1;
    gd.slot[1].gen = 0;
    gd.slot[1].state = FF_RELOAD_SLOT_LIVE;
    gd.slot[1].master_pid = dead;
    gd.slot[1].pad = p2_now_ms() - (FF_RELOAD_SLOT_STALE_MS + 1000u);
    gd.rx_owner_word = ((uint64_t)1 << 32) | 0u;

    /* but one of its workers is still marked active and alive */
    gd.user[0].epoch = 1;
    gd.user[0].gen = 0;
    gd.user[0].pid = (uint32_t)getppid();
    gd.user[0].state = FF_RELOAD_USER_ACTIVE;

    assert_int_equal(ff_reload_gendir_users_clear(1, 0), 0);
    assert_int_equal(ff_reload_gendir_rx_reclaim(2, 1),
        FF_RELOAD_HANDOVER_BUSY);
    assert_int_equal(ff_reload_gendir_reclaim_refused(), 1);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 1);
    assert_int_equal(og, 0);

    /* proof delivered: the takeover is allowed once */
    gd.user[0].state = FF_RELOAD_USER_STOPPED;
    assert_int_equal(ff_reload_gendir_rx_reclaim(2, 1),
        FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_gendir_reclaim_refused(), 1);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 2);
    assert_int_equal(og, 1);
    ff_reload_gendir_install(NULL, 0);
}

/* C-P2-3/5: the USR2 release path needs the same proof as a HUP handover. */
static void
test_p2_release_epoch_needs_proof(void **state)
{
    struct ff_reload_state st;
    struct ff_reload_gendir gd;
    unsigned saved = ff_reload_reclaim_timeout_ms();

    (void)state;
    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    st.rx_owner_gen = 0;
    ff_reload_attach_state(&st);

    p2_gendir_init(&gd);
    ff_reload_set_epoch(1);
    ff_reload_set_gen(0);
    gd.rx_owner_word = ((uint64_t)1 << 32) | 0u;

    /* a peer worker of our own coordinate is still inside the hardware */
    gd.user[0].epoch = 1;
    gd.user[0].gen = 0;
    gd.user[0].pid = (uint32_t)getppid();
    gd.user[0].state = FF_RELOAD_USER_ACTIVE;

    ff_reload_reclaim_timeout_set(20);
    assert_int_equal(ff_reload_rx_release_epoch(2, 1),
        FF_RELOAD_HANDOVER_BUSY);
    assert_int_equal(ff_reload_gendir_reclaim_refused(), 1);
    assert_int_equal(ff_reload_rx_owner_gen(), 0);      /* nothing flipped */

    gd.user[0].state = FF_RELOAD_USER_STOPPED;
    assert_int_equal(ff_reload_rx_release_epoch(2, 1), FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_rx_owner_gen(), 1);
    assert_int_equal(ff_reload_gendir_reclaim_refused(), 1);

    ff_reload_reclaim_timeout_set(saved);
    ff_reload_gendir_install(NULL, 0);
    ff_reload_attach_state(NULL);
}

/* B02-1: orphan workers keep their epoch live until the stamp goes stale.
 * Observed through the takeover itself (ff_reload_gendir_epoch_live() lives
 * in the DPDK-side object this binary does not link). */
static void
test_p2_orphan_workers_keep_epoch_live(void **state)
{
    struct ff_reload_gendir gd;
    uint32_t dead = p2_dead_pid();

    (void)state;
    p2_gendir_init(&gd);
    ff_reload_set_epoch(3);
    ff_reload_set_gen(0);
    gd.rx_owner_word = ((uint64_t)1 << 32) | 0u;

    /* master gone, but workers still refresh the stamp: still the owner */
    gd.slot[2].epoch = 1;
    gd.slot[2].gen = 0;
    gd.slot[2].state = FF_RELOAD_SLOT_LIVE;
    gd.slot[2].master_pid = dead;
    gd.slot[2].pad = p2_now_ms();
    assert_int_equal(ff_reload_gendir_rx_reclaim(3, 0),
        FF_RELOAD_HANDOVER_BUSY);

    /* their death notice: the stamp stops being refreshed */
    gd.slot[2].pad = p2_now_ms() - (FF_RELOAD_SLOT_STALE_MS + 1000u);
    assert_int_equal(ff_reload_gendir_rx_reclaim(3, 0), FF_RELOAD_HANDOVER_OK);

    /* a live master is live regardless of the stamp */
    gd.rx_owner_word = ((uint64_t)1 << 32) | 0u;
    gd.slot[2].master_pid = (uint32_t)getpid();
    gd.slot[2].pad = p2_now_ms() - (FF_RELOAD_SLOT_STALE_MS + 1000u);
    assert_int_equal(ff_reload_gendir_rx_reclaim(3, 0),
        FF_RELOAD_HANDOVER_BUSY);

    /* and a retired slot is never live */
    gd.slot[2].state = FF_RELOAD_SLOT_DEAD;
    assert_int_equal(ff_reload_gendir_rx_reclaim(3, 0), FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_gendir_reclaim_refused(), 0);
    ff_reload_gendir_install(NULL, 0);
}

/* RX-15: the drain-ring user table the resident primary purges against. */
static void
test_rx15_ring_user_census_and_purge_lock(void **state)
{
    uint32_t live[FF_RELOAD_EPOCH_SLOT_MAX][FF_RELOAD_GEN_MAX];
    uint32_t dead[FF_RELOAD_EPOCH_SLOT_MAX][FF_RELOAD_GEN_MAX];
    struct ff_reload_gendir gd;
    uint32_t gone = p2_dead_pid();

    (void)state;
    /* no directory: attach is a no-op, census and purge are refused */
    ff_reload_gendir_install(NULL, 0);
    assert_int_equal(ff_reload_gendir_ring_attach(1, 0, 0), 0);
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 0), -1);
    assert_int_equal(ff_reload_gendir_ring_purge_lock(0), -1);

    p2_gendir_init(&gd);

    /* attach registers exactly one live entry; detach drops it */
    assert_int_equal(ff_reload_gendir_ring_attach(1, 0, 0), 0);
    assert_int_equal(ff_reload_gendir_ring_attach(1, 0, 0), 0);
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 0), 0);
    assert_int_equal(live[1][0], 1);
    assert_int_equal(live[1][1] + dead[1][0] + dead[1][1], 0);
    ff_reload_gendir_ring_detach(1, 0);
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 0), 0);
    assert_int_equal(live[1][0], 0);

    /* an exited worker leaves a dead entry; a new user takes a free entry
     * first, so the marker survives (epoch 4 shares ring slot 1) */
    gd.ring_user[0].epoch = 1;
    gd.ring_user[0].gen = 1;
    gd.ring_user[0].pid = gone;
    gd.ring_user[0].state = FF_RELOAD_USER_ACTIVE;
    assert_int_equal(ff_reload_gendir_ring_attach(4, 0, 0), 0);
    assert_int_equal(gd.ring_user[0].pid, gone);
    assert_int_equal(gd.ring_user[1].pid, (uint32_t)getpid());

    /* the slot is busy: the marker is counted and kept */
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 1), 0);
    assert_int_equal(live[1][0], 1);
    assert_int_equal(dead[1][1], 1);
    assert_int_equal(gd.ring_user[0].pid, gone);

    /* a dead entry of another slot does not count for slot 1 */
    gd.ring_user[2].epoch = 2;
    gd.ring_user[2].gen = 0;
    gd.ring_user[2].pid = gone;
    gd.ring_user[2].state = FF_RELOAD_USER_ACTIVE;
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 0), 0);
    assert_int_equal(dead[1][0], 0);
    assert_int_equal(dead[2][0], 1);

    /* once slot 1 is idle its markers are reported one last time and then
     * forgotten; slot 2 is idle too and is cleared the same way */
    ff_reload_gendir_ring_detach(4, 0);
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 1), 0);
    assert_int_equal(dead[1][1], 1);
    assert_int_equal(gd.ring_user[0].pid, 0);
    assert_int_equal(gd.ring_user[2].pid, 0);
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 1), 0);
    assert_int_equal(dead[1][1] + dead[2][0], 0);

    /* the table holds both generations of two masters: with as many live
     * users as one master can have, attach still finds an entry */
    {
        unsigned k;

        for (k = 0; k < FF_RELOAD_MAX_PROCS; k++) {
            gd.ring_user[k].epoch = 2;
            gd.ring_user[k].gen = 1;
            gd.ring_user[k].pid = 1u;
            gd.ring_user[k].state = FF_RELOAD_USER_ACTIVE;
        }
        assert_int_equal(ff_reload_gendir_ring_attach(1, 0, 0), 0);
        assert_int_equal(gd.ring_user[FF_RELOAD_MAX_PROCS].pid,
            (uint32_t)getpid());
        assert_int_equal(ff_reload_gendir_ring_census(live, dead, 0), 0);
        assert_int_equal(live[2][1], FF_RELOAD_MAX_PROCS);
        assert_int_equal(live[1][0], 1);
        ff_reload_gendir_ring_detach(1, 0);
        memset(gd.ring_user, 0, sizeof(gd.ring_user));
    }

    /* purge lock: exclusive, idempotent for the holder */
    assert_int_equal(ff_reload_gendir_ring_purge_lock(0), 0);
    assert_int_equal(gd.ring_purge_owner, (uint32_t)getpid());
    assert_int_equal(ff_reload_gendir_ring_purge_lock(0), 0);
    ff_reload_gendir_ring_purge_unlock();
    assert_int_equal(gd.ring_purge_owner, 0);

    /* a live foreign holder (pid 1): lock times out, attach gives up
     * without leaving an entry behind */
    gd.ring_purge_owner = 1u;
    assert_int_equal(ff_reload_gendir_ring_purge_lock(5), -1);
    assert_int_equal(ff_reload_gendir_ring_attach(1, 0, 20), -1);
    assert_int_equal(ff_reload_gendir_ring_census(live, dead, 0), 0);
    assert_int_equal(live[1][0], 0);
    ff_reload_gendir_ring_purge_unlock();     /* not ours: untouched */
    assert_int_equal(gd.ring_purge_owner, 1u);

    /* a dead holder blocks nobody and can be taken over */
    gd.ring_purge_owner = gone;
    assert_int_equal(ff_reload_gendir_ring_attach(1, 0, 0), 0);
    assert_int_equal(ff_reload_gendir_ring_purge_lock(0), 0);
    ff_reload_gendir_ring_purge_unlock();
    ff_reload_gendir_ring_detach(1, 0);

    ff_reload_gendir_install(NULL, 0);
    ff_global_cfg.dpdk.graceful_reload = 0;
}
