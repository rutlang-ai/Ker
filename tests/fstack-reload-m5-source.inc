static void
test_ut_nr_m5_gendir_arbitration(void **state)
{
    struct ff_reload_state st;
    struct ff_reload_gendir gd;
    uint32_t oe = 0, og = 0, stopped = 0, ae = 0, ag = 0, pe = 0;
    int pg = -1;

    (void)state;

    memset(&st, 0, sizeof(st));
    memset(&gd, 0, sizeof(gd));

    /* only a well-formed directory is accepted */
    assert_int_equal(ff_reload_gendir_install(NULL, 0), -1);
    assert_int_equal(ff_reload_gendir_install(&gd, sizeof(gd)), -1);
    gd.magic = FF_RELOAD_GENDIR_MAGIC;
    gd.version = FF_RELOAD_GENDIR_VERSION;
    gd.len = (uint32_t)sizeof(gd);
    gd.gen_max = FF_RELOAD_GEN_MAX;
    gd.slot_max = FF_RELOAD_EPOCH_SLOT_MAX - 1;   /* foreign layout */
    assert_int_equal(ff_reload_gendir_install(&gd, sizeof(gd)), -1);
    gd.slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    assert_int_equal(ff_reload_gendir_install(&gd, sizeof(gd)), 0);

    /* nothing claimed yet */
    gd.active_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd.rx_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd.kni_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);

    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    st.active_gen = 0;
    st.kni_owner_gen = 0;
    st.rx_owner_gen = 0;
    st.rx_stopped = 0;

    ff_reload_attach_state(&st);
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_reload_set_epoch(1);
    ff_reload_set_gen(0);
    ff_reload_dir_sync_enable(1);

    /* two live masters: epoch 1 (ours, primary-flagged) and epoch 2 */
    gd.slot[0].epoch = 1;
    gd.slot[0].master_pid = (uint32_t)getpid();
    gd.slot[0].state = FF_RELOAD_SLOT_LIVE;
    gd.slot[0].flags = FF_RELOAD_SLOT_PRIMARY;
    gd.slot[1].epoch = 2;
    gd.slot[1].gen = 1;
    gd.slot[1].master_pid = (uint32_t)getpid();
    gd.slot[1].state = FF_RELOAD_SLOT_LIVE;

    /* an unclaimed directory narrows nothing */
    assert_int_equal(ff_no_hw_mode(), 0);

    /* first pass claims rx/kni/active for our epoch and publishes the peer
     * coordinate into the block — the master has no EAL and can only read
     * the block, so this is its only route to the other master's epoch. */
    ff_reload_dir_sync();
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 1);
    assert_int_equal(og, 0);
    assert_int_equal(stopped, 0);
    assert_int_equal(ff_reload_gendir_active(&ae, &ag), 0);
    assert_int_equal(ae, 1);
    assert_int_equal(ag, 0);
    assert_int_equal(st.peer_epoch, 2);
    assert_int_equal(st.peer_gen, 1);

    assert_int_equal(ff_no_hw_mode(), 0);
    assert_int_equal(ff_reload_kni_owner_match(), 1);

    /* the probe reply must carry the epoch of the serving generation, not
     * the answering process's own — otherwise a tool targeting proc N
     * builds slot-0 names nobody dequeues (M5 review P0-1). */
    {
        struct ff_msg m;

        memset(&m, 0, sizeof(m));
        ff_reload_msg_fill(&m, FF_RELOAD_CMD_QUERY, 0, 0, 7);
        assert_int_equal(m.reload.active_gen, 0);
        assert_int_equal(m.reload.epoch, 1);
        assert_int_equal(m.reload.heartbeat, 7);
    }

    /* the other generation of the same master stays parked */
    ff_reload_set_gen(1);
    assert_int_equal(ff_no_hw_mode(), 1);
    assert_int_equal(ff_reload_kni_owner_match(), 0);
    ff_reload_set_gen(0);

    /* another master running the same gen: the anonymous block alone would
     * answer "owner" for both, the directory is the tie-breaker. */
    ff_reload_set_epoch(2);
    assert_int_equal(ff_no_hw_mode(), 1);
    assert_int_equal(ff_reload_kni_owner_match(), 0);
    /* and a live owner is never displaced by a foreign sync */
    ff_reload_dir_sync();
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 1);
    ff_reload_set_epoch(1);

    /* release: park first, then transfer — only the current owner may */
    assert_int_equal(ff_reload_gendir_rx_release(2, 1),
        FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 2);
    assert_int_equal(og, 1);
    assert_int_equal(stopped, 1);            /* parked until claimed */
    assert_int_equal(ff_reload_gendir_rx_release(1, 0),
        FF_RELOAD_HANDOVER_BUSY);

    /* claim: satisfied immediately once the transfer happened */
    assert_int_equal(ff_reload_gendir_rx_claim(2, 0, 2, 1, 10),
        FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(stopped, 0);
    /* a third coordinate is refused instead of stolen */
    assert_int_equal(ff_reload_gendir_rx_claim(9, 0, 9, 1, 10),
        FF_RELOAD_HANDOVER_BUSY);

    /* reclaim (M4 DR6-1 / RT-04b): only from a dead owner */
    assert_int_equal(ff_reload_gendir_rx_reclaim(1, 0),
        FF_RELOAD_HANDOVER_BUSY);
    gd.slot[1].state = FF_RELOAD_SLOT_DEAD;
    assert_int_equal(ff_reload_gendir_rx_reclaim(1, 0),
        FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 1);
    assert_int_equal(og, 0);
    assert_int_equal(stopped, 0);

    /* peer: newest live epoch other than ours, else our own peer gen */
    gd.slot[1].state = FF_RELOAD_SLOT_LIVE;   /* revived after the reclaim */
    ff_reload_peer_coord(&pe, &pg);
    assert_int_equal(pe, 2);
    assert_int_equal(pg, 1);
    gd.slot[1].state = FF_RELOAD_SLOT_DEAD;
    ff_reload_peer_coord(&pe, &pg);
    assert_int_equal(pe, 1);
    assert_int_equal(pg, 1);

    /* F-M5-1 (USR2): a dead master whose workers still drain — the slot
     * stamp stays fresh — remains a peer; a fully dead epoch does not. */
    {
        struct timespec ts;
        pid_t child = fork();
        int wstatus;

        assert_true(child >= 0);
        if (child == 0) {
            _exit(0);
        }
        assert_int_equal(waitpid(child, &wstatus, 0), child);

        gd.slot[1].state = FF_RELOAD_SLOT_LIVE;
        gd.slot[1].master_pid = (uint32_t)child;   /* reaped: gone */
        gd.slot[1].pad = 0;                        /* stale stamp */
        ff_reload_peer_coord(&pe, &pg);
        assert_int_equal(pe, 1);                   /* fallback: fully dead */
        assert_int_equal(pg, 1);
        assert_int_equal(ff_reload_peer_draining(), 0);

        assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &ts), 0);
        gd.slot[1].pad = (uint32_t)(ts.tv_sec * 1000
            + ts.tv_nsec / 1000000);
        ff_reload_peer_coord(&pe, &pg);
        assert_int_equal(pe, 2);                   /* draining peer */
        assert_int_equal(pg, 1);
        assert_int_equal(ff_reload_peer_draining(), 1);

        /* during our own master's reload window the peer must stay the
         * intra-master pair even with a foreign epoch alive: an M4 round
         * must not capture a coexisting master's drain rings */
        st.reload_active = 1;
        ff_reload_peer_coord(&pe, &pg);
        assert_int_equal(pe, 1);
        assert_int_equal(pg, 1);
        assert_int_equal(ff_reload_peer_draining(), 0);
        st.reload_active = 0;

        /* the block-mirror view follows after a sync pass — the per-packet
         * gate of the nginx dispatcher reads exactly this */
        ff_reload_dir_sync();
        assert_int_equal(st.peer_epoch, 2);
        assert_int_equal(ff_reload_peer_mirror_draining(), 1);

        gd.slot[1].state = FF_RELOAD_SLOT_DEAD;
        ff_reload_dir_sync();
        assert_int_equal(ff_reload_peer_mirror_draining(), 0);
    }

    /* no directory (graceful=0 / no primary / master): nothing narrows */
    ff_reload_gendir_install(NULL, 0);
    ff_reload_dir_sync_enable(0);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), -1);
    assert_int_equal(ff_no_hw_mode(), 0);
    assert_int_equal(ff_reload_kni_owner_match(), 1);
    {
        struct ff_msg m;

        /* without a directory the reply is the process's own epoch — for
         * the pre-M5 / directory-less identity that is 0, i.e. slot 0. */
        ff_reload_set_epoch(0);
        memset(&m, 0, sizeof(m));
        ff_reload_msg_fill(&m, FF_RELOAD_CMD_QUERY, 0, 0, 0);
        assert_int_equal(m.reload.epoch, 0);
    }

    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_reload_set_epoch(0);
    ff_reload_set_gen(0);
    ff_reload_attach_state(NULL);
}

static void
test_ut_nr_m5_probe_epoch_fallback(void **state)
{
    struct ff_reload_gendir gd;
    struct ff_msg m;
    uint32_t me = (uint32_t)getpid();

    (void)state;

    memset(&gd, 0, sizeof(gd));
    gd.magic = FF_RELOAD_GENDIR_MAGIC;
    gd.version = FF_RELOAD_GENDIR_VERSION;
    gd.len = (uint32_t)sizeof(gd);
    gd.slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    gd.gen_max = FF_RELOAD_GEN_MAX;
    gd.active_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd.rx_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd.kni_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);

    /* This process is the resident primary: epoch 0 / slot 0, and it is the
     * one that answers ff_ipc probes until a worker has mirrored an active
     * generation into the directory. */
    gd.slot[0].epoch = 0;
    gd.slot[0].master_pid = me;
    gd.slot[0].state = FF_RELOAD_SLOT_LIVE;
    gd.slot[0].flags = FF_RELOAD_SLOT_PRIMARY;
    gd.slot[1].epoch = 1;
    gd.slot[1].gen = 0;
    gd.slot[1].master_pid = me;
    gd.slot[1].state = FF_RELOAD_SLOT_LIVE;
    gd.slot[2].epoch = 2;
    gd.slot[2].gen = 1;
    gd.slot[2].master_pid = me;
    gd.slot[2].state = FF_RELOAD_SLOT_LIVE;

    assert_int_equal(ff_reload_gendir_install(&gd, sizeof(gd)), 0);
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_reload_set_epoch(0);
    ff_reload_set_gen(0);

    /* no active mirror yet: report the newest live master, not slot 0 */
    memset(&m, 0, sizeof(m));
    ff_reload_msg_fill(&m, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    assert_int_equal(m.reload.epoch, 2);
    assert_int_equal(m.reload.active_gen, 1);

    /* that master retires: the fallback follows the next newest one */
    gd.slot[2].state = FF_RELOAD_SLOT_DEAD;
    memset(&m, 0, sizeof(m));
    ff_reload_msg_fill(&m, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    assert_int_equal(m.reload.epoch, 1);
    assert_int_equal(m.reload.active_gen, 0);

    /* no other master left: pre-M5 behaviour, slot 0 */
    gd.slot[1].state = FF_RELOAD_SLOT_DEAD;
    memset(&m, 0, sizeof(m));
    ff_reload_msg_fill(&m, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    assert_int_equal(m.reload.epoch, 0);

    /* an explicit active word always outranks the fallback */
    gd.slot[1].state = FF_RELOAD_SLOT_LIVE;
    gd.slot[2].state = FF_RELOAD_SLOT_LIVE;
    ff_reload_gendir_active_set(1, 0);
    memset(&m, 0, sizeof(m));
    ff_reload_msg_fill(&m, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    assert_int_equal(m.reload.epoch, 1);
    assert_int_equal(m.reload.active_gen, 0);

    ff_reload_gendir_install(NULL, 0);
    ff_global_cfg.dpdk.graceful_reload = 0;
}

static void
test_ut_nr_m5_cross_master_name_isolation(void **state)
{
    static const unsigned procs[] = { 0u, 1u, 7u, 127u };
    char a[64], b[64], c[64], d[64];
    unsigned i, p;
    int g, t;

    (void)state;

    for (i = 0; i < sizeof(procs) / sizeof(procs[0]); i++) {
        p = procs[i];
        for (g = 0; g < FF_RELOAD_GEN_MAX; g++) {
            assert_int_equal(ff_reload_msg_ring_name_e(a, sizeof(a),
                FF_MSG_RING_IN, p, -1, g, 1, 1), 0);
            assert_int_equal(ff_reload_msg_ring_name_e(b, sizeof(b),
                FF_MSG_RING_IN, p, -1, g, 2, 1), 0);
            assert_int_not_equal(strcmp(a, b), 0);
            assert_non_null(strstr(a, "_e1_"));
            assert_non_null(strstr(b, "_e2_"));
            assert_true(strlen(a) <= 28);      /* RTE_RING_NAMESIZE-1 */
            assert_true(strlen(b) <= 28);

            /* the pre-M5 identity is shared by every master: that is the
             * collision this milestone exists to remove. */
            assert_int_equal(ff_reload_msg_ring_name_e(c, sizeof(c),
                FF_MSG_RING_IN, p, -1, g, 0, 1), 0);
            assert_int_equal(ff_reload_msg_ring_name_e(d, sizeof(d),
                FF_MSG_RING_IN, p, -1, g, FF_RELOAD_EPOCH_NONE, 1), 0);
            assert_string_equal(c, d);

            for (t = FF_SYSCTL; t < FF_MSG_NUM; t++) {
                assert_int_equal(ff_reload_msg_ring_name_e(a, sizeof(a),
                    FF_MSG_RING_OUT, p, t, g, 1, 1), 0);
                assert_int_equal(ff_reload_msg_ring_name_e(b, sizeof(b),
                    FF_MSG_RING_OUT, p, t, g, 2, 1), 0);
                assert_int_not_equal(strcmp(a, b), 0);
                assert_non_null(strstr(a, "_e1_"));
                assert_non_null(strstr(b, "_e2_"));
                assert_true(strlen(a) <= 28);
                assert_true(strlen(b) <= 28);
            }
        }
    }
}

static void
test_ut_nr_m5_cross_master_handover_sequence(void **state)
{
    /* Two anonymous blocks: each master owns a private one, which is the
     * whole reason a cross-master transfer needs the directory at all. */
    struct ff_reload_state st_old, st_new;
    struct ff_reload_gendir gd;
    uint32_t oe = 0, og = 0, stopped = 0;
    uint32_t me = (uint32_t)getpid();

    (void)state;

    memset(&st_old, 0, sizeof(st_old));
    memset(&st_new, 0, sizeof(st_new));
    memset(&gd, 0, sizeof(gd));
    gd.magic = FF_RELOAD_GENDIR_MAGIC;
    gd.version = FF_RELOAD_GENDIR_VERSION;
    gd.len = (uint32_t)sizeof(gd);
    gd.slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    gd.gen_max = FF_RELOAD_GEN_MAX;
    gd.active_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd.rx_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd.kni_owner_word = ((uint64_t)FF_RELOAD_EPOCH_NONE << 32);
    gd.slot[1].epoch = 1;
    gd.slot[1].master_pid = me;
    gd.slot[1].state = FF_RELOAD_SLOT_LIVE;
    gd.slot[2].epoch = 2;
    gd.slot[2].master_pid = me;
    gd.slot[2].state = FF_RELOAD_SLOT_LIVE;

    st_old.magic = FF_RELOAD_STATE_MAGIC;
    st_old.version = FF_RELOAD_STATE_VERSION;
    st_old.len = (uint32_t)sizeof(st_old);
    st_new.magic = FF_RELOAD_STATE_MAGIC;
    st_new.version = FF_RELOAD_STATE_VERSION;
    st_new.len = (uint32_t)sizeof(st_new);

    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_reload_set_gen(0);
    ff_reload_dir_sync_enable(1);
    assert_int_equal(ff_reload_gendir_install(&gd, sizeof(gd)), 0);

    /* T0: the old master (epoch 1) owns the hardware and serves. */
    ff_reload_attach_state(&st_old);
    ff_reload_set_epoch(1);
    ff_reload_dir_sync();
    assert_int_equal(ff_no_hw_mode(), 0);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 1);
    assert_int_equal(og, 0);
    /* the only route by which a master without an EAL learns the peer */
    assert_int_equal(st_old.peer_epoch, 2);
    assert_int_equal(st_old.peer_gen, 0);

    /* T3a: the old master parks and hands the coordinate over. */
    assert_int_equal(ff_reload_rx_release_epoch(st_old.peer_epoch,
        (int)st_old.peer_gen), FF_RELOAD_HANDOVER_OK);
    assert_int_equal(st_old.reserved[4], 2);  /* handed-to epoch */
    assert_int_equal(ff_reload_rx_stopped(), 1);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 2);
    assert_int_equal(stopped, 1);             /* parked until claimed */
    assert_int_equal(ff_no_hw_mode(), 1);     /* old master off the hardware */

    /* T3b: the new master claims, the hardware unparks. Note the new master
     * reads its OWN block (rx_stopped 0) — the old one's park flag is not
     * visible to it, which is why the directory has to arbitrate. */
    ff_reload_attach_state(&st_new);
    ff_reload_set_epoch(2);
    assert_int_equal(ff_reload_gendir_rx_claim(1, 0, 2, 0, 50),
        FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(stopped, 0);
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_reload_attach_state(&st_old);
    ff_reload_set_epoch(1);
    assert_int_equal(ff_no_hw_mode(), 1);

    /* RT-04b rollback while the new master is alive: refused. */
    assert_int_equal(ff_reload_gendir_rx_reclaim(1, 0),
        FF_RELOAD_HANDOVER_BUSY);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 2);

    /* ... and granted once its epoch is gone. */
    gd.slot[2].state = FF_RELOAD_SLOT_DEAD;
    assert_int_equal(ff_reload_gendir_rx_reclaim(1, 0),
        FF_RELOAD_HANDOVER_OK);
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 1);
    assert_int_equal(stopped, 0);
    /* reclaim() only clears the DIRECTORY park flag. The master must also
     * drop its own hand-over target (reserved[4]) and unpark its block —
     * ff_reload_master_abort() is the existing path that does both. Without
     * that reset the old generation's workers keep publishing the dead
     * epoch as the rx owner on every dir_sync() pass and the rollback never
     * resumes service. */
    ff_reload_master_abort();
    assert_int_equal(st_old.reserved[4], 1);
    assert_int_equal(ff_reload_rx_stopped(), 0);
    assert_int_equal(ff_no_hw_mode(), 0);     /* old generation serving again */

    /* The rolled-back generation's workers may still be alive (draining).
     * They must stay off the hardware and must not be able to steal it back
     * by mirroring their own block: double poll is the failure this
     * milestone exists to prevent. */
    gd.slot[2].state = FF_RELOAD_SLOT_LIVE;
    ff_reload_attach_state(&st_new);
    ff_reload_set_epoch(2);
    assert_int_equal(ff_no_hw_mode(), 1);
    ff_reload_dir_sync();
    assert_int_equal(ff_reload_gendir_rx_owner(&oe, &og, &stopped), 0);
    assert_int_equal(oe, 1);
    ff_reload_attach_state(&st_old);
    ff_reload_set_epoch(1);
    assert_int_equal(ff_no_hw_mode(), 0);

    ff_reload_gendir_install(NULL, 0);
    ff_reload_dir_sync_enable(0);
    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_reload_set_epoch(0);
    ff_reload_attach_state(NULL);
}
