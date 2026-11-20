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
