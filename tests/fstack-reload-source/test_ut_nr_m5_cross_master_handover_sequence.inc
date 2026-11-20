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
