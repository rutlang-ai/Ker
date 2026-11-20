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
