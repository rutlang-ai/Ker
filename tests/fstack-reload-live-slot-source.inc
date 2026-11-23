static void
p1_directory_conflict(int full)
{
    unsigned i, attempt;
    uint64_t owner;
    struct ff_reload_epoch_slot primary;
    p1_dir->next_epoch = 0;
    for (i = 0; i < (full ? FF_RELOAD_EPOCH_SLOT_MAX : 2u); i++) {
        p1_dir->slot[i].epoch = i;
        p1_dir->slot[i].state = FF_RELOAD_SLOT_LIVE;
        p1_dir->slot[i].master_pid = getpid();
    }
    primary = p1_dir->slot[0];
    owner = p1_dir->rx_owner_word;
    p1_process_type = RTE_PROC_SECONDARY;
    p1_parent = __real_getppid();
    ff_reload_set_epoch(9);
    for (attempt = 0; attempt < 2; attempt++) {
        p1_dir->next_epoch = 0;
        expect_assert_failure(ff_reload_gendir_attach());
        assert_int_equal(ff_reload_gendir_present(), 0);
        assert_int_equal(ff_reload_epoch(), 9);
        assert_int_equal(ff_reload_gendir_reset_pending(), 0);
        ff_reload_dir_sync();
        assert_int_equal(p1_dir->rx_owner_word, owner);
        assert_memory_equal(&p1_dir->slot[0], &primary, sizeof(primary));
        if (!full)
            assert_int_equal(p1_dir->slot[2].master_pid, 0);
    }
}

static void test_p1_directory_live_slot(void **state) { (void)state; p1_directory_conflict(0); }