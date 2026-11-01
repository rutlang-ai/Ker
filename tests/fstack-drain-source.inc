static struct ff_config p1_saved_cfg;
static struct lcore_conf p1_saved_qconf;
static struct ff_reload_state p1_reload;
static struct ff_reload_gendir *p1_dir;
static struct rte_ring *p1_rings[2][2][2];
static struct rte_mempool *p1_pool;
static struct ff_port_cfg p1_port;
static uint16_t p1_port_id;

static int
p1_teardown(void **state)
{
    unsigned tx, q, gen;
    void *obj;
    (void)state;
    p1_process_type = -1;
    p1_parent = 0;
    p1_missing_directory = 0;
    ff_reload_dir_sync_enable(0);
    ff_reload_gendir_detach();
    ff_reload_attach_state(NULL);
    for (tx = 0; tx < 2; tx++)
        for (q = 0; q < 2; q++)
            for (gen = 0; gen < 2; gen++)
                while (p1_rings[tx][q][gen] != NULL &&
                    rte_ring_dequeue(p1_rings[tx][q][gen], &obj) == 0)
                    rte_pktmbuf_free(obj);
    ff_drain_ring_unregist();
    if (p1_pool != NULL) {
        assert_int_equal(rte_mempool_avail_count(p1_pool), 64);
        rte_mempool_free(p1_pool);
        p1_pool = NULL;
    }
    ff_global_cfg = p1_saved_cfg;
    lcore_conf[0] = p1_saved_qconf;
    ff_reload_set_epoch(0);
    ff_reload_set_gen(0);
    return 0;
}

static int
p1_setup(void **state)
{
    const struct rte_memzone *mz;
    unsigned tx, q, gen;
    char name[64];
    (void)state;
    p1_saved_cfg = ff_global_cfg;
    p1_saved_qconf = lcore_conf[0];
    memset(p1_rings, 0, sizeof(p1_rings));
    assert_true(equiv_eal_init_once() >= 0);
    ff_reload_gendir_detach();
    ff_reload_dir_sync_enable(0);
    memset(&p1_reload, 0, sizeof(p1_reload));
    p1_reload.magic = FF_RELOAD_STATE_MAGIC;
    p1_reload.version = FF_RELOAD_STATE_VERSION;
    p1_reload.len = sizeof(p1_reload);
    ff_reload_attach_state(&p1_reload);
    ff_reload_set_epoch(1);
    ff_reload_set_gen(0);
    ff_global_cfg.dpdk.thread_mode = 0;
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_global_cfg.dpdk.nb_ports = 1;
    ff_global_cfg.dpdk.portid_list = &p1_port_id;
    memset(&p1_port, 0, sizeof(p1_port));
    p1_port.nb_lcores = 2;
    ff_global_cfg.dpdk.port_cfgs = &p1_port;
    ff_global_cfg.dpdk.drain_ring_size = 64;
    memset(&lcore_conf[0], 0, sizeof(lcore_conf[0]));
    lcore_conf[0].nb_rx_queue = 1;
    lcore_conf[0].rx_queue_list[0].queue_id = 0;
    lcore_conf[0].nb_tx_port = 1;
    lcore_conf[0].tx_queue_id[0] = 1;
    assert_int_equal(ff_drain_ring_init(), 0);
    p1_pool = rte_pktmbuf_pool_create("p1_drain_pool", 64, 0, 0, 256, SOCKET_ID_ANY);
    assert_non_null(p1_pool);
    for (tx = 0; tx < 2; tx++)
        for (q = 0; q < 2; q++)
            for (gen = 0; gen < 2; gen++) {
                snprintf(name, sizeof(name), "drain_%s_p0_q%u_e1_g%u",
                    tx ? "tx" : "rx", q, gen);
                p1_rings[tx][q][gen] = rte_ring_lookup(name);
                assert_non_null(p1_rings[tx][q][gen]);
                assert_int_equal(rte_ring_count(p1_rings[tx][q][gen]), 0);
            }
    mz = rte_memzone_lookup(FF_RELOAD_GENDIR_NAME);
    if (mz == NULL)
        mz = rte_memzone_reserve(FF_RELOAD_GENDIR_NAME, sizeof(*p1_dir), SOCKET_ID_ANY, 0);
    assert_non_null(mz);
    p1_dir = mz->addr;
    memset(p1_dir, 0, sizeof(*p1_dir));
    p1_dir->magic = FF_RELOAD_GENDIR_MAGIC;
    p1_dir->version = FF_RELOAD_GENDIR_VERSION;
    p1_dir->len = sizeof(*p1_dir);
    p1_dir->slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    p1_dir->gen_max = FF_RELOAD_GEN_MAX;
    p1_dir->rx_owner_word = (uint64_t)1 << 32;
    p1_dir->active_word = (uint64_t)1 << 32;
    p1_dir->kni_owner_word = (uint64_t)1 << 32;
    return 0;
}

static void
p1_drain_check(unsigned mode)
{
    unsigned tx, q, gen;
    if (mode == 1)
        p1_reload.rx_owner_gen = 1;
    if (mode == 2) {
        assert_int_equal(ff_reload_gendir_install(p1_dir, sizeof(*p1_dir)), 0);
        p1_dir->slot[2].epoch = 2;
        p1_dir->slot[2].state = FF_RELOAD_SLOT_LIVE;
        p1_dir->slot[2].master_pid = getpid();
    }
    if (mode == 3) {
        assert_int_equal(ff_reload_gendir_install(p1_dir, sizeof(*p1_dir)), 0);
        p1_dir->rx_owner_word = (uint64_t)2 << 32;
    }
    if (mode == 4) {
        lcore_conf[0].nb_rx_queue = 0;
        lcore_conf[0].nb_tx_port = 0;
    }
    for (tx = 0; tx < 2; tx++)
        for (q = 0; q < 2; q++)
            for (gen = 0; gen < 2; gen++) {
                struct rte_mbuf *m = rte_pktmbuf_alloc(p1_pool);
                assert_non_null(m);
                assert_int_equal(rte_ring_enqueue(p1_rings[tx][q][gen], m), 0);
            }
    ff_drain_ring_unregist();
    for (tx = 0; tx < 2; tx++)
        for (q = 0; q < 2; q++)
            for (gen = 0; gen < 2; gen++) {
                int drained = gen == 0 && mode != 4 &&
                    ((!tx && q == 0) || (tx && q == 1 && mode == 0));
                assert_int_equal(rte_ring_count(p1_rings[tx][q][gen]), !drained);
            }
    assert_int_equal(rte_mempool_avail_count(p1_pool), 56 + (mode == 0 ? 2 : mode == 4 ? 0 : 1));
    ff_drain_ring_unregist();
    assert_int_equal(ff_drain_ring_ready(), 0);
    assert_int_equal(ff_drain_ring_init(), 0);
    assert_ptr_equal(rte_ring_lookup("drain_rx_p0_q0_e1_g0"), p1_rings[0][0][0]);
}

static void test_p1_drain_foreign_epoch_tx(void **state) { (void)state; p1_drain_check(3); }
