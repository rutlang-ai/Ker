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

static void
rx15_ring_empty(struct rte_ring *r)
{
    void *obj;

    while (rte_ring_dequeue(r, &obj) == 0)
        rte_pktmbuf_free((struct rte_mbuf *)obj);
}

static void
rx15_ring_put(struct rte_mempool *pool, struct rte_ring *r)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);

    assert_non_null(m);
    assert_int_equal(rte_ring_enqueue(r, m), 0);
}

static void
test_rx15_primary_purges_orphaned_rings(void **state)
{
    static uint16_t port_list[1] = { 0 };
    static struct ff_port_cfg port_cfgs[1];
    static struct ff_reload_gendir gd;
    struct rte_mempool *pool;
    struct rte_ring *rx11, *rx10, *tx11;
    uint32_t gone;
    unsigned avail;

    (void)state;
    if (equiv_eal_init_once() < 0) {
        printf("[INFO] rte_eal_init failed; RX-15 purge skipped\n");
        skip();
        return;
    }
    pool = rte_pktmbuf_pool_create("ut_rx15_pool", 64, 0, 0, 256,
        SOCKET_ID_ANY);
    if (pool == NULL) {
        printf("[INFO] mbuf pool failed; RX-15 purge skipped\n");
        skip();
        return;
    }
    avail = rte_mempool_avail_count(pool);
    gone = p1_dead_pid();

    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_global_cfg.dpdk.nb_ports = 1;
    ff_global_cfg.dpdk.portid_list = port_list;
    memset(port_cfgs, 0, sizeof(port_cfgs));
    port_cfgs[0].nb_lcores = 1;
    ff_global_cfg.dpdk.port_cfgs = port_cfgs;
    ff_global_cfg.dpdk.drain_ring_size = 64;
    lcore_conf[0].socket_id = 0;
    ff_reload_set_gen(0);
    assert_int_equal(ff_drain_ring_init(), 0);

    /* ring slot 1 (epoch 1): drain_rx of gen 1 and gen 0, drain_tx of gen 1 */
    rx11 = rte_ring_lookup("drain_rx_p0_q0_e1_g1");
    rx10 = rte_ring_lookup("drain_rx_p0_q0_e1_g0");
    tx11 = rte_ring_lookup("drain_tx_p0_q0_e1_g1");
    assert_non_null(rx11);
    assert_non_null(rx10);
    assert_non_null(tx11);
    rx15_ring_empty(rx11);
    rx15_ring_empty(rx10);
    rx15_ring_empty(tx11);

    /* no directory: nothing proves the consumer is gone */
    ff_reload_gendir_install(NULL, 0);
    rx15_ring_put(pool, rx11);
    assert_int_equal(ff_drain_ring_purge_orphans(), 0);
    assert_int_equal(rte_ring_count(rx11), 1);

    memset(&gd, 0, sizeof(gd));
    gd.magic = FF_RELOAD_GENDIR_MAGIC;
    gd.version = FF_RELOAD_GENDIR_VERSION;
    gd.len = (uint32_t)sizeof(gd);
    gd.slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    gd.gen_max = FF_RELOAD_GEN_MAX;
    assert_int_equal(ff_reload_gendir_install(&gd, sizeof(gd)), 0);

    /* (1, 1) has no dead user: the packet may be for a process that is
     * still starting, so it stays (pid 1 stands for a live (1, 0) user) */
    gd.ring_user[1].epoch = 1;
    gd.ring_user[1].gen = 0;
    gd.ring_user[1].pid = 1u;
    gd.ring_user[1].state = FF_RELOAD_USER_ACTIVE;
    (void)ff_drain_ring_purge_orphans();
    assert_int_equal(rte_ring_count(rx11), 1);

    /* (1, 1) exited without detaching while (1, 0) is live: its drain_rx
     * goes, drain_tx stays (a live hardware owner may be reading it) */
    gd.ring_user[0].epoch = 1;
    gd.ring_user[0].gen = 1;
    gd.ring_user[0].pid = gone;
    gd.ring_user[0].state = FF_RELOAD_USER_ACTIVE;
    rx15_ring_put(pool, rx10);
    rx15_ring_put(pool, tx11);
    assert_true(ff_drain_ring_purge_orphans() >= 1);
    assert_int_equal(rte_ring_count(rx11), 0);
    assert_int_equal(rte_ring_count(rx10), 1);
    assert_int_equal(rte_ring_count(tx11), 1);
    assert_int_equal(gd.ring_user[0].pid, gone);

    /* a purge held by another live process: hands off */
    rx15_ring_put(pool, rx11);
    gd.ring_purge_owner = 1u;
    assert_int_equal(ff_drain_ring_purge_orphans(), 0);
    assert_int_equal(rte_ring_count(rx11), 1);
    /* a recycled-slot reset waits for the lock and reports a timeout */
    ff_reload_reclaim_timeout_set(20);
    assert_int_equal(ff_drain_ring_reset_slot(1), -1);
    assert_int_equal(rte_ring_count(rx11), 1);
    ff_reload_reclaim_timeout_set(0);
    gd.ring_purge_owner = 0;

    /* the live user detaches: nobody is attached any more, drain_tx goes
     * too and the slot's dead marker is forgotten; drain_rx of (1, 0)
     * never had a dead consumer and is kept */
    gd.ring_user[1].pid = 0;
    assert_true(ff_drain_ring_purge_orphans() >= 2);
    assert_int_equal(rte_ring_count(rx11), 0);
    assert_int_equal(rte_ring_count(tx11), 0);
    assert_int_equal(rte_ring_count(rx10), 1);
    assert_int_equal(gd.ring_user[0].pid, 0);
    assert_int_equal(gd.ring_purge_owner, 0);

    /* with the marker gone, a new packet for (1, 1) is kept again */
    rx15_ring_put(pool, rx11);
    (void)ff_drain_ring_purge_orphans();
    assert_int_equal(rte_ring_count(rx11), 1);

    /* with the lock free the reset empties the whole slot */
    rx15_ring_put(pool, tx11);
    assert_int_equal(ff_drain_ring_reset_slot(1), 0);
    assert_int_equal(rte_ring_count(rx11), 0);
    assert_int_equal(rte_ring_count(rx10), 0);
    assert_int_equal(rte_ring_count(tx11), 0);
    assert_int_equal(gd.ring_purge_owner, 0);
    assert_int_equal(rte_mempool_avail_count(pool), avail);

    ff_drain_ring_unregist();
    ff_reload_gendir_install(NULL, 0);
    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_global_cfg.dpdk.nb_ports = 0;
    ff_global_cfg.dpdk.portid_list = NULL;
    ff_global_cfg.dpdk.port_cfgs = NULL;
    ff_global_cfg.dpdk.drain_ring_size = 0;
}
