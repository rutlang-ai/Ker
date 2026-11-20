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

static void test_p1_drain_queue_ownership(void **state) { (void)state; p1_drain_check(0); }
static void test_p1_drain_nonowner_tx(void **state) { (void)state; p1_drain_check(1); }
static void test_p1_drain_peer_tx(void **state) { (void)state; p1_drain_check(2); }
static void test_p1_drain_foreign_epoch_tx(void **state) { (void)state; p1_drain_check(3); }
static void test_p1_drain_empty_qconf(void **state) { (void)state; p1_drain_check(4); }

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
static void test_p1_directory_full(void **state) { (void)state; p1_directory_conflict(1); }

static void
test_p1_directory_missing(void **state)
{
    (void)state;
    p1_process_type = RTE_PROC_SECONDARY;
    p1_missing_directory = 1;
    expect_assert_failure(ff_reload_gendir_attach());
    assert_int_equal(ff_reload_gendir_present(), 0);
}

static void
test_p1_directory_invalid(void **state)
{
    (void)state;
    p1_process_type = RTE_PROC_SECONDARY;
    p1_dir->version++;
    expect_assert_failure(ff_reload_gendir_attach());
    assert_int_equal(ff_reload_gendir_present(), 0);
}

static void
test_p1_directory_success(void **state)
{
    uint32_t epoch;
    (void)state;
    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_reload_gendir_attach();
    assert_int_equal(ff_reload_gendir_present(), 0);
    ff_global_cfg.dpdk.graceful_reload = 1;
    p1_process_type = RTE_PROC_SECONDARY;
    p1_parent = __real_getppid();
    ff_reload_gendir_attach();
    epoch = ff_reload_epoch();
    assert_int_equal(ff_reload_gendir_present(), 1);
    assert_int_not_equal(epoch, 0);
    ff_reload_gendir_attach();
    assert_int_equal(ff_reload_epoch(), epoch);
    assert_int_equal(p1_dir->next_epoch, epoch);
}

static void
test_p1_directory_primary_slot_busy(void **state)
{
    uint64_t owner;

    (void)state;
    /* slot 0 is the resident primary's own identity: a primary that cannot
     * claim it must not silently share it with a live predecessor. */
    owner = p1_dir->rx_owner_word;
    p1_dir->slot[0].epoch = 0;
    p1_dir->slot[0].state = FF_RELOAD_SLOT_LIVE;
    p1_dir->slot[0].master_pid = (uint32_t)__real_getppid();
    p1_process_type = RTE_PROC_PRIMARY;
    ff_reload_set_epoch(7);
    expect_assert_failure(ff_reload_gendir_attach());
    assert_int_equal(ff_reload_gendir_present(), 0);
    assert_int_equal(ff_reload_epoch(), 7);
    ff_reload_dir_sync();
    assert_int_equal(p1_dir->rx_owner_word, owner);
}

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

static void
test_f_m4_1_drain_ring_full_visible(void **state)
{
    static uint16_t port_list[1] = { 0 };
    static struct ff_port_cfg port_cfgs[1];
    static struct ff_reload_drain_state drain_state;
    struct rte_mempool *pool = NULL;
    struct rte_ring *r;
    uint64_t rx_fwd, tx_fwd, rx_peak, tx_peak;
    uint64_t rf = 0, tf = 0, td = 0;
    unsigned cap;
    int i;

    (void)state;
    if (equiv_eal_init_once() < 0) {
        printf("[INFO] rte_eal_init failed; F-M4-1 skipped\n");
        skip();
        return;
    }

    pool = rte_pktmbuf_pool_create("ut_f_m4_1_pool", 512, 0, 0, 256,
        SOCKET_ID_ANY);
    if (pool == NULL) {
        printf("[INFO] mbuf pool failed; F-M4-1 skipped\n");
        skip();
        return;
    }

    /* the shared drain block the completion summary reads its peak from */
    memset(&drain_state, 0, sizeof(drain_state));
    drain_state.magic = FF_RELOAD_DRAIN_MAGIC;
    drain_state.len = (uint32_t)sizeof(drain_state);
    assert_int_equal(ff_reload_drain_attach(&drain_state,
        sizeof(drain_state)), 0);
    ff_reload_drain_reset();

    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_global_cfg.dpdk.nb_ports = 1;
    ff_global_cfg.dpdk.portid_list = port_list;
    memset(port_cfgs, 0, sizeof(port_cfgs));
    port_cfgs[0].nb_lcores = 1;
    ff_global_cfg.dpdk.port_cfgs = port_cfgs;
    ff_global_cfg.dpdk.drain_ring_size = 64;    /* power of two */
    lcore_conf[0].socket_id = 0;
    ff_reload_set_gen(0);

    assert_int_equal(ff_drain_ring_init(), 0);
    r = rte_ring_lookup("drain_tx_p0_q0_g0");
    assert_non_null(r);
    cap = rte_ring_get_capacity(r);

    /* fill it; the enqueue after that is the one that must not stay quiet */
    for (i = 0; i < (int)cap + 4; i++) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);

        if (m == NULL) {
            break;
        }
        if (ff_drain_ring_tx_enqueue(0, 0, 0, m) != 0) {
            rte_pktmbuf_free(m);
            break;
        }
    }
    assert_int_equal((int)rte_ring_count(r), (int)cap);

    /* the ring-layer counter stays exact */
    ff_drain_ring_stats(&rf, &tf, &td);
    assert_int_equal((int)tf, 1);
    assert_int_equal((int)td, 0);

    /* and the watermark the "graceful reload complete" line prints now
     * carries the occupancy the 1 Hz sampler would have missed */
    ff_reload_drain_counters(&rx_fwd, &tx_fwd, &rx_peak, &tx_peak);
    assert_true(tx_peak >= (uint64_t)cap);
    assert_int_equal((int)rx_peak, 0);

    ff_drain_ring_unregist();
    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_global_cfg.dpdk.nb_ports = 0;
    ff_global_cfg.dpdk.portid_list = NULL;
    ff_global_cfg.dpdk.port_cfgs = NULL;
    ff_global_cfg.dpdk.drain_ring_size = 0;
}

static void
test_ut_nr_19_drain_ring_sp_sc(void **state)
{
    static uint16_t port_list[1] = { 0 };
    /* Two queues = two independent stack instances. Without a queue
     * dimension a packet would be handed to a stack that has no PCB for it
     * (it would answer RST), and two workers would share one SP/SC ring. */
    static struct ff_port_cfg port_cfgs[1];
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    struct rte_mempool *pool = NULL;
    struct rte_mbuf *m;
    struct rte_ring *r, *r_q1;
    char name[RTE_RING_NAMESIZE];
    int g, q;

    (void)state;
    if (equiv_eal_init_once() < 0) {
        printf("[INFO] rte_eal_init failed; UT-NR-19 skipped\n");
        skip();
        return;
    }

    pool = rte_pktmbuf_pool_create("ut_nr_19_pool", 128, 0, 0, 256,
        SOCKET_ID_ANY);
    if (pool == NULL) {
        printf("[INFO] mbuf pool failed; UT-NR-19 skipped\n");
        skip();
        return;
    }

    /* graceful_reload=0: no rings at all (zero-regression) */
    ff_global_cfg.dpdk.graceful_reload = 0;
    assert_int_equal(ff_drain_ring_init(), 0);
    assert_int_equal(ff_drain_ring_ready(), 0);

    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_global_cfg.dpdk.nb_ports = 1;
    ff_global_cfg.dpdk.portid_list = port_list;
    memset(port_cfgs, 0, sizeof(port_cfgs));
    port_cfgs[0].nb_lcores = 2;
    ff_global_cfg.dpdk.port_cfgs = port_cfgs;
    /* smaller than the pool so the fill loop below can actually overflow it */
    ff_global_cfg.dpdk.drain_ring_size = 64;    /* power of two */
    lcore_conf[0].socket_id = 0;
    ff_reload_set_gen(0);

    assert_int_equal(ff_drain_ring_init(), 0);
    assert_int_equal(ff_drain_ring_ready(), 1);

    /* one pair per (queue, generation). P1-a: drain_rx is multi-producer —
     * the same-queue miss forwarder and the ARP/NDP clone fan-out (any
     * peer worker, nb_queues >= 2) can race one ring — but stays
     * single-consumer; drain_tx keeps SP/SC (its only producer is the
     * parked generation's own queue worker). */
    for (q = 0; q < 2; q++) {
        for (g = 0; g < FF_RELOAD_GEN_MAX; g++) {
            snprintf(name, sizeof(name), "drain_rx_p0_q%d_g%d", q, g);
            r = rte_ring_lookup(name);
            assert_non_null(r);
            assert_int_equal(rte_ring_is_prod_single(r), 0);
            assert_int_equal(rte_ring_is_cons_single(r), 1);

            snprintf(name, sizeof(name), "drain_tx_p0_q%d_g%d", q, g);
            r = rte_ring_lookup(name);
            assert_non_null(r);
            assert_int_equal(rte_ring_is_prod_single(r), 1);
            assert_int_equal(rte_ring_is_cons_single(r), 1);
        }
    }

    /* We are gen0. rx_enqueue takes the DESTINATION generation, so a
     * flow-map miss here goes to gen1's ring; our own gen would be a
     * self-loop and is rejected outright. */
    m = rte_pktmbuf_alloc(pool);
    assert_non_null(m);
    assert_int_equal(ff_drain_ring_rx_enqueue(0, 0, 0, m), -1);
    assert_int_equal(ff_drain_ring_rx_enqueue(0, 0, 1, m), 0);
    r = rte_ring_lookup("drain_rx_p0_q0_g1");
    r_q1 = rte_ring_lookup("drain_rx_p0_q1_g1");
    assert_non_null(r_q1);
    assert_int_equal((int)rte_ring_count(r), 1);
    /* queue isolation: a queue-0 flow must not land in queue 1's ring. */
    assert_int_equal((int)rte_ring_count(r_q1), 0);
    /* our own inbound ring (gen0) is untouched by that enqueue */
    assert_int_equal(ff_drain_ring_rx_dequeue(0, 0, pkts, NULL), 0);
    assert_int_equal((int)rte_ring_count(r), 1);

    /* seen from gen1 it is ours to consume: ctx == NULL frees instead of
     * leaking, and the ring is drained either way. */
    ff_reload_set_gen(1);
    assert_int_equal(ff_drain_ring_rx_dequeue(0, 1, pkts, NULL), 0);
    assert_int_equal(ff_drain_ring_rx_dequeue(0, 0, pkts, NULL), 0);
    assert_int_equal((int)rte_ring_count(r), 0);
    assert_int_equal((int)rte_mempool_avail_count(pool), 128);
    ff_reload_set_gen(0);

    /* tx_enqueue takes the SOURCE generation, i.e. our own; gen1 reads it
     * and is the only side allowed to call rte_eth_tx_burst. */
    m = rte_pktmbuf_alloc(pool);
    assert_non_null(m);
    assert_int_equal(ff_drain_ring_tx_enqueue(0, 0, 1, m), -1);
    assert_int_equal(ff_drain_ring_tx_enqueue(0, 0, 0, m), 0);
    assert_int_equal((int)rte_ring_count(
        rte_ring_lookup("drain_tx_p0_q0_g0")), 1);
    assert_int_equal((int)rte_ring_count(
        rte_ring_lookup("drain_tx_p0_q1_g0")), 0);

    /* tx_drain on an empty peer ring returns 0 without touching ethdev */
    assert_int_equal(ff_drain_ring_tx_drain(0, 0, pkts, MAX_PKT_BURST), 0);

    /* out-of-range gen / queue / port / not-ready are rejected, mbuf stays
     * owned by the caller (R-303-1: the dispatcher must free it itself) */
    assert_int_equal(ff_drain_ring_rx_enqueue(0, 0, FF_RELOAD_GEN_MAX, m), -1);
    assert_int_equal(ff_drain_ring_tx_enqueue(0, 0, -1, m), -1);
    assert_int_equal(ff_drain_ring_rx_enqueue(RTE_MAX_ETHPORTS, 0, 0, m), -1);
    assert_int_equal(ff_drain_ring_rx_enqueue(0, 99, 0, m), -1);
    assert_int_equal(ff_drain_ring_rx_enqueue(0, 0, 0, NULL), -1);

    /* fill the rx ring: enqueue fails (counted, never a silent drop) and the
     * caller keeps the mbuf. */
    {
        uint64_t rx_full_before, rx_full_after, tx_full, tx_drop;
        int i;

        ff_drain_ring_stats(&rx_full_before, &tx_full, &tx_drop);
        for (i = 0; i < 200; i++) {
            struct rte_mbuf *mm = rte_pktmbuf_alloc(pool);
            if (mm == NULL)
                break;
            if (ff_drain_ring_rx_enqueue(0, 0, 1, mm) != 0) {
                rte_pktmbuf_free(mm);
                break;
            }
        }
        ff_drain_ring_stats(&rx_full_after, &tx_full, &tx_drop);
        assert_int_equal((int)(rx_full_after - rx_full_before), 1);
    }

    /* R-310-1: unregister detaches without destroying — the rings stay
     * lookup-able so the next reload round can reuse them. */
    ff_drain_ring_unregist();
    assert_int_equal(ff_drain_ring_ready(), 0);
    assert_int_equal(ff_drain_ring_rx_enqueue(0, 0, 1, m), -1);
    assert_int_equal(ff_drain_ring_tx_enqueue(0, 0, 0, m), -1);
    assert_int_equal(ff_drain_ring_rx_dequeue(0, 0, pkts, NULL), 0);
    assert_int_equal(ff_drain_ring_tx_drain(0, 0, pkts, MAX_PKT_BURST), 0);
    assert_non_null(rte_ring_lookup("drain_rx_p0_q0_g0"));
    ff_drain_ring_unregist();    /* idempotent */
    /* re-init reuses the pointer arrays instead of leaking a new block */
    assert_int_equal(ff_drain_ring_init(), 0);
    assert_int_equal(ff_drain_ring_ready(), 1);
    assert_non_null(rte_ring_lookup("drain_rx_p0_q1_g1"));
    ff_drain_ring_unregist();

    /* mbufs still sitting in the rings stay owned by the rings; the pool is
     * never freed (it stays registered with the EAL for the process). */
    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_global_cfg.dpdk.nb_ports = 0;
    ff_global_cfg.dpdk.portid_list = NULL;
    ff_global_cfg.dpdk.port_cfgs = NULL;
    ff_global_cfg.dpdk.drain_ring_size = 0;
}
