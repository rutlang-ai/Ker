static int p1_cold;
static int p1_kind = -1;
static const char *p1_oom;
static void *p1_allocs[16];
static unsigned p1_alloc_count, p1_hotplug, p1_tx_calls, p1_tx_limit;
static struct rte_ring *p1_rx, *p1_inject;
static struct rte_ring **p1_saved_rp, **p1_saved_inject;
static struct kni_interface_stats **p1_saved_stats;
static struct ff_config p1_saved_cfg;
static struct ff_reload_state p1_state;
static struct rte_eth_fp_ops p1_saved_ops;
static void *p1_tx_data[1], *p1_tx_callbacks[1];
extern struct rte_ring **kni_inject_rp;
extern void *__real_rte_zmalloc(const char *, size_t, unsigned);
extern enum rte_proc_type_t __real_rte_eal_process_type(void);
extern int __real_rte_eal_hotplug_add(const char *, const char *, const char *);
extern int __real_rte_eth_macaddr_get(uint16_t, struct rte_ether_addr *);

enum rte_proc_type_t
__wrap_rte_eal_process_type(void)
{
    return p1_kind < 0 ? __real_rte_eal_process_type() : (enum rte_proc_type_t)p1_kind;
}

void *
__wrap_rte_zmalloc(const char *type, size_t size, unsigned align)
{
    void *p;
    if (p1_cold && p1_oom && type && strcmp(type, p1_oom) == 0)
        return NULL;
    p = __real_rte_zmalloc(type, size, align);
    if (p1_cold && p != NULL) {
        assert_true(p1_alloc_count < sizeof(p1_allocs) / sizeof(p1_allocs[0]));
        p1_allocs[p1_alloc_count++] = p;
    }
    return p;
}

int
__wrap_rte_eal_hotplug_add(const char *bus, const char *name, const char *args)
{
    if (!p1_cold)
        return __real_rte_eal_hotplug_add(bus, name, args);
    p1_hotplug++;
    return 0;
}

int
__wrap_rte_eth_macaddr_get(uint16_t port, struct rte_ether_addr *addr)
{
    if (!p1_cold)
        return __real_rte_eth_macaddr_get(port, addr);
    memset(addr, 0, sizeof(*addr));
    return 0;
}

void
__wrap___rte_panic(const char *func, const char *format, ...)
{
    (void)func; (void)format;
    mock_assert(0, "rte_panic", __FILE__, __LINE__);
}

static uint16_t
p1_tx(void *queue, struct rte_mbuf **pkts, uint16_t count)
{
    uint16_t i, sent = count < p1_tx_limit ? count : p1_tx_limit;
    (void)queue;
    p1_tx_calls++;
    for (i = 0; i < sent; i++)
        rte_pktmbuf_free(pkts[i]);
    return sent;
}

static int
p1_cold_setup(void **state)
{
    (void)state;
    assert_true(eal_initialized);
    p1_saved_cfg = ff_global_cfg;
    p1_saved_rp = kni_rp;
    p1_saved_inject = kni_inject_rp;
    p1_saved_stats = kni_stat;
    p1_saved_ops = rte_eth_fp_ops[0];
    kni_rp = NULL; kni_inject_rp = NULL; kni_stat = NULL;
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));
    ff_global_cfg.dpdk.primary_slim = 1;
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_global_cfg.dpdk.proc_id = 1;
    ff_global_cfg.kni.owner_proc_id = 1;
    memset(&p1_state, 0, sizeof(p1_state));
    p1_state.magic = FF_RELOAD_STATE_MAGIC;
    p1_state.version = FF_RELOAD_STATE_VERSION;
    p1_state.len = sizeof(p1_state);
    p1_state.target_gen = 1;
    ff_reload_set_epoch(0);
    ff_reload_set_gen(1);
    ff_reload_attach_state(&p1_state);
    ff_reload_dir_sync_enable(0);
    ff_reload_gendir_install(NULL, 0);
    p1_rx = rte_ring_create("kni_ring_0", 16, SOCKET_ID_ANY, RING_F_SC_DEQ);
    p1_inject = rte_ring_create("kni_inject_0", 16, SOCKET_ID_ANY, RING_F_SC_DEQ);
    assert_non_null(p1_rx);
    assert_non_null(p1_inject);
    p1_alloc_count = p1_hotplug = p1_tx_calls = 0;
    p1_tx_limit = 3;
    p1_oom = NULL;
    p1_kind = RTE_PROC_SECONDARY;
    p1_cold = 1;
    rte_eth_fp_ops[0].tx_pkt_burst = p1_tx;
    rte_eth_fp_ops[0].txq.data = p1_tx_data;
    rte_eth_fp_ops[0].txq.clbk = p1_tx_callbacks;
    return 0;
}

static int
p1_cold_teardown(void **state)
{
    void *obj;
    (void)state;
    p1_cold = 0;
    p1_kind = -1;
    p1_oom = NULL;
    rte_eth_fp_ops[0] = p1_saved_ops;
    while (p1_rx && rte_ring_dequeue(p1_rx, &obj) == 0)
        rte_pktmbuf_free(obj);
    while (p1_inject && rte_ring_dequeue(p1_inject, &obj) == 0)
        rte_pktmbuf_free(obj);
    rte_ring_free(p1_rx);
    rte_ring_free(p1_inject);
    p1_rx = p1_inject = NULL;
    while (p1_alloc_count)
        rte_free(p1_allocs[--p1_alloc_count]);
    kni_rp = p1_saved_rp;
    kni_inject_rp = p1_saved_inject;
    kni_stat = p1_saved_stats;
    ff_global_cfg = p1_saved_cfg;
    ff_reload_attach_state(NULL);
    ff_reload_set_gen(0);
    assert_int_equal(rte_mempool_avail_count(test_pool), KNI_TEST_POOL_SZ);
    return 0;
}

static void
p1_cold_init(void)
{
    assert_int_equal(ff_kni_is_runtime_owner(), 0);
    ff_kni_init(1, NULL, NULL);
    assert_non_null(kni_stat);
    assert_null(kni_stat[0]);
    ff_kni_alloc(0, 0, 0, 16);
    assert_non_null(kni_stat[0]);
    assert_int_equal(kni_stat[0]->tx_packets, 0);
    assert_int_equal(kni_stat[0]->port_id, nb_dev_ports);
    assert_int_equal(p1_hotplug, 0);
    assert_int_equal(ff_kni_is_runtime_owner(), 0);
    ff_reload_master_complete();
    assert_int_equal(ff_kni_is_runtime_owner(), 1);
}

static void
p1_cold_tx_check(unsigned limit)
{
    struct rte_mbuf *burst[3];
    unsigned i;
    p1_cold_init();
    ff_kni_inject_process(0, 0, burst, 3);
    assert_int_equal(p1_tx_calls, 0);
    for (i = 0; i < 3; i++) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
        assert_non_null(m);
        assert_int_equal(rte_ring_enqueue(p1_inject, m), 0);
    }
    p1_tx_limit = limit;
    ff_kni_inject_process(0, 0, burst, 3);
    assert_int_equal(p1_tx_calls, 1);
    assert_int_equal(kni_stat[0]->tx_packets, limit);
    assert_int_equal(kni_stat[0]->tx_dropped, 3 - limit);
    assert_int_equal(rte_mempool_avail_count(test_pool), KNI_TEST_POOL_SZ);
}

static void test_p1_future_kni_owner(void **state) { (void)state; p1_cold_tx_check(3); }
static void test_p1_future_kni_short_tx(void **state) { (void)state; p1_cold_tx_check(1); }

static void
test_p1_future_kni_full_ring(void **state)
{
    unsigned i;
    struct rte_mbuf *m;
    (void)state;
    p1_cold_init();
    for (i = 0; i < rte_ring_get_capacity(p1_rx); i++) {
        m = rte_pktmbuf_alloc(test_pool);
        assert_non_null(m);
        assert_int_equal(ff_kni_enqueue(FILTER_ARP, 0, m), 0);
    }
    m = rte_pktmbuf_alloc(test_pool);
    assert_non_null(m);
    assert_int_equal(ff_kni_enqueue(FILTER_ARP, 0, m), -1);
    assert_int_equal(kni_stat[0]->rx_dropped, 1);
    assert_int_equal(rte_mempool_avail_count(test_pool), KNI_TEST_POOL_SZ - rte_ring_get_capacity(p1_rx));
}

static void
test_p1_kni_nonowner(void **state)
{
    (void)state;
    ff_global_cfg.dpdk.proc_id = 2;
    ff_kni_init(1, NULL, NULL);
    ff_kni_alloc(0, 0, 0, 16);
    assert_null(kni_stat);
    assert_int_equal(p1_hotplug, 0);
    assert_ptr_equal(kni_rp[0], p1_rx);
    assert_ptr_equal(kni_inject_rp[0], p1_inject);
}
