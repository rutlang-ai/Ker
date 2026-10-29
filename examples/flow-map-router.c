/* Caller-side single-thread UDP metadata routing demonstration. No PCB,
 * handshake or protocol state is implemented here. All packets are private
 * synthetic L3 fixtures, transported by original DPDK net_ring queues. */
#define _GNU_SOURCE
#include "flow-map-policy.h"
#include <ker/reload.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "flow router: %s errno=%d\n", #x, errno); exit(1); } } while (0)
static struct rte_ring *input, *local, *peer, *tx;
static struct rte_mempool *pool;
static uint16_t port;
static unsigned callbacks, delivered;

static void eal(void)
{
    cpu_set_t allowed;
    CHECK(!sched_getaffinity(0, sizeof(allowed), &allowed));
    int cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); cpu++) {}
    CHECK(cpu < CPU_SETSIZE);
    char mapping[64], prefix[64];
    snprintf(mapping, sizeof(mapping), "--lcores=0@%d", cpu);
    snprintf(prefix, sizeof(prefix), "--file-prefix=flow-router-%ld", (long)getpid());
    char *args[] = {"flow-router", mapping, prefix, "--no-huge", "--no-pci",
        "--no-shconf", "--iova-mode=va", "--no-telemetry", "-m", "64", NULL};
    CHECK(rte_eal_init((int)(sizeof(args) / sizeof(args[0])) - 1, args) >= 0);
}
static struct rte_mbuf *packet(const ff_flow_key_t *key)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(pool); CHECK(m);
    unsigned size = key->af == FF_FLOW_MAP_V4 ? 28 : 48;
    uint8_t *b = (uint8_t *)rte_pktmbuf_append(m, size); CHECK(b);
    memset(b, 0, size);
    unsigned udp;
    if (key->af == FF_FLOW_MAP_V4) {
        b[0] = 0x45; b[3] = 28; b[8] = 64; b[9] = 17;
        memcpy(b + 12, key->src, 4); memcpy(b + 16, key->dst, 4); udp = 20;
    } else {
        b[0] = 0x60; b[5] = 8; b[6] = 17; b[7] = 64;
        memcpy(b + 8, key->src, 16); memcpy(b + 24, key->dst, 16); udp = 40;
    }
    memcpy(b + udp, &key->sport, 2); memcpy(b + udp + 2, &key->dport, 2); b[udp + 5] = 8;
    return m;
}
static int route(void *argument)
{
    CHECK(argument == pool);
    struct rte_mbuf *m;
    if (!rte_eth_rx_burst(port, 0, &m, 1)) return 0;
    callbacks++;
    int result = example_flow_route(m, local, peer);
    if (result) rte_pktmbuf_free(m); /* failed enqueue retains caller ownership */
    return result;
}
static void deliver(const ff_flow_key_t *key, unsigned queue)
{
    struct rte_mbuf *m = packet(key), *received = NULL;
    uint8_t expected[48]; unsigned size = m->pkt_len;
    memcpy(expected, rte_pktmbuf_mtod(m, void *), size);
    CHECK(!rte_ring_enqueue(input, m));
    unsigned before = callbacks;
    CHECK(!ker_reload_poll(route, pool)); CHECK(callbacks == before + 1);
    CHECK(rte_eth_rx_burst(port, queue, &received, 1) == 1);
    CHECK(received == m && received->pkt_len == size);
    CHECK(!memcmp(rte_pktmbuf_mtod(received, void *), expected, size));
    rte_pktmbuf_free(received); delivered++;
    CHECK(rte_ring_empty(input) && rte_ring_empty(local) && rte_ring_empty(peer));
    CHECK(rte_mempool_avail_count(pool) == 63);
}
int main(void)
{
    eal();
    pool = rte_pktmbuf_pool_create("flow_pool", 63, 0, 0, 512, SOCKET_ID_ANY); CHECK(pool);
    input = rte_ring_create("flow_input", 8, SOCKET_ID_ANY, 0);
    local = rte_ring_create("flow_local", 8, SOCKET_ID_ANY, 0);
    peer = rte_ring_create("flow_peer", 8, SOCKET_ID_ANY, 0);
    tx = rte_ring_create("flow_tx", 8, SOCKET_ID_ANY, 0);
    CHECK(input && local && peer && tx);
    struct rte_ring *rx[] = {input, local, peer}, *out[] = {tx};
    int created_port = rte_eth_from_rings("flow_router", rx, 3, out, 1, SOCKET_ID_ANY);
    CHECK(created_port >= 0); port = (uint16_t)created_port;
    struct rte_eth_conf conf = {0};
    CHECK(!rte_eth_dev_configure(port, 3, 1, &conf));
    for (unsigned i = 0; i < 3; i++) CHECK(!rte_eth_rx_queue_setup(port, i, 8, SOCKET_ID_ANY, NULL, pool));
    CHECK(!rte_eth_tx_queue_setup(port, 0, 8, SOCKET_ID_ANY, NULL));
    CHECK(!rte_eth_dev_start(port));
    size_t size = ker_reload_state_size(); void *state = calloc(1, size); CHECK(state);
    CHECK(!ker_reload_state_init(state, size, 0));
    CHECK(!ker_reload_bind_state(state, size, 1, 0));
    CHECK(!ker_reload_worker_select(0, 0));
    example_flow_enable(1);
    for (unsigned family = 0; family < 2; family++) {
        ff_flow_key_t key = {0}; key.af = family;
        key.src[0] = 0x0100000a; key.dst[0] = 0x0200000a;
        if (family) { key.src[3] = 0x01000000; key.dst[3] = 0x02000000; }
        key.sport = 0x3412; key.dport = 0x5000;
        for (unsigned round = 0; round < 2; round++) {
            ff_flow_map_close(); deliver(&key, 1); /* untracked normal local path */
            ff_flow_map_open(); deliver(&key, 2); /* unknown caller metadata -> peer */
            int fresh = 0;
            CHECK(ff_flow_map_admit(&key, &fresh) == 1 && fresh == 1); deliver(&key, 1);
            fresh = 1; CHECK(ff_flow_map_admit(&key, &fresh) == 1 && fresh == 0); deliver(&key, 1);
            CHECK(ff_flow_map_revoke(&key) == 1); deliver(&key, 2);
            CHECK(ff_flow_map_insert(&key) == 0); deliver(&key, 1);
            ff_flow_map_close(); ff_flow_map_open(); deliver(&key, 2);
        }
        /* Full output queue: failed enqueue leaves ownership with the caller. */
        unsigned capacity = rte_ring_get_capacity(peer);
        for (unsigned i = 0; i < capacity; i++) CHECK(!rte_ring_enqueue(peer, packet(&key)));
        struct rte_mbuf *held = packet(&key);
        CHECK(example_flow_route(held, local, peer) == -ENOBUFS);
        CHECK(held->refcnt == 1 && rte_mempool_avail_count(pool) == 63 - capacity - 1);
        rte_pktmbuf_free(held);
        while (!rte_ring_empty(peer)) { CHECK(!rte_ring_dequeue(peer, (void **)&held)); rte_pktmbuf_free(held); }
        CHECK(rte_mempool_avail_count(pool) == 63);
        /* Production gate must deny the callback without consuming its input. */
        CHECK(!rte_ring_enqueue(input, packet(&key)));
        CHECK(!ker_reload_rx_mark(1, 0));
        unsigned before = callbacks;
        CHECK(!ker_reload_poll(route, pool)); CHECK(callbacks == before && rte_ring_count(input) == 1);
        CHECK(!ker_reload_rx_mark(0, 0)); CHECK(!ker_reload_poll(route, pool));
        CHECK(rte_eth_rx_burst(port, 2, &held, 1) == 1); rte_pktmbuf_free(held); delivered++;
        CHECK(rte_mempool_avail_count(pool) == 63);
    }
    /* Unsupported packet profile must preserve caller ownership and queues. */
    ff_flow_key_t key = {0}; struct rte_mbuf *bad = packet(&key);
    rte_pktmbuf_mtod(bad, uint8_t *)[9] = 6; /* TCP is outside this UDP example */
    CHECK(example_flow_route(bad, local, peer) == -EPROTONOSUPPORT);
    CHECK(bad->refcnt == 1 && rte_ring_empty(local) && rte_ring_empty(peer)); rte_pktmbuf_free(bad);
    ff_flow_map_close(); example_flow_enable(0); ker_reload_unbind_state(); free(state);
    struct rte_eth_stats statistics; CHECK(!rte_eth_stats_get(port, &statistics));
    CHECK(statistics.ipackets == 2 * delivered && delivered == 30 && callbacks == 30);
    CHECK(rte_mempool_avail_count(pool) == 63);
    CHECK(!rte_eth_dev_stop(port)); CHECK(!rte_eth_dev_close(port));
    rte_ring_free(input); rte_ring_free(local); rte_ring_free(peer); rte_ring_free(tx); rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    puts("PASS: real EAL/net_ring IPv4+IPv6 caller metadata routing 30/30; gate denial, queue-full ownership, unsupported TCP, pool63/63 and cleanup");
    return 0;
}
