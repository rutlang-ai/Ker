#include <ker/reload.h>
#include <ker/reload-tx.h>
#include <rte_eal.h>
#include <rte_bus_vdev.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "reload-frame-cycle.h"
struct example_reload_cycle {
    void *state;
    struct rte_mempool *pool;
    struct rte_ring *rx[2], *tx[2], *wire;
    struct ker_reload_tx *sender[2];
    const struct rte_eth_rxtx_callback *hook;
    uint16_t port;
    unsigned bound, started, hooks, lcore;
    uint64_t tx_calls, tx_packets;
};
static uint16_t observe_tx(uint16_t port, uint16_t queue, struct rte_mbuf **packets,
    uint16_t count, void *opaque)
{
    struct example_reload_cycle *c = opaque;
    if (port != c->port || queue != 0 || !packets || !count) abort();
    ++c->tx_calls; c->tx_packets += count;
    return count;
}
static int valid(const struct example_reload_cycle *c)
{
    return c && rte_eal_process_type() == RTE_PROC_PRIMARY && rte_lcore_id() == c->lcore;
}
int example_reload_cycle_open(struct example_reload_cycle **out)
{
    if (!out || *out || rte_eal_process_type() != RTE_PROC_PRIMARY || rte_lcore_id() == LCORE_ID_ANY)
        return -EINVAL;
    struct ker_reload_runtime view;
    if (ker_reload_runtime_view(&view) || view.attached) return -EBUSY;
    struct example_reload_cycle *c = calloc(1, sizeof(*c));
    if (!c) return -ENOMEM;
    c->port = UINT16_MAX; c->lcore = rte_lcore_id();
    const char *step = "state binding";
    c->state = calloc(1, ker_reload_state_size());
    if (!c->state || ker_reload_state_init(c->state, ker_reload_state_size(), 0) ||
        ker_reload_bind_state(c->state, ker_reload_state_size(), 1, 0)) goto failure;
    c->bound = 1;
    if (ker_reload_worker_select(0, 0)) goto failure;
    step = "pool/ring creation";
    c->pool = rte_pktmbuf_pool_create("reload_cycle_pool", 511, 0, 0, 512, SOCKET_ID_ANY);
    c->rx[0] = rte_ring_create("drain_rx_p0_q0_g0", 64, SOCKET_ID_ANY, 0);
    c->rx[1] = rte_ring_create("drain_rx_p0_q0_g1", 64, SOCKET_ID_ANY, 0);
    c->tx[0] = rte_ring_create("drain_tx_p0_q0_g0", 64, SOCKET_ID_ANY, 0);
    c->tx[1] = rte_ring_create("drain_tx_p0_q0_g1", 64, SOCKET_ID_ANY, 0);
    c->wire = rte_ring_create("reload_cycle_wire", 64, SOCKET_ID_ANY, 0);
    if (!c->pool || !c->rx[0] || !c->rx[1] || !c->tx[0] || !c->tx[1] || !c->wire) goto failure;
    step = "ethdev creation";
    struct rte_ring *rings[] = {c->wire};
    int created = rte_eth_from_rings("reload_cycle", rings, 1, rings, 1, SOCKET_ID_ANY);
    if (created < 0) goto failure;
    c->port = (uint16_t)created;
    step = "ethdev configuration";
    struct rte_eth_conf config = {0};
    if (rte_eth_dev_configure(c->port, 1, 1, &config) ||
        rte_eth_rx_queue_setup(c->port, 0, 64, SOCKET_ID_ANY, NULL, c->pool) ||
        rte_eth_tx_queue_setup(c->port, 0, 64, SOCKET_ID_ANY, NULL)) goto failure;
    *out = c; return 0;
failure:
    fprintf(stderr, "reload-frame startup failed at %s: rte_errno=%d errno=%d\n", step, rte_errno, errno);
    (void)example_reload_cycle_close(&c); return -EIO;
}
struct ker_reload_tx *example_reload_cycle_register(struct example_reload_cycle *c)
{
    if (!valid(c) || c->sender[0] || c->sender[1]) return NULL;
    if (ker_reload_tx_create(c->pool, c->tx[0], c->port, 0, &c->sender[0]) ||
        ker_reload_tx_create(c->pool, c->tx[1], c->port, 0, &c->sender[1])) return NULL;
    return c->sender[0];
}
int example_reload_cycle_start(struct example_reload_cycle *c)
{
    if (!valid(c) || !c->sender[0] || !c->sender[1] || c->started) return -EINVAL;
    int result = rte_eth_dev_start(c->port);
    if (result) return result;
    c->started = 1;
    c->hook = rte_eth_add_tx_callback(c->port, 0, observe_tx, c);
    if (!c->hook) return -ENOMEM;
    c->hooks = 1;
    return 0;
}
int example_reload_cycle_ready(const struct example_reload_cycle *c)
{
    if (!valid(c)) return 0;
    const char *names[] = {"drain_rx_p0_q0_g0", "drain_rx_p0_q0_g1", "drain_tx_p0_q0_g0", "drain_tx_p0_q0_g1"};
    struct rte_ring *expected[] = {c->rx[0], c->rx[1], c->tx[0], c->tx[1]};
    for (unsigned i = 0; i < 4; ++i)
        if (!expected[i] || rte_ring_lookup(names[i]) != expected[i]) return 0;
    return 1;
}
unsigned example_reload_cycle_hooks(const struct example_reload_cycle *c) { return c->hooks; }
uint64_t example_reload_cycle_tx_calls(const struct example_reload_cycle *c) { return c->tx_calls; }
uint64_t example_reload_cycle_tx_packets(const struct example_reload_cycle *c) { return c->tx_packets; }
uint16_t example_reload_cycle_port(const struct example_reload_cycle *c) { return c->port; }
struct rte_mempool *example_reload_cycle_pool(struct example_reload_cycle *c) { return c->pool; }
struct rx_context { struct example_reload_cycle *cycle; unsigned generation; };
static int receive_one(void *opaque)
{
    struct rx_context *r = opaque; struct rte_mbuf *packet = NULL;
    if (rte_eth_rx_burst(r->cycle->port, 0, &packet, 1) != 1) return -ENODATA;
    if (rte_ring_enqueue(r->cycle->rx[r->generation], packet)) {
        rte_pktmbuf_free(packet); return -ENOBUFS;
    }
    return 1;
}
static int forbidden(void *opaque) { (void)opaque; abort(); }
static int handover(unsigned from, unsigned to)
{
    uint32_t epoch;
    /* No callback is in flight: both logical workers run on this one lcore. */
    if (ker_reload_worker_select((int)from, from) || ker_reload_park_arm(&epoch) ||
        ker_reload_rx_mark((int)from, 1) || ker_reload_poll(forbidden, NULL) ||
        !ker_reload_parked(from, epoch) || ker_reload_rx_release((int)to) ||
        ker_reload_worker_select((int)to, to) || ker_reload_rx_claim((int)from, (int)to, 100)) return -EIO;
    return 0;
}
int example_reload_cycle_transfer(struct example_reload_cycle *c, struct rte_mbuf **input,
    struct rte_mbuf **output)
{
    if (!valid(c) || !c->started || !c->hook || !input || !*input || !output || *output) return -EINVAL;
    if (ker_reload_worker_select(0, 0) || !ker_reload_rx_allowed() || rte_ring_enqueue(c->wire, *input)) return -EBUSY;
    *input = NULL;
    for (unsigned from = 0; from < 2; ++from) {
        struct rx_context r = {c, from};
        if (ker_reload_poll(receive_one, &r) != 1 || handover(from, 1 - from) ||
            ker_reload_worker_select((int)from, from)) return -EIO;
        struct rte_mbuf *packet = NULL;
        if (rte_ring_dequeue(c->rx[from], (void **)&packet) ||
            ker_reload_tx_owned(c->sender[from], &packet) || packet || rte_ring_count(c->tx[from]) != 1)
            return -EIO;
        /* A parked worker cannot dequeue its own TX ring or call the PMD. */
        uint64_t before = c->tx_calls;
        if (ker_reload_tx_drain(c->sender[from], c->tx[from]) != 0 || c->tx_calls != before ||
            rte_ring_count(c->tx[from]) != 1 || ker_reload_worker_select((int)(1 - from), 1 - from) ||
            ker_reload_tx_drain(c->sender[1 - from], c->tx[from]) != 1) return -EIO;
    }
    struct rx_context r = {c, 0};
    if (ker_reload_poll(receive_one, &r) != 1 || rte_ring_dequeue(c->rx[0], (void **)output)) return -EIO;
    return 0;
}
int example_reload_cycle_close(struct example_reload_cycle **pointer)
{
    if (!pointer || !*pointer) return -EINVAL;
    struct example_reload_cycle *c = *pointer;
    if (!valid(c)) return -EXDEV;
    for (unsigned g = 0; g < 2; ++g) {
        if ((c->rx[g] && !rte_ring_empty(c->rx[g])) || (c->tx[g] && !rte_ring_empty(c->tx[g]))) return -EBUSY;
        if (c->sender[g]) {
            struct ker_reload_tx_stats stats;
            if (ker_reload_tx_snapshot(c->sender[g], &stats) || stats.staged) return -EBUSY;
        }
    }
    if ((c->wire && !rte_ring_empty(c->wire)) || (c->pool && rte_mempool_avail_count(c->pool) != 511)) return -EBUSY;
    for (unsigned g = 0; g < 2; ++g) if (c->sender[g] && ker_reload_tx_destroy(&c->sender[g])) return -EIO;
    if (c->hook) {
        if (rte_eth_remove_tx_callback(c->port, 0, c->hook)) return -EIO;
        rte_free((void *)c->hook);
    }
    if (c->started && rte_eth_dev_stop(c->port)) return -EIO;
    if (c->port != UINT16_MAX && rte_vdev_uninit("net_ring_reload_cycle")) return -EIO;
    for (unsigned g = 0; g < 2; ++g) { rte_ring_free(c->rx[g]); rte_ring_free(c->tx[g]); }
    rte_ring_free(c->wire); if (c->pool) rte_mempool_free(c->pool);
    if (c->bound) ker_reload_unbind_state();
    free(c->state); free(c); *pointer = NULL; return 0;
}
