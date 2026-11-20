#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <string.h>
#include "owned-frame-port.h"
#include "worker-mbuf.h"
struct rte_mbuf *example_frame_from_bytes(struct rte_mempool *pool,
    const unsigned char *bytes, unsigned length)
{
    return ker_worker_mbuf_from_bytes(pool, bytes, length);
}
int example_frame_port_open(struct example_frame_port *p)
{
    *p = (struct example_frame_port){.port = UINT16_MAX};
    p->pool = rte_pktmbuf_pool_create("owned_frame_pool", 511, 0, 0, 512, SOCKET_ID_ANY);
    if (!p->pool) return -1;
    p->wire = rte_ring_create("owned_frame_wire", 64, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!p->wire) goto failure;
    struct rte_ring *rings[] = {p->wire};
    int id = rte_eth_from_rings("owned_frame", rings, 1, rings, 1, SOCKET_ID_ANY);
    if (id < 0) goto failure;
    p->port = (uint16_t)id;
    struct rte_eth_conf config = {0};
    if (rte_eth_dev_configure(p->port, 1, 1, &config) ||
        rte_eth_rx_queue_setup(p->port, 0, 64, SOCKET_ID_ANY, NULL, p->pool) ||
        rte_eth_tx_queue_setup(p->port, 0, 64, SOCKET_ID_ANY, NULL) ||
        rte_eth_dev_start(p->port)) goto failure;
    p->sender = example_owned_sender_new(p->pool, p->port, 0);
    if (!p->sender) goto failure;
    return 0;
failure:
    (void)example_frame_port_close(p); return -1;
}
int example_frame_port_close(struct example_frame_port *p)
{
    int result = 0;
    example_owned_sender_delete(p->sender); p->sender = NULL;
    if (p->port != UINT16_MAX) {
        if (rte_eth_dev_stop(p->port)) result = -1;
        if (rte_eth_dev_close(p->port)) result = -1;
        p->port = UINT16_MAX;
    }
    if (p->wire) {
        struct rte_mbuf *packet;
        while (rte_ring_dequeue(p->wire, (void **)&packet) == 0) rte_pktmbuf_free(packet);
        rte_ring_free(p->wire); p->wire = NULL;
    }
    if (p->pool) {
        if (rte_mempool_avail_count(p->pool) != 511) result = -1;
        rte_mempool_free(p->pool); p->pool = NULL;
    }
    return result;
}
