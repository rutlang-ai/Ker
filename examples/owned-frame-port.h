#ifndef EXAMPLE_OWNED_FRAME_PORT_H
#define EXAMPLE_OWNED_FRAME_PORT_H
#include "owned-frame-send.h"
struct rte_ring;
struct example_frame_port {
    struct rte_mempool *pool;
    struct rte_ring *wire;
    struct example_owned_sender *sender;
    uint16_t port;
};
/* Caller example's original net_ring loopback device; not a physical NIC. */
int example_frame_port_open(struct example_frame_port *port);
int example_frame_port_close(struct example_frame_port *port);
struct rte_mbuf *example_frame_from_bytes(struct rte_mempool *pool,
    const unsigned char *bytes, unsigned length);
#endif
