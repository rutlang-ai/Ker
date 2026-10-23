/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_SESSION_PACKET_H
#define KER_SESSION_PACKET_H
#include <stdint.h>
#include <stdatomic.h>
#include <signal.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#define KER_SESSION_PACKET_RX "ker_session_packet_rx"
#define KER_SESSION_PACKET_TX "ker_session_packet_tx"
#define KER_SESSION_PACKET_PORT "net_ring_ker_packet"
/* Original ring PMD with independent inbound/outbound queues. The secondary
 * is both the PMD consumer and the software-device backing for a byte-only
 * external Ethernet endpoint. No primary packet relay or protocol logic. */
int ker_session_packet_create(struct rte_ring **rx, struct rte_ring **tx);
int ker_session_packet_endpoint(int fd, int type);
int ker_session_packet_loop(uint16_t port, int packet_fd, int wire_fd, int mtu_fd,
    int control, int resident_pidfd, _Atomic uint64_t *owner, uint64_t expected_owner,
    struct rte_mbuf *tx_packet, struct rte_mbuf *rx_packet, const volatile sig_atomic_t *stopping);
#endif
