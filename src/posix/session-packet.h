/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_SESSION_PACKET_H
#define KER_SESSION_PACKET_H
#include <stdint.h>
#include <stdatomic.h>
#include <signal.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "worker-exception.h"
#include "session-generation-rings.h"
#define KER_SESSION_PACKET_RX "ker_session_packet_rx"
#define KER_SESSION_PACKET_TX "ker_session_packet_tx"
#define KER_SESSION_GENERATION_RX_BATCH_MAX 32U
#define KER_SESSION_GENERATION_RX_IDLE_WAIT_MS 100U
static inline int ker_session_generation_rx_wait_timeout_ms(unsigned delivered)
{
    return delivered >= KER_SESSION_GENERATION_RX_BATCH_MAX ? 0 :
        (int)KER_SESSION_GENERATION_RX_IDLE_WAIT_MS;
}
#define KER_SESSION_PACKET_PORT "net_ring_ker_packet"
/* Original ring PMD with independent inbound/outbound queues. The secondary
 * is both the PMD consumer and the software-device backing for a byte-only
 * external Ethernet endpoint. No primary packet relay or protocol logic. */
int ker_session_packet_create(struct rte_ring **rx, struct rte_ring **tx);
int ker_session_packet_endpoint(int fd, int type);
/* Deliver one authenticated generation RX lease to its original Linux
 * session endpoint. 0 means no packet/EAGAIN, 1 means complete datagram
 * delivery and exact lease release, negative errno means fail closed. */
int ker_session_generation_rx_deliver(int packet_fd,
    struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,
    struct rte_mbuf **pending);
/* Drain at most one bounded generation-RX batch. A full batch tells the
 * caller to recheck its control/heartbeat sources without sleeping before
 * trying again. Empty, dequeue-EAGAIN, or socket backpressure ends the batch. */
int ker_session_generation_rx_drain_batch(int packet_fd,
    struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,
    struct rte_mbuf **pending, unsigned *delivered);
/* Drain one opposite-generation TX lease to the physical wire datagram sink. */
int ker_session_generation_peer_tx_deliver(int wire_fd,
    struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,
    struct rte_mbuf **pending);
typedef int (*ker_session_heartbeat_fn)(void *context);
#ifdef KER_SESSION_TEST_HOOKS
typedef int (*ker_session_packet_test_control_fn)(char command, void *context);
#endif
struct ker_session_packet_stats {
    uint64_t tx, rx, to_wire, from_wire, exception_to_wire, exception_from_wire;
    uint64_t exception_to_native, fragment_to_native, exception_endpoint_owner_key;
    unsigned retained;
    int status;
};
int ker_session_packet_loop(uint16_t port, int packet_fd, int wire_fd, int mtu_fd,
    int control, int registration_fd, int resident_pidfd, _Atomic uint64_t *owner, uint64_t expected_owner,
    struct rte_mbuf *tx_packet, struct rte_mbuf *rx_packet,
    struct ker_worker_exception *exception, const volatile sig_atomic_t *stopping,
    struct ker_generation_rings *generation_rings,
    const struct ker_generation_identity *generation_identity,
    ker_session_heartbeat_fn heartbeat_tick, ker_session_heartbeat_fn heartbeat_pump,
    void *heartbeat_context,
#ifdef KER_SESSION_TEST_HOOKS
    ker_session_packet_test_control_fn test_control, void *test_control_context,
#endif
    struct ker_session_packet_stats *stats);
#endif
