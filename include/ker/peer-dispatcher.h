#ifndef KER_PEER_DISPATCHER_H
#define KER_PEER_DISPATCHER_H
#include <ker/packet-dispatcher.h>
#ifdef __cplusplus
extern "C" {
#endif
struct rte_ring;
enum ker_peer_dispatch_result {
    KER_PEER_FORWARDED = 0,
    KER_PEER_DROPPED = 1,
    KER_PEER_PASSTHROUGH = 2
};
#define KER_DISPATCH_PEER (-3)
struct ker_peer_dispatch_stats {
    uint64_t forwarded, full, closed, dropped_segments;
};
/* Optional ker::peer_dispatcher owns only the PEER (-3) result path. Callback
 * always borrows data under the existing dispatcher registration lease.
 * Non-PEER results return PASSTHROUGH with *packet unchanged and the original
 * decision/length for caller policy. On PEER, a live bound ker::reload round
 * permits enqueue to the caller-selected opposite-generation ring; otherwise
 * drop. Successful enqueue transfers ownership; a full ring or closed round
 * frees exactly once. Both consumed outcomes set *packet=NULL. Callback length
 * edits never alter PEER mbuf metadata (the original upstream behavior).
 * Negative errno leaves *packet with the caller, even if callback ran.
 * decision and length outputs are valid only after callback dispatch.
 *
 * The caller owns and validates the ring's port/queue/epoch identity and keeps
 * it alive for this call. This API does not create/authenticate rings, choose
 * peers or implement USR2 mirror/draining-peer selection. Serialize reload
 * control, this call and stats accesses; quiesce users before unbind/release.
 * The ordinary borrowed dispatcher API retains its ownership contract. */
KER_API int ker_packet_dispatch_peer(struct rte_mbuf **packet, uint16_t *length,
    uint16_t queue, uint16_t queues, struct rte_ring *peer,
    int *decision, struct ker_peer_dispatch_stats *stats);
#ifdef __cplusplus
}
#endif
#endif
