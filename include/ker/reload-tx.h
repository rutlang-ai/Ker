#ifndef KER_RELOAD_TX_H
#define KER_RELOAD_TX_H
#include <ker/ker.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct rte_mbuf;
struct rte_mempool;
struct rte_ring;
struct ker_reload_tx;
#define KER_RELOAD_TX_BURST 32
struct ker_reload_tx_stats {
    uint64_t accepted, diverted, full, divert_dropped_segments;
    uint64_t hardware_calls, hardware_packets, hardware_dropped_segments;
    uint64_t guard_dropped_segments;
    unsigned staged;
    int last_poll_error;
};
/* Optional ker::reload_tx. Caller configures/starts and owns the port/queue,
 * pool and its generation's TX drain ring. Serialize calls and reload control;
 * select the actual worker through ker::reload before every event-loop pass.
 * These APIs transfer bytes/mbufs only, with no protocol or peer selection.
 * All resources must remain alive until staged and ring-owned packets clear.
 * Recursive use of the same context from a PMD callback returns -EBUSY.
 * Hardware bursts run only inside the synchronous ker_reload_poll gate.
 * Run these TX entrypoints outside an existing ker_reload_poll callback:
 * the bridge owns burst admission; nested gate errors drop/count an already
 * accepted batch and return the error rather than transmitting without proof.
 * Directory lifetime/park proof requirements of that API still apply. */
KER_API int ker_reload_tx_create(struct rte_mempool *, struct rte_ring *,
    uint16_t port, uint16_t queue, struct ker_reload_tx **);
/* Empty-only; returns -EBUSY rather than discard staged packets. */
KER_API int ker_reload_tx_destroy(struct ker_reload_tx **);
/* Valid input is consumed (*packet=NULL): owner stages up to32, parked worker
 * diverts to its own drain ring. A full ring drops/counts and returns0, as in
 * the source divert contract. Prevalidation errors retain input. A negative
 * poll error after acceptance consumes/drops the batch and is recorded. */
KER_API int ker_reload_tx_owned(struct ker_reload_tx *, struct rte_mbuf **);
/* Contiguous borrowed bytes; the caller retains its input. Allocation or room
 * failure is returned before acceptance. No user-pointer fault recovery. */
KER_API int ker_reload_tx_copy(struct ker_reload_tx *, const void *, uint16_t);
/* Caller has selected RESPONSE policy. Stage a single-segment reply (length
 * may only trim); the final burst guard drops/counts if ownership is lost.
 * No automatic VLAN insertion, checksum/offload or TCP reply generation. */
KER_API int ker_reload_tx_reply(struct ker_reload_tx *, struct rte_mbuf **, uint16_t length);
/* Defensive flush: a denied hardware gate drops staged packets, never bursts.
 * A normal parked loop pass instead diverts staged residue into its own ring. */
KER_API int ker_reload_tx_flush(struct ker_reload_tx *);
KER_API int ker_reload_tx_pass(struct ker_reload_tx *);
/* Owner-only, at most32 packets from an explicitly caller-selected drain ring.
 * A denied gate returns0 without dequeue. Return is packets processed; PMD
 * shortfalls are freed/counted, not retried with ambiguous ownership. */
KER_API int ker_reload_tx_drain(struct ker_reload_tx *, struct rte_ring *);
/* Return the oldest staged packet to caller ownership (1), or0 when empty. */
KER_API int ker_reload_tx_cancel(struct ker_reload_tx *, struct rte_mbuf **);
KER_API int ker_reload_tx_snapshot(const struct ker_reload_tx *, struct ker_reload_tx_stats *);
#ifdef __cplusplus
}
#endif
#endif
