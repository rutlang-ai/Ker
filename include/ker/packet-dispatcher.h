#ifndef KER_PACKET_DISPATCHER_H
#define KER_PACKET_DISPATCHER_H
#include <ker/ker.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Literal upstream callback declarations/layout with public Ker names. */
#define dispatch_func_t ker_dispatcher_fn
#define dispatch_func_context_t ker_dispatcher_context_fn
#define ff_dispatcher_context ker_dispatcher_context
#include <ker/detail/fstack-dispatch-api.inc>
#undef ff_dispatcher_context
#undef dispatch_func_context_t
#undef dispatch_func_t
struct rte_mbuf;
/* Optional ker::packet_dispatcher. Registration is process-wide. Plain takes
 * precedence over context when both are set, as in F-Stack. Replacement and
 * unregister wait for previous dispatches to finish. Returns0 or EDEADLK for
 * registration from a callback, leaving the registration unchanged. */
KER_API int ker_packet_dispatcher_register(ker_dispatcher_fn callback);
KER_API int ker_packet_dispatcher_register_context(ker_dispatcher_context_fn callback);
KER_API int ker_packet_dispatcher_unregister(void);
KER_API int ker_packet_dispatcher_unregister_context(void);
/* Borrow one caller-owned mbuf, its first-segment data and writable local
 * length. Callback receives original queue/count and optional VLAN metadata:
 * stripped flag and network-order TCI, or both0. Result and output length are
 * returned unchanged. No callback returns the current queue. The adapter
 * never frees/enqueues/transmits the mbuf or changes its length/flags.
 *
 * The caller owns routing/response/drop policy and validates a changed length
 * before changing mbuf metadata. Legacy results -1/-2/-3 mean error/response/
 * peer; this API forwards them and does not implement FreeBSD peer routing.
 * No EAL needed by dispatch itself. Invalid arguments return-1/errno EINVAL.
 * Callbacks must not longjmp out. Deferred cancellation releases the lease;
 * registration defers cancellation until completion. Not async-signal-safe;
 * fork only with quiescent callers. */
KER_API int ker_packet_dispatch(struct rte_mbuf *packet, uint16_t *length,
    uint16_t queue, uint16_t queues);
#ifdef __cplusplus
}
#endif
#endif
