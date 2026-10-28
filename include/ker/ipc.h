#ifndef KER_IPC_H
#define KER_IPC_H
#include <ker/ker.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#ifdef __cplusplus
#error "ker::ipc preserves the pinned C-only F-Stack message layout; use a C adapter"
#endif
#include <ker/fstack/ff_msg.h>

/* Optional ker::ipc component: pinned F-Stack shared-message transport, not
 * the Ker resident's authenticated internal session protocol. The original
 * message layout/type tags are preserved. Payload commands are interpreted by
 * the caller, not this library; no FreeBSD control operation is implemented.
 * Only cooperating, trusted processes in the caller's EAL namespace may use
 * these pointer-bearing queues. This is not an authentication boundary.
 * The pinned client has one process-global pending request. Serialize all
 * API calls and keep its pool/rings alive until all accepted requests return. */
#define KER_IPC_GEN_AUTO (-1)
#define KER_IPC_EPOCH_NONE UINT32_MAX
struct ker_ipc_address { uint16_t process; int generation; uint32_t epoch; };
typedef struct ff_msg ker_ipc_message;
struct rte_mempool;

/* Argument compatibility entrypoints retain upstream's explicit exit(1) on
 * malformed input. Call before attach. A busy attached client returns -EBUSY.
 * process: PROC[:GEN[:EPOCH]], generation override: GEN[:EPOCH]. NULL options
 * select process0/AUTO/unspecified epoch. Return selected process on success.
 * The snapshot preserves AUTO and EPOCH_NONE rather than guessing a target. */
KER_API int ker_ipc_select_or_exit(const char *process, const char *generation);
KER_API int ker_ipc_epoch_or_exit(uint32_t epoch);
KER_API int ker_ipc_address(struct ker_ipc_address *address);
KER_API unsigned ker_ipc_epoch_slot(uint32_t epoch);
/* Provider-side builder for caller-created rings. generation_aware=0 preserves
 * the legacy unsuffixed namespace regardless of generation/epoch. No EAL is
 * needed to format a name. A too-small buffer returns the upstream -1. */
KER_API int ker_ipc_format_ring(char *buffer, size_t size,
    const struct ker_ipc_address *address, int output, enum FF_MSG_TYPE type,
    int generation_aware);
/* output=0: input ring, type ignored; output=1: type-specific reply ring.
 * Detached explicit coordinates can be formatted without EAL. AUTO cannot
 * be resolved without a live provider and returns -EAGAIN while detached. */
KER_API int ker_ipc_ring_name(char *buffer, size_t size, int output, enum FF_MSG_TYPE type);

/* The caller initializes original EAL and owns its lifetime. Create a typed
 * original DPDK pool (payload0..10240, cache0), then borrow it with attach.
 * Both original EAL primary and secondary roles are accepted; transport
 * requires explicit generation unless an actual legacy proc0 input ring exists;
 * AUTO then uses original legacy detection. Probe requires process0.
 * Attach accepts only cache0 typed pools. No implicit root-only EAL initialization or cleanup occurs in this adapter.
 * Pool/ring destruction remains the caller's responsibility after reclamation.
 * DPDK creation failures return NULL/rte_errno; guards return negative errno. */
KER_API struct rte_mempool *ker_ipc_pool_create(const char *name, unsigned count, unsigned payload);
KER_API int ker_ipc_attach(struct rte_mempool *pool);
/* Detach requires a quiescent pool: pending/stashed or any outstanding pool
 * object returns -EBUSY, including timed-out requests still owned by a provider. Never
 * silently frees another live client's reply or tears down the caller's EAL. */
KER_API int ker_ipc_detach(void);
/* Transport results retain upstream 0/success and negative/failure values.
 * alloc/free/send take only messages from the attached typed pool. alloc
 * stamps current pid/nonzero cookie; a sent request remains transport-owned
 * until returned. Never free a pending request or a foreign-owned message. */
KER_API ker_ipc_message *ker_ipc_alloc(void);
KER_API int ker_ipc_free(ker_ipc_message *message);
KER_API int ker_ipc_send(const ker_ipc_message *message);
KER_API int ker_ipc_recv(ker_ipc_message **message, enum FF_MSG_TYPE type);
/* Bounded source QUERY probe of existing primary ring coordinates. A timed
 * out accepted request may still belong to the input ring/provider; drain it
 * before destroying the pool. Unrelated replies remain owned by their client. */
KER_API int ker_ipc_probe(uint32_t *epoch, int *generation);
KER_API void ker_ipc_reply_stats(uint64_t *foreign_requeued, uint64_t *orphan_dropped,
    uint64_t *reply_lost);
#endif
