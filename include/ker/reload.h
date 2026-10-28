#ifndef KER_RELOAD_H
#define KER_RELOAD_H
#include <ker/ipc.h>

/* Optional ker::reload component. The original F-Stack reload runtime is
 * isolated from Ker's authenticated resident sessions. It does not implement
 * any network protocol or execute a FreeBSD control command. The caller owns
 * the state storage and all coordination. Serialize these process-global APIs;
 * stop all users before unbind/free. No EAL lifetime is owned here. */
KER_API size_t ker_reload_state_size(void);
/* Initialize aligned caller storage to the original valid block layout.
 * active_generation must be0 or1. Existing live storage must be quiesced. */
KER_API int ker_reload_state_init(void *storage, size_t size, int active_generation);
/* Borrow a valid original block. The epoch/generation identify this process;
 * no directory is installed by this entrypoint. Rebinding requires unbind. */
KER_API int ker_reload_bind_state(void *storage, size_t size, uint32_t epoch, int generation);
KER_API void ker_reload_unbind_state(void);
/* Original message fill/parse contract, including NULL fill no-op, NULL parse
 * failure and independently optional outputs. Fill samples the bound runtime's
 * coherent active coordinate. Without a bound state, original directory-less
 * defaults apply. It changes only type/result/reload fields, preserving the
 * transport's PID/cookie and payload ownership. Parse returns0 or original-1;
 * it validates the message type and known subcommand, not command support. */
KER_API void ker_reload_message_fill(ker_ipc_message *message, int command,
    int generation, int status, uint64_t heartbeat);
KER_API int ker_reload_message_parse(const ker_ipc_message *message, int *command,
    int *generation, int *status, uint64_t *heartbeat);
/* Block-only, same-master polling adapter. A controller must wait for every
 * old worker's exact park-epoch acknowledgement before releasing ownership.
 * Callback runs synchronously only when the original runtime permits RX.
 * A denied pass acknowledges only after the prior callback has returned.
 * Callback owns its packet/API work; its result is forwarded unchanged.
 * Select a worker slot before polling. Serialize calls within each process;
 * recursive poll/control fails EBUSY. Unbinding inside a callback aborts.
 * No cross-master directory, hardware journal or crash recovery is provided. */
typedef int (*ker_reload_poll_fn)(void *argument);
KER_API int ker_reload_poll(ker_reload_poll_fn poll, void *argument);
/* Select the process's generation and worker slot (0..127). Changing either
 * requires a quiescent worker. This is not an authenticated registration. */
KER_API int ker_reload_worker_select(int generation, unsigned slot);
/* Legacy enabled=0 preserves original always-poll behavior. Configure before
 * the first poll after bind; cannot change it during a polling lifetime. */
KER_API int ker_reload_set_enabled(int enabled);
KER_API int ker_reload_rx_owner(void);
KER_API int ker_reload_rx_stopped(void);
KER_API int ker_reload_rx_allowed(void);
/* Controller-only marker restoration: all affected callbacks must already be
 * quiescent. Ordinary handover uses arm, exact acknowledgements, release/claim.
 * These original marker primitives do not themselves prove quiescence. */
KER_API int ker_reload_rx_mark(int owner, int stopped);
enum ker_reload_handover_result {
    KER_RELOAD_HANDOVER_OK = 0,
    KER_RELOAD_HANDOVER_INVAL = -1,
    KER_RELOAD_HANDOVER_BUSY = -2,
    KER_RELOAD_HANDOVER_TIMEOUT = -3
};
KER_API int ker_reload_rx_release(int to_generation);
KER_API int ker_reload_rx_claim(int from_generation, int to_generation, unsigned timeout_ms);
KER_API int ker_reload_park_arm(uint32_t *epoch);
KER_API int ker_reload_parked(unsigned slot, uint32_t epoch);
/* Manual acknowledgement only after the caller has quiesced its RX callback
 * and will keep it stopped until release. Normal workers use poll's denied
 * pass instead. Acknowledgement is epoch-tagged, not an authorization token. */
KER_API int ker_reload_park_ack(void);
#endif
