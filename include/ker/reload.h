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
/* Same-master polling adapter, optionally gated by reload-directory.h. A
 * controller must wait for every old worker's exact park-epoch acknowledgement
 * before releasing ownership.
 * Callback runs synchronously only when the original runtime permits RX.
 * A denied pass acknowledges only after the prior callback has returned.
 * Callback owns its packet/API work; its result is forwarded unchanged.
 * Select a worker slot before polling. Serialize calls within each process;
 * recursive poll/control fails EBUSY. Unbinding inside a callback aborts.
 * Cross-master directory attachment is explicit; no hardware journal or
 * automatic crash supervisor is provided. */
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
/* Gate observation only; does not register a hardware-user lease. Use poll
 * for directory-backed hardware work. */
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
/* Original shared-block validation and read-only observations. View fields are
 * individually atomic; quiesce the controller for a coherent round snapshot. */
KER_API int ker_reload_state_valid(const void *storage, size_t size);
struct ker_reload_runtime {
    int attached, active_generation, target_generation, worker_generation;
    int reload_active, observation_owner_generation, rx_owner, rx_stopped;
    uint32_t round_epoch;
    uint64_t heartbeat, heartbeat_stalls;
};
KER_API int ker_reload_runtime_view(struct ker_reload_runtime *view);
/* Controller primitives retain original begin/commit/abort behavior. Commit
 * and abort can change RX ownership: first quiesce every affected callback and
 * obtain the required park proof. They do not replace that proof or supervise
 * processes. Re-entry into an open round is rejected. */
KER_API int ker_reload_round_begin(uint32_t *epoch, uint32_t *target_generation);
KER_API int ker_reload_round_finish(int commit);
/* Heartbeats count target-generation loop passes while a round is open,
 * including denied RX passes. Poll ticks automatically. Other event loops may
 * tick explicitly. Timeout and sample stamps use the caller's same monotonic
 * units (e.g. original DPDK timer cycles); timeout0 disables detection.
 * A detected stall is observation only and never transfers RX ownership. */
KER_API int ker_reload_heartbeat_timeout(uint64_t timeout);
KER_API int ker_reload_heartbeat_tick(void);
KER_API int ker_reload_heartbeat_sample(uint64_t now);
KER_API int ker_reload_heartbeat_eval(uint64_t previous, uint64_t current,
    uint64_t now, uint64_t *last_advance, uint64_t timeout);
/* Trusted-caller READY bookkeeping, correlated to the current round and PID;
 * it is not authentication or proof that native listening sockets exist. */
KER_API int ker_reload_ready_publish(unsigned slot, int pid);
KER_API int ker_reload_ready_matches(unsigned slot, int pid, uint32_t epoch);
#endif
