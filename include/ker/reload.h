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
#endif
