#ifndef KER_RELOAD_H
#define KER_RELOAD_H

#include <ker/ipc.h>

/* Fill the native FF_RELOAD message fields using the original F-Stack
 * implementation. This API does not start a reload or modify IPC ownership.
 * There is no reload state attached by these message-only entry points. */
KER_API void ker_reload_message_fill(ker_ipc_message *message, int command,
    int generation, int status, uint64_t heartbeat);

/* Return 0 for an FF_RELOAD message with a recognized command or -1 for
 * invalid input. Output pointers are optional and untouched on failure. */
KER_API int ker_reload_message_parse(const ker_ipc_message *message, int *command,
    int *generation, int *status, uint64_t *heartbeat);

#endif
