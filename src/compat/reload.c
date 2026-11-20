#include <ker/reload.h>
#include "ff_config.h"
#include "ff_reload.h"

/* Original reload code uses the pinned config layout and starts inactive. */
struct ff_config ff_global_cfg;

void ker_reload_message_fill(ker_ipc_message *message, int command,
    int generation, int status, uint64_t heartbeat)
{
    ff_reload_msg_fill(message, command, generation, status, heartbeat);
}

int ker_reload_message_parse(const ker_ipc_message *message, int *command,
    int *generation, int *status, uint64_t *heartbeat)
{
    return ff_reload_msg_parse(message, command, generation, status, heartbeat);
}
