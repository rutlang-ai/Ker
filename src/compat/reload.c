#define _GNU_SOURCE
#include <ker/reload.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "ff_config.h"
/* Keep the exact upstream configuration layout private. Only its original
 * graceful_reload field is consumed by this runtime translation unit. */
struct ff_config ff_global_cfg;
#include "ff_reload.c"

static int borrowed;
size_t ker_reload_state_size(void) { return sizeof(struct ff_reload_state); }
int ker_reload_state_init(void *storage, size_t size, int generation)
{
    if (borrowed && storage == g_reload_state) return -EBUSY;
    if (!storage || size < sizeof(struct ff_reload_state) ||
        (uintptr_t)storage % _Alignof(struct ff_reload_state) || generation < 0 || generation >= FF_RELOAD_GEN_MAX)
        return -EINVAL;
    struct ff_reload_state *state = storage;
    memset(state, 0, sizeof(*state));
    state->magic = FF_RELOAD_STATE_MAGIC;
    state->version = FF_RELOAD_STATE_VERSION;
    state->len = sizeof(*state);
    state->active_gen = state->target_gen = state->kni_owner_gen = state->rx_owner_gen = (uint32_t)generation;
    state->peer_epoch = FF_RELOAD_EPOCH_NONE;
    return 0;
}
int ker_reload_bind_state(void *storage, size_t size, uint32_t epoch, int generation)
{
    if (borrowed) return -EBUSY;
    if (!storage || (uintptr_t)storage % _Alignof(struct ff_reload_state) ||
        !ff_reload_state_valid(storage, size) || epoch == FF_RELOAD_EPOCH_NONE ||
        generation < 0 || generation >= FF_RELOAD_GEN_MAX) return -EINVAL;
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_reload_set_epoch(epoch);
    ff_reload_set_gen(generation);
    ff_reload_attach_state(storage);
    borrowed = 1;
    return 0;
}
void ker_reload_unbind_state(void)
{
    ff_reload_attach_state(NULL);
    ff_reload_gendir_install(NULL, 0);
    ff_reload_set_epoch(0);
    ff_reload_set_gen(0);
    ff_global_cfg.dpdk.graceful_reload = 0;
    borrowed = 0;
}
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
