#include <ker/reload.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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


static struct ff_reload_state *borrowed;
static int polling;
static int polled;

size_t ker_reload_state_size(void)
{
    return sizeof(struct ff_reload_state);
}

int ker_reload_state_valid(const void *storage, size_t size)
{
    return storage && !((uintptr_t)storage % _Alignof(struct ff_reload_state)) &&
        ff_reload_state_valid(storage, size);
}

int ker_reload_state_init(void *storage, size_t size, int generation)
{
    if (borrowed && storage == borrowed) return -EBUSY;
    if (!storage || size < sizeof(struct ff_reload_state) ||
        (uintptr_t)storage % _Alignof(struct ff_reload_state) ||
        generation < 0 || generation >= FF_RELOAD_GEN_MAX)
        return -EINVAL;
    struct ff_reload_state *state = storage;
    memset(state, 0, sizeof(*state));
    state->magic = FF_RELOAD_STATE_MAGIC;
    state->version = FF_RELOAD_STATE_VERSION;
    state->len = sizeof(*state);
    state->active_gen = state->target_gen = state->kni_owner_gen =
        state->rx_owner_gen = (uint32_t)generation;
    state->peer_epoch = FF_RELOAD_EPOCH_NONE;
    return 0;
}

int ker_reload_bind_state(void *storage, size_t size, uint32_t epoch, int generation)
{
    if (borrowed) return -EBUSY;
    if (!ker_reload_state_valid(storage, size) || epoch == FF_RELOAD_EPOCH_NONE ||
        generation < 0 || generation >= FF_RELOAD_GEN_MAX)
        return -EINVAL;
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_reload_set_epoch(epoch);
    ff_reload_set_gen(generation);
    ff_reload_set_slot(-1);
    ff_reload_attach_state(storage);
    borrowed = storage;
    polled = 0;
    return 0;
}

void ker_reload_unbind_state(void)
{
    if (polling) {
        fputs("ker reload: unbind while caller is polling\n", stderr);
        abort();
    }
    if (!borrowed) return;
    ff_reload_attach_state(NULL);
    ff_reload_gendir_install(NULL, 0);
    ff_reload_set_epoch(0);
    ff_reload_set_gen(0);
    ff_reload_set_slot(-1);
    ff_global_cfg.dpdk.graceful_reload = 0;
    borrowed = NULL;
    polled = 0;
}

int ker_reload_poll(ker_reload_poll_fn poll, void *argument)
{
    if (polling) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (!poll || ff_reload_slot() < 0) return -EINVAL;
    polled = 1;
    ff_reload_heartbeat_tick();
    if (ff_no_hw_mode()) {
        ff_reload_handover_ack();
        return 0;
    }
    polling = 1;
    int result = poll(argument);
    polling = 0;
    return result;
}

int ker_reload_worker_select(int generation, unsigned slot)
{
    if (polling) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (generation < 0 || generation >= FF_RELOAD_GEN_MAX || slot >= FF_RELOAD_MAX_PROCS)
        return -EINVAL;
    ff_reload_set_gen(generation);
    ff_reload_set_slot((int)slot);
    return 0;
}

int ker_reload_selected_generation(void) { return ff_reload_gen(); }
int ker_reload_rx_owner(void) { return ff_reload_rx_owner_gen(); }
int ker_reload_rx_stopped(void) { return ff_reload_rx_stopped(); }
int ker_reload_rx_allowed(void) { return !ff_no_hw_mode(); }

int ker_reload_set_enabled(int enabled)
{
    if (polling || polled) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (enabled != 0 && enabled != 1) return -EINVAL;
    ff_global_cfg.dpdk.graceful_reload = enabled;
    return 0;
}

int ker_reload_rx_mark(int owner, int stopped)
{
    if (polling) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (owner < 0 || owner >= FF_RELOAD_GEN_MAX || (stopped != 0 && stopped != 1))
        return -EINVAL;
    ff_reload_rx_stopped_set(stopped);
    ff_reload_rx_owner_gen_set(owner);
    return 0;
}

_Static_assert(KER_RELOAD_HANDOVER_TIMEOUT == FF_RELOAD_HANDOVER_TIMEOUT, "source result ABI");

int ker_reload_rx_release(int to_generation)
{
    if (polling) return -EBUSY;
    return ff_reload_rx_release(to_generation);
}

int ker_reload_rx_claim(int from_generation, int to_generation, unsigned timeout_ms)
{
    if (polling) return -EBUSY;
    return ff_queue_handover_mutex(0, 0, from_generation, to_generation, timeout_ms);
}

int ker_reload_park_arm(uint32_t *epoch)
{
    if (polling) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    ff_reload_handover_arm(epoch);
    return 0;
}

int ker_reload_parked(unsigned slot, uint32_t epoch) { return ff_reload_handover_parked(slot, epoch); }

int ker_reload_park_ack(void)
{
    if (polling) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (ff_reload_slot() < 0) return -EINVAL;
    ff_reload_handover_ack();
    return 0;
}

int ker_reload_runtime_view(struct ker_reload_runtime *view)
{
    if (!view) return -EINVAL;
    *view = (struct ker_reload_runtime){
        .attached = ff_reload_state_attached(),
        .active_generation = ff_reload_active_gen(),
        .target_generation = ff_reload_target_gen(),
        .worker_generation = ff_reload_worker_gen(),
        .reload_active = ff_reload_hw_locked(),
        .observation_owner_generation = ff_reload_kni_owner_gen(),
        .rx_owner = ff_reload_rx_owner_gen(),
        .rx_stopped = ff_reload_rx_stopped(),
        .round_epoch = ff_reload_shared_epoch(),
        .heartbeat = ff_reload_heartbeat_counter(),
        .heartbeat_stalls = borrowed ? __atomic_load_n(&borrowed->heartbeat_stalls, __ATOMIC_SEQ_CST) : 0,
    };
    return 0;
}

int ker_reload_round_begin(uint32_t *epoch, uint32_t *target_generation)
{
    if (polling) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (ff_reload_hw_locked()) return -EBUSY;
    ff_reload_master_begin(epoch, target_generation);
    return 0;
}

int ker_reload_round_finish(int commit)
{
    if (polling) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (!ff_reload_hw_locked() || (commit != 0 && commit != 1)) return -EINVAL;
    if (commit) ff_reload_master_complete();
    else ff_reload_master_abort();
    return 0;
}
