/* Admission for the original same-master worker, whose reload block and
 * graceful configuration are already attached by the unchanged caller.
 * The original ff_mod_init subsequently registers its own dispatcher. */
#define _GNU_SOURCE
#include <ngx_config.h>
#include <ngx_core.h>
#include <ff_config.h>
#include <ff_reload.h>
#include "ff_flow_map.h"
#include "ff-owner-admission-control.h"
#include "ff-admission-task.h"
#include "nginx-source-bootstrap.h"
#include "socket-broker-preload-internal.h"
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern struct ff_config ff_global_cfg;

static struct ker_nginx_source_bootstrap_record admission_binding;
static struct ff_reload_state *admission_source;
static pid_t admission_pid, admission_tid;
static int admission_prepared, admission_retired;
static int admission_retire_requested;

/* Called only by the authenticated original owner loop, after its source FSM
 * closes the window. Keep the map available while the native task disables
 * its hook, drains every pending admission/revoke, and acknowledges RETIRED. */
int ker_nginx_source_owner_admission_steady(void)
{
    if (!admission_prepared || admission_pid != getpid() ||
            admission_tid != (pid_t)syscall(SYS_gettid) ||
            !ker_sb_preload_owner_loop_active()) return -EPERM;
    if (!admission_retire_requested) {
        if (ker_sb_preload_ff_owner_admission_retire()) return -errno;
        admission_retire_requested = 1;
    }
    struct ker_ff_owner_admission_window window = {0};
    if (ker_sb_preload_ff_owner_admission_status(&window)) return -errno;
    if (window.status) return window.status < 0 ? window.status : -EPROTO;
    if (window.state == KER_FF_ADMISSION_TASK_RETIRED)
        return admission_retired ? 1 : -EPROTO;
    return window.state == KER_FF_ADMISSION_TASK_RETIRING ? 0 : -EPROTO;
}

static int source_live(void *context)
{
    (void)context;
    typedef int (*binding_live_fn)(const struct ker_nginx_source_bootstrap_record *);
    binding_live_fn live = (binding_live_fn)dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_source_worker_binding_live");
    struct ff_reload_state **source = dlsym(RTLD_DEFAULT, "ngx_ff_reload_shm");
    return admission_prepared && !admission_retired && live &&
        !live(&admission_binding) && source && *source == admission_source &&
        admission_pid == getpid() && admission_tid == (pid_t)syscall(SYS_gettid) &&
        ker_sb_preload_owner_loop_active() && ff_reload_state_attached() &&
        ff_global_cfg.dpdk.graceful_reload == 1 &&
        ff_reload_gen() == (int)admission_binding.generation &&
        admission_source->epoch == admission_binding.source_epoch &&
        admission_source->target_gen == admission_binding.generation &&
        ff_flow_map_active();
}

static int map_active(void *context)
{
    (void)context;
    return admission_prepared && !admission_retired && ff_flow_map_active();
}

static int admit(const struct ker_ff_admission_key *key, int *created, void *context)
{
    if (!key || !created || !source_live(context)) return -ESTALE;
    struct ff_flow_key original;
    _Static_assert(sizeof(original) == sizeof(*key), "original admission key layout");
    memcpy(&original, key, sizeof(original));
    return ff_flow_map_admit(&original, created);
}

static int revoke_key(const struct ker_ff_admission_key *key, void *context)
{
    if (!key || !source_live(context)) return -ESTALE;
    struct ff_flow_key original;
    memcpy(&original, key, sizeof(original));
    return ff_flow_map_revoke(&original);
}

static int retire(void *context)
{
    if (!source_live(context)) return -ESTALE;
    /* Retiring native SYN admission must not erase the original classifier's
     * flow table: it still identifies old TCP tuples until the source FSM
     * confirms that generation drained. Its source loop owns that lifetime. */
    admission_retired = 1;
    return 0;
}

static int rearm(void *context)
{
    (void)context;
    /* Only the first source HUP is delegated in this bounded profile. */
    return -EOPNOTSUPP;
}

int ker_nginx_source_owner_admission_prepare(
    const struct ker_nginx_source_bootstrap_record *binding, int slot)
{
    typedef int (*binding_live_fn)(const struct ker_nginx_source_bootstrap_record *);
    binding_live_fn live = (binding_live_fn)dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_source_worker_binding_live");
    struct ff_reload_state **source = dlsym(RTLD_DEFAULT, "ngx_ff_reload_shm");
    if (!binding || !live || live(binding) || admission_prepared || slot < 3 ||
        binding->flags != KER_NGINX_SOURCE_WORKER_CANDIDATE ||
        !source || !*source || (uintptr_t)*source != binding->source_block_address ||
        !ff_reload_state_valid(*source, sizeof(**source)) ||
        !ff_reload_state_attached() || ff_global_cfg.dpdk.graceful_reload != 1 ||
        ff_reload_gen() != (int)binding->generation ||
        (*source)->epoch != binding->source_epoch ||
        (*source)->target_gen != binding->generation ||
        !ff_reload_hw_locked() || ff_flow_map_active()) return -EPROTO;

    admission_binding = *binding;
    admission_source = *source;
    admission_pid = getpid();
    admission_tid = (pid_t)syscall(SYS_gettid);
    /* Prepare the same original table ff_mod_init opens immediately after
     * ff_init returns. Preserve generation, directory epoch, and gr1. */
    ff_flow_map_open();
    if (!ff_flow_map_active()) return -ENOTCONN;
    admission_prepared = 1;
    const struct ker_ff_admission_map_ops ops = {
        .context_live = source_live, .active = map_active, .admit = admit,
        .revoke = revoke_key, .retire = retire, .rearm = rearm};
    int status = ker_sb_preload_owner_loop_enter();
    if (!status) {
        if (ker_sb_preload_ff_owner_admission_attach(&ops) ||
            ker_sb_preload_ff_owner_candidate_listener_prepare(slot))
            status = errno ? -errno : -EPROTO;
        ker_sb_preload_owner_loop_leave();
    }
    if (status) {
        /* The caller must fail ff_init and exit, releasing its staged claim
         * and admission channel; there is no successful partial binding. */
        admission_prepared = 0;
        ff_flow_map_close();
    }
    return status;
}
