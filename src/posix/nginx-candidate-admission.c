/* Private candidate-listener binding for the exact pinned Nginx caller.
 * This does not enable the Nginx generation FSM. */
#define _GNU_SOURCE
#include <ngx_config.h>
#include <ngx_core.h>
#include "nginx-candidate-map-namespace.h"
#include <ff_api.h>
#include <ff_config.h>
#include <ff_reload.h>
#include "ff_flow_map.h"
#include "ff-owner-admission-control.h"
#include "socket-broker-preload-internal.h"
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

extern volatile ngx_cycle_t *ngx_cycle;

static struct ff_reload_state *candidate_state;
struct ff_config ff_global_cfg;

#ifdef KER_NGINX_SOURCE_ADMISSION_RELAY_TEST
int ker_nginx_source_admission_prepare(struct ff_reload_state *state, int slot);
void ker_nginx_source_admission_abort(void);
#endif

struct ff_reload_state *ker_nginx_source_flowmap_state(void)
{
    return candidate_state;
}

int ker_nginx_candidate_master_prepare(ngx_cycle_t *cycle)
{
    int *enabled = dlsym(RTLD_DEFAULT, "ngx_ff_graceful_reload");
    struct ff_reload_state **block = dlsym(RTLD_DEFAULT, "ngx_ff_reload_shm");
    ngx_int_t (*create)(ngx_cycle_t *) = dlsym(RTLD_DEFAULT, "ngx_ff_reload_state_create");
    if (!enabled || !block || !create || *enabled || *block) {
        errno = EOPNOTSUPP;
        return -1;
    }
    /* Let the original caller allocate and initialize its inherited block.
     * Keep its generation orchestration disabled for this private leaf. */
    *enabled = 1;
    ngx_int_t result = create(cycle);
    *enabled = 0;
    if (result != NGX_OK || !*block || !ff_reload_state_valid(*block, sizeof(**block))) {
        errno = EPROTO;
        return -1;
    }
    candidate_state = *block;
#ifdef KER_NGINX_SOURCE_FLOWMAP_TEST
    const char *old_source = getenv("KER_NGINX_SOURCE_PEER_OLD");
    if (old_source) {
        if (strcmp(old_source, "1") || !getenv("KER_NGINX_SOURCE_PEER_PAIR")) {
            errno = EINVAL; return -1;
        }
        uint32_t epoch = 0, target = 0;
        /* Prime a completed 0->1 round, then prepare the original 1->0
         * window in which this worker's original callback will be armed.
         * No source structure fields or protocol state are manufactured. */
        ff_reload_master_begin(&epoch, &target);
        if (target != 1 || !epoch) { errno = EPROTO; return -1; }
        ff_reload_set_epoch(epoch);
        ff_reload_master_complete();
        ff_reload_master_begin(&epoch, &target);
        ff_reload_set_epoch(epoch);
        if (epoch != 2 || target != 0 || !ff_reload_hw_locked()) { errno = EPROTO; return -1; }
    }
    const char *source_test = getenv("KER_NGINX_SOURCE_FLOWMAP_TEST");
    if (source_test && strcmp(source_test, "1") != 0) {
        errno = EINVAL;
        return -1;
    }
    if (source_test) {
        uint32_t epoch = 0, target = 0;
        /* Exercise the original reload window transition API against the
         * source-created block. This is a private classifier fixture, not a
         * production HUP/FSM lifecycle claim. */
        ff_reload_master_begin(&epoch, &target);
        if (!epoch || target >= FF_RELOAD_GEN_MAX ||
            !ff_reload_state_attached() || !ff_reload_hw_locked()) {
            errno = EPROTO;
            return -1;
        }
    }
#endif
#ifdef KER_NGINX_SOURCE_ADMISSION_RELAY_TEST
    const char *source_admission = getenv("KER_NGINX_SOURCE_ADMISSION_RELAY");
    if (source_admission) {
        if (strcmp(source_admission, "1") != 0) {
            errno = EINVAL;
            return -1;
        }
        uint32_t epoch = 0, target = 0;
        if (getenv("KER_NGINX_SOURCE_PEER_PAIR")) {
            for (unsigned round = 0; round < 2; ++round) {
                ff_reload_master_begin(&epoch, &target);
                if (!epoch || target != (round ^ 1u)) { errno = EPROTO; return -1; }
                ff_reload_set_epoch(epoch);
                ff_reload_master_complete();
            }
        }
        ff_reload_master_begin(&epoch, &target);
        if (epoch) ff_reload_set_epoch(epoch);
        if (!epoch || target >= FF_RELOAD_GEN_MAX ||
            !ff_reload_state_attached() || !ff_reload_hw_locked() ||
            ff_reload_epoch() != epoch || ff_reload_target_gen() != (int)target) {
            errno = EPROTO;
            return -1;
        }
    }
#endif
    return 0;
}

static int context_live(void *context)
{
    (void)context;
    return candidate_state && ff_reload_state_attached() && ff_global_cfg.dpdk.graceful_reload;
}

static int active(void *context)
{
    (void)context;
    return ff_flow_map_active();
}

static int admit(const struct ker_ff_admission_key *key, int *created, void *context)
{
    (void)context;
    struct ff_flow_key original;
    _Static_assert(sizeof(original) == sizeof(*key), "admission key layout");
    memcpy(&original, key, sizeof(original));
    int allowed = ff_flow_map_admit(&original, created);
    static int reported;
    if (!reported && allowed == 1 && created && *created == 1) {
        reported = 1;
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
            "private candidate admission: allowed=%d created=%d", allowed, *created);
    }
    return allowed;
}

static int revoke_key(const struct ker_ff_admission_key *key, void *context)
{
    (void)context;
    struct ff_flow_key original;
    memcpy(&original, key, sizeof(original));
    return ff_flow_map_revoke(&original);
}

static int retire(void *context)
{
    if (!active(context)) return -ESTALE;
    ff_flow_map_close();
    return ff_flow_map_active() ? -EIO : 0;
}

static int rearm(void *context)
{
    if (!context_live(context) || ff_flow_map_active()) return -ESTALE;
    ff_flow_map_open();
    return ff_flow_map_active() ? 0 : -EIO;
}

int ker_nginx_candidate_worker_commit(int slot)
{
    if (!candidate_state || !ff_reload_state_valid(candidate_state, sizeof(*candidate_state))) {
        errno = EPROTO;
        return -1;
    }
#ifdef KER_NGINX_SOURCE_ADMISSION_RELAY_TEST
    const char *source_admission = getenv("KER_NGINX_SOURCE_ADMISSION_RELAY");
    if (source_admission) {
        if (strcmp(source_admission, "1") != 0) { errno = EINVAL; return -1; }
        extern int ker_nginx_source_admission_prepare(struct ff_reload_state *, int);
        int status = ker_nginx_source_admission_prepare(candidate_state, slot);
        if (status) {
            ker_nginx_source_admission_abort();
            errno = status < 0 ? -status : EPROTO;
            return -1;
        }
        return 0;
    }
#endif
    ff_reload_attach_state(candidate_state);
    ff_reload_set_epoch(candidate_state->epoch);
    ff_reload_set_gen(0);
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_flow_map_open();
    if (!ff_flow_map_active()) { errno = EPROTO; return -1; }
    const struct ker_ff_admission_map_ops ops = {
        .context_live = context_live, .active = active, .admit = admit,
        .revoke = revoke_key, .retire = retire, .rearm = rearm};
    /* Nginx opens its listener before entering ff_run. Initialize the owner
     * channel on that same worker/event-loop thread before original listen;
     * ff_run subsequently pumps it on the same thread. */
    int entered = ker_sb_preload_owner_loop_enter();
    if (entered) { errno = -entered; return -1; }
    int result = ker_sb_preload_ff_owner_admission_attach(&ops);
    if (!result) result = ker_sb_preload_ff_owner_candidate_listener_prepare(slot);
    int error = errno;
    ker_sb_preload_owner_loop_leave();
    errno = error;
    return result;
}
