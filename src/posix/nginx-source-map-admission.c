/* Private candidate admission binding for the unchanged upstream flow map.
 * Kept separate from nginx-candidate-admission.c so its namespace macros can
 * never redirect these operations to Ker's candidate table. */
#define _GNU_SOURCE
#include <ngx_config.h>
#include <ngx_core.h>
#include <ff_config.h>
#include <ff_reload.h>
#include "ff_flow_map.h"
#include "ff-owner-admission-control.h"
#include "socket-broker-preload-internal.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

extern struct ff_config ff_global_cfg;
#ifdef KER_NGINX_SOURCE_ADMISSION_RELAY_TEST
extern volatile ngx_cycle_t *ngx_cycle;
#endif

static struct ff_reload_state *source_state;
static int source_armed;
static int source_saved_graceful;
static int source_saved_gen;
static int source_saved_attached;
static uint32_t source_saved_epoch;
static uint32_t source_epoch;
static uint32_t source_target;
static pid_t source_owner_pid;
static pid_t source_owner_tid;

void ker_nginx_source_admission_abort(void);

static void source_trace(const char *event, long a, long b, long c, long d)
{
    const char *path = getenv("KER_FSTACK_RUNTIME_TRACE");
    if (!path || !*path) return;
    char line[256];
    int length = snprintf(line, sizeof(line),
        "SOURCE_ADMISSION %s pid=%ld tid=%ld a=%ld b=%ld c=%ld d=%ld\n",
        event, (long)getpid(), (long)syscall(SYS_gettid), a, b, c, d);
    if (length <= 0 || (size_t)length >= sizeof(line)) return;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    (void)syscall(SYS_write, fd, line, (size_t)length);
    (void)syscall(SYS_close, fd);
}

static int source_context_live(void *context)
{
    (void)context;
    return source_armed && source_state &&
        source_owner_pid == getpid() &&
        source_owner_tid == (pid_t)syscall(SYS_gettid) &&
        ff_reload_state_attached() &&
        ff_global_cfg.dpdk.graceful_reload &&
        ff_reload_epoch() == source_epoch &&
        source_state->epoch == source_epoch &&
        ff_reload_target_gen() == (int)source_target &&
        ff_reload_gen() == (int)source_target &&
        source_state->target_gen == source_target &&
        ff_reload_hw_locked() && ff_flow_map_active();
}

static int source_map_active(void *context)
{
    (void)context;
    return ff_flow_map_active();
}

static int source_admit(const struct ker_ff_admission_key *key,
    int *created, void *context)
{
    (void)context;
    if (!key || !created || !source_context_live(NULL)) return -ESTALE;
    struct ff_flow_key source_key;
    _Static_assert(sizeof(source_key) == sizeof(*key), "admission key layout");
    memcpy(&source_key, key, sizeof(source_key));
    int allowed = ff_flow_map_admit(&source_key, created);
#ifdef KER_NGINX_SOURCE_ADMISSION_RELAY_TEST
    char source_address[INET6_ADDRSTRLEN] = {0};
    char destination_address[INET6_ADDRSTRLEN] = {0};
    int af = source_key.af == FF_FLOW_MAP_V4 ? AF_INET : AF_INET6;
    (void)inet_ntop(af, source_key.src, source_address, sizeof(source_address));
    (void)inet_ntop(af, source_key.dst, destination_address,
        sizeof(destination_address));
    struct timespec admitted_at = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &admitted_at);
    unsigned long long admitted_ns = (unsigned long long)admitted_at.tv_sec *
        1000000000ULL + (unsigned long long)admitted_at.tv_nsec;
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "SOURCE_UNPREFIXED_MAP_ADMIT allowed=%d created=%d family=%ui source=%s destination=%s source_port=%ui destination_port=%ui monotonic_ns=%uL pid=%P tid=%P",
        allowed, created ? *created : -1,
        source_key.af == FF_FLOW_MAP_V4 ? 4 : 6, source_address,
        destination_address, (unsigned)ntohs(source_key.sport),
        (unsigned)ntohs(source_key.dport), admitted_ns,
        (ngx_pid_t)getpid(), (ngx_pid_t)syscall(SYS_gettid));
    if (created && *created) {
        const char *delay_text = getenv("KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US");
        if (delay_text && *delay_text) {
            char *end = NULL;
            errno = 0;
            unsigned long delay_us = strtoul(delay_text, &end, 10);
            if (!errno && end != delay_text && !*end && delay_us > 0 &&
                delay_us <= 500000UL) {
                struct timespec pause = {
                    .tv_sec = (time_t)(delay_us / 1000000UL),
                    .tv_nsec = (long)(delay_us % 1000000UL) * 1000L};
                while (nanosleep(&pause, &pause) && errno == EINTR) { }
            }
        }
    }
#endif
    return allowed;
}

static int source_revoke_key(const struct ker_ff_admission_key *key,
    void *context)
{
    (void)context;
    if (!key || !source_context_live(NULL)) return -ESTALE;
    struct ff_flow_key source_key;
    memcpy(&source_key, key, sizeof(source_key));
    int status = ff_flow_map_revoke(&source_key);
#ifdef KER_NGINX_SOURCE_ADMISSION_RELAY_TEST
    char source_address[INET6_ADDRSTRLEN] = {0};
    char destination_address[INET6_ADDRSTRLEN] = {0};
    int af = source_key.af == FF_FLOW_MAP_V4 ? AF_INET : AF_INET6;
    (void)inet_ntop(af, source_key.src, source_address, sizeof(source_address));
    (void)inet_ntop(af, source_key.dst, destination_address,
        sizeof(destination_address));
    struct timespec revoked_at = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &revoked_at);
    unsigned long long revoked_ns = (unsigned long long)revoked_at.tv_sec *
        1000000000ULL + (unsigned long long)revoked_at.tv_nsec;
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "SOURCE_UNPREFIXED_MAP_REVOKE status=%d family=%ui source=%s destination=%s source_port=%ui destination_port=%ui monotonic_ns=%uL pid=%P tid=%P",
        status, source_key.af == FF_FLOW_MAP_V4 ? 4 : 6, source_address,
        destination_address, (unsigned)ntohs(source_key.sport),
        (unsigned)ntohs(source_key.dport), revoked_ns, (ngx_pid_t)getpid(),
        (ngx_pid_t)syscall(SYS_gettid));
#endif
    return status;
}

static int source_retire(void *context)
{
    if (!source_context_live(context)) return -ESTALE;
    ff_unregist_packet_dispatcher_context();
    source_armed = 0;
    ff_flow_map_close();
    return ff_flow_map_active() ? -EIO : 0;
}

static int source_rearm(void *context)
{
    (void)context;
    /* This candidate slice has no authenticated rearm generation producer. */
    return -EOPNOTSUPP;
}

int ker_nginx_source_admission_prepare(struct ff_reload_state *state, int slot)
{
    if (!state || slot < 3 || !ff_reload_state_valid(state, sizeof(*state)) ||
        !state->reload_active || source_state || source_armed ||
        ff_reload_state_attached()) {
        source_trace("prepare-precondition", slot, state != NULL,
            state && ff_reload_state_valid(state, sizeof(*state)),
            state ? (long)state->reload_active : -1);
        return -EPROTO;
    }

    source_state = state;
    source_saved_graceful = ff_global_cfg.dpdk.graceful_reload;
    source_saved_gen = ff_reload_gen();
    source_saved_attached = ff_reload_state_attached();
    source_saved_epoch = ff_reload_epoch();
    source_epoch = state->epoch;
    ff_reload_attach_state(state);
    /* runtime_commit intentionally starts each worker at epoch zero. Bind the
     * authenticated inherited source epoch only after validating its block. */
    ff_reload_set_epoch(source_epoch);
    uint32_t target = (uint32_t)ff_reload_target_gen();
    source_trace("prepare-bound", ff_reload_state_attached(), state->epoch,
        source_saved_epoch, ((long)state->target_gen << 16) | target);
    if (state->epoch != source_epoch || !source_epoch ||
        state->target_gen != target || target >= FF_RELOAD_GEN_MAX ||
        !ff_reload_hw_locked()) {
        ker_nginx_source_admission_abort();
        return -ESTALE;
    }
    source_target = target;
    ff_reload_set_gen((int)target);
    const int saved_graceful = ff_global_cfg.dpdk.graceful_reload;
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_flow_map_open();
    int result = ff_flow_map_active() ? 0 : -ENOTCONN;
    const struct ker_ff_admission_map_ops ops = {
        .context_live = source_context_live,
        .active = source_map_active,
        .admit = source_admit,
        .revoke = source_revoke_key,
        .retire = source_retire,
        .rearm = source_rearm,
    };
    int entered = 0;
    if (!result) {
        entered = ker_sb_preload_owner_loop_enter();
        if (entered) result = entered < 0 ? entered : -EPROTO;
        else {
            source_owner_pid = getpid();
            source_owner_tid = (pid_t)syscall(SYS_gettid);
            if (ker_sb_preload_ff_owner_admission_attach(&ops))
                result = errno ? -errno : -EPROTO;
            if (!result && ker_sb_preload_ff_owner_candidate_listener_prepare(slot))
                result = errno ? -errno : -EPROTO;
            ker_sb_preload_owner_loop_leave();
        }
    }

    /* Keep the inherited source block/map prepared, but restore the exact
     * gr0 projection before the pinned upstream ff_mod_init consistency check.
     * No admission is allowed until source_activate() on the READY worker. */
    ff_global_cfg.dpdk.graceful_reload = saved_graceful;
    return result;
}

int ker_nginx_source_admission_activate(void)
{
    if (!source_state) return -ESTALE;
    if (source_armed)
        return source_context_live(NULL) ? 0 : -ESTALE;
    ff_global_cfg.dpdk.graceful_reload = 1;
    if (source_owner_pid != getpid() ||
        source_owner_tid != (pid_t)syscall(SYS_gettid) ||
        !ker_sb_preload_owner_loop_active() || !ff_reload_state_attached() ||
        !ff_reload_state_valid(source_state, sizeof(*source_state)) ||
        ff_reload_epoch() != source_epoch ||
        source_state->epoch != source_epoch ||
        ff_reload_target_gen() != (int)source_target ||
        source_state->target_gen != source_target ||
        ff_reload_gen() != (int)source_target || !ff_reload_hw_locked() ||
        !ff_flow_map_active()) {
        ff_global_cfg.dpdk.graceful_reload = source_saved_graceful;
        return -ESTALE;
    }
    typedef int (*arm_fn)(void);
    arm_fn arm = (arm_fn)dlsym(RTLD_DEFAULT, "ker_nginx_original_flow_map_arm");
    if (!arm) {
        ff_global_cfg.dpdk.graceful_reload = source_saved_graceful;
        return -ENOSYS;
    }
    int status = arm();
    if (status) {
        ff_global_cfg.dpdk.graceful_reload = source_saved_graceful;
        return status < 0 ? status : -EPROTO;
    }
    source_armed = 1;
    return 0;
}

void ker_nginx_source_admission_abort(void)
{
    if (!source_state) return;
    if (source_armed) ff_unregist_packet_dispatcher_context();
    ff_flow_map_close();
    if (!source_saved_attached) ff_reload_attach_state(NULL);
    ff_reload_set_epoch(source_saved_epoch);
    ff_reload_set_gen(source_saved_gen);
    ff_global_cfg.dpdk.graceful_reload = source_saved_graceful;
    source_armed = 0;
    source_state = NULL;
    source_owner_pid = 0;
    source_owner_tid = 0;
    source_epoch = 0;
    source_target = 0;
}
