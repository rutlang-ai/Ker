#define _GNU_SOURCE
#include <ff_api.h>
#include <ff_config.h>
#include <ff_reload.h>
#include <ker/ini.h>
#include <ker/socket-broker.h>
#include "socket-broker-preload-internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

struct ff_config ff_global_cfg;

struct runtime_config {
    char broker_path[KER_SOCKET_BROKER_PATH_MAX + 1];
    unsigned version;
    int graceful_reload;
    int saw_lcore_mask;
    int saw_version;
    int saw_path;
    int saw_graceful_reload;
};

struct runtime_init_plan {
    struct runtime_config config;
    char config_path[PATH_MAX];
    unsigned proc_id;
    const char *proc_type;
    intptr_t *nginx_max_sockets;
    int (*nginx_is_fstack_fd)(int);
    int worker_generation;
    uint32_t source_round_epoch;
};

static int runtime_initialized;
static char runtime_config_path[PATH_MAX];
static _Thread_local struct runtime_init_plan pending_init_plan;
static _Thread_local int pending_init_plan_ready;
static volatile sig_atomic_t runtime_stop;
static intptr_t *nginx_max_sockets;
static int (*nginx_is_fstack_fd)(int);
static _Atomic uint64_t ff_leaf_epoll_ctl_calls;
static void runtime_trace(const char *format, ...);
static int runtime_fail(int error, const char *message);

typedef int (*nginx_worker_authorization_fn)(unsigned int proc_id);

static int
consume_nginx_secondary_authorization(unsigned int proc_id)
{
    /* This one-shot handshake is cooperative DSO validation, not a same-process
     * security boundary: other code loaded into the process can export the symbol.
     */
    nginx_worker_authorization_fn authorize =
        (nginx_worker_authorization_fn)dlsym(RTLD_DEFAULT,
            "ker_fstack_nginx_worker_consume_authorization");
    return authorize != NULL && authorize(proc_id) == 1;
}

void
ker_fstack_runtime_trace_leaf(const char *name, int fd, long result)
{
    static const char *const traced[] = {
        "ff_socket", "ff_bind", "ff_listen", "ff_accept", "ff_read",
        "ff_readv", "ff_write", "ff_writev", "ff_recv", "ff_send",
        "ff_close"
    };
    static _Atomic uint32_t reported;
    for (unsigned index = 0; index < sizeof(traced) / sizeof(traced[0]); ++index) {
        if (strcmp(name, traced[index]) != 0)
            continue;
        unsigned bit = index * 2 + (result < 0 ? 1U : 0U);
        uint32_t mask = UINT32_C(1) << bit;
        if ((atomic_fetch_or_explicit(&reported, mask, memory_order_relaxed) & mask) == 0)
            runtime_trace("ff_leaf pid=%ld name=%s fd=%d result=%ld first=%s\n",
                (long)getpid(), name, fd, result, result < 0 ? "error" : "success");
        return;
    }
}

static int
runtime_ini(void *opaque, const char *section, const char *name, const char *value)
{
    struct runtime_config *config = opaque;
    char *end = NULL;
    unsigned long parsed;

    if (strcmp(section, "ker_socket_broker") == 0) {
        if (strcmp(name, "version") == 0 && !config->saw_version) {
            errno = 0;
            parsed = strtoul(value, &end, 10);
            if (errno || end == value || *end || parsed != 1)
                return 0;
            config->version = (unsigned)parsed;
            config->saw_version = 1;
            return 1;
        }
        if (strcmp(name, "path") == 0 && !config->saw_path) {
            size_t length = strlen(value);
            if (length == 0 || length > KER_SOCKET_BROKER_PATH_MAX)
                return 0;
            memcpy(config->broker_path, value, length + 1);
            config->saw_path = 1;
            return 1;
        }
        return 0;
    }

    if (strcmp(section, "dpdk") == 0 &&
        strcmp(name, "graceful_reload") == 0 && !config->saw_graceful_reload) {
        if (strcmp(value, "0") != 0 && strcmp(value, "1") != 0)
            return 0;
        config->graceful_reload = value[0] == '1';
        config->saw_graceful_reload = 1;
        return 1;
    }

    /* The unchanged Nginx master reads this field before creating its
     * inherited reload block. The broker runtime does not consume a DPDK
     * lcore mask, but accepts the key so source startup can reach ff_init()
     * and validate that block at the actual runtime boundary. */
    if (strcmp(section, "dpdk") == 0 && strcmp(name, "lcore_mask") == 0 &&
        !config->saw_lcore_mask) {
        size_t length = strlen(value);
        if (length < 3 || length > 34 || value[0] != '0' ||
            (value[1] != 'x' && value[1] != 'X'))
            return 0;
        unsigned bits = 0;
        for (size_t i = 2; i < length; ++i) {
            char ch = value[i];
            if (!((ch >= '0' && ch <= '9') ||
                  (ch >= 'a' && ch <= 'f') ||
                  (ch >= 'A' && ch <= 'F')))
                return 0;
            unsigned nibble = ch >= '0' && ch <= '9' ? (unsigned)(ch - '0') :
                (unsigned)((ch | 0x20) - 'a' + 10);
            bits += (unsigned)__builtin_popcount(nibble);
        }
        if (bits != 2)
            return 0;
        config->saw_lcore_mask = 1;
        return 1;
    }
    return 0;
}

static int
validate_source_reload_binding(unsigned proc_id, const char *proc_type,
    struct runtime_init_plan *plan)
{
    struct ff_reload_state **source_symbol;
    struct ff_reload_state *source_state;
    uint32_t active, target, reload_active, round_epoch;
    int expected, selected;

    source_symbol = (struct ff_reload_state **)dlsym(RTLD_DEFAULT,
        "ngx_ff_reload_shm");
    if (source_symbol == NULL || *source_symbol == NULL ||
        !ff_reload_state_attached() ||
        !ff_reload_state_valid(*source_symbol, sizeof(**source_symbol))) {
        runtime_trace("ff_init_stage stage=graceful_source_state_invalid pid=%ld proc_id=%u proc_type=%s attached=%d source_block=%d\n",
            (long)getpid(), proc_id, proc_type, ff_reload_state_attached(),
            source_symbol != NULL && *source_symbol != NULL);
        return runtime_fail(EPROTO,
            "ker fstack runtime: graceful reload requires the source-inherited Nginx state block\n");
    }

    source_state = *source_symbol;
    active = __atomic_load_n(&source_state->active_gen, __ATOMIC_SEQ_CST);
    target = __atomic_load_n(&source_state->target_gen, __ATOMIC_SEQ_CST);
    reload_active = __atomic_load_n(&source_state->reload_active, __ATOMIC_SEQ_CST);
    round_epoch = __atomic_load_n(&source_state->epoch, __ATOMIC_SEQ_CST);
    selected = ff_reload_gen();
    expected = reload_active ? (int)target : (int)active;

    if (active >= FF_RELOAD_GEN_MAX || target >= FF_RELOAD_GEN_MAX ||
        reload_active > 1 || expected != ff_reload_worker_gen() ||
        ff_reload_active_gen() != (int)active ||
        ff_reload_target_gen() != (int)target) {
        runtime_trace("ff_init_stage stage=graceful_source_state_mismatch pid=%ld proc_id=%u proc_type=%s round_epoch=%u active=%u target=%u reload_active=%u selected=%d expected=%d helper_expected=%d\n",
            (long)getpid(), proc_id, proc_type, round_epoch, active, target,
            reload_active, selected, expected, ff_reload_worker_gen());
        return runtime_fail(EPROTO,
            "ker fstack runtime: inherited Nginx generation state is inconsistent\n");
    }

    if (strcmp(proc_type, "primary") == 0) {
        if (proc_id != 0 || selected != 0) {
            runtime_trace("ff_init_stage stage=graceful_source_role_mismatch pid=%ld proc_id=%u proc_type=%s round_epoch=%u active=%u target=%u selected=%d\n",
                (long)getpid(), proc_id, proc_type, round_epoch, active,
                target, selected);
            return runtime_fail(EPROTO,
                "ker fstack runtime: graceful slim primary requires source generation zero\n");
        }
    } else if (strcmp(proc_type, "secondary") != 0 || proc_id == 0 ||
        selected != expected) {
        runtime_trace("ff_init_stage stage=graceful_source_role_mismatch pid=%ld proc_id=%u proc_type=%s round_epoch=%u active=%u target=%u selected=%d expected=%d\n",
            (long)getpid(), proc_id, proc_type, round_epoch, active,
            target, selected, expected);
        return runtime_fail(EPROTO,
            "ker fstack runtime: graceful worker generation does not match the source state\n");
    }

    plan->worker_generation = selected;
    plan->source_round_epoch = round_epoch;
    runtime_trace("ff_init_stage stage=graceful_source_state_valid pid=%ld proc_id=%u proc_type=%s round_epoch=%u directory_epoch=%u active=%u target=%u reload_active=%u selected=%d\n",
        (long)getpid(), proc_id, proc_type, round_epoch, ff_reload_epoch(),
        active, target, reload_active, selected);
    return 0;
}

static void
runtime_trace(const char *format, ...)
{
    int saved_errno = errno;
    const char *path = getenv("KER_FSTACK_RUNTIME_TRACE");
    char line[384];
    va_list arguments;
    int fd, length;
    if (path == NULL || path[0] == '\0') {
        errno = saved_errno;
        return;
    }
    va_start(arguments, format);
    length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0 || (size_t)length >= sizeof(line)) {
        errno = saved_errno;
        return;
    }
    fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        errno = saved_errno;
        return;
    }
    (void)syscall(SYS_write, fd, line, (size_t)length);
    (void)syscall(SYS_close, fd);
    errno = saved_errno;
}

static int
copy_event_from_caller(struct epoll_event *destination,
    const struct epoll_event *source)
{
    struct iovec local = {.iov_base = destination, .iov_len = sizeof(*destination)};
    struct iovec remote = {.iov_base = (void *)source, .iov_len = sizeof(*destination)};
    ssize_t copied;
    do {
        copied = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
    } while (copied < 0 && errno == EINTR);
    if (copied != (ssize_t)sizeof(*destination)) {
        errno = EFAULT;
        return -1;
    }
    return 0;
}

static int
runtime_fail(int error, const char *message)
{
    (void)syscall(SYS_write, STDERR_FILENO, message, strlen(message));
    errno = error;
    return -1;
}

static int
parse_uint_arg(const char *arg, const char *prefix, unsigned *result)
{
    size_t prefix_length = strlen(prefix);
    char *end = NULL;
    unsigned long value;
    if (strncmp(arg, prefix, prefix_length) != 0 || arg[prefix_length] == '\0')
        return -1;
    errno = 0;
    value = strtoul(arg + prefix_length, &end, 10);
    if (errno || *end || value > 127)
        return -1;
    *result = (unsigned)value;
    return 0;
}

static int
resolve_nginx_epoll_boundary(struct runtime_init_plan *plan)
{
    void *offset_symbol = dlsym(RTLD_DEFAULT, "ngx_max_sockets");
    void *classifier_symbol = dlsym(RTLD_DEFAULT, "is_fstack_fd");
    if (offset_symbol == NULL || classifier_symbol == NULL)
        return runtime_fail(ENOSYS,
            "ker fstack runtime: nginx FF fd-offset exports are unavailable\n");
    plan->nginx_max_sockets = offset_symbol;
    plan->nginx_is_fstack_fd = (int (*)(int))classifier_symbol;
    if (*plan->nginx_max_sockets <= 0 || *plan->nginx_max_sockets > INT_MAX)
        return runtime_fail(ERANGE,
            "ker fstack runtime: nginx FF fd offset is outside the supported range\n");
    return 0;
}

int
ker_fstack_nginx_runtime_preflight(int argc, char * const argv[])
{
    struct runtime_init_plan plan = {0};
    struct ker_socket_client probe = {.session_fd = -1};
    unsigned proc_id;
    const char *proc_type;
    FILE *config_file;
    const char *broker_environment;
    size_t config_path_length;
    int parse_result, close_result;

    if (runtime_initialized || pending_init_plan_ready)
        return runtime_fail(EALREADY, "ker fstack runtime: duplicate ff_init\n");
    if (getenv("FF_FAULT") != NULL)
        return runtime_fail(ENOTSUP,
            "ker fstack runtime: FF_FAULT is unsupported in the broker profile\n");
    if (argc != 4 || argv == NULL || argv[0] == NULL ||
        strcmp(argv[0], "nginx") != 0 || argv[1] == NULL || argv[2] == NULL ||
        argv[3] == NULL || strncmp(argv[1], "--conf=", 7) != 0 ||
        argv[1][7] == '\0' || parse_uint_arg(argv[2], "--proc-id=", &proc_id))
        return runtime_fail(EINVAL,
            "ker fstack runtime: expected nginx --conf=PATH --proc-id=N --proc-type=ROLE\n");

    if (strcmp(argv[3], "--proc-type=primary") == 0)
        proc_type = "primary";
    else if (strcmp(argv[3], "--proc-type=secondary") == 0)
        proc_type = "secondary";
    else
        return runtime_fail(EINVAL, "ker fstack runtime: invalid process role\n");
    if ((proc_id == 0 && strcmp(proc_type, "primary") != 0) ||
        (proc_id == 1 && (strcmp(proc_type, "secondary") != 0 ||
            !consume_nginx_secondary_authorization(proc_id))) || proc_id > 1)
        return runtime_fail(ENOTSUP,
            "ker fstack runtime: worker role requires the validated two-worker Nginx shim\n");

    config_file = fopen(argv[1] + 7, "r");
    if (config_file == NULL) {
        int saved_errno = errno;
        runtime_trace("ff_init_stage stage=config_open_failed pid=%ld path=%s errno=%d\n",
            (long)getpid(), argv[1] + 7, saved_errno);
        errno = saved_errno;
        return -1;
    }
    parse_result = ker_ini_parse_file(config_file, runtime_ini, &plan.config);
    close_result = fclose(config_file);
    if (parse_result != 0 || close_result != 0 || !plan.config.saw_version ||
        !plan.config.saw_path || !plan.config.saw_graceful_reload)
        return runtime_fail(EINVAL,
            "ker fstack runtime: config requires broker version/path and a valid graceful_reload value\n");

    if (plan.config.graceful_reload) {
        if (!plan.config.saw_lcore_mask)
            return runtime_fail(EINVAL,
                "ker fstack runtime: graceful source bootstrap requires the original dpdk.lcore_mask\n");
        if (validate_source_reload_binding(proc_id, proc_type, &plan) != 0)
            return -1;

        /* The broker runtime currently has no native generation packet
         * dispatcher or EAL owner binding. Reject after validating the real
         * source block, but before opening a broker owner capability. A
         * graceful flag alone must never authorize the upstream FSM. */
        runtime_trace("ff_init_stage stage=graceful_backend_unbound pid=%ld proc_id=%u proc_type=%s round_epoch=%u selected=%d dispatcher=0 packet_owner=0\n",
            (long)getpid(), proc_id, proc_type,
            plan.source_round_epoch,
            plan.worker_generation);
        return runtime_fail(ENOTSUP,
            "ker fstack runtime: graceful reload requires an authenticated generation packet-owner and dispatcher binding\n");
    }
    if (plan.config.saw_lcore_mask)
        return runtime_fail(EINVAL,
            "ker fstack runtime: dpdk.lcore_mask is accepted only for source graceful-startup validation\n");

    broker_environment = getenv("KER_SOCKET_BROKER_PATH");
    if (broker_environment == NULL || strcmp(broker_environment, plan.config.broker_path) != 0)
        return runtime_fail(EINVAL,
            "ker fstack runtime: config broker path must match KER_SOCKET_BROKER_PATH\n");
    config_path_length = strlen(argv[1] + 7);
    if (config_path_length >= sizeof(plan.config_path))
        return runtime_fail(ENAMETOOLONG, "ker fstack runtime: config path is too long\n");
    memcpy(plan.config_path, argv[1] + 7, config_path_length + 1);
    if (resolve_nginx_epoll_boundary(&plan) != 0) {
        int saved_errno = errno;
        runtime_trace("ff_init_stage stage=epoll_boundary_failed pid=%ld errno=%d\n",
            (long)getpid(), saved_errno);
        errno = saved_errno;
        return -1;
    }
    runtime_trace("ff_init_stage stage=broker_probe_begin pid=%ld path=%s\n",
        (long)getpid(), plan.config.broker_path);
    if (ker_socket_client_open(&probe, plan.config.broker_path) != 0) {
        int saved_errno = errno;
        runtime_trace("ff_init_stage stage=broker_probe_failed pid=%ld path=%s errno=%d\n",
            (long)getpid(), plan.config.broker_path, saved_errno);
        errno = saved_errno;
        return -1;
    }
    ker_socket_client_close(&probe);
    runtime_trace("ff_init_stage stage=broker_probe_ready pid=%ld path=%s\n",
        (long)getpid(), plan.config.broker_path);
    if (ker_sb_preload_ff_owner_begin() != 0) {
        int saved_errno = errno;
        runtime_trace("ff_init_stage stage=owner_context_failed pid=%ld errno=%d\n",
            (long)getpid(), saved_errno);
        errno = saved_errno;
        return -1;
    }
    runtime_trace("ff_init_stage stage=broker_owner_begin_ready pid=%ld proc_id=%u proc_type=%s\n",
        (long)getpid(), proc_id, proc_type);

    plan.proc_id = proc_id;
    plan.proc_type = proc_type;
    pending_init_plan = plan;
    pending_init_plan_ready = 1;
    return 0;
}

int
ker_fstack_nginx_runtime_commit(void)
{
    if (!pending_init_plan_ready || runtime_initialized)
        return runtime_fail(EINVAL, "ker fstack runtime: no prepared ff_init plan to commit\n");

    memcpy(runtime_config_path, pending_init_plan.config_path,
        sizeof(runtime_config_path));
    nginx_max_sockets = pending_init_plan.nginx_max_sockets;
    nginx_is_fstack_fd = pending_init_plan.nginx_is_fstack_fd;

    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));
    ff_global_cfg.filename = runtime_config_path;
    ff_global_cfg.dpdk.proc_id = (int)pending_init_plan.proc_id;
    ff_global_cfg.dpdk.proc_type = (char *)pending_init_plan.proc_type;
    ff_global_cfg.dpdk.graceful_reload = 0;

    /* This runtime commits only the bounded graceful-off profile. Source
     * graceful=1 is checked in preflight and remains fail-closed until the
     * native generation dispatcher and EAL ownership path are bound. */
    ff_reload_attach_state(NULL);
    ff_reload_set_epoch(0);
    ff_reload_set_gen(0);
    (void)ff_reload_gendir_install(NULL, 0);
    ff_reload_dir_sync_enable(0);
    runtime_initialized = 1;
    pending_init_plan_ready = 0;
    runtime_trace("ff_init pid=%ld proc_id=%u proc_type=%s graceful_reload=%d attached=%d active=%d target=%d selected=%d\n",
        (long)getpid(), pending_init_plan.proc_id, pending_init_plan.proc_type,
        ff_global_cfg.dpdk.graceful_reload,
        ff_reload_state_attached(), ff_reload_active_gen(), ff_reload_target_gen(),
        ff_reload_gen());
    return 0;
}

int
ff_init(int argc, char * const argv[])
{
    if (ker_fstack_nginx_runtime_preflight(argc, argv) != 0)
        return -1;
    return ker_fstack_nginx_runtime_commit();
}

void
ff_run(loop_func_t loop, void *arg)
{
    if (!runtime_initialized || loop == NULL) {
        static const char message[] = "ker fstack runtime: ff_run before init or null callback\n";
        (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
        abort();
    }
    runtime_stop = 0;
    if (ker_sb_preload_owner_loop_enter() != 0) abort();
    typedef int (*worker_ready_fn)(void);
    worker_ready_fn notify_ready = (worker_ready_fn)dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_owner_activation_worker_ready");
    if (!notify_ready && getenv("KER_NGINX_OWNER_READY_FD")) abort();
    int ready_sent = notify_ready == NULL;
    while (!runtime_stop) {
        int pump_status = ker_sb_preload_owner_pump();
        if (pump_status) {
            runtime_trace("ff_owner_pump failure stage=before-loop errno=%d\n",
                pump_status < 0 ? -pump_status : EPROTO);
            abort();
        }
        if (!ready_sent) {
            int status = notify_ready();
            if (!status) ready_sent = 1;
            else if (status != -EAGAIN) {
                runtime_trace("ff_owner_ready failure errno=%d\n", -status);
                abort();
            }
        }
        (void)loop(arg);
        pump_status = ker_sb_preload_owner_pump();
        if (pump_status) {
            runtime_trace("ff_owner_pump failure stage=after-loop errno=%d\n",
                pump_status < 0 ? -pump_status : EPROTO);
            abort();
        }
    }
    ker_sb_preload_owner_loop_leave();
}

void ff_stop_run(void) { runtime_stop = 1; }

int
ff_getmaxfd(void)
{
    struct rlimit limit;
    int result;
    int saved_errno;
    intptr_t max_sockets = nginx_max_sockets != NULL ? *nginx_max_sockets : -1;
    if (!runtime_initialized) {
        errno = EINVAL;
        runtime_trace("ff_getmaxfd pid=%ld result=-1 max_sockets=%ld errno=%d\n",
            (long)getpid(), (long)max_sockets, errno);
        return -1;
    }
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        saved_errno = errno;
        runtime_trace("ff_getmaxfd pid=%ld result=-1 max_sockets=%ld errno=%d\n",
            (long)getpid(), (long)max_sockets, saved_errno);
        errno = saved_errno;
        return -1;
    }
    if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > INT_MAX)
        result = INT_MAX;
    else
        result = (int)limit.rlim_cur;
    runtime_trace("ff_getmaxfd pid=%ld result=%d max_sockets=%ld combined=%lld\n",
        (long)getpid(), result, (long)max_sockets,
        (long long)max_sockets + result);
    return result;
}

#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 31)
int ff_gettimeofday(struct timeval *tv, void *tz)
#else
int ff_gettimeofday(struct timeval *tv, struct timezone *tz)
#endif
{ return (int)syscall(SYS_gettimeofday, tv, tz); }

/* Nginx stores raw FF descriptors as raw_fd + ngx_max_sockets. Translate only
 * targets accepted by its own classifier; the namespaced preload function
 * preserves host and composite-epoll bookkeeping in both cases. */
int
epoll_ctl(int epfd, int operation, int fd, struct epoll_event *event)
{
    int caller_fd = fd;
    int fstack_target = runtime_initialized && nginx_is_fstack_fd(fd);
    int clear_event_mapped = 0;
    struct epoll_event adapted_event;
    if (fstack_target) {
        intptr_t offset = *nginx_max_sockets;
        if ((intptr_t)fd < offset || (intptr_t)fd - offset > INT_MAX) {
            errno = EBADF;
            return -1;
        }
        fd = (int)((intptr_t)fd - offset);
        atomic_fetch_add_explicit(&ff_leaf_epoll_ctl_calls, 1,
            memory_order_relaxed);
    }
    if (operation == EPOLL_CTL_DEL) {
        event = NULL;
    } else if (event != NULL) {
        if (copy_event_from_caller(&adapted_event, event) != 0)
            return -1;
        /* The pinned FF build chooses its kqueue event constants ahead of
         * epoll constants. EV_CLEAR is 0x20 there; Linux epoll needs EPOLLET. */
        if (adapted_event.events & UINT32_C(0x20)) {
            adapted_event.events &= ~UINT32_C(0x20);
            adapted_event.events |= EPOLLET;
            clear_event_mapped = 1;
        }
        event = &adapted_event;
    }
    int result = ker_sb_posix_epoll_ctl(epfd, operation, fd, event);
    int saved_errno = errno;
    if (fstack_target || clear_event_mapped)
        runtime_trace("ff_epoll_ctl pid=%ld target=%s op=%d fd=%d events=%#x result=%d\n",
            (long)getpid(), fstack_target ? "ff" : "host", operation, caller_fd,
            event ? event->events : 0, result);
    errno = saved_errno;
    return result;
}

uint64_t
ker_fstack_runtime_epoll_ctl_calls(void)
{ return atomic_load_explicit(&ff_leaf_epoll_ctl_calls, memory_order_relaxed); }

static void __attribute__((noreturn))
unsupported_abort(const char *name)
{
    char message[160];
    int length = snprintf(message, sizeof(message),
        "ker fstack runtime: unsupported FF runtime hook reached: %s\n", name);
    if (length > 0)
        (void)syscall(SYS_write, STDERR_FILENO, message,
            (size_t)length < sizeof(message) ? (size_t)length : sizeof(message));
    abort();
}

void ff_regist_packet_dispatcher_context(dispatch_func_context_t callback)
{ (void)callback; unsupported_abort("ff_regist_packet_dispatcher_context"); }
void ff_unregist_packet_dispatcher_context(void)
{ unsupported_abort("ff_unregist_packet_dispatcher_context"); }
int ff_syncache_count(void)
{
    uint64_t count = 0;
    if (ker_sb_preload_ff_owner_requests(&count) < 0 || count > INT_MAX) {
        int error = count > INT_MAX ? EOVERFLOW : errno;
        char message[160];
        int length = snprintf(message, sizeof(message),
            "ker fstack request-sock snapshot failed: errno=%d\n", error);
        if (length > 0)
            (void)syscall(SYS_write, STDERR_FILENO, message,
                (size_t)length < sizeof(message) ? (size_t)length : sizeof(message));
        abort();
    }
    return (int)count;
}
