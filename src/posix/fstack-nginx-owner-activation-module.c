/*
 * C22's opt-in initial listener adoption module for the pinned F-Stack Nginx.
 * The master reserves one staged owner-group slot per cycle. The worker gets
 * only slot zero and adopts it through the normal F-Stack socket bridge.
 */
#define _GNU_SOURCE
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_connection.h>
#include <ngx_module.h>
#include <ngx_process.h>

#include <ker/ini.h>
#include <ker/socket-broker.h>

#include <dlfcn.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

extern ngx_uint_t ngx_test_config;
extern ngx_uint_t ngx_process;
extern volatile ngx_cycle_t *ngx_cycle;
extern ngx_module_t ngx_core_module;

static struct ker_socket_client broker;
static int broker_open;
static int current_plan = -1;
static int current_slot = -1;
static int retiring_census = -1;
static bool retirement_proven;
static struct sockaddr_in owner_address;
static int owner_backlog;
static bool respawn_plan_pending;
static bool worker_prepared;

static void
trace_line(const char *format, ...)
{
    const char *path = getenv("KER_FSTACK_RUNTIME_TRACE");
    if (!path || !*path) return;
    char line[256];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0 || (size_t)length >= sizeof(line)) return;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    (void)syscall(SYS_write, fd, line, (size_t)length);
    (void)syscall(SYS_close, fd);
}

struct module_config {
    char broker_path[KER_SOCKET_BROKER_PATH_MAX + 1];
    bool version;
    bool path;
    bool graceful_reload;
};

static int
parse_ini(void *opaque, const char *section, const char *name,
    const char *value)
{
    struct module_config *config = opaque;
    if (!strcmp(section, "ker_socket_broker")) {
        if (!strcmp(name, "version") && !config->version && !strcmp(value, "1")) {
            config->version = true;
            return 1;
        }
        if (!strcmp(name, "path") && !config->path) {
            size_t length = strlen(value);
            if (!length || length > KER_SOCKET_BROKER_PATH_MAX) return 0;
            memcpy(config->broker_path, value, length + 1);
            config->path = true;
            return 1;
        }
        return 0;
    }
    if (!strcmp(section, "dpdk") && !strcmp(name, "graceful_reload") &&
        !config->graceful_reload && !strcmp(value, "0")) {
        config->graceful_reload = true;
        return 1;
    }
    return 0;
}

static ngx_int_t
validate_profile(ngx_cycle_t *cycle, struct sockaddr_in *address,
    int *backlog)
{
#define PROFILE_REJECT(message) do { \
    ngx_log_error(NGX_LOG_ERR, cycle ? cycle->log : NULL, 0, \
        "C22 profile validation: %s", message); \
    return NGX_ERROR; \
} while (0)
    ngx_core_conf_t *conf;
    ngx_listening_t *listener;
    ngx_uint_t *process = dlsym(RTLD_DEFAULT, "ngx_process");
    ngx_module_t *core_symbol = dlsym(RTLD_DEFAULT, "ngx_core_module");
    void *worker_shim = dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_worker_consume_authorization");
    const char *ini_path = getenv("KER_FSTACK_NGINX_INI");
    char configured_ini[KER_SOCKET_BROKER_PATH_MAX + 1];
    struct module_config config = {0};
    FILE *file;
    int parsed, close_status;

    if (!cycle || !process || !core_symbol ||
        core_symbol->version != nginx_version ||
        !core_symbol->signature || strcmp(core_symbol->signature,
            NGX_MODULE_SIGNATURE)) PROFILE_REJECT("Nginx ABI symbols");
    if (*process == NGX_PROCESS_WORKER || *process == NGX_PROCESS_SIGNALLER)
        return NGX_DECLINED;
    if (!worker_shim) PROFILE_REJECT("missing pinned worker activation shim");
    if (!cycle->modules || !cycle->conf_ctx || cycle->modules_n == 0 ||
        core_symbol->index >= cycle->modules_n ||
        cycle->modules[core_symbol->index] != core_symbol ||
        !cycle->conf_ctx[core_symbol->index]) PROFILE_REJECT("core config context");
    conf = (ngx_core_conf_t *)cycle->conf_ctx[core_symbol->index];
    if (!conf->fstack_conf.data || conf->fstack_conf.len == 0 ||
        conf->fstack_conf.len > KER_SOCKET_BROKER_PATH_MAX ||
        memchr(conf->fstack_conf.data, '\0', conf->fstack_conf.len) != NULL)
        PROFILE_REJECT("invalid configured F-Stack INI path");
    memcpy(configured_ini, conf->fstack_conf.data, conf->fstack_conf.len);
    configured_ini[conf->fstack_conf.len] = '\0';
    if (!ini_path || !*ini_path || strcmp(ini_path, configured_ini))
        PROFILE_REJECT("runtime INI environment differs from fstack_conf");
    if (!conf || !conf->master || conf->worker_processes != 1 ||
        cycle->listening.size != sizeof(ngx_listening_t) ||
        cycle->listening.nelts != 1 || !cycle->listening.elts ||
        cycle->listening.nalloc < 1 || cycle->listening.nalloc > 16)
        PROFILE_REJECT("master/worker/listener count");
    listener = cycle->listening.elts;
    if (!listener->reuseport || listener->belong_to_host ||
        listener->type != SOCK_STREAM || !listener->sockaddr ||
        listener->sockaddr->sa_family != AF_INET ||
        listener->socklen != sizeof(struct sockaddr_in) ||
        listener->fd != (ngx_socket_t)-1 || listener->connection != NULL ||
        listener->ignore || !listener->open || listener->bound ||
        listener->inherited || listener->add_reuseport || listener->backlog < 1 ||
        listener->backlog > 65535 || listener->rcvbuf != -1 ||
        listener->sndbuf != -1 || listener->keepalive || listener->deferred_accept ||
        listener->add_deferred || listener->delete_deferred || listener->quic ||
        listener->logp == NULL) PROFILE_REJECT("listener structure/options");
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    if (listener->keepidle != 0 || listener->keepintvl != 0 ||
        listener->keepcnt != 0) PROFILE_REJECT("TCP keepalive tuning");
#endif
#if (NGX_HAVE_SETFIB)
    if (listener->setfib != -1) PROFILE_REJECT("setfib option");
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    if (listener->fastopen != -1) PROFILE_REJECT("TCP fast-open option");
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    if (listener->accept_filter != NULL) PROFILE_REJECT("accept-filter option");
#endif
    *address = *(struct sockaddr_in *)listener->sockaddr;
    *backlog = listener->backlog;

    file = fopen(configured_ini, "r");
    if (!file) PROFILE_REJECT("runtime ini unreadable");
    parsed = ker_ini_parse_file(file, parse_ini, &config);
    close_status = fclose(file);
    const char *broker_path = getenv("KER_SOCKET_BROKER_PATH");
    if (parsed || close_status || !config.version || !config.path ||
        !config.graceful_reload || !broker_path ||
        strcmp(broker_path, config.broker_path)) PROFILE_REJECT("runtime ini contents");
#undef PROFILE_REJECT
    return NGX_OK;
}

static ngx_int_t
close_cycle_caps(void)
{
    if (current_slot >= 0) {
        (void)syscall(SYS_close, current_slot);
        current_slot = -1;
    }
    if (current_plan >= 0) {
        (void)syscall(SYS_close, current_plan);
        current_plan = -1;
    }
    if (broker_open) {
        ker_socket_client_close(&broker);
        broker_open = false;
    }
    return NGX_OK;
}

static ngx_int_t
drain_previous_cycle(ngx_log_t *log)
{
    int group, census;
    struct ker_socket_member_census_snapshot snapshot;
    struct ker_socket_member_payload_snapshot payload;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    if (!broker_open) return current_plan < 0 && retiring_census < 0
        ? NGX_OK : NGX_ERROR;
    if (retiring_census < 0 && current_plan >= 0 && current_slot >= 0) {
        group = -1;
        for (unsigned attempt = 0; attempt < 500; ++attempt) {
            group = ker_socket_client_owner_group_control_after_exit(&broker,
                current_plan);
            if (group >= 0 || errno != EAGAIN) break;
            (void)nanosleep(&pause, NULL);
        }
        if (group < 0) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "C22 old listener owner has not reached authenticated exit");
            return NGX_ERROR;
        }
        census = ker_socket_client_member_census_create(&broker, group, 0);
        if (census < 0) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "C22 could not census previous published listener");
            (void)syscall(SYS_close, group);
            return NGX_ERROR;
        }
        (void)syscall(SYS_close, group);
        retiring_census = census;
        /* The plan and slot pin the listener. Retain only the independent
         * census capability while old TCP state drains, including retries. */
        (void)syscall(SYS_close, current_slot);
        current_slot = -1;
        (void)syscall(SYS_close, current_plan);
        current_plan = -1;
    }
    if (retiring_census < 0) return NGX_OK;
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
        memset(&snapshot, 0, sizeof(snapshot));
        if (ker_socket_client_member_census_snapshot(&broker, retiring_census, &snapshot)) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "C22 previous listener census failed");
            return NGX_ERROR;
        }
        memset(&payload, 0, sizeof(payload));
        if (ker_socket_client_member_payload_snapshot(&broker, retiring_census, &payload)) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "C22 previous listener payload census failed");
            return NGX_ERROR;
        }
        uint64_t time_wait = snapshot.state_counts[KER_SOCKET_TCP_STATE_TIME_WAIT];
        if (snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 0 &&
            snapshot.total == time_wait && snapshot.listener_cookie != 0 &&
            payload.payload_bytes == 0) {
            trace_line("C22_RETIRED pid=%ld cookie=%llu total=%llu timewait=%llu listen=0 payload=0\n",
                (long)getpid(), (unsigned long long)snapshot.listener_cookie,
                (unsigned long long)snapshot.total, (unsigned long long)time_wait);
            (void)syscall(SYS_close, retiring_census);
            retiring_census = -1;
            retirement_proven = true;
            return NGX_OK;
        }
        (void)nanosleep(&pause, NULL);
    }
    ngx_log_error(NGX_LOG_ERR, log, 0,
        "C22 previous listener did not drain before the bounded deadline");
    return NGX_ERROR;
}

static ngx_int_t
create_owner_plan(ngx_log_t *log)
{
    const char *path = getenv("KER_SOCKET_BROKER_PATH");
    if (!broker_open) {
        if (!path || ker_socket_client_open(&broker, path)) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "C22 could not reopen broker control connection");
            return NGX_ERROR;
        }
        broker_open = true;
    }
    current_plan = ker_socket_client_owner_group_staged_plan(&broker,
        &owner_address, owner_backlog,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    if (current_plan < 0) goto failed;
    current_slot = ker_socket_client_owner_group_slot(&broker, current_plan, 0);
    if (current_slot < 0) goto failed;
    retirement_proven = false;
    trace_line("C22_PLAN pid=%ld address=%s port=%u backlog=%d\n",
        (long)getpid(), inet_ntoa(owner_address.sin_addr),
        ntohs(owner_address.sin_port), owner_backlog);
    return NGX_OK;

failed:
    ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
        "C22 could not reserve owner-group respawn slot");
    (void)close_cycle_caps();
    return NGX_ERROR;
}

/* Called by the pinned fork interposer only at ngx_spawn_process's exact
 * worker-respawn callsite, after the previous child has been reaped. */
int
ker_fstack_nginx_owner_activation_respawn_prepare(void)
{
    if (ngx_process != NGX_PROCESS_MASTER || ngx_cycle == NULL ||
        (current_plan < 0 && retiring_census < 0 && !retirement_proven) ||
        respawn_plan_pending) {
        errno = EPROTO;
        return -1;
    }
    if ((current_plan >= 0 || retiring_census >= 0) &&
        drain_previous_cycle(ngx_cycle->log) != NGX_OK) {
        errno = EAGAIN;
        trace_line("C22_RESPAWN_DRAIN_PENDING pid=%ld\n", (long)getpid());
        return -1;
    }
    if (!retirement_proven && current_plan >= 0) {
        errno = EPROTO;
        return -1;
    }
    if (create_owner_plan(ngx_cycle->log) != NGX_OK) return -1;
    respawn_plan_pending = true;
    trace_line("C22_RESPAWN_PLAN pid=%ld slot=%d\n",
        (long)getpid(), current_slot);
    return 0;
}

void
ker_fstack_nginx_owner_activation_respawn_commit(void)
{
    respawn_plan_pending = false;
}

void
ker_fstack_nginx_owner_activation_respawn_abort(void)
{
    if (!respawn_plan_pending) return;
    if (current_slot >= 0) {
        (void)syscall(SYS_close, current_slot);
        current_slot = -1;
    }
    if (current_plan >= 0) {
        (void)syscall(SYS_close, current_plan);
        current_plan = -1;
    }
    respawn_plan_pending = false;
    retirement_proven = true;
    trace_line("C22_RESPAWN_FORK_FAILED pid=%ld\n", (long)getpid());
}

static ngx_int_t
module_init(ngx_cycle_t *cycle)
{
    typedef int (*abi_matches_fn)(void);
    abi_matches_fn abi_matches = (abi_matches_fn)dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_owner_activation_abi_matches");
    static const char abi_error[] =
        "C22 owner-activation module: pinned Nginx build ID mismatch or missing pinned worker activation shim\n";
    /* The executable's custom ngx_* layout is unsafe to read until the
     * preloaded shim verifies the running main ELF's pinned GNU build ID. */
    if (!abi_matches || abi_matches() != 0) {
        (void)syscall(SYS_write, STDERR_FILENO, abi_error, sizeof(abi_error) - 1);
        return NGX_ERROR;
    }
    struct sockaddr_in address;
    int backlog;
    const char *path;
    ngx_int_t profile_status = validate_profile(cycle, &address, &backlog);
    if (profile_status == NGX_DECLINED) return NGX_OK;
    if (profile_status != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "C22 owner-activation module refuses unsupported Nginx profile");
        return NGX_ERROR;
    }
    if (ngx_test_config) return NGX_OK;
    if (drain_previous_cycle(cycle->log) != NGX_OK) return NGX_ERROR;
    if (broker_open) {
        ker_socket_client_close(&broker);
        broker_open = false;
    }
    path = getenv("KER_SOCKET_BROKER_PATH");
    if (!path || ker_socket_client_open(&broker, path)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
            "C22 could not open broker control connection");
        return NGX_ERROR;
    }
    broker_open = true;
    owner_address = address;
    owner_backlog = backlog;
    return create_owner_plan(cycle->log);
}

/* Called by the existing F-Stack ff_init shim after owner creation and before
 * Nginx's first original socket() call. The worker never sees plan control. */
int
ker_fstack_nginx_owner_activation_worker_prepare(ngx_cycle_t *cycle)
{
    typedef int (*prepare_fn)(int);
    prepare_fn prepare;
    ngx_uint_t *process = dlsym(RTLD_DEFAULT, "ngx_process");
    ngx_uint_t *worker = dlsym(RTLD_DEFAULT, "ngx_worker");
    if (worker_prepared || !process || !worker ||
        *process != NGX_PROCESS_WORKER || *worker != 0 ||
        ngx_cycle != cycle ||
        current_slot < 0 || current_plan < 0) { errno = EPROTO; return -1; }
    int slot = current_slot;
    trace_line("C22_WORKER_SLOT pid=%ld slot=%d\n", (long)getpid(), slot);
    (void)syscall(SYS_close, current_plan);
    current_plan = -1;
    if (broker_open) {
        ker_socket_client_close(&broker);
        broker_open = false;
    }
    prepare = (prepare_fn)dlsym(RTLD_DEFAULT,
        "ker_sb_preload_ff_owner_initial_listener_prepare");
    if (!prepare || prepare(slot)) {
        int error = errno ? errno : ENOTSUP;
        trace_line("C22_WORKER_PREPARE_FAILED pid=%ld error=%d\n",
            (long)getpid(), error);
        (void)syscall(SYS_close, slot);
        current_slot = -1;
        errno = error;
        return -1;
    }
    (void)syscall(SYS_close, slot);
    current_slot = -1;
    worker_prepared = true;
    respawn_plan_pending = false;
    trace_line("C22_WORKER_PREPARED pid=%ld\n", (long)getpid());
    return 0;
}

static void
module_exit_master(ngx_cycle_t *cycle)
{
    if ((current_plan >= 0 || retiring_census >= 0) && broker_open)
        (void)drain_previous_cycle(cycle->log);
    if (retiring_census >= 0) {
        (void)syscall(SYS_close, retiring_census);
        retiring_census = -1;
    }
    (void)close_cycle_caps();
}

static ngx_core_module_t module_context = {
    ngx_string("ker_fstack_nginx_owner_activation"), NULL, NULL
};

ngx_module_t ker_fstack_nginx_owner_activation_module = {
    NGX_MODULE_V1,
    &module_context,
    NULL,
    NGX_CORE_MODULE,
    NULL,
    module_init,
    NULL,
    NULL,
    NULL,
    NULL,
    module_exit_master,
    NGX_MODULE_V1_PADDING
};

ngx_module_t *ngx_modules[] = { &ker_fstack_nginx_owner_activation_module, NULL };
char *ngx_module_names[] = { "ker_fstack_nginx_owner_activation_module", NULL };
char *ngx_module_order[] = { NULL };
