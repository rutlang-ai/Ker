/*
 * Per-worker reuseport listener preparation for the pinned F-Stack Nginx
 * caller. This translation unit must be compiled against that executable's
 * original source headers and generated configuration. It is not part of the
 * generic runtime DSO because ngx_listening_t is a build-specific ABI.
 */

#define _GNU_SOURCE
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_connection.h>
#include <ngx_module.h>
#include <ngx_process_cycle.h>

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef KER_FSTACK_NGINX_EXPECTED_BUILD_ID
#error "build the shim with the selected Nginx ELF build ID"
#endif

#if !NGX_HAVE_FSTACK || !NGX_HAVE_REUSEPORT
#error "the multiworker shim requires the pinned FF and reuseport build"
#endif

static __thread int secondary_authorization_active;

int
ker_fstack_nginx_worker_consume_authorization(unsigned int proc_id)
{
    if (!secondary_authorization_active || proc_id != 1)
        return 0;
    secondary_authorization_active = 0;
    return 1;
}

struct build_id_search {
    unsigned char expected[64];
    size_t expected_size;
    int found;
    int malformed;
};

static size_t
align_note(size_t value)
{
    if (value > SIZE_MAX - 3)
        return SIZE_MAX;
    return (value + 3) & ~(size_t)3;
}

static int
read_note_segment(const struct dl_phdr_info *info, const ElfW(Phdr) *phdr,
    struct build_id_search *search)
{
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    uintptr_t segment;
    size_t offset = 0;

    if (phdr->p_vaddr > UINTPTR_MAX - base || phdr->p_memsz > SIZE_MAX)
        return -1;
    segment = base + (uintptr_t)phdr->p_vaddr;
    if ((size_t)phdr->p_memsz > UINTPTR_MAX - segment)
        return -1;

    while (offset < (size_t)phdr->p_memsz) {
        ElfW(Nhdr) note;
        size_t name_size, desc_size, total;
        const unsigned char *name, *desc;

        if ((size_t)phdr->p_memsz - offset < sizeof(note))
            return -1;
        memcpy(&note, (const void *)(segment + offset), sizeof(note));
        name_size = align_note(note.n_namesz);
        desc_size = align_note(note.n_descsz);
        if (name_size == SIZE_MAX || desc_size == SIZE_MAX ||
            name_size > SIZE_MAX - sizeof(note) ||
            desc_size > SIZE_MAX - sizeof(note) - name_size)
            return -1;
        total = sizeof(note) + name_size + desc_size;
        if (total > (size_t)phdr->p_memsz - offset)
            return -1;

        name = (const unsigned char *)(segment + offset + sizeof(note));
        desc = name + name_size;
        if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
            memcmp(name, "GNU\0", 4) == 0)
        {
            if (note.n_descsz != search->expected_size ||
                memcmp(desc, search->expected, search->expected_size) != 0)
                search->malformed = 1;
            else
                search->found = 1;
            return 1;
        }
        offset += total;
    }

    return 0;
}

static int
main_build_id_callback(struct dl_phdr_info *info, size_t info_size, void *opaque)
{
    struct build_id_search *search = opaque;
    size_t index;
    (void)info_size;

    if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0')
        return 0;

    for (index = 0; index < info->dlpi_phnum; ++index) {
        int result;
        if (info->dlpi_phdr[index].p_type != PT_NOTE)
            continue;
        result = read_note_segment(info, &info->dlpi_phdr[index], search);
        if (result != 0)
            return 1;
    }
    return 1;
}

static int
expected_build_id(struct build_id_search *search)
{
    static const char expected[] = KER_FSTACK_NGINX_EXPECTED_BUILD_ID;
    size_t index;

    if (sizeof(expected) != 41)
        return -1;
    search->expected_size = 20;
    for (index = 0; index < search->expected_size; ++index) {
        unsigned int high, low;
        char a = expected[index * 2], b = expected[index * 2 + 1];
        if (a >= '0' && a <= '9') high = (unsigned int)(a - '0');
        else if (a >= 'a' && a <= 'f') high = (unsigned int)(a - 'a' + 10);
        else return -1;
        if (b >= '0' && b <= '9') low = (unsigned int)(b - '0');
        else if (b >= 'a' && b <= 'f') low = (unsigned int)(b - 'a' + 10);
        else return -1;
        search->expected[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int
main_binary_matches_pinned_build(void)
{
    struct build_id_search search = {0};

    if (expected_build_id(&search) != 0 ||
        dl_iterate_phdr(main_build_id_callback, &search) == 0 ||
        search.malformed || !search.found)
    {
        errno = ENOTSUP;
        return -1;
    }
    return 0;
}

int
ker_fstack_nginx_owner_activation_abi_matches(void)
{
    return main_binary_matches_pinned_build();
}

static int
unsupported(const char *reason)
{
    char line[192];
    int count = snprintf(line, sizeof(line),
        "ker fstack nginx worker shim: refusing profile: %s\n", reason);
    if (count > 0)
        (void)syscall(SYS_write, STDERR_FILENO, line,
            (size_t)count < sizeof(line) ? (size_t)count : sizeof(line));
    errno = ENOTSUP;
    return -1;
}

static void
trace_worker_preparation(ngx_uint_t worker, ngx_uint_t worker_count,
    ngx_uint_t listeners)
{
    const char *path = getenv("KER_FSTACK_RUNTIME_TRACE");
    char line[192];
    int fd, length;

    if (path == NULL || path[0] == '\0')
        return;
    length = snprintf(line, sizeof(line),
        "nginx_worker_shim pid=%ld worker=%lu workers=%lu listeners=%lu ignored_worker=%s\n",
        (long)getpid(), (unsigned long)worker, (unsigned long)worker_count,
        (unsigned long)listeners, worker_count == 2 ? (worker == 0 ? "1" : "0") : "none");
    if (length <= 0 || (size_t)length >= sizeof(line))
        return;
    fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    (void)syscall(SYS_write, fd, line, (size_t)length);
    (void)syscall(SYS_close, fd);
}

static int
parse_worker_argument(int argc, char * const argv[], ngx_uint_t *worker,
    int *primary)
{
    char *end = NULL;
    unsigned long value;
    const char *prefix = "--proc-id=";
    size_t prefix_size = strlen(prefix);

    if (argc != 4 || argv == NULL || argv[0] == NULL || argv[1] == NULL ||
        argv[2] == NULL || argv[3] == NULL || strcmp(argv[0], "nginx") != 0 ||
        strncmp(argv[1], "--conf=", 7) != 0 || argv[1][7] == '\0' ||
        strncmp(argv[2], prefix, prefix_size) != 0 || argv[2][prefix_size] == '\0')
        return -1;
    errno = 0;
    value = strtoul(argv[2] + prefix_size, &end, 10);
    if (errno != 0 || end == argv[2] + prefix_size || *end != '\0' || value > 1)
        return -1;

    if (strcmp(argv[3], "--proc-type=primary") == 0)
        *primary = 1;
    else if (strcmp(argv[3], "--proc-type=secondary") == 0)
        *primary = 0;
    else
        return -1;
    *worker = (ngx_uint_t)value;
    return 0;
}

static const char *
listener_option_violation(const ngx_listening_t *listener)
{
    if (listener->rcvbuf != -1) return "receive-buffer option";
    if (listener->sndbuf != -1) return "send-buffer option";
    if (listener->keepalive != 0) return "keepalive option";
    if (listener->deferred_accept || listener->add_deferred || listener->delete_deferred)
        return "deferred-accept option";
    if (listener->quic) return "QUIC listener flag";
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    if (listener->keepidle != 0) return "TCP keep-idle option";
    if (listener->keepintvl != 0) return "TCP keep-interval option";
    if (listener->keepcnt != 0) return "TCP keep-count option";
#endif
#if (NGX_HAVE_SETFIB)
    if (listener->setfib != -1) return "setfib option";
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    if (listener->fastopen != -1) return "TCP fast-open option";
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    if (listener->accept_filter != NULL) return "accept-filter option";
#endif
    return NULL;
}

static int
same_address(const ngx_listening_t *left, const ngx_listening_t *right)
{
    if (left->sockaddr == NULL || right->sockaddr == NULL ||
        left->socklen != right->socklen || left->sockaddr->sa_family !=
            right->sockaddr->sa_family)
        return 0;
    if (left->sockaddr->sa_family == AF_INET &&
        left->socklen >= sizeof(struct sockaddr_in))
    {
        const struct sockaddr_in *a = (const struct sockaddr_in *)left->sockaddr;
        const struct sockaddr_in *b = (const struct sockaddr_in *)right->sockaddr;
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
#if (NGX_HAVE_INET6)
    if (left->sockaddr->sa_family == AF_INET6 &&
        left->socklen >= sizeof(struct sockaddr_in6))
    {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)left->sockaddr;
        const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)right->sockaddr;
        return a->sin6_port == b->sin6_port && a->sin6_scope_id == b->sin6_scope_id &&
            memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
    }
#endif
    return 0;
}

static int
validate_worker_cycle(int argc, char * const argv[], ngx_cycle_t **cycle_out,
    ngx_uint_t *worker_out, ngx_uint_t *worker_count_out)
{
    ngx_module_t *core_module;
    ngx_cycle_t **cycle_slot;
    ngx_uint_t *worker_slot, *process_slot;
    ngx_cycle_t *cycle;
    ngx_core_conf_t *core_conf;
    ngx_listening_t *listeners;
    ngx_uint_t worker;
    int primary, seen[2] = {0, 0};

    if (getenv("FF_FAULT") != NULL)
        return unsupported("FF_FAULT is unsupported by this bounded profile");
    core_module = dlsym(RTLD_DEFAULT, "ngx_core_module");
    cycle_slot = dlsym(RTLD_DEFAULT, "ngx_cycle");
    worker_slot = dlsym(RTLD_DEFAULT, "ngx_worker");
    process_slot = dlsym(RTLD_DEFAULT, "ngx_process");
    if (core_module == NULL || cycle_slot == NULL || worker_slot == NULL ||
        process_slot == NULL)
        return unsupported("required Nginx ABI exports are unavailable");

    if (core_module->version != nginx_version || core_module->signature == NULL ||
        strcmp(core_module->signature, NGX_MODULE_SIGNATURE) != 0)
        return unsupported("Nginx module version or signature mismatch");
    cycle = *cycle_slot;
    if (cycle == NULL || cycle->modules == NULL || cycle->conf_ctx == NULL ||
        cycle->modules_n == 0 || cycle->modules_n > 4096 ||
        core_module->index >= cycle->modules_n ||
        cycle->modules[core_module->index] != core_module ||
        cycle->conf_ctx[core_module->index] == NULL)
        return unsupported("Nginx core module configuration layout mismatch");

    if (*process_slot != NGX_PROCESS_WORKER || *worker_slot > 1 ||
        parse_worker_argument(argc, argv, &worker, &primary) != 0 ||
        worker != *worker_slot || (worker == 0) != (primary != 0))
        return unsupported("F-Stack role does not match the Nginx worker identity");

    core_conf = (ngx_core_conf_t *)ngx_get_conf(cycle->conf_ctx, core_module[0]);
    if (core_conf == NULL || !core_conf->master ||
        (core_conf->worker_processes != 1 && core_conf->worker_processes != 2))
        return unsupported("only master mode with one or two workers is supported");
    if (worker != *worker_slot || worker >= (ngx_uint_t)core_conf->worker_processes)
        return unsupported("worker identity is outside the configured Nginx worker set");

    if (cycle->listening.size != sizeof(ngx_listening_t) ||
        cycle->listening.elts == NULL ||
        cycle->listening.nelts != (ngx_uint_t)core_conf->worker_processes ||
        cycle->listening.nalloc < cycle->listening.nelts ||
        cycle->listening.nalloc > 16)
        return unsupported("listener array is outside the bounded reuseport profile");
    listeners = cycle->listening.elts;

    /* Validate the complete array before modifying any listener or entering
     * the runtime's ff_init. The two entries must be clones of one TCP endpoint.
     */
    for (ngx_uint_t index = 0; index < cycle->listening.nelts; ++index) {
        ngx_listening_t *listener = &listeners[index];
        ngx_uint_t owner = listener->worker;
        const char *option_error;
        if (owner >= (ngx_uint_t)core_conf->worker_processes || seen[owner])
            return unsupported("listener clone has a duplicate or invalid worker owner");
        if (!listener->reuseport || listener->belong_to_host ||
            listener->type != SOCK_STREAM || listener->sockaddr == NULL ||
            (listener->sockaddr->sa_family != AF_INET &&
             listener->sockaddr->sa_family != AF_INET6) ||
            !same_address(listener, &listeners[0]))
            return unsupported("listener clone is not the expected INET reuseport TCP endpoint");
        if (listener->fd != (ngx_socket_t)-1)
            return unsupported("listener clone already has an fd");
        if (listener->connection != NULL)
            return unsupported("listener clone already has a connection");
        if (listener->ignore)
            return unsupported("listener clone is already ignored");
        if (!listener->open)
            return unsupported("listener clone is not marked open");
        if (listener->bound)
            return unsupported("listener clone is already bound");
        if (listener->inherited)
            return unsupported("listener clone is inherited");
        if (listener->add_reuseport)
            return unsupported("listener clone has pending add_reuseport");
        option_error = listener_option_violation(listener);
        if (option_error != NULL)
            return unsupported(option_error);
        if (listener->logp == NULL)
            return unsupported("listener clone has no log pointer");
        seen[owner] = 1;
    }
    if (!seen[0] || (core_conf->worker_processes == 2 && !seen[1]))
        return unsupported("reuseport endpoint is missing a configured worker clone");

    *cycle_out = cycle;
    *worker_out = worker;
    *worker_count_out = (ngx_uint_t)core_conf->worker_processes;
    return 0;
}

int
ff_init(int argc, char * const argv[])
{
    typedef int (*preflight_fn)(int, char * const []);
    typedef int (*commit_fn)(void);
    typedef int (*initial_owner_prepare_fn)(ngx_cycle_t *);
    preflight_fn runtime_preflight;
    commit_fn runtime_commit;
    initial_owner_prepare_fn initial_owner_prepare;
    ngx_cycle_t *cycle;
    ngx_listening_t *listeners;
    ngx_uint_t worker, worker_count;
    const char *error;

    if (main_binary_matches_pinned_build() != 0)
        return unsupported("main executable build ID mismatch");

    dlerror();
    runtime_preflight = (preflight_fn)dlsym(RTLD_NEXT,
        "ker_fstack_nginx_runtime_preflight");
    runtime_commit = (commit_fn)dlsym(RTLD_NEXT,
        "ker_fstack_nginx_runtime_commit");
    error = dlerror();
    if (error != NULL || runtime_preflight == NULL || runtime_commit == NULL)
        return unsupported("the Ker FF runtime preflight/commit entry points are unavailable");

    if (validate_worker_cycle(argc, argv, &cycle, &worker, &worker_count) != 0)
        return -1;

    secondary_authorization_active = worker == 1 && worker_count == 2;
    if (runtime_preflight(argc, argv) != 0) {
        secondary_authorization_active = 0;
        return -1;
    }

    /* The optional pinned C22 dynamic module reserves the initial listener
     * before fork and exposes only slot 0 to this worker. Its helper runs
     * after runtime_preflight established the authenticated FF owner, but
     * before Nginx's first ff_socket call in ngx_open_listening_sockets(). */
    initial_owner_prepare = (initial_owner_prepare_fn)dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_owner_activation_worker_prepare");
    if (initial_owner_prepare == NULL &&
        getenv("KER_FSTACK_NGINX_INI") != NULL)
        return unsupported("C22 owner activation module helper is unavailable");
    if (initial_owner_prepare != NULL) {
        if (worker != 0 || worker_count != 1 || initial_owner_prepare(cycle) != 0) {
            secondary_authorization_active = 0;
            return unsupported("initial owner activation requires the validated one-worker profile");
        }
    }

    /* The upstream socket-open loop honors ignore. Its later configure pass
     * does not, so we require all FD-affecting options to be default above and
     * clear listen only on an unowned clone. One-worker mode makes no changes.
     */
    if (worker_count == 2) {
        listeners = cycle->listening.elts;
        for (ngx_uint_t index = 0; index < cycle->listening.nelts; ++index) {
            if (listeners[index].worker != worker) {
                listeners[index].ignore = 1;
                listeners[index].listen = 0;
            }
        }
    }

    trace_worker_preparation(worker, worker_count, cycle->listening.nelts);
    secondary_authorization_active = 0;
    return runtime_commit();
}
