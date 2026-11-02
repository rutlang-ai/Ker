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
#include <openssl/evp.h>
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
#include <sys/socket.h>
#include <poll.h>
#include <sys/stat.h>

#include "nginx-cycle-wire.h"
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

/* Serial-cycle control exists only in the explicitly configured profile. */
static int cycle_control_fd = -1;
static int cycle_outer_pidfd = -1;
static bool cycle_control_enabled;
static bool cycle_control_initialized;
static bool cycle_watch_published;
static bool cycle_control_unresolved;
static pid_t cycle_outer_pid;
static uid_t cycle_outer_uid;
static gid_t cycle_outer_gid;
static uint64_t cycle_outer_start;
static uint8_t cycle_outer_exe_sha256[32];
static struct stat cycle_control_stat;
static struct stat cycle_outer_pidfd_stat;
static uint64_t cycle_control_cookie;
static uint64_t cycle_master_start;
static uint8_t cycle_master_nonce[16];
static uint64_t cycle_message_sequence = 1;
static uint64_t cycle_id = 1;
static struct ker_nginx_cycle_runtime cycle_runtime;

#define CYCLE_CONTROL_TIMEOUT_MS 30000
#define CYCLE_CONTROL_CMSG_BYTES (CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 8))

static int cycle_monotonic_ns(uint64_t *now_ns);
static void cycle_close_fd(int fd);

static int
cycle_read_start_ticks(pid_t pid, uint64_t *ticks)
{
    char path[64], buffer[4096], *cursor, *end;
    int length, fd;
    ssize_t got;
    unsigned field;
    if (pid <= 0 || !ticks) { errno = EINVAL; return -1; }
    length = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) { errno = EOVERFLOW; return -1; }
    fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    got = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    errno = saved;
    if (got <= 0 || (size_t)got >= sizeof(buffer) - 1) { errno = EPROTO; return -1; }
    buffer[got] = '\0';
    cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ') { errno = EPROTO; return -1; }
    cursor += 2;
    /* Field 3 starts after comm; starttime is field 22. */
    for (field = 3; field <= 22; ++field) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) { errno = EPROTO; return -1; }
        end = cursor;
        while (*end && *end != ' ') ++end;
        if (field == 22) {
            char saved_char = *end;
            *end = '\0';
            errno = 0;
            unsigned long long value = strtoull(cursor, &end, 10);
            int parse_error = errno;
            *end = saved_char;
            if (parse_error || end == cursor || value == 0) { errno = EPROTO; return -1; }
            *ticks = (uint64_t)value;
            return 0;
        }
        cursor = end;
    }
    errno = EPROTO;
    return -1;
}

static void
cycle_close_fd(int fd)
{
    (void)syscall(SYS_close, fd);
}

static int
cycle_peer_alive(void)
{
    struct pollfd pollfd = {.fd = cycle_outer_pidfd,
        .events = POLLIN | POLLHUP | POLLERR | POLLNVAL};
    uint64_t current_start;
    if (cycle_outer_pidfd < 0 || syscall(SYS_poll, &pollfd, 1, 0) < 0 ||
        pollfd.revents != 0 || cycle_read_start_ticks(cycle_outer_pid,
            &current_start) < 0) return 0;
    return current_start == cycle_outer_start;
}

static int
cycle_hash_outer_exe(uint64_t deadline_ns, uint8_t digest[32])
{
    char path[64];
    uint8_t buffer[16384];
    unsigned int digest_bytes = 0;
    int fd, path_bytes;
    ssize_t got;
    EVP_MD_CTX *ctx = NULL;
    path_bytes = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)cycle_outer_pid);
    if (path_bytes <= 0 || (size_t)path_bytes >= sizeof(path)) { errno = EOVERFLOW; return -1; }
    fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto failed;
    for (;;) {
        uint64_t now_ns;
        if (cycle_monotonic_ns(&now_ns) < 0 || now_ns >= deadline_ns) {
            errno = ETIMEDOUT;
            goto failed;
        }
        got = syscall(SYS_read, fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) goto failed;
        if (got == 0) break;
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) {
            errno = EIO;
            goto failed;
        }
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_bytes) != 1 || digest_bytes != 32) {
        errno = EIO;
        goto failed;
    }
    EVP_MD_CTX_free(ctx);
    (void)syscall(SYS_close, fd);
    return 0;
failed:
    EVP_MD_CTX_free(ctx);
    (void)syscall(SYS_close, fd);
    if (!errno) errno = EIO;
    return -1;
}

static int
cycle_outer_identity_valid(uint64_t deadline_ns)
{
    uint64_t current_start;
    uint8_t digest[32];
    if (!cycle_peer_alive() || cycle_read_start_ticks(cycle_outer_pid,
            &current_start) < 0 || current_start != cycle_outer_start ||
        cycle_hash_outer_exe(deadline_ns, digest) < 0 ||
        memcmp(digest, cycle_outer_exe_sha256, sizeof(digest)) != 0 ||
        !cycle_peer_alive() || cycle_read_start_ticks(cycle_outer_pid,
            &current_start) < 0 || current_start != cycle_outer_start) {
        errno = EPERM;
        return 0;
    }
    uint64_t now_ns;
    if (cycle_monotonic_ns(&now_ns) < 0 || now_ns >= deadline_ns) {
        errno = ETIMEDOUT;
        return 0;
    }
    return 1;
}

static int
cycle_monotonic_ns(uint64_t *now_ns)
{
    struct timespec now;
    if (!now_ns || clock_gettime(CLOCK_MONOTONIC, &now) < 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) return -1;
    *now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec;
    return 0;
}

static int
cycle_control_init(void)
{
    const char *fd_text = getenv("KER_NGINX_CYCLE_FD");
    const char *nonce_text = getenv("KER_NGINX_CYCLE_NONCE");
    const char *runtime_nonce = getenv("KER_NGINX_CYCLE_RUNTIME_NONCE");
    const char *runtime_epoch = getenv("KER_NGINX_CYCLE_RUNTIME_EPOCH");
    const char *runtime_profile = getenv("KER_NGINX_CYCLE_WORKER_PROFILE_SHA256");
    struct ucred peer;
    socklen_t peer_bytes = sizeof(peer);
    int type = 0;
    socklen_t type_bytes = sizeof(type);
    uint64_t epoch;
    if (cycle_control_initialized) return cycle_control_unresolved ? -1 : 0;
    cycle_control_initialized = true;
    if (!fd_text) return 0;
    uint64_t parsed_fd;
    if (ker_nginx_cycle_parse_decimal(fd_text, INT_MAX, 1, &parsed_fd) ||
        parsed_fd < 3 ||
        ker_nginx_cycle_parse_hex(nonce_text, cycle_master_nonce,
            sizeof(cycle_master_nonce)) ||
        ker_nginx_cycle_parse_hex(runtime_nonce, cycle_runtime.broker_nonce, 16) ||
        ker_nginx_cycle_parse_decimal(runtime_epoch, UINT64_MAX, 1, &epoch) ||
        ker_nginx_cycle_parse_hex(runtime_profile,
            cycle_runtime.worker_profile_sha256, 32) ||
        ker_nginx_cycle_parse_hex(getenv("KER_NGINX_CYCLE_OUTER_EXE_SHA256"),
            cycle_outer_exe_sha256, 32)) {
        errno = EINVAL;
        return -1;
    }
    cycle_control_fd = (int)parsed_fd;
    socklen_t cookie_bytes = sizeof(cycle_control_cookie);
    if (syscall(SYS_getsockopt, cycle_control_fd, SOL_SOCKET, SO_COOKIE,
            &cycle_control_cookie, &cookie_bytes) < 0 ||
        cookie_bytes != sizeof(cycle_control_cookie) || !cycle_control_cookie ||
        syscall(SYS_fstat, cycle_control_fd, &cycle_control_stat) < 0 ||
        syscall(SYS_getsockopt, cycle_control_fd, SOL_SOCKET, SO_TYPE,
            &type, &type_bytes) < 0 || type != SOCK_SEQPACKET ||
        syscall(SYS_getsockopt, cycle_control_fd, SOL_SOCKET, SO_PEERCRED,
            &peer, &peer_bytes) < 0 || peer_bytes != sizeof(peer) || peer.pid <= 1 ||
        peer.uid != getuid() || peer.gid != getgid() ||
        syscall(SYS_setsockopt, cycle_control_fd, SOL_SOCKET, SO_PASSCRED,
            &(int){1}, sizeof(int)) < 0) {
        errno = EPROTO;
        return -1;
    }
    cycle_outer_pid = peer.pid;
    cycle_outer_uid = peer.uid;
    cycle_outer_gid = peer.gid;
    if (cycle_read_start_ticks(cycle_outer_pid, &cycle_outer_start) < 0 ||
        cycle_read_start_ticks(getpid(), &cycle_master_start) < 0) return -1;
    cycle_outer_pidfd = (int)syscall(SYS_pidfd_open, cycle_outer_pid, 0);
    if (cycle_outer_pidfd < 0 ||
        syscall(SYS_fstat, cycle_outer_pidfd, &cycle_outer_pidfd_stat) < 0 ||
        !cycle_peer_alive()) return -1;
    uint64_t identity_deadline;
    if (cycle_monotonic_ns(&identity_deadline) < 0) return -1;
    identity_deadline += (uint64_t)CYCLE_CONTROL_TIMEOUT_MS * UINT64_C(1000000);
    if (!cycle_outer_identity_valid(identity_deadline)) return -1;
    cycle_runtime.broker_epoch = epoch;
    cycle_control_enabled = true;
    int flags = (int)syscall(SYS_fcntl, cycle_control_fd, F_GETFL, 0);
    int fdflags = (int)syscall(SYS_fcntl, cycle_control_fd, F_GETFD, 0);
    if (flags < 0 || fdflags < 0 ||
        syscall(SYS_fcntl, cycle_control_fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        syscall(SYS_fcntl, cycle_control_fd, F_SETFD, fdflags | FD_CLOEXEC) < 0)
        return -1;
    return 0;
}

/* Called by the pinned fork interposer in every child, before Nginx child code
 * can reuse either numeric descriptor. This function is async-signal-safe. */
void
ker_fstack_nginx_cycle_control_child_close(void)
{
    /* The master owns both descriptors exclusively until its exit; no master
     * path closes them earlier. Verify the socket identity before a child
     * closes its inherited number, then disable this child copy immediately. */
    if (cycle_control_fd >= 0) {
        struct stat current;
        uint64_t cookie = 0;
        socklen_t bytes = sizeof(cookie);
        if (syscall(SYS_fstat, cycle_control_fd, &current) == 0 &&
            current.st_dev == cycle_control_stat.st_dev &&
            current.st_ino == cycle_control_stat.st_ino &&
            syscall(SYS_getsockopt, cycle_control_fd, SOL_SOCKET, SO_COOKIE,
                &cookie, &bytes) == 0 && bytes == sizeof(cookie) &&
            cookie == cycle_control_cookie)
            (void)syscall(SYS_close, cycle_control_fd);
    }
    if (cycle_outer_pidfd >= 0) {
        struct stat current;
        if (syscall(SYS_fstat, cycle_outer_pidfd, &current) == 0 &&
            current.st_dev == cycle_outer_pidfd_stat.st_dev &&
            current.st_ino == cycle_outer_pidfd_stat.st_ino)
            (void)syscall(SYS_close, cycle_outer_pidfd);
    }
    cycle_control_fd = -1;
    cycle_outer_pidfd = -1;
    cycle_control_enabled = false;
}

static int
cycle_wait(short events, uint64_t deadline_ns)
{
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
        uint64_t now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
            (uint64_t)now.tv_nsec;
        if (now_ns >= deadline_ns || !cycle_peer_alive()) { errno = ETIMEDOUT; return -1; }
        uint64_t remaining = deadline_ns - now_ns;
        int timeout_ms = (int)((remaining + 999999) / 1000000);
        if (timeout_ms < 1) timeout_ms = 1;
        if (timeout_ms > 1000) timeout_ms = 1000;
        struct pollfd fds[2] = {
            {.fd = cycle_control_fd, .events = events | POLLHUP | POLLERR | POLLNVAL},
            {.fd = cycle_outer_pidfd, .events = POLLIN | POLLHUP | POLLERR | POLLNVAL}
        };
        int rc = (int)syscall(SYS_poll, fds, 2, timeout_ms);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return -1;
        if (fds[1].revents || (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))) {
            errno = EPIPE;
            return -1;
        }
        if (fds[0].revents & events) return 0;
    }
}

static int
cycle_send(uint16_t type, uint64_t cycle, uint64_t sequence,
    const struct ker_nginx_cycle_runtime *runtime, int rights_fd,
    uint64_t deadline)
{
    uint8_t packet[KER_NGX_CYCLE_WATCH_BYTES] = {0};
    size_t bytes = type == KER_NGX_CYCLE_WATCH_BOUND || type == KER_NGX_CYCLE_READY
        ? KER_NGX_CYCLE_WATCH_BYTES : KER_NGX_CYCLE_HEADER_BYTES;
    if (ker_nginx_cycle_encode_header(packet, type, (uint32_t)bytes, 0,
            cycle_master_nonce, cycle_master_start, sequence, cycle) < 0) return -1;
    if (bytes == KER_NGX_CYCLE_WATCH_BYTES &&
        ker_nginx_cycle_encode_runtime(packet + KER_NGX_CYCLE_HEADER_BYTES, runtime) < 0)
        return -1;
    uint64_t now_ns;
    if (!deadline) {
        if (cycle_monotonic_ns(&now_ns) < 0) return -1;
        deadline = now_ns + (type == KER_NGX_CYCLE_WATCH_BOUND
            ? UINT64_C(100000000) :
              (uint64_t)CYCLE_CONTROL_TIMEOUT_MS * UINT64_C(1000000));
    }
    struct iovec iov = {.iov_base = packet, .iov_len = bytes};
    union { struct cmsghdr align; uint8_t bytes[CMSG_SPACE(sizeof(int))]; } control;
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (rights_fd >= 0) {
        memset(&control, 0, sizeof(control));
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &rights_fd, sizeof(rights_fd));
    }
    for (;;) {
        if (cycle_monotonic_ns(&now_ns) < 0 || now_ns >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        ssize_t sent = syscall(SYS_sendmsg, cycle_control_fd, &message,
            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent == (ssize_t)bytes) return 0;
        if (sent >= 0) { errno = EPROTO; return -1; }
        if (errno == EINTR) {
            if (type == KER_NGX_CYCLE_WATCH_BOUND) continue;
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        /* Initial module_init must never wait for the companion STARTED path. */
        if (type == KER_NGX_CYCLE_WATCH_BOUND) return -1;
        if (cycle_wait(POLLOUT, deadline) < 0) return -1;
    }
}

static int
cycle_receive_ready(uint64_t expected_sequence, uint64_t next_cycle,
    struct ker_nginx_cycle_runtime *runtime, uint64_t deadline)
{
    uint8_t packet[KER_NGX_CYCLE_WATCH_BYTES];
    union { struct cmsghdr align; uint8_t bytes[CYCLE_CONTROL_CMSG_BYTES]; } control;
    uint64_t now_ns;
    if (!deadline && (cycle_monotonic_ns(&now_ns) < 0 ||
        (deadline = now_ns +
            (uint64_t)CYCLE_CONTROL_TIMEOUT_MS * UINT64_C(1000000)) == 0))
        return -1;
    for (;;) {
        if (cycle_wait(POLLIN, deadline) < 0) return -1;
        struct iovec iov = {.iov_base = packet, .iov_len = sizeof(packet)};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
        ssize_t received = syscall(SYS_recvmsg, cycle_control_fd, &message,
            MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (received < 0) return -1;
        /* Even a zero-length SOCK_SEQPACKET record can carry SCM_RIGHTS.
         * Parse and close ancillary data below before rejecting the record. */
        bool empty_packet = received == 0;
        struct ucred *credentials = NULL;
        int ancillary_bad = ker_nginx_cycle_validate_ready_control(&message,
            &credentials, cycle_close_fd) < 0;
        if (empty_packet) { errno = EPIPE; return -1; }
        struct ker_nginx_cycle_header header;
        struct ker_nginx_cycle_runtime decoded;
        if (ancillary_bad || !credentials || credentials->pid != cycle_outer_pid ||
            credentials->uid != cycle_outer_uid || credentials->gid != cycle_outer_gid ||
            !cycle_peer_alive() ||
            ker_nginx_cycle_decode(packet, (size_t)received, &header, &decoded) < 0 ||
            header.type != KER_NGX_CYCLE_READY || header.status != 0 ||
            memcmp(header.master_nonce, cycle_master_nonce, 16) ||
            header.master_start_ticks != cycle_master_start ||
            header.sequence != expected_sequence || header.cycle_id != next_cycle ||
            (decoded.broker_epoch == cycle_runtime.broker_epoch ||
             memcmp(decoded.broker_nonce, cycle_runtime.broker_nonce, 16) == 0) ||
            memcmp(decoded.worker_profile_sha256,
                cycle_runtime.worker_profile_sha256, 32)) {
            errno = EPROTO;
            return -1;
        }
        uint64_t after_validation_ns;
        if (cycle_monotonic_ns(&after_validation_ns) < 0 ||
            after_validation_ns > deadline || !cycle_outer_identity_valid(deadline)) {
            errno = ETIMEDOUT;
            return -1;
        }
        *runtime = decoded;
        return 0;
    }
}

static int
cycle_publish_watch(ngx_log_t *log)
{
    int watch = ker_socket_client_owner_generation_watch_create(&broker, current_plan);
    if (watch < 0) return -1;
    if (cycle_message_sequence == 0 || cycle_message_sequence == UINT64_MAX) {
        (void)syscall(SYS_close, watch);
        errno = EOVERFLOW;
        return -1;
    }
    if (cycle_send(KER_NGX_CYCLE_WATCH_BOUND, cycle_id, cycle_message_sequence,
            &cycle_runtime, watch, 0) < 0) {
        int error = errno;
        (void)syscall(SYS_close, watch);
        errno = error;
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "C22 could not transfer PLAN_BOUND generation watch");
        return -1;
    }
    (void)syscall(SYS_close, watch);
    ++cycle_message_sequence;
    return 0;
}

static int
cycle_drain_barrier(ngx_log_t *log)
{
    if (!cycle_control_enabled || cycle_control_unresolved || cycle_id == 0 ||
        cycle_message_sequence == 0 || cycle_message_sequence == UINT64_MAX) {
        errno = EPROTO;
        return -1;
    }
    uint64_t request_sequence = cycle_message_sequence++;
    uint64_t deadline_ns;
    if (cycle_monotonic_ns(&deadline_ns) < 0) return -1;
    deadline_ns += (uint64_t)CYCLE_CONTROL_TIMEOUT_MS * UINT64_C(1000000);
    if (cycle_send(KER_NGX_CYCLE_DRAINED, cycle_id, request_sequence, NULL, -1,
            deadline_ns) < 0) {
        cycle_control_unresolved = true;
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "C22 could not send cycle-drained barrier");
        return -1;
    }
    struct ker_nginx_cycle_runtime next_runtime;
    if (cycle_id == UINT64_MAX || cycle_receive_ready(request_sequence,
            cycle_id + 1, &next_runtime, deadline_ns) < 0) {
        cycle_control_unresolved = true;
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "C22 cycle-ready barrier failed or was uncertain");
        return -1;
    }
    cycle_runtime = next_runtime;
    ++cycle_id;
    return 0;
}

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
    /* The serial controller owns one watch per full HUP cycle. Nginx's
     * worker-crash respawn path does not pass through module_init, so it
     * cannot create a successor watch or obtain a matching outer receipt.
     * Refuse that path before draining or reserving any new owner plan. */
    if (cycle_control_enabled) {
        cycle_control_unresolved = true;
        errno = EOPNOTSUPP;
        trace_line("C22_SERIAL_RESPAWN_UNSUPPORTED pid=%ld\n", (long)getpid());
        return -1;
    }
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
    if (cycle_control_init() < 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
            "C22 invalid serial-cycle control endpoint/profile");
        cycle_control_unresolved = true;
        return NGX_ERROR;
    }
    if (drain_previous_cycle(cycle->log) != NGX_OK) return NGX_ERROR;
    if (broker_open) {
        ker_socket_client_close(&broker);
        broker_open = false;
    }
    if (cycle_control_enabled && cycle_watch_published &&
        cycle_drain_barrier(cycle->log) < 0) return NGX_ERROR;
    path = getenv("KER_SOCKET_BROKER_PATH");
    if (!path || ker_socket_client_open(&broker, path)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
            "C22 could not open broker control connection");
        return NGX_ERROR;
    }
    broker_open = true;
    owner_address = address;
    owner_backlog = backlog;
    if (create_owner_plan(cycle->log) != NGX_OK) return NGX_ERROR;
    if (cycle_control_enabled) {
        if (cycle_message_sequence == 1) cycle_id = 1;
        if (cycle_publish_watch(cycle->log) < 0) {
            cycle_control_unresolved = true;
            (void)close_cycle_caps();
            return NGX_ERROR;
        }
        cycle_watch_published = true;
    }
    return NGX_OK;
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
    if (cycle_control_fd >= 0) {
        (void)syscall(SYS_close, cycle_control_fd);
        cycle_control_fd = -1;
    }
    if (cycle_outer_pidfd >= 0) {
        (void)syscall(SYS_close, cycle_outer_pidfd);
        cycle_outer_pidfd = -1;
    }
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
