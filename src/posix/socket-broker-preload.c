#define _GNU_SOURCE
#include "socket-broker-preload-internal.h"
#include "socket-broker-protocol.h"
#include "ff-owner-admission-control.h"
#include "lkl-overlay/arch/lkl/include/asm/ker-host-usercopy.h"
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

/* Keep the implementation addressable when an executable (notably the
 * original F-Stack Nginx module) defines these POSIX symbols itself. Public
 * preload aliases are emitted at the end of this file. */
#define socket ker_sb_posix_socket
#define bind ker_sb_posix_bind
#define connect ker_sb_posix_connect
#define listen ker_sb_posix_listen
#define accept4 ker_sb_posix_accept4
#define accept ker_sb_posix_accept
#define close ker_sb_posix_close
#define shutdown ker_sb_posix_shutdown
#define getsockname ker_sb_posix_getsockname
#define getpeername ker_sb_posix_getpeername
#define setsockopt ker_sb_posix_setsockopt
#define getsockopt ker_sb_posix_getsockopt
#define read ker_sb_posix_read
#define write ker_sb_posix_write
#define send ker_sb_posix_send
#define recv ker_sb_posix_recv
#define sendto ker_sb_posix_sendto
#define recvfrom ker_sb_posix_recvfrom
#define sendmsg ker_sb_posix_sendmsg
#define recvmsg ker_sb_posix_recvmsg
#define readv ker_sb_posix_readv
#define writev ker_sb_posix_writev
#define epoll_create1 ker_sb_posix_epoll_create1
#define epoll_create ker_sb_posix_epoll_create
#define epoll_ctl ker_sb_posix_epoll_ctl
#define epoll_wait ker_sb_posix_epoll_wait
#define epoll_pwait ker_sb_posix_epoll_pwait
#define dup ker_sb_posix_dup
#define dup2 ker_sb_posix_dup2
#define dup3 ker_sb_posix_dup3
#define fcntl ker_sb_posix_fcntl
#define ioctl ker_sb_posix_ioctl
#define execve ker_sb_posix_execve
#define execv ker_sb_posix_execv
#define execl ker_sb_posix_execl
#define execlp ker_sb_posix_execlp
#define execle ker_sb_posix_execle
#define execvp ker_sb_posix_execvp
#define execvpe ker_sb_posix_execvpe
#define fexecve ker_sb_posix_fexecve
#define execveat ker_sb_posix_execveat
#define sendfile ker_sb_posix_sendfile
#define sendfile64 ker_sb_posix_sendfile64

#define KER_SB_MAX_IOV 64
#define KER_SB_IO_MAX 4096

extern char **environ;
static _Thread_local unsigned ff_dispatch_depth;
static _Thread_local int ff_dispatch_fds[16];
static int ff_owner_capability = -1;
static pid_t ff_owner_pid;
static bool ff_owner_context_started;
static bool unowned_network_activity;
static _Thread_local ker_sb_preload_owner_pump_fn owner_pump_callback;
static _Thread_local void *owner_pump_context;
static _Thread_local unsigned owner_pump_depth;
static _Thread_local int owner_pump_failure;
static _Thread_local unsigned owner_loop_depth;
struct ff_owner_admission_client_state {
    struct ker_ff_admission_channel *channel;
    struct ker_ff_admission_map_ops ops;
    int fd;
};
static _Thread_local struct ff_owner_admission_client_state owner_admission_state;

static int ff_owner_admission_pump(void *context)
{
    struct ff_owner_admission_client_state *state = context;
    if (!state || !state->channel) return -ENOTCONN;
#ifdef KER_C16_ADMISSION_TEST_TRACE
    static _Thread_local bool test_delay_consumed;
    const char *delay_text = getenv("KER_C16_TEST_PUMP_DELAY_US");
    if (!test_delay_consumed && delay_text && *delay_text) {
        test_delay_consumed = true;
        char *end = NULL;
        errno = 0;
        unsigned long delay_us = strtoul(delay_text, &end, 10);
        if (!errno && end != delay_text && !*end && delay_us > 0 &&
            delay_us <= 250000) {
            struct timespec pause = {
                .tv_sec = (time_t)(delay_us / 1000000UL),
                .tv_nsec = (long)(delay_us % 1000000UL) * 1000L};
            while (nanosleep(&pause, &pause) && errno == EINTR) { }
        }
    }
#endif
    int result = ker_ff_admission_channel_owner_step(state->channel, &state->ops);
#ifdef KER_C16_ADMISSION_TEST_TRACE
    static _Thread_local bool test_failure_consumed;
    const char *fail_after_step = getenv("KER_C16_TEST_PUMP_FAIL_AFTER_STEP");
    if (!test_failure_consumed && fail_after_step &&
        !strcmp(fail_after_step, "1")) {
        test_failure_consumed = true;
        (void)unsetenv("KER_C16_TEST_PUMP_FAIL_AFTER_STEP");
        return -ECONNRESET;
    }
#endif
    return result == -EAGAIN || result == -EWOULDBLOCK ? 0 : result;
}

static uint64_t owner_admission_now_ns(void)
{
    struct timespec now = {0};
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) /
            UINT64_C(1000000000)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec;
}

static int owner_admission_poll_fd(int fd, short events, uint64_t deadline)
{
    for (;;) {
        uint64_t now = owner_admission_now_ns();
        if (!now) return -EIO;
        if (now >= deadline) return -ETIMEDOUT;
        uint64_t left = deadline - now;
        int timeout = left / UINT64_C(1000000) > INT_MAX ? INT_MAX :
            (int)((left + UINT64_C(999999)) / UINT64_C(1000000));
        struct pollfd pfd = {.fd = fd, .events = events};
        int result = (int)syscall(SYS_poll, &pfd, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -errno;
        if (!result) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -ECONNRESET;
        return (pfd.revents & events) ? 0 : -EIO;
    }
}

static int owner_admission_ready_reply(int fd, uint64_t registration_id,
    pid_t broker_pid, uid_t broker_uid, gid_t broker_gid,
    struct ker_ff_owner_admission_hello_reply *reply)
{
    uint64_t now = owner_admission_now_ns();
    if (!now || now > UINT64_MAX - UINT64_C(5000000000)) return -EOVERFLOW;
    int status = owner_admission_poll_fd(fd, POLLIN,
        now + UINT64_C(5000000000));
    if (status) return status;
    unsigned char bytes[sizeof(*reply) + 1] = {0};
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 8)] = {0};
    struct iovec iov = {.iov_base = bytes, .iov_len = sizeof(bytes)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t amount = syscall(SYS_recvmsg, fd, &message,
        MSG_DONTWAIT | MSG_CMSG_CLOEXEC | MSG_TRUNC);
    if (amount < 0) return -errno;
    struct ucred credentials = {0};
    unsigned credential_count = 0;
    bool malformed = !amount ||
        !!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_CREDENTIALS &&
            cmsg->cmsg_len == CMSG_LEN(sizeof(credentials)) &&
            ++credential_count == 1) {
            memcpy(&credentials, CMSG_DATA(cmsg), sizeof(credentials));
            continue;
        }
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t fd_bytes = cmsg->cmsg_len - CMSG_LEN(0);
            if (fd_bytes % sizeof(int)) malformed = true;
            for (size_t offset = 0; offset + sizeof(int) <= fd_bytes;
                 offset += sizeof(int)) {
                int received_fd = -1;
                memcpy(&received_fd, (unsigned char *)CMSG_DATA(cmsg) + offset,
                    sizeof(received_fd));
                (void)syscall(SYS_close, received_fd);
            }
        }
        malformed = true;
    }
    if (malformed || credential_count != 1 || amount != sizeof(*reply) ||
        credentials.pid != broker_pid || credentials.uid != broker_uid ||
        credentials.gid != broker_gid) return -EPROTO;
    memcpy(reply, bytes, sizeof(*reply));
    if (reply->magic != KER_FF_OWNER_ADMISSION_HELLO_MAGIC ||
        reply->version != KER_FF_OWNER_ADMISSION_HELLO_VERSION ||
        reply->length != sizeof(*reply) ||
        reply->registration_id != registration_id || reply->reserved)
        return -EPROTO;
    if (reply->status) {
        if (reply->status > 0 || reply->status < -4095) return -EPROTO;
        return reply->status;
    }
    return reply->queue_lease ? 0 : -EPROTO;
}

static void owner_admission_trace_failure(const char *stage, int error)
{
    char message[160];
    int length = snprintf(message, sizeof(message),
        "ker admission attach failed stage=%s errno=%d\n", stage,
        error ? error : EPROTO);
    if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
        (size_t)length);
}

int ker_sb_preload_ff_owner_admission_attach(
    const struct ker_ff_admission_map_ops *ops)
{
    const char *stage = "arguments";
    struct ker_ff_owner_admission_registration registration = {0};
    struct ker_ff_owner_admission_hello hello = {
        .magic = KER_FF_OWNER_ADMISSION_HELLO_MAGIC,
        .version = KER_FF_OWNER_ADMISSION_HELLO_VERSION,
        .length = sizeof(hello)};
    struct ker_ff_owner_admission_hello_reply reply = {0};
    struct ker_ff_admission_channel *channel = NULL;
    struct ucred broker = {0};
    int fd = -1, passcred = 1, error = 0;
    socklen_t credential_length;
    stage = "owner-loop context";
    if (!owner_loop_depth || owner_pump_depth) {
        owner_admission_trace_failure(stage, EPERM);
        errno = EPERM;
        return -1;
    }
    if (!ops || !ops->active || !ops->admit || !ops->revoke ||
        !ops->retire || !ops->rearm) {
        owner_admission_trace_failure(stage, EINVAL);
        errno = EINVAL;
        return -1;
    }
    int map_active = ops->active(ops->context);
    stage = "map active";
    if (map_active <= 0) {
        owner_admission_trace_failure(stage,
            map_active < 0 && map_active >= -4095 ? -map_active : ENOTCONN);
        errno = map_active < 0 && map_active >= -4095 ? -map_active : ENOTCONN;
        return -1;
    }
    ker_sb_preload_lock();
    stage = "owner descriptor preflight";
    if (!ker_sb_preload_ff_owner_active_locked() || owner_pump_callback ||
        owner_admission_state.channel ||
        ker_sb_preload_network_registry_empty_locked() != 0) {
        error = errno ? errno : EBUSY;
        owner_admission_trace_failure(stage, error);
        ker_sb_preload_unlock();
        errno = error;
        return -1;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int owner_cap = ker_sb_preload_ff_owner_capability_locked();
    if (!client || owner_cap < 0 || client->session_fd < 0) {
        error = errno ? errno : ENOTCONN;
        owner_admission_trace_failure(stage, error);
        ker_sb_preload_unlock();
        errno = error;
        return -1;
    }
    credential_length = sizeof(broker);
    stage = "broker peer credentials";
    if (syscall(SYS_getsockopt, client->session_fd, SOL_SOCKET, SO_PEERCRED,
            &broker, &credential_length)) {
        error = errno;
        owner_admission_trace_failure(stage, error);
        ker_sb_preload_unlock();
        errno = error;
        return -1;
    }
    if (credential_length != sizeof(broker)) {
        error = EPROTO;
        owner_admission_trace_failure(stage, error);
        ker_sb_preload_unlock();
        errno = error;
        return -1;
    }
    stage = "broker prepare RPC";
    if (ker_socket_client_ff_owner_admission_prepare(client, owner_cap,
            &registration)) {
        error = errno;
        owner_admission_trace_failure(stage, error);
        ker_sb_preload_unlock();
        errno = error;
        return -1;
    }
#ifdef KER_C16_ADMISSION_TEST_TRACE
    if (getenv("KER_C16_TEST_PREPARE_ONCE")) {
        struct ker_ff_owner_admission_registration duplicate;
        memset(&duplicate, 0xa5, sizeof(duplicate));
        struct ker_ff_owner_admission_registration untouched = duplicate;
        errno = 0;
        if (ker_socket_client_ff_owner_admission_prepare(client, owner_cap,
                &duplicate) != -1 || errno != EALREADY ||
            memcmp(&duplicate, &untouched, sizeof(duplicate))) {
            error = errno ? errno : EPROTO;
            owner_admission_trace_failure("one-use prepare", error);
            ker_sb_preload_unlock();
            errno = error;
            return -1;
        }
    }
#endif
    ker_sb_preload_unlock();

#ifdef KER_C16_ADMISSION_TEST_TRACE
    if (getenv("KER_C16_TEST_PAUSE_AFTER_PREPARE")) {
        char marker[KER_SOCKET_BROKER_PATH_MAX + 64];
        int marker_length = snprintf(marker, sizeof(marker),
            "C16_ATTACH_ENDPOINT path=%s\n", registration.endpoint_path);
        if (marker_length > 0 && (size_t)marker_length < sizeof(marker))
            (void)syscall(SYS_write, STDOUT_FILENO, marker,
                (size_t)marker_length);
        long pause_ms = 500;
        const char *pause_text = getenv("KER_C20_TEST_PAUSE_AFTER_PREPARE_MS");
        if (pause_text) {
            char *end = NULL;
            long parsed = strtol(pause_text, &end, 10);
            if (*pause_text && end && !*end && parsed >= 1 && parsed <= 5000)
                pause_ms = parsed;
        }
        struct timespec pause = {.tv_sec = pause_ms / 1000,
            .tv_nsec = (pause_ms % 1000) * 1000000L};
        while (nanosleep(&pause, &pause) && errno == EINTR) { }
    }
#endif

    size_t path_length = strnlen(registration.endpoint_path,
        sizeof(registration.endpoint_path));
    stage = "endpoint path";
    if (!path_length || path_length >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        error = ENAMETOOLONG;
        goto failure;
    }
    fd = (int)syscall(SYS_socket, AF_UNIX,
        SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    stage = "endpoint connect";
    if (fd < 0) { error = errno; goto failure; }
    if (syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_PASSCRED,
            &passcred, sizeof(passcred))) { error = errno; goto failure; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, registration.endpoint_path, path_length + 1);
    if (syscall(SYS_connect, fd, &address,
            (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1))) {
        if (errno != EINPROGRESS && errno != EAGAIN) { error = errno; goto failure; }
        uint64_t now = owner_admission_now_ns();
        if (!now || now > UINT64_MAX - UINT64_C(5000000000)) {
            error = EOVERFLOW; goto failure;
        }
        int waited = owner_admission_poll_fd(fd, POLLOUT,
            now + UINT64_C(5000000000));
        if (waited) { error = -waited; goto failure; }
        int socket_error = 0;
        socklen_t socket_error_length = sizeof(socket_error);
        if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR,
                &socket_error, &socket_error_length) ||
            socket_error_length != sizeof(socket_error)) {
            error = errno ? errno : EPROTO; goto failure;
        }
        if (socket_error) { error = socket_error; goto failure; }
    }
    struct ucred endpoint_peer = {0};
    stage = "endpoint peer credentials";
    socklen_t peer_length = sizeof(endpoint_peer);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERCRED,
            &endpoint_peer, &peer_length)) {
        error = errno; goto failure;
    }
    if (peer_length != sizeof(endpoint_peer)) { error = EPROTO; goto failure; }
    if (endpoint_peer.pid != broker.pid || endpoint_peer.uid != broker.uid ||
        endpoint_peer.gid != broker.gid) { error = EACCES; goto failure; }
    hello.registration_id = registration.registration_id;
    stage = "HELLO send";
    ssize_t sent;
#ifdef KER_C16_ADMISSION_TEST_TRACE
    if (getenv("KER_C16_TEST_BAD_HELLO_RIGHTS")) {
        int passed_fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null",
            O_RDONLY | O_CLOEXEC, 0);
        if (passed_fd < 0) { error = errno; goto failure; }
        char control[CMSG_SPACE(sizeof(int))] = {0};
        struct iovec iov = {.iov_base = &hello, .iov_len = sizeof(hello)};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control)};
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(passed_fd));
        memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));
        sent = syscall(SYS_sendmsg, fd, &message, MSG_NOSIGNAL);
        (void)syscall(SYS_close, passed_fd);
    } else
#endif
        sent = syscall(SYS_sendto, fd, &hello, sizeof(hello),
            MSG_NOSIGNAL, NULL, 0);
    if (sent != sizeof(hello)) {
        error = sent < 0 ? errno : EIO; goto failure;
    }
    stage = "READY receive";
    int ready = owner_admission_ready_reply(fd, registration.registration_id,
        broker.pid, broker.uid, broker.gid, &reply);
    if (ready) { error = -ready; goto failure; }
    stage = "owner channel authentication";
    {
        int type = 0, passcred_state = 0;
        socklen_t type_length = sizeof(type), passcred_length = sizeof(passcred_state);
        if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &type_length) ||
            syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PASSCRED,
                &passcred_state, &passcred_length) || type != SOCK_SEQPACKET ||
            type_length != sizeof(type) || !passcred_state ||
            passcred_length != sizeof(passcred_state)) {
            char message[160];
            int length = snprintf(message, sizeof(message),
                "ker admission channel preflight type=%d/%u passcred=%d/%u errno=%d\n",
                type, (unsigned)type_length, passcred_state,
                (unsigned)passcred_length, errno);
            if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
                (size_t)length);
        }
    }
    int channel_status = ker_ff_admission_channel_open(fd, broker.pid,
        broker.uid, broker.gid, reply.queue_lease, &channel);
    if (channel_status) {
        error = channel_status < 0 && channel_status >= -4095 ?
            -channel_status : EPROTO;
        goto failure;
    }
    int channel_fd = fd;
    stage = "private FD registration";
    ker_sb_preload_lock();
    if (!ker_sb_preload_ff_owner_active_locked() || owner_pump_callback ||
        ker_sb_preload_track_private_fd_locked(channel_fd)) {
        error = errno ? errno : ESTALE;
    }
    ker_sb_preload_unlock();
    if (error) goto failure;
    fd = -1; /* channel owns the endpoint */
    ker_sb_preload_lock();
    stage = "owner pump registration";
    if (!ker_sb_preload_ff_owner_active_locked() || owner_pump_callback) {
        error = ESTALE;
    } else {
        owner_admission_state.fd = channel_fd;
        owner_admission_state.channel = channel;
        owner_admission_state.ops = *ops;
        if (ker_sb_preload_owner_pump_register(ff_owner_admission_pump,
                &owner_admission_state))
            error = errno;
    }
    ker_sb_preload_unlock();
    if (error) goto failure;
    channel = NULL;
    return 0;

failure:
    owner_admission_trace_failure(stage, error);
    if (channel) {
        ker_sb_preload_lock();
        ker_sb_preload_untrack_private_fd_locked(owner_admission_state.fd >= 0 ?
            owner_admission_state.fd : fd);
        ker_sb_preload_unlock();
        ker_ff_admission_channel_close(channel);
        memset(&owner_admission_state, 0, sizeof(owner_admission_state));
        owner_admission_state.fd = -1;
    } else if (fd >= 0) {
        ker_sb_preload_lock();
        ker_sb_preload_untrack_private_fd_locked(fd);
        ker_sb_preload_unlock();
    }
    if (fd >= 0) (void)syscall(SYS_close, fd);
    errno = error ? error : EPROTO;
    return -1;
}

bool ker_sb_preload_ff_owner_active_locked(void)
{
    return ff_owner_context_started && ff_owner_capability >= 0 &&
        ff_owner_pid == getpid();
}

int ker_sb_preload_ff_owner_capability_locked(void)
{ return ker_sb_preload_ff_owner_active_locked() ? ff_owner_capability : -1; }

bool ker_sb_preload_ff_owner_managed(void)
{ return ff_owner_context_started; }

int ker_sb_preload_owner_pump_register(ker_sb_preload_owner_pump_fn pump,
    void *context)
{
    if (!pump || owner_pump_callback) { errno = EINVAL; return -1; }
    ker_sb_preload_lock();
    bool active = ker_sb_preload_ff_owner_active_locked();
    ker_sb_preload_unlock();
    if (!active) { errno = ENOTCONN; return -1; }
    owner_pump_context = context;
    owner_pump_callback = pump;
    return 0;
}

void ker_sb_preload_owner_pump_unregister(void)
{
    owner_pump_callback = NULL;
    owner_pump_context = NULL;
}

int ker_sb_preload_owner_pump(void)
{
    if (owner_pump_failure) return owner_pump_failure;
    if (owner_pump_depth) return -EDEADLK;
    if (!owner_pump_callback) return 0;
    if (ff_owner_pid != getpid()) return -ESTALE;
    ++owner_pump_depth;
    int result = owner_pump_callback(owner_pump_context);
    --owner_pump_depth;
    if (result) {
        char message[128];
        int length = snprintf(message, sizeof(message),
            "ker owner pump callback status=%d\n", result);
        if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
            (size_t)length);
        owner_pump_failure = result < 0 && result >= -4095 ? result : -EPROTO;
        return owner_pump_failure;
    }
    return 0;
}

int ker_sb_preload_owner_wait_check(void)
{
    if (owner_pump_depth) return -EDEADLK;
    return owner_pump_failure;
}

bool ker_sb_preload_owner_pump_registered(void)
{ return owner_pump_callback != NULL; }

int ker_sb_preload_owner_loop_enter(void)
{
    if (owner_loop_depth == UINT_MAX) return -EOVERFLOW;
    ++owner_loop_depth;
    return 0;
}

void ker_sb_preload_owner_loop_leave(void)
{
    if (owner_loop_depth) --owner_loop_depth;
}

bool ker_sb_preload_owner_loop_active(void)
{ return owner_loop_depth != 0; }

void ker_sb_preload_note_unowned_network_locked(void)
{
    unowned_network_activity = true;
}

int ker_sb_preload_ff_owner_begin(void)
{
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock();
    if (ff_owner_context_started) {
        ker_sb_preload_unlock();
        if (ff_owner_pid == getpid()) return 0;
        errno = EOPNOTSUPP; return -1;
    }
    if (unowned_network_activity || ker_sb_preload_network_registry_empty_locked() != 0) {
        int error = unowned_network_activity ? EOPNOTSUPP : errno;
        ker_sb_preload_unlock(); errno = error; return -1;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int capability = client ? ker_socket_client_ff_owner_create(client) : -1;
    if (capability < 0) {
        int error = errno; ker_sb_preload_unlock(); errno = error; return -1;
    }
    if (ker_sb_preload_track_private_fd_locked(capability)) {
        int error = errno; (void)syscall(SYS_close, capability);
        ker_sb_preload_unlock(); errno = error; return -1;
    }
    ff_owner_capability = capability;
    ff_owner_pid = getpid();
    ff_owner_context_started = true;
    ker_sb_preload_unlock();
    return 0;
}

int ker_sb_preload_ff_staged_group_claim(int slot_cap)
{
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock();
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int owner_cap = ker_sb_preload_ff_owner_capability_locked();
    int status = owner_cap >= 0 && client ?
        ker_socket_client_ff_owner_group_claim(client, owner_cap, slot_cap) : -1;
    if (status && owner_cap < 0) errno = ENOTCONN;
    ker_sb_preload_unlock();
    return status;
}

int ker_sb_preload_ff_staged_group_member(int slot_cap)
{
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock();
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int owner_cap = ker_sb_preload_ff_owner_capability_locked();
    int member = owner_cap >= 0 && client ?
        ker_socket_client_owner_group_member(client, owner_cap, slot_cap) : -1;
    if (member >= 0 && ker_sb_preload_register_network_locked(member)) {
        int error = errno;
        (void)syscall(SYS_close, member);
        member = -1;
        errno = error;
    }
    if (member < 0 && owner_cap < 0) errno = ENOTCONN;
    ker_sb_preload_unlock();
    return member;
}

int ker_sb_preload_ff_owner_socket(int domain, int type, int protocol)
{
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock();
    if (!ker_sb_preload_ff_owner_active_locked()) {
        ker_sb_preload_unlock();
        errno = ff_owner_context_started ? EOPNOTSUPP : ENOTCONN;
        return -1;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int fd = client ? ker_socket_client_ff_owner_socket(client,
        ff_owner_capability, domain, type, protocol) : -1;
    int registration_status = fd >= 0 ? ker_sb_preload_register_network_locked(fd) : 0;
    if (registration_status) {
        int error = errno; (void)syscall(SYS_close, fd); fd = -1; errno = error;
    }
    ker_sb_preload_unlock();
    return fd;
}

int ker_sb_preload_ff_owner_payload(struct ker_socket_member_payload_snapshot *snapshot)
{
    if (!snapshot) { errno = EINVAL; return -1; }
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock();
    if (!ker_sb_preload_ff_owner_active_locked()) {
        int error = ff_owner_context_started ? EOPNOTSUPP : ENOTCONN;
        ker_sb_preload_unlock(); errno = error; return -1;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = -1;
    if (unowned_network_activity) errno = EOPNOTSUPP;
    else if (client && !ker_sb_preload_ff_owner_matches_locked(ff_owner_capability, client))
        result = ker_socket_client_ff_owner_payload_snapshot(client,
            ff_owner_capability, snapshot);
    int saved = errno;
    ker_sb_preload_unlock();
    errno = saved;
    return result;
}

int ker_sb_preload_ff_owner_requests(uint64_t *request_count)
{
    if (!request_count) { errno = EINVAL; return -1; }
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock();
    if (!ker_sb_preload_ff_owner_active_locked()) {
        int error = ff_owner_context_started ? EOPNOTSUPP : ENOTCONN;
        ker_sb_preload_unlock(); errno = error; return -1;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = -1;
    if (unowned_network_activity) errno = EOPNOTSUPP;
    else if (client && !ker_sb_preload_ff_owner_matches_locked(ff_owner_capability, client))
        result = ker_socket_client_ff_owner_requests(client, ff_owner_capability,
            request_count);
    int saved = errno;
    ker_sb_preload_unlock();
    errno = saved;
    return result;
}

static int ff_owner_admission_window_call(uint16_t operation,
	struct ker_ff_owner_admission_window *window)
{
	if (!window) { errno = EINVAL; return -1; }
	if (!owner_loop_depth || owner_pump_depth) { errno = EPERM; return -1; }
	if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
	ker_sb_preload_lock();
	if (!ker_sb_preload_ff_owner_active_locked()) {
		ker_sb_preload_unlock(); errno = ENOTCONN; return -1;
	}
	struct ker_socket_client *client = ker_sb_preload_client_locked();
	int result = -1;
	if (unowned_network_activity) errno = EOPNOTSUPP;
	else if (client && !ker_sb_preload_ff_owner_matches_locked(
		ff_owner_capability, client))
		result = ker_socket_client_ff_owner_admission_window(client,
			ff_owner_capability, operation, window);
	int saved = errno;
	ker_sb_preload_unlock();
	errno = saved;
	return result;
}

int ker_sb_preload_ff_owner_admission_retire(void)
{
	struct ker_ff_owner_admission_window ignored = {0};
	return ff_owner_admission_window_call(
		KER_SB_FF_OWNER_ADMISSION_RETIRE, &ignored);
}

int ker_sb_preload_ff_owner_admission_rearm(void)
{
	struct ker_ff_owner_admission_window ignored = {0};
	return ff_owner_admission_window_call(
		KER_SB_FF_OWNER_ADMISSION_REARM, &ignored);
}

int ker_sb_preload_ff_owner_admission_status(
	struct ker_ff_owner_admission_window *window)
{
	return ff_owner_admission_window_call(
		KER_SB_FF_OWNER_ADMISSION_STATUS, window);
}

int ker_sb_preload_ff_dispatch_begin(int fd)
{
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    if (ff_dispatch_depth >= sizeof(ff_dispatch_fds) / sizeof(ff_dispatch_fds[0])) {
        errno = EOVERFLOW;
        return -1;
    }
    ff_dispatch_fds[ff_dispatch_depth++] = fd;
    return 0;
}
void ker_sb_preload_ff_dispatch_end(void)
{ if (ff_dispatch_depth) --ff_dispatch_depth; }
static bool ff_dispatch_active(int fd)
{ return ff_dispatch_depth && ff_dispatch_fds[ff_dispatch_depth - 1] == fd; }
static int ff_reject_host_fd(int fd)
{
    if (!ff_dispatch_active(fd)) return 0;
    if (syscall(SYS_fcntl, fd, F_GETFD) < 0) { errno = EBADF; return -1; }
    errno = EOPNOTSUPP;
    return -1;
}

struct host_libc_functions {
    int (*socket)(int, int, int);
    int (*close)(int);
    ssize_t (*read)(int, void *, size_t);
    ssize_t (*write)(int, const void *, size_t);
    ssize_t (*readv)(int, const struct iovec *, int);
    ssize_t (*writev)(int, const struct iovec *, int);
    int (*connect)(int, const struct sockaddr *, socklen_t);
    int (*accept)(int, struct sockaddr *, socklen_t *);
    int (*accept4)(int, struct sockaddr *, socklen_t *, int);
    ssize_t (*send)(int, const void *, size_t, int);
    ssize_t (*recv)(int, void *, size_t, int);
    ssize_t (*sendto)(int, const void *, size_t, int,
        const struct sockaddr *, socklen_t);
    ssize_t (*recvfrom)(int, void *, size_t, int,
        struct sockaddr *, socklen_t *);
    ssize_t (*sendmsg)(int, const struct msghdr *, int);
    ssize_t (*recvmsg)(int, struct msghdr *, int);
    int (*epoll_pwait)(int, struct epoll_event *, int, int, const sigset_t *);
    int (*fcntl)(int, int, ...);
    ssize_t (*sendfile)(int, int, off_t *, size_t);
};

static struct host_libc_functions host_libc;
static atomic_bool host_libc_initialized = false;
static void *host_libc_handle;

static bool host_libc_ready(void)
{
    return atomic_load_explicit(&host_libc_initialized, memory_order_acquire);
}

int ker_sb_preload_resolve_host_functions(void)
{
#define RESOLVE_HOST_FUNCTION(member, symbol) do { \
    host_libc.member = (__typeof__(host_libc.member))dlsym(RTLD_NEXT, symbol); \
    if (!host_libc.member) { \
        if (!host_libc_handle) \
            host_libc_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD); \
        if (host_libc_handle) \
            host_libc.member = (__typeof__(host_libc.member))dlsym(host_libc_handle, symbol); \
        if (!host_libc.member) { errno = ENOSYS; return -1; } \
    } \
} while (0)
    RESOLVE_HOST_FUNCTION(socket, "socket");
    RESOLVE_HOST_FUNCTION(close, "close");
    RESOLVE_HOST_FUNCTION(read, "read");
    RESOLVE_HOST_FUNCTION(write, "write");
    RESOLVE_HOST_FUNCTION(readv, "readv");
    RESOLVE_HOST_FUNCTION(writev, "writev");
    RESOLVE_HOST_FUNCTION(connect, "connect");
    RESOLVE_HOST_FUNCTION(accept, "accept");
    RESOLVE_HOST_FUNCTION(accept4, "accept4");
    RESOLVE_HOST_FUNCTION(send, "send");
    RESOLVE_HOST_FUNCTION(recv, "recv");
    RESOLVE_HOST_FUNCTION(sendto, "sendto");
    RESOLVE_HOST_FUNCTION(recvfrom, "recvfrom");
    RESOLVE_HOST_FUNCTION(sendmsg, "sendmsg");
    RESOLVE_HOST_FUNCTION(recvmsg, "recvmsg");
    RESOLVE_HOST_FUNCTION(epoll_pwait, "epoll_pwait");
    RESOLVE_HOST_FUNCTION(fcntl, "fcntl");
    RESOLVE_HOST_FUNCTION(sendfile, "sendfile");
#undef RESOLVE_HOST_FUNCTION
    atomic_store_explicit(&host_libc_initialized, true, memory_order_release);
    return 0;
}

static int host_socket(int domain, int type, int protocol)
{
    return host_libc_ready() ? host_libc.socket(domain, type, protocol) :
        (int)syscall(SYS_socket, domain, type, protocol);
}

static int host_close(int fd)
{
    return host_libc_ready() ? host_libc.close(fd) : (int)syscall(SYS_close, fd);
}

static int host_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    return host_libc_ready() ? host_libc.connect(fd, address, length) :
        (int)syscall(SYS_connect, fd, address, length);
}

static int host_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    return host_libc_ready() ? host_libc.accept(fd, address, length) :
        (int)syscall(SYS_accept, fd, address, length);
}

static int host_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags)
{
#ifdef SYS_accept4
    if (host_libc_ready()) return host_libc.accept4(fd, address, length, flags);
    if (!flags) return host_accept(fd, address, length);
    return (int)syscall(SYS_accept4, fd, address, length, flags);
#else
    if (flags) { errno = EINVAL; return -1; }
    return host_accept(fd, address, length);
#endif
}

static ssize_t host_read(int fd, void *buffer, size_t length)
{
    return host_libc_ready() ? host_libc.read(fd, buffer, length) :
        (ssize_t)syscall(SYS_read, fd, buffer, length);
}

static ssize_t host_write(int fd, const void *buffer, size_t length)
{
    return host_libc_ready() ? host_libc.write(fd, buffer, length) :
        (ssize_t)syscall(SYS_write, fd, buffer, length);
}

static ssize_t host_readv(int fd, const struct iovec *vectors, int count)
{
    return host_libc_ready() ? host_libc.readv(fd, vectors, count) :
        (ssize_t)syscall(SYS_readv, fd, vectors, count);
}

static ssize_t host_writev(int fd, const struct iovec *vectors, int count)
{
    return host_libc_ready() ? host_libc.writev(fd, vectors, count) :
        (ssize_t)syscall(SYS_writev, fd, vectors, count);
}

static ssize_t host_send(int fd, const void *buffer, size_t length, int flags)
{
    return host_libc_ready() ? host_libc.send(fd, buffer, length, flags) :
        (ssize_t)syscall(SYS_sendto, fd, buffer, length, flags, NULL, 0);
}

static ssize_t host_recv(int fd, void *buffer, size_t length, int flags)
{
    return host_libc_ready() ? host_libc.recv(fd, buffer, length, flags) :
        (ssize_t)syscall(SYS_recvfrom, fd, buffer, length, flags, NULL, NULL);
}

static ssize_t host_sendto(int fd, const void *buffer, size_t length, int flags,
    const struct sockaddr *address, socklen_t address_length)
{
    return host_libc_ready() ? host_libc.sendto(fd, buffer, length, flags, address,
        address_length) : (ssize_t)syscall(SYS_sendto, fd, buffer, length, flags,
        address, address_length);
}

static ssize_t host_recvfrom(int fd, void *buffer, size_t length, int flags,
    struct sockaddr *address, socklen_t *address_length)
{
    return host_libc_ready() ? host_libc.recvfrom(fd, buffer, length, flags, address,
        address_length) : (ssize_t)syscall(SYS_recvfrom, fd, buffer, length, flags,
        address, address_length);
}

static ssize_t host_sendmsg(int fd, const struct msghdr *message, int flags)
{
    return host_libc_ready() ? host_libc.sendmsg(fd, message, flags) :
        (ssize_t)syscall(SYS_sendmsg, fd, message, flags);
}

static ssize_t host_recvmsg(int fd, struct msghdr *message, int flags)
{
    return host_libc_ready() ? host_libc.recvmsg(fd, message, flags) :
        (ssize_t)syscall(SYS_recvmsg, fd, message, flags);
}

static int host_fcntl_none(int fd, int command)
{
    return host_libc_ready() ? host_libc.fcntl(fd, command) :
        (int)syscall(SYS_fcntl, fd, command);
}

static int host_fcntl_integer(int fd, int command, unsigned long argument)
{
    return host_libc_ready() ? host_libc.fcntl(fd, command, argument) :
        (int)syscall(SYS_fcntl, fd, command, argument);
}

static int host_fcntl_pointer(int fd, int command, void *argument)
{
    return host_libc_ready() ? host_libc.fcntl(fd, command, argument) :
        (int)syscall(SYS_fcntl, fd, command, argument);
}

static ssize_t host_sendfile(int output, int input, off_t *offset, size_t count)
{
    return host_libc_ready() ? host_libc.sendfile(output, input, offset, count) :
        (ssize_t)syscall(SYS_sendfile, output, input, offset, count);
}

int ker_sb_preload_host_epoll_pwait(int epfd, struct epoll_event *events,
    int maximum, int timeout, const sigset_t *mask)
{
    return host_libc_ready() ? host_libc.epoll_pwait(epfd, events, maximum, timeout, mask) :
        (int)syscall(SYS_epoll_pwait, epfd, events, maximum, timeout, mask,
            sizeof(uint64_t));
}

static int copy_in(void *destination, const void *source, size_t length)
{
    if ((!source && length) || ker_host_usercopy(destination, source, length, 0)) {
        errno = EFAULT;
        return -1;
    }
    return 0;
}

static int copy_out(void *destination, const void *source, size_t length)
{
    if ((!destination && length) || ker_host_usercopy(destination, source, length, 1)) {
        errno = EFAULT;
        return -1;
    }
    return 0;
}

static bool descriptor_may_be_broker_capability(int fd)
{
    struct stat status = {0};
    int flags = (int)syscall(SYS_fcntl, fd, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == O_WRONLY &&
        syscall(SYS_fstat, fd, &status) == 0 && S_ISFIFO(status.st_mode);
}

static int native_socket_fd(int fd, int *cap_fd)
{
    int result = ker_sb_preload_network_fd_locked(fd, cap_fd);
    return result;
}

int socket(int domain, int type, int protocol)
{
    if (!ker_sb_preload_runtime_ready()) {
        if (domain == AF_INET || domain == AF_INET6) { errno = ENOTCONN; return -1; }
        return host_socket(domain, type, protocol);
    }
    if (domain != AF_INET && domain != AF_INET6)
        return host_socket(domain, type, protocol);
    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (base_type != SOCK_STREAM || (protocol != 0 && protocol != IPPROTO_TCP)) {
        errno = EOPNOTSUPP; return -1;
    }
    ker_sb_preload_lock();
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    if (!client) { ker_sb_preload_unlock(); return -1; }
    int fd = ker_socket_client_socket(client, domain, type, protocol);
    if (fd >= 0 && ker_sb_preload_register_network_locked(fd)) {
        int error = errno; (void)syscall(SYS_close, fd); fd = -1; errno = error;
    }
    ker_sb_preload_unlock();
    return fd;
}

int bind(int fd, const struct sockaddr *address, socklen_t length)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_bind, fd, address, length);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : (int)syscall(SYS_bind, fd, address, length);
    }
    if (length > sizeof(struct sockaddr_storage)) {
        ker_sb_preload_unlock(); errno = EINVAL; return -1;
    }
    struct sockaddr_storage local = {0};
    if (copy_in(&local, address, length)) { ker_sb_preload_unlock(); return -1; }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_bind(client, cap,
        (const struct sockaddr *)&local, length) : -1;
    ker_sb_preload_unlock(); return result;
}

int connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (!ker_sb_preload_runtime_ready()) return host_connect(fd, address, length);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : host_connect(fd, address, length);
    }
    if (length > sizeof(struct sockaddr_storage)) {
        ker_sb_preload_unlock(); errno = EINVAL; return -1;
    }
    struct sockaddr_storage local = {0};
    if (copy_in(&local, address, length)) { ker_sb_preload_unlock(); return -1; }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_connect(client, cap,
        (const struct sockaddr *)&local, length) : -1;
    ker_sb_preload_unlock(); return result;
}

int listen(int fd, int backlog)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_listen, fd, backlog);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : (int)syscall(SYS_listen, fd, backlog);
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_listen(client, cap, backlog) : -1;
    ker_sb_preload_unlock(); return result;
}

int accept4(int fd, struct sockaddr *address, socklen_t *length, int flags)
{
    if (!ker_sb_preload_runtime_ready()) return host_accept4(fd, address, length, flags);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
#ifdef SYS_accept4
        return native < 0 ? -1 : host_accept4(fd, address, length, flags);
#else
        if (flags) { errno = EINVAL; return -1; }
        return native < 0 ? -1 : host_accept(fd, address, length);
#endif
    }
    struct sockaddr_storage local = {0};
    socklen_t local_length = sizeof(local), output_capacity = 0;
    if (address) {
        if (!length || copy_in(&local_length, length, sizeof(local_length)) ||
            local_length > sizeof(local)) {
            ker_sb_preload_unlock(); if (errno == 0) errno = EINVAL; return -1;
        }
        output_capacity = local_length;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    bool ff_owner_accept = ff_dispatch_active(fd) && ff_owner_context_started;
    if (ff_owner_accept) {
        if (!ker_sb_preload_ff_owner_active_locked() || !client) {
            ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
        }
        int matches = ker_socket_client_ff_owner_match(client, ff_owner_capability, cap);
        if (matches != 1) {
            int error = matches < 0 ? errno : EXDEV;
            ker_sb_preload_note_unowned_network_locked();
            ker_sb_preload_unlock(); errno = error; return -1;
        }
    }
    int accepted = client ? ker_socket_client_accept4(client, cap,
        address ? (struct sockaddr *)&local : NULL,
        address ? &local_length : NULL, flags) : -1;
    if (accepted >= 0 && ff_owner_accept) {
        int matches = ff_owner_pid == getpid() && client ?
            ker_socket_client_ff_owner_match(client, ff_owner_capability, accepted) : -1;
        if (matches != 1) {
            int error = matches < 0 ? (errno ? errno : EOPNOTSUPP) : EXDEV;
            ker_sb_preload_note_unowned_network_locked();
            (void)syscall(SYS_close, accepted); accepted = -1; errno = error;
        } else {
        }
    }
    if (accepted >= 0 && ker_sb_preload_register_network_locked(accepted)) {
        int error = errno; (void)syscall(SYS_close, accepted); accepted = -1; errno = error;
    }
    if (accepted >= 0 && address &&
        (copy_out(address, &local, output_capacity < local_length ? output_capacity : local_length) ||
         copy_out(length, &local_length, sizeof(local_length)))) {
        int error = errno; ker_sb_preload_remove_network_locked(accepted);
        (void)syscall(SYS_close, accepted); accepted = -1; errno = error;
    }
    ker_sb_preload_unlock(); return accepted;
}

int accept(int fd, struct sockaddr *address, socklen_t *length)
{
    return accept4(fd, address, length, 0);
}

int close(int fd)
{
    if (!ker_sb_preload_runtime_ready()) return host_close(fd);
    ker_sb_preload_lock();
    if (ff_dispatch_active(fd)) {
        int cap = -1;
        int socket = ker_sb_preload_network_fd_locked(fd, &cap);
        if (socket != 1) {
            ker_sb_preload_unlock();
            if (socket == 0) return ff_reject_host_fd(fd);
            return -1;
        }
    }
    int native = ker_sb_preload_any_native_locked(fd);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : host_close(fd);
    }
    int result = ker_sb_preload_close_locked(fd);
    ker_sb_preload_unlock(); return result;
}

int shutdown(int fd, int how)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_shutdown, fd, how);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : (int)syscall(SYS_shutdown, fd, how);
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_shutdown(client, cap, how) : -1;
    ker_sb_preload_unlock(); return result;
}

static int name_query(int fd, struct sockaddr *address, socklen_t *length,
    bool peer)
{
    if (!ker_sb_preload_runtime_ready()) {
        long number = peer ? SYS_getpeername : SYS_getsockname;
        return (int)syscall(number, fd, address, length);
    }
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        long syscall_number = peer ? SYS_getpeername : SYS_getsockname;
        return native < 0 ? -1 : (int)syscall(syscall_number, fd, address, length);
    }
    if (!length) { ker_sb_preload_unlock(); errno = EFAULT; return -1; }
    socklen_t capacity;
    if (copy_in(&capacity, length, sizeof(capacity)) ||
        capacity > sizeof(struct sockaddr_storage)) {
        ker_sb_preload_unlock(); if (!errno) errno = EINVAL; return -1;
    }
    struct sockaddr_storage local = {0}; socklen_t local_length = capacity;
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = -1;
    if (client) result = peer ? ker_socket_client_getpeername(client, cap,
        (struct sockaddr *)&local, &local_length) : ker_socket_client_getsockname(client,
        cap, (struct sockaddr *)&local, &local_length);
    if (result == 0 && (copy_out(address, &local, capacity < local_length ? capacity : local_length) ||
            copy_out(length, &local_length, sizeof(local_length)))) result = -1;
    ker_sb_preload_unlock(); return result;
}

int getsockname(int fd, struct sockaddr *address, socklen_t *length)
{ return name_query(fd, address, length, false); }
int getpeername(int fd, struct sockaddr *address, socklen_t *length)
{ return name_query(fd, address, length, true); }

int setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_setsockopt, fd, level, option, value, length);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : (int)syscall(SYS_setsockopt, fd, level, option, value, length);
    }
    if (length > KER_SB_IO_MAX) { ker_sb_preload_unlock(); errno = EINVAL; return -1; }
    unsigned char local[KER_SB_IO_MAX];
    if (copy_in(local, value, length)) { ker_sb_preload_unlock(); return -1; }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_setsockopt(client, cap, level, option,
        local, length) : -1;
    ker_sb_preload_unlock(); return result;
}

int getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_getsockopt, fd, level, option, value, length);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : (int)syscall(SYS_getsockopt, fd, level, option, value, length);
    }
    if (!length) { ker_sb_preload_unlock(); errno = EFAULT; return -1; }
    socklen_t capacity;
    if (copy_in(&capacity, length, sizeof(capacity)) || capacity > KER_SB_IO_MAX) {
        ker_sb_preload_unlock(); if (!errno) errno = EINVAL; return -1;
    }
    unsigned char local[KER_SB_IO_MAX] = {0}; socklen_t actual = capacity;
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_getsockopt(client, cap, level, option,
        local, &actual) : -1;
    if (result == 0 && (actual > capacity || copy_out(value, local, actual) ||
            copy_out(length, &actual, sizeof(actual)))) result = -1;
    ker_sb_preload_unlock(); return result;
}

static ssize_t native_io(int fd, void *buffer, size_t length, bool writing,
    bool *broker_native)
{
    if (broker_native) *broker_native = false;
    if (!ker_sb_preload_runtime_ready()) {
        if (ff_reject_host_fd(fd)) return -1;
        return writing ? host_write(fd, buffer, length) : host_read(fd, buffer, length);
    }
    if (!ff_dispatch_active(fd) && !descriptor_may_be_broker_capability(fd))
        return writing ? host_write(fd, buffer, length) : host_read(fd, buffer, length);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : writing ? host_write(fd, buffer, length) :
            host_read(fd, buffer, length);
    }
    if (broker_native) *broker_native = true;
    if (length > KER_SB_IO_MAX) length = KER_SB_IO_MAX;
    unsigned char local[KER_SB_IO_MAX];
    if (writing && copy_in(local, buffer, length)) { ker_sb_preload_unlock(); return -1; }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    ssize_t result = client ? (writing ? ker_socket_client_write(client, cap,
        local, length) : ker_socket_client_read(client, cap, local, length)) : -1;
    if (result > 0 && !writing && copy_out(buffer, local, (size_t)result)) result = -1;
    ker_sb_preload_unlock(); return result;
}

ssize_t read(int fd, void *buffer, size_t length)
{ return native_io(fd, buffer, length, false, NULL); }
ssize_t write(int fd, const void *buffer, size_t length)
{
    bool broker_native = false;
    ssize_t result = native_io(fd, (void *)buffer, length, true, &broker_native);
    int error = errno;
    if (broker_native && result < 0 && error == EPIPE) {
        (void)syscall(SYS_tgkill, syscall(SYS_getpid), syscall(SYS_gettid), SIGPIPE);
        errno = error;
    }
    return result;
}

ssize_t send(int fd, const void *buffer, size_t length, int flags)
{
    if (!ker_sb_preload_runtime_ready()) return host_send(fd, buffer, length, flags);
    ker_sb_preload_lock(); int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : host_send(fd, buffer, length, flags);
    }
    if (length > KER_SB_IO_MAX) length = KER_SB_IO_MAX;
    unsigned char local[KER_SB_IO_MAX];
    if (copy_in(local, buffer, length)) { ker_sb_preload_unlock(); return -1; }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    ssize_t result = client ? ker_socket_client_send(client, cap, local, length, flags) : -1;
    ker_sb_preload_unlock();
    int error = errno;
    if (result < 0 && error == EPIPE && !(flags & MSG_NOSIGNAL)) {
        (void)syscall(SYS_tgkill, syscall(SYS_getpid), syscall(SYS_gettid), SIGPIPE);
        errno = error;
    }
    return result;
}

ssize_t recv(int fd, void *buffer, size_t length, int flags)
{
    if (!ker_sb_preload_runtime_ready()) return host_recv(fd, buffer, length, flags);
    ker_sb_preload_lock(); int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : host_recv(fd, buffer, length, flags);
    }
    if (length > KER_SB_IO_MAX) length = KER_SB_IO_MAX;
    unsigned char local[KER_SB_IO_MAX];
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    ssize_t result = client ? ker_socket_client_recv(client, cap, local, length, flags) : -1;
    if (result > 0 && copy_out(buffer, local, (size_t)result)) result = -1;
    ker_sb_preload_unlock(); return result;
}

ssize_t sendto(int fd, const void *buffer, size_t length, int flags,
    const struct sockaddr *address, socklen_t address_length)
{
    if (!ker_sb_preload_runtime_ready())
        return host_sendto(fd, buffer, length, flags, address, address_length);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) {
        if (address || address_length) { errno = EOPNOTSUPP; return -1; }
        return send(fd, buffer, length, flags);
    }
    return host_sendto(fd, buffer, length, flags, address, address_length);
}

ssize_t recvfrom(int fd, void *buffer, size_t length, int flags,
    struct sockaddr *address, socklen_t *address_length)
{
    if (!ker_sb_preload_runtime_ready())
        return host_recvfrom(fd, buffer, length, flags, address, address_length);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) {
        if (address || address_length) { errno = EOPNOTSUPP; return -1; }
        return recv(fd, buffer, length, flags);
    }
    return host_recvfrom(fd, buffer, length, flags, address, address_length);
}

ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
    if (!ker_sb_preload_runtime_ready()) return host_sendmsg(fd, message, flags);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) { errno = EOPNOTSUPP; return -1; }
    return host_sendmsg(fd, message, flags);
}

ssize_t recvmsg(int fd, struct msghdr *message, int flags)
{
    if (!ker_sb_preload_runtime_ready()) return host_recvmsg(fd, message, flags);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) { errno = EOPNOTSUPP; return -1; }
    return host_recvmsg(fd, message, flags);
}

static ssize_t vector_io(int fd, const struct iovec *user_iov, int count, bool writing)
{
    if (!ker_sb_preload_runtime_ready())
        return writing ? host_writev(fd, user_iov, count) : host_readv(fd, user_iov, count);
    ker_sb_preload_lock(); int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : writing ? host_writev(fd, user_iov, count) :
            host_readv(fd, user_iov, count);
    }
    if (count < 0 || count > KER_SB_MAX_IOV) { ker_sb_preload_unlock(); errno = EINVAL; return -1; }
    struct iovec vectors[KER_SB_MAX_IOV];
    if (count && copy_in(vectors, user_iov, (size_t)count * sizeof(*vectors))) {
        ker_sb_preload_unlock(); return -1;
    }
    unsigned char bytes[KER_SB_IO_MAX]; size_t total = 0;
    for (int i = 0; i < count && total < sizeof(bytes); ++i) {
        size_t amount = vectors[i].iov_len;
        if (amount > sizeof(bytes) - total) amount = sizeof(bytes) - total;
        if (writing && amount && copy_in(bytes + total, vectors[i].iov_base, amount)) {
            ker_sb_preload_unlock(); return -1;
        }
        total += amount;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    ssize_t result = client ? (writing ? ker_socket_client_write(client, cap,
        bytes, total) : ker_socket_client_read(client, cap, bytes, total)) : -1;
    if (result > 0 && !writing) {
        size_t left = (size_t)result, offset = 0;
        for (int i = 0; i < count && left; ++i) {
            size_t amount = vectors[i].iov_len < left ? vectors[i].iov_len : left;
            if (copy_out(vectors[i].iov_base, bytes + offset, amount)) { result = -1; break; }
            left -= amount; offset += amount;
        }
    }
    ker_sb_preload_unlock();
    int error = errno;
    if (writing && result < 0 && error == EPIPE) {
        (void)syscall(SYS_tgkill, syscall(SYS_getpid), syscall(SYS_gettid), SIGPIPE);
        errno = error;
    }
    return result;
}

ssize_t readv(int fd, const struct iovec *vectors, int count)
{ return vector_io(fd, vectors, count, false); }
ssize_t writev(int fd, const struct iovec *vectors, int count)
{ return vector_io(fd, vectors, count, true); }

int epoll_create1(int flags)
{
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock(); int result = ker_sb_preload_epoll_create_locked(flags);
    ker_sb_preload_unlock(); return result;
}

int epoll_create(int size)
{
    if (size <= 0) { errno = EINVAL; return -1; }
    return epoll_create1(0);
}

int epoll_ctl(int epfd, int operation, int fd, struct epoll_event *event)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_epoll_ctl, epfd, operation, fd, event);
    ker_sb_preload_lock();
    int epoll_cap = -1;
    int composite = ker_sb_preload_composite_epoll_locked(epfd, &epoll_cap);
    if (composite < 0) { ker_sb_preload_unlock(); return -1; }
    /* A composite epoll is split between a host epoll and a broker epoll.
     * Registering its host half in another epoll would silently lose native
     * readiness, regardless of whether the outer epoll is composite. */
    int target_epoll = ker_sb_preload_composite_epoll_locked(fd, NULL);
    if (target_epoll < 0) { ker_sb_preload_unlock(); return -1; }
    if (target_epoll) {
        ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
    }
    int cap = -1, native = ker_sb_preload_network_fd_locked(fd, &cap);
    if (native < 0) { ker_sb_preload_unlock(); return -1; }
    if (!composite) {
        ker_sb_preload_unlock();
        if (native) { errno = EOPNOTSUPP; return -1; }
        return (int)syscall(SYS_epoll_ctl, epfd, operation, fd, event);
    }
    struct epoll_event local_event;
    const struct epoll_event *selected = NULL;
    if (event) {
        if (copy_in(&local_event, event, sizeof(local_event))) {
            ker_sb_preload_unlock(); return -1;
        }
        selected = &local_event;
    }
    int result;
    if (native) {
        struct ker_socket_client *client = ker_sb_preload_client_locked();
        result = client ? ker_socket_client_epoll_ctl(client, epoll_cap,
            operation, cap, selected) : -1;
    } else {
        result = (int)syscall(SYS_epoll_ctl, epfd, operation, fd, selected);
    }
    ker_sb_preload_unlock(); return result;
}

static int epoll_wait_common(int epfd, struct epoll_event *user_events,
    int maximum, int timeout, const sigset_t *mask)
{
    int owner_wait_status = ker_sb_preload_owner_wait_check();
    if (owner_wait_status) {
        char message[128];
        int length = snprintf(message, sizeof(message),
            "ker owner wait guard status=%d\n", owner_wait_status);
        if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
            (size_t)length);
        errno = -owner_wait_status;
        return -1;
    }
    if (!ker_sb_preload_runtime_ready())
        return ker_sb_preload_host_epoll_pwait(epfd, user_events, maximum, timeout, mask);
    sigset_t all_signals, old_mask;
    sigfillset(&all_signals);
    int mask_error = pthread_sigmask(SIG_SETMASK, &all_signals, &old_mask);
    if (mask_error) { errno = mask_error; return -1; }
    ker_sb_preload_lock();
    int broker_fd = -1;
    int composite = ker_sb_preload_composite_epoll_locked(epfd, &broker_fd);
    if (composite < 0) {
        int error = errno;
        ker_sb_preload_unlock();
        (void)pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        errno = error;
        return -1;
    }
    if (!composite) {
        ker_sb_preload_unlock();
        (void)pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        if (ker_sb_preload_owner_pump_registered()) {
            char message[128];
            int length = snprintf(message, sizeof(message),
                "ker owner epoll wait lacks composite fd=%d max=%d timeout=%d\n",
                epfd, maximum, timeout);
            if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
                (size_t)length);
            errno = EOPNOTSUPP;
            return -1;
        }
        return ker_sb_preload_host_epoll_pwait(epfd, user_events, maximum, timeout, mask);
    }
    if (maximum <= 0 || maximum > 4096) {
        ker_sb_preload_unlock();
        (void)pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        errno = EINVAL;
        return -1;
    }
    struct epoll_event local[4096];
    ker_sb_preload_unlock();
    const sigset_t *wait_mask = mask ? mask : &old_mask;
    int count = ker_sb_preload_epoll_wait_mixed_locked(epfd, local, maximum, timeout,
        wait_mask);
    if (count > 0 && copy_out(user_events, local, (size_t)count * sizeof(*local))) count = -1;
    int saved_errno = errno;
    (void)pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
    errno = saved_errno;
    return count;
}

int epoll_wait(int epfd, struct epoll_event *events, int maximum, int timeout)
{ return epoll_wait_common(epfd, events, maximum, timeout, NULL); }

int epoll_pwait(int epfd, struct epoll_event *events, int maximum, int timeout,
    const sigset_t *mask)
{ return epoll_wait_common(epfd, events, maximum, timeout, mask); }

int dup(int old_fd)
{
    if (!ker_sb_preload_runtime_ready()) return (int)syscall(SYS_dup, old_fd);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(old_fd, &cap);
    if (native < 0) { ker_sb_preload_unlock(); return -1; }
    int epoll_cap = -1;
    int composite = native ? 0 : ker_sb_preload_composite_epoll_locked(old_fd, &epoll_cap);
    if (composite < 0) { ker_sb_preload_unlock(); return -1; }
    int result = native ? ker_sb_preload_duplicate_network_locked(old_fd, 0, false) :
        composite ? ker_sb_preload_epoll_duplicate_locked(old_fd, 0, false) :
        (int)syscall(SYS_dup, old_fd);
    ker_sb_preload_unlock(); return result;
}

int dup2(int old_fd, int new_fd)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_dup2, old_fd, new_fd);
    if (old_fd == new_fd) return (int)syscall(SYS_dup2, old_fd, new_fd);
    ker_sb_preload_lock(); int cap = -1;
    int source = ker_sb_preload_network_fd_locked(old_fd, &cap);
    int target = ker_sb_preload_any_native_locked(new_fd);
    if (source < 0 || target < 0) { ker_sb_preload_unlock(); return -1; }
    int source_epoll = source ? 0 : ker_sb_preload_composite_epoll_locked(old_fd, NULL);
    int target_epoll = target ? 0 : ker_sb_preload_composite_epoll_locked(new_fd, NULL);
    if (source_epoll < 0 || target_epoll < 0) { ker_sb_preload_unlock(); return -1; }
    if (source || target || source_epoll || target_epoll) {
        ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
    }
    int result = (int)syscall(SYS_dup2, old_fd, new_fd);
    ker_sb_preload_unlock(); return result;
}

int dup3(int old_fd, int new_fd, int flags)
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_dup3, old_fd, new_fd, flags);
    if (old_fd == new_fd) { errno = EINVAL; return -1; }
    ker_sb_preload_lock(); int cap = -1;
    int source = ker_sb_preload_network_fd_locked(old_fd, &cap);
    int target = ker_sb_preload_any_native_locked(new_fd);
    if (source < 0 || target < 0) { ker_sb_preload_unlock(); return -1; }
    int source_epoll = source ? 0 : ker_sb_preload_composite_epoll_locked(old_fd, NULL);
    int target_epoll = target ? 0 : ker_sb_preload_composite_epoll_locked(new_fd, NULL);
    if (source_epoll < 0 || target_epoll < 0) { ker_sb_preload_unlock(); return -1; }
    if (source || target || source_epoll || target_epoll) {
        ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
    }
    int result = (int)syscall(SYS_dup3, old_fd, new_fd, flags);
    ker_sb_preload_unlock(); return result;
}

static bool fcntl_command_has_argument(int command)
{
    switch (command) {
    case F_GETFD: case F_GETFL: case F_GETOWN:
#ifdef F_GETSIG
    case F_GETSIG:
#endif
#ifdef F_GETLEASE
    case F_GETLEASE:
#endif
        return false;
    default: return true;
    }
}

static bool fcntl_command_argument_is_pointer(int command)
{
    switch (command) {
    case F_GETLK: case F_SETLK: case F_SETLKW:
#ifdef F_OFD_GETLK
    case F_OFD_GETLK: case F_OFD_SETLK: case F_OFD_SETLKW:
#endif
#ifdef F_GETOWN_EX
    case F_GETOWN_EX: case F_SETOWN_EX:
#endif
#ifdef F_GET_RW_HINT
    case F_GET_RW_HINT: case F_SET_RW_HINT:
#endif
#ifdef F_GET_FILE_RW_HINT
    case F_GET_FILE_RW_HINT: case F_SET_FILE_RW_HINT:
#endif
        return true;
    default: return false;
    }
}

int fcntl(int fd, int command, ...)
{
    unsigned long argument = 0;
    void *pointer_argument = NULL;
    if (fcntl_command_has_argument(command)) {
        va_list ap; va_start(ap, command);
        if (fcntl_command_argument_is_pointer(command))
            pointer_argument = va_arg(ap, void *);
        else
            argument = va_arg(ap, unsigned long);
        va_end(ap);
    }
    if (!ker_sb_preload_runtime_ready()) {
        if (!fcntl_command_has_argument(command)) return host_fcntl_none(fd, command);
        if (fcntl_command_argument_is_pointer(command))
            return host_fcntl_pointer(fd, command, pointer_argument);
        return host_fcntl_integer(fd, command, argument);
    }
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    if (native < 0) { ker_sb_preload_unlock(); return -1; }
    if (!native) {
        int epoll_cap = -1;
        int composite = ker_sb_preload_composite_epoll_locked(fd, &epoll_cap);
        if (composite < 0) { ker_sb_preload_unlock(); return -1; }
        if (ff_dispatch_active(fd)) {
            ker_sb_preload_unlock(); return ff_reject_host_fd(fd);
        }
        if (composite && (command == F_DUPFD || command == F_DUPFD_CLOEXEC)) {
            int result = ker_sb_preload_epoll_duplicate_locked(fd, (int)argument,
                command == F_DUPFD_CLOEXEC);
            ker_sb_preload_unlock(); return result;
        }
        if (composite && (command == F_GETFL || command == F_SETFL)) {
            ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
        }
        ker_sb_preload_unlock();
        if (!fcntl_command_has_argument(command)) return host_fcntl_none(fd, command);
        if (fcntl_command_argument_is_pointer(command))
            return host_fcntl_pointer(fd, command, pointer_argument);
        return host_fcntl_integer(fd, command, argument);
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = -1;
    if (!client) { ker_sb_preload_unlock(); return -1; }
    switch (command) {
    case F_GETFL: result = ker_socket_client_getfl(client, cap); break;
    case F_SETFL: result = ker_socket_client_setfl(client, cap, (int)argument); break;
    case F_GETFD: case F_SETFD:
        result = fcntl_command_has_argument(command) ?
            (int)syscall(SYS_fcntl, fd, command, argument) :
            (int)syscall(SYS_fcntl, fd, command);
        break;
    case F_DUPFD: case F_DUPFD_CLOEXEC:
        if (ff_dispatch_active(fd) && ff_owner_context_started) {
            if (!ker_sb_preload_ff_owner_active_locked()) {
                errno = EOPNOTSUPP;
                result = -1;
                break;
            }
            int matches = ker_socket_client_ff_owner_match(client,
                ff_owner_capability, cap);
            if (matches != 1) {
                if (matches == 0) errno = EXDEV;
                result = -1;
                break;
            }
            result = ker_sb_preload_duplicate_network_locked(fd, (int)argument,
                command == F_DUPFD_CLOEXEC);
        } else {
            result = ker_sb_preload_duplicate_network_locked(fd, (int)argument,
                command == F_DUPFD_CLOEXEC);
        }
        break;
    default: errno = EOPNOTSUPP; result = -1; break;
    }
    ker_sb_preload_unlock(); return result;
}

int ioctl(int fd, unsigned long request, ...)
{
    va_list ap; va_start(ap, request); void *user_argument = va_arg(ap, void *); va_end(ap);
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_ioctl, fd, request, user_argument);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        if (native == 0 && ff_reject_host_fd(fd)) return -1;
        return native < 0 ? -1 : (int)syscall(SYS_ioctl, fd, request, user_argument);
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = -1;
    if (client && request == FIONBIO) {
        int enabled;
        if (!copy_in(&enabled, user_argument, sizeof(enabled)))
            result = ker_socket_client_fionbio(client, cap, enabled != 0);
    } else if (client && request == FIONREAD) {
        int available = 0;
        result = ker_socket_client_fionread(client, cap, &available);
        if (!result) result = copy_out(user_argument, &available, sizeof(available));
    } else if (client) { errno = EOPNOTSUPP; }
    ker_sb_preload_unlock(); return result;
}

static int exec_guard(void)
{
    if (!ker_sb_preload_runtime_ready()) return 0;
    ker_sb_preload_lock();
    if (ker_sb_preload_has_exec_unsafe_epoll_locked()) {
        ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
    }
    ker_sb_preload_unlock();
    return 0;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_execve, path, argv, envp);
    if (exec_guard()) return -1;
    return (int)syscall(SYS_execve, path, argv, envp);
}

int execv(const char *path, char *const argv[])
{ return execve(path, argv, environ); }

static int exec_list(const char *path, const char *arg0, va_list input,
    char *const *explicit_environment, bool use_explicit_environment,
    bool search_path)
{
    size_t count = arg0 ? 1 : 0;
    if ((uintptr_t)arg0 != 0) {
        va_list count_args; va_copy(count_args, input);
        while (va_arg(count_args, const char *)) ++count;
        va_end(count_args);
    }
    char **arguments = calloc(count + 1, sizeof(*arguments));
    if (!arguments) return -1;
    if (arg0) arguments[0] = (char *)arg0;
    if (arg0) {
        for (size_t i = 1; i < count; ++i)
            arguments[i] = (char *)va_arg(input, const char *);
        (void)va_arg(input, const char *); /* terminating NULL */
    }
    arguments[count] = NULL;
    int result;
    if (search_path) {
        if (exec_guard()) result = -1;
        else if (use_explicit_environment) {
            typedef int (*execvpe_fn)(const char *, char *const[], char *const[]);
            execvpe_fn function = (execvpe_fn)dlsym(RTLD_NEXT, "execvpe");
            if (!function) { errno = ENOSYS; result = -1; }
            else result = function(path, arguments, (char *const *)explicit_environment);
        } else {
            typedef int (*execvp_fn)(const char *, char *const[]);
            execvp_fn function = (execvp_fn)dlsym(RTLD_NEXT, "execvp");
            if (!function) { errno = ENOSYS; result = -1; }
            else result = function(path, arguments);
        }
    } else {
        result = execve(path, arguments, use_explicit_environment ?
            (char *const *)explicit_environment : environ);
    }
    int error = errno; free(arguments); errno = error; return result;
}

int execl(const char *path, const char *arg0, ...)
{
    va_list args; va_start(args, arg0); int result = exec_list(path, arg0, args,
        NULL, false, false); va_end(args); return result;
}

int execlp(const char *file, const char *arg0, ...)
{
    va_list args; va_start(args, arg0); int result = exec_list(file, arg0, args,
        NULL, false, true); va_end(args); return result;
}

int execle(const char *path, const char *arg0, ...)
{
    va_list args; va_start(args, arg0);
    char *const *environment = NULL;
    volatile uintptr_t arg0_value = (uintptr_t)arg0;
    if (arg0_value != 0) {
        va_list scan; va_copy(scan, args);
        while (va_arg(scan, const char *)) { }
        environment = va_arg(scan, char *const *);
        va_end(scan);
    } else {
        environment = va_arg(args, char *const *);
    }
    int result = exec_list(path, arg0, args, environment, true, false);
    va_end(args); return result;
}

int execvp(const char *file, char *const argv[])
{
    if (exec_guard()) return -1;
    typedef int (*function_type)(const char *, char *const[]);
    function_type function = (function_type)dlsym(RTLD_NEXT, "execvp");
    if (!function) { errno = ENOSYS; return -1; }
    return function(file, argv);
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    if (exec_guard()) return -1;
    typedef int (*function_type)(const char *, char *const[], char *const[]);
    function_type function = (function_type)dlsym(RTLD_NEXT, "execvpe");
    if (!function) { errno = ENOSYS; return -1; }
    return function(file, argv, envp);
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
    if (exec_guard()) return -1;
#ifdef SYS_execveat
    return (int)syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
#else
    errno = ENOSYS; return -1;
#endif
}

int execveat(int dirfd, const char *path, char *const argv[], char *const envp[], int flags)
{
#ifdef SYS_execveat
    if (!ker_sb_preload_runtime_ready())
        return (int)syscall(SYS_execveat, dirfd, path, argv, envp, flags);
    ker_sb_preload_lock();
    if (ker_sb_preload_has_exec_unsafe_epoll_locked()) {
        ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
    }
    ker_sb_preload_unlock();
    return (int)syscall(SYS_execveat, dirfd, path, argv, envp, flags);
#else
    (void)dirfd; (void)path; (void)argv; (void)envp; (void)flags;
    errno = ENOSYS; return -1;
#endif
}

ssize_t sendfile(int out_fd, int in_fd, off_t *user_offset, size_t count)
{
    if (!ker_sb_preload_runtime_ready()) return host_sendfile(out_fd, in_fd, user_offset, count);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(out_fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : host_sendfile(out_fd, in_fd, user_offset, count);
    }
    off_t position;
    bool explicit_offset = user_offset != NULL;
    if (explicit_offset) {
        if (copy_in(&position, user_offset, sizeof(position))) {
            ker_sb_preload_unlock(); return -1;
        }
    } else {
        position = (off_t)syscall(SYS_lseek, in_fd, 0, SEEK_CUR);
        if (position < 0) { ker_sb_preload_unlock(); return -1; }
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    if (!client) { ker_sb_preload_unlock(); return -1; }
    size_t total = 0;
    unsigned char buffer[KER_SB_IO_MAX];
    while (total < count) {
        size_t request = count - total;
        if (request > sizeof(buffer)) request = sizeof(buffer);
        ssize_t got;
        do { got = (ssize_t)syscall(SYS_pread64, in_fd, buffer, request,
            position + (off_t)total); } while (got < 0 && errno == EINTR);
        if (got <= 0) {
            if (got < 0 && total == 0) { ker_sb_preload_unlock(); return -1; }
            break;
        }
        ssize_t sent = ker_socket_client_send(client, cap, buffer, (size_t)got,
            MSG_NOSIGNAL);
        if (sent < 0) {
            int error = errno;
            if (!total) {
                ker_sb_preload_unlock();
                if (error == EPIPE)
                    (void)syscall(SYS_tgkill, syscall(SYS_getpid), syscall(SYS_gettid), SIGPIPE);
                errno = error; return -1;
            }
            break;
        }
        total += (size_t)sent;
        if ((size_t)sent != (size_t)got) break;
    }
    if (explicit_offset) {
        position += (off_t)total;
        if (copy_out(user_offset, &position, sizeof(position))) {
            ker_sb_preload_unlock(); return -1;
        }
    } else if (total && syscall(SYS_lseek, in_fd, position + (off_t)total, SEEK_SET) < 0) {
        ker_sb_preload_unlock(); return -1;
    }
    ker_sb_preload_unlock(); return (ssize_t)total;
}

ssize_t sendfile64(int out_fd, int in_fd, off64_t *offset, size_t count)
{
    return sendfile(out_fd, in_fd, (off_t *)offset, count);
}

/* POSIX aliases for LD_PRELOAD users. The bridge links against the namespaced
 * symbols above, so executable-defined functions cannot intercept its calls. */
#undef socket
#undef bind
#undef connect
#undef listen
#undef accept4
#undef accept
#undef close
#undef shutdown
#undef getsockname
#undef getpeername
#undef setsockopt
#undef getsockopt
#undef read
#undef write
#undef send
#undef recv
#undef sendto
#undef recvfrom
#undef sendmsg
#undef recvmsg
#undef readv
#undef writev
#undef epoll_create1
#undef epoll_create
#undef epoll_ctl
#undef epoll_wait
#undef epoll_pwait
#undef dup
#undef dup2
#undef dup3
#undef fcntl
#undef ioctl
#undef execve
#undef execv
#undef execl
#undef execlp
#undef execle
#undef execvp
#undef execvpe
#undef fexecve
#undef execveat
#undef sendfile
#undef sendfile64

#define KER_SB_PUBLIC_ALIAS(public_name, implementation_name) \
    extern __typeof(implementation_name) public_name \
        __attribute__((alias(#implementation_name)))
KER_SB_PUBLIC_ALIAS(socket, ker_sb_posix_socket);
KER_SB_PUBLIC_ALIAS(bind, ker_sb_posix_bind);
KER_SB_PUBLIC_ALIAS(connect, ker_sb_posix_connect);
KER_SB_PUBLIC_ALIAS(listen, ker_sb_posix_listen);
KER_SB_PUBLIC_ALIAS(accept4, ker_sb_posix_accept4);
KER_SB_PUBLIC_ALIAS(accept, ker_sb_posix_accept);
KER_SB_PUBLIC_ALIAS(close, ker_sb_posix_close);
KER_SB_PUBLIC_ALIAS(shutdown, ker_sb_posix_shutdown);
KER_SB_PUBLIC_ALIAS(getsockname, ker_sb_posix_getsockname);
KER_SB_PUBLIC_ALIAS(getpeername, ker_sb_posix_getpeername);
KER_SB_PUBLIC_ALIAS(setsockopt, ker_sb_posix_setsockopt);
KER_SB_PUBLIC_ALIAS(getsockopt, ker_sb_posix_getsockopt);
KER_SB_PUBLIC_ALIAS(read, ker_sb_posix_read);
KER_SB_PUBLIC_ALIAS(write, ker_sb_posix_write);
KER_SB_PUBLIC_ALIAS(send, ker_sb_posix_send);
KER_SB_PUBLIC_ALIAS(recv, ker_sb_posix_recv);
KER_SB_PUBLIC_ALIAS(sendto, ker_sb_posix_sendto);
KER_SB_PUBLIC_ALIAS(recvfrom, ker_sb_posix_recvfrom);
KER_SB_PUBLIC_ALIAS(sendmsg, ker_sb_posix_sendmsg);
KER_SB_PUBLIC_ALIAS(recvmsg, ker_sb_posix_recvmsg);
KER_SB_PUBLIC_ALIAS(readv, ker_sb_posix_readv);
KER_SB_PUBLIC_ALIAS(writev, ker_sb_posix_writev);
KER_SB_PUBLIC_ALIAS(epoll_create1, ker_sb_posix_epoll_create1);
KER_SB_PUBLIC_ALIAS(epoll_create, ker_sb_posix_epoll_create);
KER_SB_PUBLIC_ALIAS(epoll_ctl, ker_sb_posix_epoll_ctl);
KER_SB_PUBLIC_ALIAS(epoll_wait, ker_sb_posix_epoll_wait);
KER_SB_PUBLIC_ALIAS(epoll_pwait, ker_sb_posix_epoll_pwait);
KER_SB_PUBLIC_ALIAS(dup, ker_sb_posix_dup);
KER_SB_PUBLIC_ALIAS(dup2, ker_sb_posix_dup2);
KER_SB_PUBLIC_ALIAS(dup3, ker_sb_posix_dup3);
KER_SB_PUBLIC_ALIAS(fcntl, ker_sb_posix_fcntl);
KER_SB_PUBLIC_ALIAS(fcntl64, ker_sb_posix_fcntl);
KER_SB_PUBLIC_ALIAS(ioctl, ker_sb_posix_ioctl);
KER_SB_PUBLIC_ALIAS(execve, ker_sb_posix_execve);
KER_SB_PUBLIC_ALIAS(execv, ker_sb_posix_execv);
KER_SB_PUBLIC_ALIAS(execl, ker_sb_posix_execl);
KER_SB_PUBLIC_ALIAS(execlp, ker_sb_posix_execlp);
KER_SB_PUBLIC_ALIAS(execle, ker_sb_posix_execle);
KER_SB_PUBLIC_ALIAS(execvp, ker_sb_posix_execvp);
KER_SB_PUBLIC_ALIAS(execvpe, ker_sb_posix_execvpe);
KER_SB_PUBLIC_ALIAS(fexecve, ker_sb_posix_fexecve);
KER_SB_PUBLIC_ALIAS(execveat, ker_sb_posix_execveat);
KER_SB_PUBLIC_ALIAS(sendfile, ker_sb_posix_sendfile);
KER_SB_PUBLIC_ALIAS(sendfile64, ker_sb_posix_sendfile64);
#undef KER_SB_PUBLIC_ALIAS
