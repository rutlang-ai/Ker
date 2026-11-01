#define _GNU_SOURCE
#include "socket-broker-preload-internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PRELOAD_FD_SLOTS 4096
#define PRELOAD_PRIVATE_SLOTS 8192
#define PRELOAD_WAIT_SLOTS 4096

struct fd_identity { dev_t device; ino_t inode; };
struct network_entry {
    int app_fd;
    int private_fd;
    struct fd_identity identity;
};
struct epoll_entry {
    int app_fd;
    int broker_fd;
    struct fd_identity identity;
    bool remote_first;
};
struct wait_pin_entry { int host_fd; int broker_fd; pid_t owner_tid; };

static pthread_mutex_t preload_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool preload_runtime_initialized = false;
static _Thread_local sigset_t preload_saved_signal_mask;
static _Thread_local unsigned preload_lock_depth;
static _Thread_local pid_t preload_fork_owner_tid;
static struct ker_socket_client preload_client = {.session_fd = -1};
static bool client_open;
static struct network_entry network_fds[PRELOAD_FD_SLOTS];
static struct epoll_entry epoll_fds[PRELOAD_FD_SLOTS];
static int private_fds[PRELOAD_PRIVATE_SLOTS];
static struct wait_pin_entry wait_pins[PRELOAD_WAIT_SLOTS];

int ker_sb_preload_runtime_ready(void)
{
    return atomic_load_explicit(&preload_runtime_initialized, memory_order_acquire);
}

struct linux_dirent64 {
    uint64_t inode;
    int64_t offset;
    unsigned short record_length;
    unsigned char type;
    char name[];
};

static int block_signals(sigset_t *previous)
{
    sigset_t all_signals;
    sigfillset(&all_signals);
    int error = pthread_sigmask(SIG_SETMASK, &all_signals, previous);
    if (error) { errno = error; return -1; }
    return 0;
}

static int restore_signals(const sigset_t *previous)
{
    int error = pthread_sigmask(SIG_SETMASK, previous, NULL);
    if (error) { errno = error; return -1; }
    return 0;
}

static _Noreturn void preload_lock_fatal(const char *message)
{
    size_t length = strlen(message);
    (void)syscall(SYS_write, STDERR_FILENO, message, length);
    _exit(127);
}

static void close_vanished_wait_pins_locked(pid_t owner_tid);

static void fork_prepare(void)
{
    ker_sb_preload_lock();
    preload_fork_owner_tid = (pid_t)syscall(SYS_gettid);
}

static void fork_parent(void)
{
    preload_fork_owner_tid = 0;
    ker_sb_preload_unlock();
}

static void fork_child(void)
{
    close_vanished_wait_pins_locked(preload_fork_owner_tid);
    preload_fork_owner_tid = 0;
    ker_sb_preload_unlock();
}

static int ensure_client_locked(void)
{
    if (client_open) return 0;
    const char *path = getenv("KER_SOCKET_BROKER_PATH");
    if (!path || !path[0]) { errno = ENOTCONN; return -1; }
    if (ker_socket_client_open(&preload_client, path)) return -1;
    client_open = true;
    return 0;
}

void ker_sb_preload_lock(void)
{
    if (preload_lock_depth) { ++preload_lock_depth; return; }
    if (block_signals(&preload_saved_signal_mask))
        preload_lock_fatal("ker socket preload: cannot block signals before locking\n");
    int error = pthread_mutex_lock(&preload_lock);
    if (error) {
        (void)restore_signals(&preload_saved_signal_mask);
        preload_lock_fatal("ker socket preload: descriptor-map lock failed\n");
    }
    preload_lock_depth = 1;
}

void ker_sb_preload_unlock(void)
{
    if (!preload_lock_depth)
        preload_lock_fatal("ker socket preload: unmatched descriptor-map unlock\n");
    if (--preload_lock_depth) return;
    int error = pthread_mutex_unlock(&preload_lock);
    if (error) preload_lock_fatal("ker socket preload: descriptor-map unlock failed\n");
    if (restore_signals(&preload_saved_signal_mask))
        preload_lock_fatal("ker socket preload: cannot restore signal mask\n");
}
struct ker_socket_client *ker_sb_preload_client_locked(void)
{
    return ensure_client_locked() ? NULL : &preload_client;
}

static int descriptor_identity(int fd, struct fd_identity *identity)
{
    struct stat value = {0};
    if (syscall(SYS_fstat, fd, &value)) return -1;
    identity->device = value.st_dev;
    identity->inode = value.st_ino;
    return 0;
}

static bool identity_matches(int fd, struct fd_identity identity)
{
    struct fd_identity current;
    return descriptor_identity(fd, &current) == 0 &&
        current.device == identity.device && current.inode == identity.inode;
}

static size_t find_network_slot(int fd)
{
    for (size_t i = 0; i < PRELOAD_FD_SLOTS; ++i)
        if (network_fds[i].app_fd == fd) return i;
    return PRELOAD_FD_SLOTS;
}

static size_t free_network_slot(void)
{
    for (size_t i = 0; i < PRELOAD_FD_SLOTS; ++i)
        if (network_fds[i].app_fd < 0) return i;
    return PRELOAD_FD_SLOTS;
}

int ker_sb_preload_track_private_fd_locked(int fd)
{
    for (size_t i = 0; i < PRELOAD_PRIVATE_SLOTS; ++i) {
        if (private_fds[i] == fd) return 0;
        if (private_fds[i] < 0) { private_fds[i] = fd; return 0; }
    }
    errno = EMFILE; return -1;
}

void ker_sb_preload_untrack_private_fd_locked(int fd)
{
    for (size_t i = 0; i < PRELOAD_PRIVATE_SLOTS; ++i)
        if (private_fds[i] == fd) { private_fds[i] = -1; return; }
}

static int track_wait_pin_locked(int host_fd, int broker_fd)
{
    for (size_t i = 0; i < PRELOAD_WAIT_SLOTS; ++i) {
        if (wait_pins[i].host_fd < 0) {
            wait_pins[i] = (struct wait_pin_entry){.host_fd = host_fd,
                .broker_fd = broker_fd, .owner_tid = (pid_t)syscall(SYS_gettid)};
            return 0;
        }
    }
    errno = EMFILE;
    return -1;
}

static void untrack_wait_pin_locked(int host_fd, int broker_fd)
{
    for (size_t i = 0; i < PRELOAD_WAIT_SLOTS; ++i) {
        if (wait_pins[i].host_fd == host_fd && wait_pins[i].broker_fd == broker_fd) {
            wait_pins[i] = (struct wait_pin_entry){.host_fd = -1, .broker_fd = -1};
            return;
        }
    }
}

static void close_vanished_wait_pins_locked(pid_t owner_tid)
{
    pid_t child_tid = (pid_t)syscall(SYS_gettid);
    for (size_t i = 0; i < PRELOAD_WAIT_SLOTS; ++i) {
        struct wait_pin_entry *pin = &wait_pins[i];
        if (pin->host_fd < 0) continue;
        if (pin->owner_tid == owner_tid) {
            pin->owner_tid = child_tid;
            continue;
        }
        ker_sb_preload_untrack_private_fd_locked(pin->host_fd);
        ker_sb_preload_untrack_private_fd_locked(pin->broker_fd);
        (void)syscall(SYS_close, pin->host_fd);
        (void)syscall(SYS_close, pin->broker_fd);
        *pin = (struct wait_pin_entry){.host_fd = -1, .broker_fd = -1};
    }
}

int ker_sb_preload_is_private_fd_locked(int fd)
{
    if (client_open && preload_client.session_fd == fd) return 1;
    for (size_t i = 0; i < PRELOAD_PRIVATE_SLOTS; ++i)
        if (private_fds[i] == fd) return 1;
    return 0;
}

static void close_wait_descriptors(int host_fd, int broker_fd)
{
    ker_sb_preload_lock();
    untrack_wait_pin_locked(host_fd, broker_fd);
    if (host_fd >= 0) {
        ker_sb_preload_untrack_private_fd_locked(host_fd);
        (void)syscall(SYS_close, host_fd);
    }
    if (broker_fd >= 0) {
        ker_sb_preload_untrack_private_fd_locked(broker_fd);
        (void)syscall(SYS_close, broker_fd);
    }
    ker_sb_preload_unlock();
}

struct wait_pin_context { int host_fd; int broker_fd; bool active; };

static void close_wait_pin_context(void *opaque)
{
    volatile struct wait_pin_context *pins = opaque;
    if (!pins->active) return;
    pins->active = false;
    close_wait_descriptors(pins->host_fd, pins->broker_fd);
}

void ker_sb_preload_remove_network_locked(int app_fd)
{
    size_t slot = find_network_slot(app_fd);
    if (slot == PRELOAD_FD_SLOTS) return;
    if (network_fds[slot].private_fd >= 0) {
        ker_sb_preload_untrack_private_fd_locked(network_fds[slot].private_fd);
        (void)syscall(SYS_close, network_fds[slot].private_fd);
    }
    network_fds[slot] = (struct network_entry){.app_fd = -1, .private_fd = -1};
}

int ker_sb_preload_register_network_locked(int app_fd)
{
    struct fd_identity identity;
    int flags = (int)syscall(SYS_fcntl, app_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY ||
        descriptor_identity(app_fd, &identity)) return -1;
    struct stat value = {0};
    if (syscall(SYS_fstat, app_fd, &value)) return -1;
    if (!S_ISFIFO(value.st_mode)) { errno = EBADF; return -1; }

    size_t slot = find_network_slot(app_fd);
    if (slot != PRELOAD_FD_SLOTS) {
        if (network_fds[slot].identity.device == identity.device &&
            network_fds[slot].identity.inode == identity.inode) return 0;
        ker_sb_preload_remove_network_locked(app_fd);
    }
    slot = free_network_slot();
    if (slot == PRELOAD_FD_SLOTS) { errno = EMFILE; return -1; }
    int private_fd = (int)syscall(SYS_fcntl, app_fd, F_DUPFD_CLOEXEC, 0);
    if (private_fd < 0) return -1;
    if (ker_sb_preload_track_private_fd_locked(private_fd)) {
        int error = errno; (void)syscall(SYS_close, private_fd); errno = error; return -1;
    }
    network_fds[slot] = (struct network_entry){.app_fd = app_fd,
        .private_fd = private_fd, .identity = identity};
    return 0;
}

int ker_sb_preload_network_fd_locked(int app_fd, int *broker_fd)
{
    if (ker_sb_preload_is_private_fd_locked(app_fd)) { errno = EOPNOTSUPP; return -1; }
    size_t slot = find_network_slot(app_fd);
    if (slot != PRELOAD_FD_SLOTS) {
        if (identity_matches(app_fd, network_fds[slot].identity)) {
            if (broker_fd) *broker_fd = network_fds[slot].private_fd;
            return 1;
        }
        ker_sb_preload_remove_network_locked(app_fd);
    }
    /* POSIX preload capabilities are registered by socket/accept/dup or the
     * authenticated inherited-capability scan. Never probe arbitrary host
     * pipes with a blocking DESCRIBE RPC from ordinary descriptor operations. */
    return 0;
}

int ker_sb_preload_socket_drain_count(void)
{
    if (!ker_sb_preload_runtime_ready()) { errno = ENOTCONN; return -1; }
    ker_sb_preload_lock();
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    if (!client) {
        int saved_errno = errno;
        ker_sb_preload_unlock();
        errno = saved_errno;
        return -1;
    }

    int count = 0;
    for (size_t i = 0; i < PRELOAD_FD_SLOTS; ++i) {
        int app_fd = network_fds[i].app_fd;
        if (app_fd < 0) continue;

        struct fd_identity current;
        if (descriptor_identity(app_fd, &current)) {
            if (errno == EBADF) {
                ker_sb_preload_remove_network_locked(app_fd);
                continue;
            }
            goto error;
        }
        if (current.device != network_fds[i].identity.device ||
            current.inode != network_fds[i].identity.inode) {
            ker_sb_preload_remove_network_locked(app_fd);
            continue;
        }
        int broker_fd = network_fds[i].private_fd;

        int domain = -1;
        socklen_t length = sizeof(domain);
        if (ker_socket_client_getsockopt(client, broker_fd, SOL_SOCKET, SO_DOMAIN,
                &domain, &length) < 0) goto error;
        if (length != sizeof(domain)) { errno = EPROTO; goto error; }
        if (domain != AF_INET && domain != AF_INET6) continue;

        int accepting = 0;
        length = sizeof(accepting);
        if (ker_socket_client_getsockopt(client, broker_fd, SOL_SOCKET,
                SO_ACCEPTCONN, &accepting, &length) < 0) goto error;
        if (length != sizeof(accepting)) { errno = EPROTO; goto error; }
        if (!accepting) ++count;
    }
    ker_sb_preload_unlock();
    return count;

error:
    {
        int saved_errno = errno;
        ker_sb_preload_unlock();
        errno = saved_errno;
        return -1;
    }
}

int ker_sb_preload_any_native_locked(int fd)
{
    int broker_fd = -1;
    int result = ker_sb_preload_network_fd_locked(fd, &broker_fd);
    if (result) return result;
    result = ker_sb_preload_epoll_fd_locked(fd, &broker_fd);
    return result;
}

int ker_sb_preload_composite_epoll_locked(int fd, int *broker_fd)
{
    return ker_sb_preload_epoll_fd_locked(fd, broker_fd);
}

int ker_sb_preload_close_locked(int fd)
{
    int native = ker_sb_preload_network_fd_locked(fd, NULL);
    if (native < 0) return -1;
    if (native) ker_sb_preload_remove_network_locked(fd);
    else {
        native = ker_sb_preload_epoll_fd_locked(fd, NULL);
        if (native < 0) return -1;
        if (native) ker_sb_preload_remove_epoll_locked(fd);
    }
    return (int)syscall(SYS_close, fd);
}

int ker_sb_preload_duplicate_network_locked(int fd, int minimum, bool cloexec)
{
    int broker_fd = -1;
    if (ker_sb_preload_network_fd_locked(fd, &broker_fd) != 1) {
        if (!errno) errno = EBADF;
        return -1;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    if (!client) return -1;
    int duplicate = ker_socket_client_dup(client, broker_fd);
    if (duplicate < 0) return -1;
    int target = (int)syscall(SYS_fcntl, duplicate,
        cloexec ? F_DUPFD_CLOEXEC : F_DUPFD, minimum);
    int error = errno;
    if (target < 0) { (void)syscall(SYS_close, duplicate); errno = error; return -1; }
    if (target != duplicate) (void)syscall(SYS_close, duplicate);
    if (ker_sb_preload_register_network_locked(target)) {
        error = errno; (void)syscall(SYS_close, target); errno = error; return -1;
    }
    if (!cloexec) {
        int descriptor_flags = (int)syscall(SYS_fcntl, target, F_GETFD);
        if (descriptor_flags < 0 || syscall(SYS_fcntl, target, F_SETFD,
                descriptor_flags & ~FD_CLOEXEC) < 0) {
            error = errno; ker_sb_preload_remove_network_locked(target);
            (void)syscall(SYS_close, target); errno = error; return -1;
        }
    }
    return target;
}

int ker_sb_preload_epoll_duplicate_locked(int fd, int minimum, bool cloexec)
{
    return ker_sb_preload_duplicate_epoll_locked(fd, minimum, cloexec);
}

int ker_sb_preload_epoll_create_locked(int flags)
{
    if (flags & ~EPOLL_CLOEXEC) { errno = EINVAL; return -1; }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    if (!client) return -1;
    int broker_fd = ker_socket_client_epoll_create1(client, 0);
    if (broker_fd < 0) return -1;
    int app_fd = (int)syscall(SYS_epoll_create1, flags);
    int error = errno;
    if (app_fd < 0) { (void)syscall(SYS_close, broker_fd); errno = error; return -1; }
    if (ker_sb_preload_register_epoll_locked(app_fd, broker_fd)) {
        error = errno; (void)syscall(SYS_close, app_fd);
        (void)syscall(SYS_close, broker_fd); errno = error; return -1;
    }
    (void)syscall(SYS_close, broker_fd);
    return app_fd;
}

static int64_t monotonic_milliseconds(void)
{
    struct timespec now = {0};
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) < 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int ker_sb_preload_epoll_wait_mixed_locked(int fd, struct epoll_event *events,
    int maximum, int timeout, const sigset_t *mask)
{
    /* pthread cleanup may use setjmp; volatile preserves state across cancellation. */
    volatile int result = -1, saved_errno = 0;
    volatile struct wait_pin_context pins = {
        .host_fd = -1, .broker_fd = -1, .active = false};
    volatile bool pin_registered = false;
    int broker_fd = -1, first_remote = 0;
    int64_t start = -1, deadline = 0;
    pthread_cleanup_push(close_wait_pin_context, (void *)&pins);
    ker_sb_preload_lock();
    if (ker_sb_preload_composite_epoll_locked(fd, &broker_fd) != 1) {
        if (!errno) errno = EBADF;
        saved_errno = errno;
        ker_sb_preload_unlock();
        goto finished;
    }
    first_remote = ker_sb_preload_epoll_next_remote_first_locked(fd);
    if (first_remote < 0) {
        saved_errno = errno;
        ker_sb_preload_unlock();
        goto finished;
    }
    pins.host_fd = (int)syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 0);
    pins.broker_fd = (int)syscall(SYS_fcntl, broker_fd, F_DUPFD_CLOEXEC, 0);
    if (pins.host_fd >= 0 && ker_sb_preload_track_private_fd_locked(pins.host_fd)) {
        (void)syscall(SYS_close, pins.host_fd); pins.host_fd = -1;
    }
    if (pins.broker_fd >= 0 && ker_sb_preload_track_private_fd_locked(pins.broker_fd)) {
        (void)syscall(SYS_close, pins.broker_fd); pins.broker_fd = -1;
    }
    pins.active = pins.host_fd >= 0 || pins.broker_fd >= 0;
    if (pins.host_fd >= 0 && pins.broker_fd >= 0) {
        if (track_wait_pin_locked(pins.host_fd, pins.broker_fd)) {
            saved_errno = errno;
        } else {
            pin_registered = true;
        }
    } else {
        saved_errno = errno;
    }
    ker_sb_preload_unlock();
    if (!pin_registered) {
        if (!saved_errno) saved_errno = errno ? errno : EMFILE;
        goto finished;
    }
    if (maximum <= 0) { saved_errno = EINVAL; goto finished; }
    start = monotonic_milliseconds();
    if (start < 0) { saved_errno = errno; goto finished; }
    deadline = timeout < 0 ? INT64_MAX : start + timeout;
    for (;;) {
        int count = 0;
        int remote_first = first_remote;
        first_remote = !first_remote;
        int remote_budget = maximum;
        if (remote_budget > KER_SOCKET_BROKER_EVENTS_MAX)
            remote_budget = KER_SOCKET_BROKER_EVENTS_MAX;
        if (remote_first) {
            ker_sb_preload_lock();
            struct ker_socket_client *client = ker_sb_preload_client_locked();
            if (!client) { saved_errno = errno; ker_sb_preload_unlock(); goto finished; }
            int got = ker_socket_client_epoll_wait(client, pins.broker_fd, events,
                remote_budget);
            int error = errno; ker_sb_preload_unlock();
            if (got < 0) { saved_errno = error; goto finished; }
            count += got;
        }
        if (!remote_first) {
            int got = ker_sb_preload_host_epoll_pwait(pins.host_fd, events,
                maximum, 0, mask);
            if (got < 0) { saved_errno = errno; goto finished; }
            count += got;
        }
        if (!remote_first && count < maximum) {
            ker_sb_preload_lock();
            struct ker_socket_client *client = ker_sb_preload_client_locked();
            if (!client) { saved_errno = errno; ker_sb_preload_unlock(); goto finished; }
            int room = maximum - count;
            if (room > KER_SOCKET_BROKER_EVENTS_MAX)
                room = KER_SOCKET_BROKER_EVENTS_MAX;
            int got = ker_socket_client_epoll_wait(client, pins.broker_fd,
                events + count, room);
            int error = errno; ker_sb_preload_unlock();
            if (got < 0) { saved_errno = error; goto finished; }
            count += got;
        }
        if (remote_first && count < maximum) {
            int got = ker_sb_preload_host_epoll_pwait(pins.host_fd, events + count,
                maximum - count, 0, mask);
            if (got < 0) { saved_errno = errno; goto finished; }
            count += got;
        }
        if (count || timeout == 0) { result = count; goto finished; }
        int64_t now = monotonic_milliseconds();
        if (now < 0) { saved_errno = errno; goto finished; }
        if (now >= deadline) { result = 0; goto finished; }
        int slice = deadline == INT64_MAX || deadline - now > 1 ? 1 :
            (int)(deadline - now);
        /* The host epoll is the bounded sleep point; remote readiness is
         * polled from its authoritative original-Linux epoll each millisecond. */
        int got = ker_sb_preload_host_epoll_pwait(pins.host_fd, events, maximum,
            slice, mask);
        if (got < 0) { saved_errno = errno; goto finished; }
        if (got) { result = got; goto finished; }
    }
finished:
    if (pins.active) close_wait_pin_context((void *)&pins);
    pthread_cleanup_pop(0);
    if (saved_errno) errno = saved_errno;
    return result;
}

static size_t find_epoll_slot(int fd)
{
    for (size_t i = 0; i < PRELOAD_FD_SLOTS; ++i)
        if (epoll_fds[i].app_fd == fd) return i;
    return PRELOAD_FD_SLOTS;
}

static size_t free_epoll_slot(void)
{
    for (size_t i = 0; i < PRELOAD_FD_SLOTS; ++i)
        if (epoll_fds[i].app_fd < 0) return i;
    return PRELOAD_FD_SLOTS;
}

void ker_sb_preload_remove_epoll_locked(int app_fd)
{
    size_t slot = find_epoll_slot(app_fd);
    if (slot == PRELOAD_FD_SLOTS) return;
    if (epoll_fds[slot].broker_fd >= 0) {
        ker_sb_preload_untrack_private_fd_locked(epoll_fds[slot].broker_fd);
        (void)syscall(SYS_close, epoll_fds[slot].broker_fd);
    }
    epoll_fds[slot] = (struct epoll_entry){.app_fd = -1, .broker_fd = -1};
}

int ker_sb_preload_register_epoll_locked(int app_fd, int broker_epoll_fd)
{
    struct fd_identity identity;
    if (descriptor_identity(app_fd, &identity)) return -1;
    size_t slot = find_epoll_slot(app_fd);
    if (slot != PRELOAD_FD_SLOTS) ker_sb_preload_remove_epoll_locked(app_fd);
    slot = free_epoll_slot();
    if (slot == PRELOAD_FD_SLOTS) { errno = EMFILE; return -1; }
    int private_fd = (int)syscall(SYS_fcntl, broker_epoll_fd, F_DUPFD_CLOEXEC, 0);
    if (private_fd < 0) return -1;
    if (ker_sb_preload_track_private_fd_locked(private_fd)) {
        int error = errno; (void)syscall(SYS_close, private_fd); errno = error; return -1;
    }
    epoll_fds[slot] = (struct epoll_entry){.app_fd = app_fd,
        .broker_fd = private_fd, .identity = identity, .remote_first = true};
    return 0;
}

int ker_sb_preload_register_inherited_epoll_locked(int app_fd)
{
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    if (!client) return -1;
    enum ker_socket_broker_kind kind = 0; int flags = 0;
    if (ker_socket_client_describe(client, app_fd, &kind, &flags)) return -1;
    if (kind != KER_SOCKET_BROKER_EPOLL) { errno = EPROTO; return -1; }
    int descriptor_flags = (int)syscall(SYS_fcntl, app_fd, F_GETFD);
    if (descriptor_flags < 0) return -1;
    int broker_duplicate = (int)syscall(SYS_fcntl, app_fd, F_DUPFD_CLOEXEC, 0);
    if (broker_duplicate < 0) return -1;
    int temporary = (int)syscall(SYS_epoll_create1, EPOLL_CLOEXEC);
    if (temporary < 0) { int error = errno; (void)syscall(SYS_close, broker_duplicate); errno = error; return -1; }
    if (syscall(SYS_dup3, temporary, app_fd,
            descriptor_flags & FD_CLOEXEC ? O_CLOEXEC : 0) < 0) {
        int error = errno; (void)syscall(SYS_close, temporary);
        (void)syscall(SYS_close, broker_duplicate); errno = error; return -1;
    }
    (void)syscall(SYS_close, temporary);
    if (ker_sb_preload_register_epoll_locked(app_fd, broker_duplicate)) {
        int error = errno; (void)syscall(SYS_close, broker_duplicate); errno = error; return -1;
    }
    (void)syscall(SYS_close, broker_duplicate);
    return 0;
}

int ker_sb_preload_epoll_fd_locked(int app_fd, int *broker_epoll_fd)
{
    size_t slot = find_epoll_slot(app_fd);
    if (slot == PRELOAD_FD_SLOTS) return 0;
    if (!identity_matches(app_fd, epoll_fds[slot].identity)) {
        ker_sb_preload_remove_epoll_locked(app_fd);
        return 0;
    }
    if (broker_epoll_fd) *broker_epoll_fd = epoll_fds[slot].broker_fd;
    return 1;
}

int ker_sb_preload_duplicate_epoll_locked(int old_fd, int minimum, bool cloexec)
{
    size_t slot = find_epoll_slot(old_fd);
    if (slot == PRELOAD_FD_SLOTS || !identity_matches(old_fd, epoll_fds[slot].identity)) {
        errno = EBADF;
        return -1;
    }
    int host_fd = (int)syscall(SYS_fcntl, old_fd,
        cloexec ? F_DUPFD_CLOEXEC : F_DUPFD, minimum);
    if (host_fd < 0) return -1;
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    if (!client) { int error = errno; (void)syscall(SYS_close, host_fd); errno = error; return -1; }
    int broker_fd = ker_socket_client_dup(client, epoll_fds[slot].broker_fd);
    if (broker_fd < 0) { int error = errno; (void)syscall(SYS_close, host_fd); errno = error; return -1; }
    if (ker_sb_preload_register_epoll_locked(host_fd, broker_fd)) {
        int error = errno;
        (void)syscall(SYS_close, broker_fd); (void)syscall(SYS_close, host_fd);
        errno = error; return -1;
    }
    (void)syscall(SYS_close, broker_fd);
    return host_fd;
}

int ker_sb_preload_epoll_next_remote_first_locked(int fd)
{
    size_t slot = find_epoll_slot(fd);
    if (slot == PRELOAD_FD_SLOTS || !identity_matches(fd, epoll_fds[slot].identity)) {
        errno = EBADF; return -1;
    }
    int value = epoll_fds[slot].remote_first;
    epoll_fds[slot].remote_first = !epoll_fds[slot].remote_first;
    return value;
}

bool ker_sb_preload_has_exec_unsafe_epoll_locked(void)
{
    for (size_t i = 0; i < PRELOAD_FD_SLOTS; ++i) {
        if (epoll_fds[i].app_fd < 0 || !identity_matches(epoll_fds[i].app_fd,
                epoll_fds[i].identity)) continue;
        int flags = (int)syscall(SYS_fcntl, epoll_fds[i].app_fd, F_GETFD);
        if (flags >= 0 && !(flags & FD_CLOEXEC)) return true;
    }
    return false;
}

static int initialize_inherited_capabilities(void)
{
    const char *path = getenv("KER_SOCKET_BROKER_PATH");
    if (!path || !path[0]) return 0;
    ker_sb_preload_lock();
    if (ensure_client_locked()) { ker_sb_preload_unlock(); return -1; }
    int directory = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/fd",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (directory < 0) { ker_sb_preload_unlock(); return -1; }
    char buffer[8192]; int candidates[PRELOAD_FD_SLOTS]; size_t candidate_count = 0;
    for (;;) {
        long amount = syscall(SYS_getdents64, directory, buffer, sizeof(buffer));
        if (amount < 0) {
            if (errno == EINTR) continue;
            int error = errno; (void)syscall(SYS_close, directory);
            ker_sb_preload_unlock(); errno = error; return -1;
        }
        if (amount == 0) break;
        for (long offset = 0; offset < amount;) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *)(buffer + offset);
            if (!entry->record_length || offset + entry->record_length > amount) {
                (void)syscall(SYS_close, directory); ker_sb_preload_unlock(); errno = EPROTO; return -1;
            }
            char *end = NULL;
            long value = strtol(entry->name, &end, 10);
            if (end && !*end && value >= 0 && value <= INT32_MAX && value != directory) {
                struct stat status = {0};
                int flags = (int)syscall(SYS_fcntl, (int)value, F_GETFL);
                if (flags >= 0 && (flags & O_ACCMODE) == O_WRONLY &&
                    syscall(SYS_fstat, (int)value, &status) == 0 && S_ISFIFO(status.st_mode)) {
                    if (candidate_count == PRELOAD_FD_SLOTS) {
                        (void)syscall(SYS_close, directory); ker_sb_preload_unlock(); errno = EMFILE; return -1;
                    }
                    candidates[candidate_count++] = (int)value;
                }
            }
            offset += entry->record_length;
        }
    }
    (void)syscall(SYS_close, directory);
    for (size_t i = 0; i < candidate_count; ++i) {
        int fd = candidates[i]; enum ker_socket_broker_kind kind = 0; int status_flags = 0;
        if (ker_socket_client_describe(&preload_client, fd, &kind, &status_flags)) {
            if (errno == EBADF) continue; /* An unrelated ordinary host pipe. */
            int error = errno; ker_sb_preload_unlock(); errno = error; return -1;
        }
        if (kind == KER_SOCKET_BROKER_SOCKET) {
            if (ker_sb_preload_register_network_locked(fd)) {
                int error = errno; ker_sb_preload_unlock(); errno = error; return -1;
            }
        } else if (kind == KER_SOCKET_BROKER_EPOLL) {
            if (ker_sb_preload_register_inherited_epoll_locked(fd)) {
                int error = errno; ker_sb_preload_unlock(); errno = error; return -1;
            }
        } else if ((kind == KER_SOCKET_BROKER_REUSEPORT_GROUP ||
                    kind == KER_SOCKET_BROKER_MEMBER_CENSUS) && status_flags == 0) {
            /* Group and census descriptors are opaque metadata/control
             * capabilities, not application sockets or composite epolls.
             * Preserve them across exec without adding them to either map. */
            continue;
        } else if (kind == KER_SOCKET_BROKER_TCP_OBSERVER && status_flags == 0) {
            /* Observer capabilities carry metadata authority only. Preserve
             * the inherited host descriptor without treating it as a socket
             * or retaining any TCP descriptor in the preload map. */
            continue;
        } else {
            (void)status_flags; ker_sb_preload_unlock(); errno = EPROTO; return -1;
        }
    }
    ker_sb_preload_unlock();
    return 0;
}

__attribute__((constructor)) static void socket_broker_preload_initialize(void)
{
    if (ker_sb_preload_resolve_host_functions()) {
        static const char message[] = "ker socket preload: cannot resolve host libc calls\n";
        (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
        _exit(127);
    }
    for (size_t i = 0; i < PRELOAD_FD_SLOTS; ++i) {
        network_fds[i].app_fd = -1;
        network_fds[i].private_fd = -1;
        epoll_fds[i].app_fd = -1;
        epoll_fds[i].broker_fd = -1;
    }
    for (size_t i = 0; i < PRELOAD_PRIVATE_SLOTS; ++i) private_fds[i] = -1;
    for (size_t i = 0; i < PRELOAD_WAIT_SLOTS; ++i)
        wait_pins[i] = (struct wait_pin_entry){.host_fd = -1, .broker_fd = -1};
    if (pthread_atfork(fork_prepare, fork_parent, fork_child)) {
        static const char message[] = "ker socket preload: pthread_atfork registration failed\n";
        (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
        _exit(127);
    }
    if (initialize_inherited_capabilities()) {
        static const char message[] = "ker socket preload: inherited capability scan failed\n";
        (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
        _exit(127);
    }
    atomic_store_explicit(&preload_runtime_initialized, true, memory_order_release);
}
