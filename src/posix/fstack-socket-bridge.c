#define _GNU_SOURCE
#include <ff_api.h>
#include <ker/socket-broker.h>
#include "socket-broker-preload-internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(struct linux_sockaddr) == sizeof(struct sockaddr),
    "F-Stack linux_sockaddr must retain the Linux sockaddr ABI");

static int unsupported(void)
{
    errno = EOPNOTSUPP;
    return -1;
}

#ifdef KER_FSTACK_NGINX_RUNTIME
extern void ker_fstack_runtime_trace_leaf(const char *name, int fd, long result);
extern int ker_fstack_runtime_application_io_allowed(void);
extern bool ker_fstack_runtime_polls_kevent(void);
extern void ker_fstack_runtime_relay_checkpoint(void);
#define FF_PROGRESS() ker_fstack_runtime_relay_checkpoint()
#define FF_TRACE(fd, result) ker_fstack_runtime_trace_leaf(__func__, (fd), (long)(result))
#define FF_IO_ALLOWED() ker_fstack_runtime_application_io_allowed()
#define FF_POLL_KEVENT() ker_fstack_runtime_polls_kevent()
#else
#define FF_TRACE(fd, result) ((void)0)
#define FF_IO_ALLOWED() 1
#define FF_POLL_KEVENT() false
#define FF_PROGRESS() ((void)0)
#endif

#define FF_DISPATCH_RETURN(type, expression) do { \
    if (!FF_IO_ALLOWED()) return (type)-1; \
    if (ker_sb_preload_ff_dispatch_begin(fd)) return (type)-1; \
    type result = (expression); \
    int saved_errno = errno; \
    FF_TRACE(fd, result); \
    ker_sb_preload_ff_dispatch_end(); \
    FF_PROGRESS(); \
    errno = saved_errno; \
    return result; \
} while (0)

int ff_socket(int domain, int type, int protocol)
{
    if (!FF_IO_ALLOWED()) return -1;
    int family = domain == AF_INET6_LINUX ? AF_INET6 : domain;
    if (family != AF_INET && family != AF_INET6) return unsupported();
    int base = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (base != SOCK_STREAM || (protocol && protocol != IPPROTO_TCP))
        return unsupported();
    int fd = ker_sb_preload_ff_owner_managed() ?
        ker_sb_preload_ff_owner_socket(family, type, protocol) :
        ker_sb_posix_socket(family, type, protocol);
    int saved_errno = errno;
    FF_TRACE(-1, fd);
    FF_PROGRESS();
    errno = saved_errno;
    return fd;
}

int ff_bind(int fd, const struct linux_sockaddr *address, socklen_t length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_bind(fd, (const struct sockaddr *)address, length)); }

int ff_connect(int fd, const struct linux_sockaddr *address, socklen_t length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_connect(fd, (const struct sockaddr *)address, length)); }

int ff_listen(int fd, int backlog)
{
    if (!FF_IO_ALLOWED()) return -1;
    if (ker_sb_preload_ff_dispatch_begin(fd)) return -1;
    int result = ker_sb_posix_listen(fd, backlog);
    int saved_errno = errno;
    if (!result) ker_sb_preload_trace_initial_listener(fd);
    FF_TRACE(fd, result);
    ker_sb_preload_ff_dispatch_end();
    FF_PROGRESS();
    errno = saved_errno;
    return result;
}

int ff_accept4(int fd, struct linux_sockaddr *address, socklen_t *length, int flags)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_accept4(fd, (struct sockaddr *)address, length, flags)); }

int ff_accept(int fd, struct linux_sockaddr *address, socklen_t *length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_accept4(fd, (struct sockaddr *)address, length, 0)); }

int ff_close(int fd)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_close(fd)); }

int ff_socket_drain_count(void)
{
    if (!FF_IO_ALLOWED()) return -1;
    FF_TRACE(-1, 0);
    int count = ker_sb_preload_socket_drain_count();
    if (count < 0) {
        char message[128];
        int length = snprintf(message, sizeof(message),
            "ker fstack socket census failed: errno=%d\n", errno);
        if (length > 0)
            (void)syscall(SYS_write, STDERR_FILENO, message,
                (size_t)length < sizeof(message) ? (size_t)length : sizeof(message));
        abort();
    }
    FF_PROGRESS();
    FF_TRACE(0, count);
    return count;
}

int ff_socket_snd_pending(void)
{
    if (!FF_IO_ALLOWED()) return -1;
    FF_TRACE(-1, 0);
    struct ker_socket_member_payload_snapshot snapshot = {0};
    if (ker_sb_preload_ff_owner_payload(&snapshot) < 0) {
        char message[160];
        int length = snprintf(message, sizeof(message),
            "ker fstack payload snapshot failed: errno=%d\n", errno);
        if (length > 0)
            (void)syscall(SYS_write, STDERR_FILENO, message,
                (size_t)length < sizeof(message) ? (size_t)length : sizeof(message));
        abort();
    }
    FF_PROGRESS();
    FF_TRACE(0, snapshot.payload_bytes > INT_MAX ? INT_MAX : (int)snapshot.payload_bytes);
    return snapshot.payload_bytes > INT_MAX ? INT_MAX : (int)snapshot.payload_bytes;
}

int ff_shutdown(int fd, int how)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_shutdown(fd, how)); }

int ff_getsockname(int fd, struct linux_sockaddr *address, socklen_t *length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_getsockname(fd, (struct sockaddr *)address, length)); }

int ff_getpeername(int fd, struct linux_sockaddr *address, socklen_t *length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_getpeername(fd, (struct sockaddr *)address, length)); }

int ff_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_setsockopt(fd, level, option, value, length)); }

int ff_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_getsockopt(fd, level, option, value, length)); }

ssize_t ff_read(int fd, void *buffer, size_t length)
{ FF_DISPATCH_RETURN(ssize_t, ker_sb_posix_read(fd, buffer, length)); }

ssize_t ff_write(int fd, const void *buffer, size_t length)
{ FF_DISPATCH_RETURN(ssize_t, ker_sb_posix_write(fd, buffer, length)); }

ssize_t ff_readv(int fd, const struct iovec *vectors, int count)
{ FF_DISPATCH_RETURN(ssize_t, ker_sb_posix_readv(fd, vectors, count)); }

ssize_t ff_writev(int fd, const struct iovec *vectors, int count)
{ FF_DISPATCH_RETURN(ssize_t, ker_sb_posix_writev(fd, vectors, count)); }

ssize_t ff_send(int fd, const void *buffer, size_t length, int flags)
{ FF_DISPATCH_RETURN(ssize_t, ker_sb_posix_send(fd, buffer, length, flags)); }

ssize_t ff_recv(int fd, void *buffer, size_t length, int flags)
{ FF_DISPATCH_RETURN(ssize_t, ker_sb_posix_recv(fd, buffer, length, flags)); }

int ff_fcntl(int fd, int command, ...)
{
    switch (command) {
    case F_GETFD: case F_GETFL:
        FF_DISPATCH_RETURN(int, ker_sb_posix_fcntl(fd, command));
    case F_SETFD: case F_SETFL: case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
    case F_DUPFD_CLOEXEC:
#endif
    {
        va_list arguments;
        va_start(arguments, command);
        int argument = va_arg(arguments, int);
        va_end(arguments);
        FF_DISPATCH_RETURN(int, ker_sb_posix_fcntl(fd, command, (unsigned long)argument));
    }
    default: return unsupported();
    }
}

int ff_ioctl(int fd, unsigned long request, ...)
{
    if (request != FIONBIO && request != FIONREAD) return unsupported();
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    FF_DISPATCH_RETURN(int, ker_sb_posix_ioctl(fd, request, argument));
}

int ff_dup(int fd)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_fcntl(fd, F_DUPFD, (unsigned long)0)); }

/* The selected C1 bridge does not implement ancillary/datagram I/O, poll/select,
 * kqueue, or `ff_dup2`. No descriptor is silently reinterpreted. */
ssize_t ff_sendto(int fd, const void *buffer, size_t length, int flags,
    const struct linux_sockaddr *address, socklen_t address_length)
{ (void)fd; (void)buffer; (void)length; (void)flags; (void)address; (void)address_length; return unsupported(); }

ssize_t ff_recvfrom(int fd, void *buffer, size_t length, int flags,
    struct linux_sockaddr *address, socklen_t *address_length)
{ (void)fd; (void)buffer; (void)length; (void)flags; (void)address; (void)address_length; return unsupported(); }

ssize_t ff_sendmsg(int fd, const struct msghdr *message, int flags)
{ (void)fd; (void)message; (void)flags; return unsupported(); }

ssize_t ff_recvmsg(int fd, struct msghdr *message, int flags)
{ (void)fd; (void)message; (void)flags; return unsupported(); }

int ff_select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{ (void)nfds; (void)readfds; (void)writefds; (void)exceptfds; (void)timeout; return unsupported(); }

int ff_poll(struct pollfd fds[], nfds_t count, int timeout)
{ (void)fds; (void)count; (void)timeout; return unsupported(); }

#define KER_FF_KQUEUE_WATCH_MAX 1024
#define KER_FF_KQUEUE_USER_MAX 1
#define KER_FF_KQUEUE_CHANGE_MAX 1024
#define KER_FF_KQUEUE_WAIT_SLICE_MS 1

struct ff_kqueue_watch {
    int fd;
    int capability_fd;
    uint64_t socket_cookie;
    uint32_t generation;
    short filter;
    unsigned short flags;
    bool present;
    bool enabled;
    void *udata;
};

struct ff_kqueue_user {
    int event_fd;
    uint32_t generation;
    uintptr_t ident;
    unsigned short flags;
    unsigned int fflags;
    int64_t data;
    void *udata;
    bool present;
    bool enabled;
};

struct ff_kqueue_context {
    pthread_mutex_t lock;
    pthread_mutex_t wait_lock;
    int read_epfd;
    int write_epfd;
    int user_epfd;
    uint32_t next_generation;
    unsigned int next_wait_queue;
    struct ff_kqueue_watch watches[KER_FF_KQUEUE_WATCH_MAX];
    struct ff_kqueue_user users[KER_FF_KQUEUE_USER_MAX];
    bool pending_ready;
    int pending_queue;
    struct epoll_event pending_event;
    int pending_error;
};

static struct ff_kqueue_watch *ff_kqueue_watch_find(
    struct ff_kqueue_context *context, int fd, short filter)
{
    for (size_t i = 0; i < KER_FF_KQUEUE_WATCH_MAX; ++i) {
        struct ff_kqueue_watch *watch = &context->watches[i];
        if (watch->present && watch->fd == fd && watch->filter == filter)
            return watch;
    }
    return NULL;
}

static struct ff_kqueue_watch *ff_kqueue_watch_slot(
    struct ff_kqueue_context *context)
{
    for (size_t i = 0; i < KER_FF_KQUEUE_WATCH_MAX; ++i)
        if (!context->watches[i].present) return &context->watches[i];
    errno = ENOSPC;
    return NULL;
}

static uint32_t ff_kqueue_next_generation(struct ff_kqueue_context *context)
{
    if (++context->next_generation == 0) ++context->next_generation;
    return context->next_generation;
}

static uint64_t ff_kqueue_token(size_t index, uint32_t generation)
{ return ((uint64_t)generation << 32) | (uint32_t)index; }

static bool ff_kqueue_token_decode(struct ff_kqueue_context *context,
    uint64_t token, struct ff_kqueue_watch **watch)
{
    size_t index = (uint32_t)token;
    uint32_t generation = (uint32_t)(token >> 32);
    if (index >= KER_FF_KQUEUE_WATCH_MAX || !generation) return false;
    struct ff_kqueue_watch *candidate = &context->watches[index];
    if (!candidate->present || candidate->generation != generation) return false;
    *watch = candidate;
    return true;
}

static int ff_kqueue_socket_cookie(int fd, uint64_t *cookie)
{
#ifdef SO_COOKIE
    socklen_t length = sizeof(*cookie);
    if (ker_sb_posix_getsockopt(fd, SOL_SOCKET, SO_COOKIE, cookie, &length) < 0)
        return -1;
    if (length != sizeof(*cookie)) { errno = EPROTO; return -1; }
    return 0;
#else
    (void)fd; (void)cookie;
    errno = EOPNOTSUPP;
    return -1;
#endif
}

static int ff_kqueue_epoll_for_filter(struct ff_kqueue_context *context,
    short filter)
{ return filter == EVFILT_READ ? context->read_epfd : context->write_epfd; }

static uint32_t ff_kqueue_epoll_events(const struct ff_kqueue_watch *watch)
{
    uint32_t events = watch->filter == EVFILT_READ ? EPOLLIN : EPOLLOUT;
    if (watch->flags & EV_CLEAR) events |= EPOLLET;
    if (watch->flags & EV_ONESHOT) events |= EPOLLONESHOT;
    return events;
}

static int ff_kqueue_watch_ctl_locked(struct ff_kqueue_context *context,
    struct ff_kqueue_watch *watch, bool add)
{
    struct epoll_event event = {0};
    event.events = ff_kqueue_epoll_events(watch);
    size_t index = (size_t)(watch - context->watches);
    event.data.u64 = ff_kqueue_token(index, watch->generation);
    int operation = add ? EPOLL_CTL_ADD : EPOLL_CTL_DEL;
    int broker_epfd = -1;
    if (ker_sb_preload_epoll_fd_locked(ff_kqueue_epoll_for_filter(context,
            watch->filter), &broker_epfd) != 1) {
        errno = EBADF;
        return -1;
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    return client ? ker_socket_client_epoll_ctl(client, broker_epfd,
        operation, watch->capability_fd, add ? &event : NULL) : -1;
}

static int ff_kqueue_user_epoll_ctl_locked(struct ff_kqueue_context *context,
    int operation, int event_fd, struct epoll_event *event)
{
    /* This eventfd belongs to this queue and is deliberately a private FD.
     * Attach it only to the host half of the composite user epoll; the generic
     * epoll adapter correctly rejects private descriptors and broker routing
     * has no authority to observe this host-local wakeup source. */
    return (int)syscall(SYS_epoll_ctl, context->user_epfd, operation,
        event_fd, event);
}

static int ff_kqueue_validate_change(const struct kevent *change)
{
    const unsigned short action_mask = EV_ADD | EV_DELETE | EV_ENABLE | EV_DISABLE;
    const unsigned short mode_mask = EV_ONESHOT | EV_CLEAR;
    unsigned short allowed = action_mask | mode_mask | EV_ERROR | EV_FLAG1;
    if ((change->filter == EVFILT_USER) && change->fflags == NOTE_TRIGGER &&
        change->flags == 0)
        return change->ident == 0 ? 0 : (errno = EOPNOTSUPP, -1);
    if ((change->flags & (unsigned short)~allowed) != 0 ||
        ((change->flags & EV_ADD) && (change->flags & EV_DELETE)) ||
        ((change->flags & EV_ENABLE) && (change->flags & EV_DISABLE)) ||
        (change->flags & (EV_ADD | EV_DELETE | EV_ENABLE | EV_DISABLE)) == 0) {
        errno = EINVAL;
        return -1;
    }
    if (change->filter == EVFILT_READ || change->filter == EVFILT_WRITE) {
        if (change->ident > INT_MAX || change->fflags ||
            (change->flags & EV_FLAG1)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return 0;
    }
    if (change->filter == EVFILT_USER) {
        if (change->ident != 0 || (change->flags & (EV_ONESHOT | EV_FLAG1)) ||
            ((change->flags & EV_ADD) && !(change->flags & EV_CLEAR))) {
            errno = EOPNOTSUPP;
            return -1;
        }
        if (change->fflags && !(change->flags == 0 &&
                change->fflags == NOTE_TRIGGER)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return 0;
    }
    errno = EOPNOTSUPP;
    return -1;
}

static int ff_kqueue_user_ctl_locked(struct ff_kqueue_context *context,
    const struct kevent *change)
{
    struct ff_kqueue_user *user = &context->users[0];
    if (change->filter == EVFILT_USER && change->fflags == NOTE_TRIGGER &&
        !(change->flags & (EV_ADD | EV_DELETE | EV_ENABLE | EV_DISABLE))) {
        if (!user->present) { errno = ENOENT; return -1; }
        user->udata = change->udata;
        uint64_t one = 1;
        if (syscall(SYS_write, user->event_fd, &one, sizeof(one)) < 0 &&
            errno != EAGAIN) return -1;
        return 0;
    }
    if (change->flags & EV_DELETE) {
        if (!user->present) { errno = ENOENT; return -1; }
        int result = ff_kqueue_user_epoll_ctl_locked(context,
            EPOLL_CTL_DEL, user->event_fd, NULL);
        if (result < 0 && errno != ENOENT) return -1;
        ker_sb_preload_untrack_private_fd_locked(user->event_fd);
        (void)syscall(SYS_close, user->event_fd);
        *user = (struct ff_kqueue_user){.event_fd = -1};
        return 0;
    }
    if (change->flags & EV_ADD) {
        bool enabled = !(change->flags & EV_DISABLE);
        if (user->present) {
            if (user->enabled && !enabled) {
                int result = ff_kqueue_user_epoll_ctl_locked(context,
                    EPOLL_CTL_DEL, user->event_fd, NULL);
                if (result < 0 && errno != ENOENT) return -1;
            } else if (!user->enabled && enabled) {
                struct epoll_event event = {.events = EPOLLIN | EPOLLET};
                event.data.u64 = ff_kqueue_token(KER_FF_KQUEUE_WATCH_MAX,
                    user->generation);
                if (ff_kqueue_user_epoll_ctl_locked(context,
                        EPOLL_CTL_ADD, user->event_fd, &event) < 0) return -1;
            }
            user->udata = change->udata;
            user->fflags = change->fflags;
            user->data = change->data;
            user->enabled = enabled;
            return 0;
        }
        int event_fd = (int)syscall(SYS_eventfd2, 0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (event_fd < 0) return -1;
        if (ker_sb_preload_track_private_fd_locked(event_fd)) {
            int error = errno; (void)syscall(SYS_close, event_fd); errno = error;
            return -1;
        }
        struct epoll_event event = {.events = EPOLLIN | EPOLLET};
        uint32_t generation = ff_kqueue_next_generation(context);
        event.data.u64 = ff_kqueue_token(KER_FF_KQUEUE_WATCH_MAX, generation);
        if (enabled && ff_kqueue_user_epoll_ctl_locked(context,
                EPOLL_CTL_ADD, event_fd, &event) < 0) {
            int error = errno;
            ker_sb_preload_untrack_private_fd_locked(event_fd);
            (void)syscall(SYS_close, event_fd); errno = error;
            return -1;
        }
        *user = (struct ff_kqueue_user){.event_fd = event_fd,
            .generation = generation, .ident = change->ident,
            .flags = change->flags, .fflags = change->fflags,
            .data = change->data, .udata = change->udata,
            .present = true, .enabled = enabled};
        return 0;
    }
    if (!user->present) { errno = ENOENT; return -1; }
    if (change->flags & EV_DISABLE) {
        int result = ff_kqueue_user_epoll_ctl_locked(context,
            EPOLL_CTL_DEL, user->event_fd, NULL);
        if (result < 0 && errno != ENOENT) return -1;
        user->enabled = false;
    } else if (change->flags & EV_ENABLE) {
        if (!user->enabled) {
            struct epoll_event event = {.events = EPOLLIN | EPOLLET};
            event.data.u64 = ff_kqueue_token(KER_FF_KQUEUE_WATCH_MAX,
                user->generation);
            if (ff_kqueue_user_epoll_ctl_locked(context,
                    EPOLL_CTL_ADD, user->event_fd, &event) < 0) return -1;
            user->enabled = true;
        }
    }
    (void)change;
    return 0;
}

static int ff_kqueue_apply_change_locked(struct ff_kqueue_context *context,
    const struct kevent *change, uint64_t cookie, int capability_fd)
{
    if (change->filter == EVFILT_USER)
        return ff_kqueue_user_ctl_locked(context, change);
    int fd = (int)change->ident;
    struct ff_kqueue_watch *watch = ff_kqueue_watch_find(context, fd,
        change->filter);
    if (change->flags & EV_DELETE) {
        if (!watch) { errno = ENOENT; return -1; }
        if (watch->enabled && ff_kqueue_watch_ctl_locked(context, watch, false) < 0 &&
            errno != ENOENT) return -1;
        *watch = (struct ff_kqueue_watch){0};
        return 0;
    }
    if (change->flags & EV_ADD) {
        if (!watch) {
            watch = ff_kqueue_watch_slot(context);
            if (!watch) return -1;
            *watch = (struct ff_kqueue_watch){.fd = fd,
                .capability_fd = capability_fd,
                .generation = ff_kqueue_next_generation(context),
                .filter = change->filter, .present = true};
        } else if (watch->socket_cookie != cookie) {
            if (watch->enabled && ff_kqueue_watch_ctl_locked(context, watch,
                    false) < 0 && errno != ENOENT) return -1;
        } else if (watch->enabled && ff_kqueue_watch_ctl_locked(context,
                watch, false) < 0 && errno != ENOENT) return -1;
        /* ADD is also MOD in kqueue. Rotate the token on every replacement so
         * a queued readiness record cannot carry the old flags/udata forward. */
        watch->generation = ff_kqueue_next_generation(context);
        watch->socket_cookie = cookie;
        watch->capability_fd = capability_fd;
        watch->flags = change->flags & (EV_ONESHOT | EV_CLEAR);
        watch->udata = change->udata;
        watch->enabled = !(change->flags & EV_DISABLE);
        if (watch->enabled) {
            if (ff_kqueue_watch_ctl_locked(context, watch, true) < 0) {
                watch->enabled = false;
                return -1;
            }
        }
        return 0;
    }
    if (!watch) { errno = ENOENT; return -1; }
    if (change->flags & EV_DISABLE) {
        if (watch->enabled && ff_kqueue_watch_ctl_locked(context, watch,
                false) < 0 && errno != ENOENT) return -1;
        watch->enabled = false;
    } else if (change->flags & EV_ENABLE) {
        if (cookie != watch->socket_cookie) { errno = ESTALE; return -1; }
        if (watch->enabled) return 0;
        watch->capability_fd = capability_fd;
        watch->generation = ff_kqueue_next_generation(context);
        watch->enabled = true;
        if (ff_kqueue_watch_ctl_locked(context, watch, true) < 0) {
            watch->enabled = false;
            return -1;
        }
    }
    return 0;
}

static int ff_kqueue_fd_closed(void *opaque, int fd, int capability_fd)
{
    struct ff_kqueue_context *context = opaque;
    pthread_mutex_lock(&context->lock);
    for (size_t i = 0; i < KER_FF_KQUEUE_WATCH_MAX; ++i) {
        struct ff_kqueue_watch *watch = &context->watches[i];
        if (!watch->present || watch->fd != fd) continue;
        if (watch->enabled) {
            int epfd = ff_kqueue_epoll_for_filter(context, watch->filter);
            int broker_epfd = -1;
            if (ker_sb_preload_epoll_fd_locked(epfd, &broker_epfd) == 1) {
                struct ker_socket_client *client = ker_sb_preload_client_locked();
                if (client && ker_socket_client_epoll_ctl(client, broker_epfd,
                        EPOLL_CTL_DEL, capability_fd, NULL) < 0 && errno != ENOENT) {
                    /* The socket close still owns final kernel cleanup. */
                }
            }
        }
        *watch = (struct ff_kqueue_watch){0};
    }
    pthread_mutex_unlock(&context->lock);
    return 0;
}

static void ff_kqueue_context_destroy(void *opaque)
{
    struct ff_kqueue_context *context = opaque;
    if (!context) return;
    for (size_t i = 0; i < KER_FF_KQUEUE_USER_MAX; ++i)
        if (context->users[i].event_fd >= 0) {
            ker_sb_preload_untrack_private_fd_locked(context->users[i].event_fd);
            (void)syscall(SYS_close, context->users[i].event_fd);
        }
    int fds[] = {context->read_epfd, context->write_epfd, context->user_epfd};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); ++i) {
        if (fds[i] < 0) continue;
        ker_sb_preload_untrack_private_fd_locked(fds[i]);
        (void)ker_sb_preload_close_locked(fds[i]);
    }
    free(context);
}

static int ff_kqueue_epoll_create_locked(void)
{ return ker_sb_preload_epoll_create_locked(EPOLL_CLOEXEC); }

int ff_kqueue(void)
{
    if (!FF_IO_ALLOWED()) { errno = EPERM; return -1; }
    struct ff_kqueue_context *context = calloc(1, sizeof(*context));
    if (!context) return -1;
    context->read_epfd = context->write_epfd = context->user_epfd = -1;
    for (size_t i = 0; i < KER_FF_KQUEUE_USER_MAX; ++i)
        context->users[i].event_fd = -1;
    int mutex_error = pthread_mutex_init(&context->lock, NULL);
    if (mutex_error) { free(context); errno = mutex_error; return -1; }
    mutex_error = pthread_mutex_init(&context->wait_lock, NULL);
    if (mutex_error) {
        pthread_mutex_destroy(&context->lock);
        free(context);
        errno = mutex_error;
        return -1;
    }

    ker_sb_preload_lock();
    int queue = ff_kqueue_epoll_create_locked();
    if (queue < 0) goto fail;
    context->read_epfd = ker_sb_preload_duplicate_epoll_locked(queue, 0, true);
    if (context->read_epfd < 0 ||
        ker_sb_preload_track_private_fd_locked(context->read_epfd)) goto fail;
    context->write_epfd = ff_kqueue_epoll_create_locked();
    if (context->write_epfd < 0 ||
        ker_sb_preload_track_private_fd_locked(context->write_epfd)) goto fail;
    context->user_epfd = ff_kqueue_epoll_create_locked();
    if (context->user_epfd < 0 ||
        ker_sb_preload_track_private_fd_locked(context->user_epfd)) goto fail;
    if (ker_sb_preload_epoll_context_install_locked(queue, context,
            ff_kqueue_fd_closed, ff_kqueue_context_destroy) < 0) goto fail;
    ker_sb_preload_unlock();
    FF_TRACE(queue, 0);
    FF_PROGRESS();
    return queue;

fail:
    {
        int error = errno;
        if (context->read_epfd >= 0) {
            ker_sb_preload_untrack_private_fd_locked(context->read_epfd);
            (void)ker_sb_preload_close_locked(context->read_epfd);
        }
        if (context->write_epfd >= 0) {
            ker_sb_preload_untrack_private_fd_locked(context->write_epfd);
            (void)ker_sb_preload_close_locked(context->write_epfd);
        }
        if (context->user_epfd >= 0) {
            ker_sb_preload_untrack_private_fd_locked(context->user_epfd);
            (void)ker_sb_preload_close_locked(context->user_epfd);
        }
        if (queue >= 0) (void)ker_sb_preload_close_locked(queue);
        ker_sb_preload_unlock();
        pthread_mutex_destroy(&context->wait_lock);
        pthread_mutex_destroy(&context->lock);
        free(context);
        errno = error;
        return -1;
    }
}

static int ff_kqueue_timeout_ms(const struct timespec *timeout,
    uint64_t *deadline)
{
    *deadline = UINT64_MAX;
    if (!timeout) return 0;
    if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
        timeout->tv_nsec >= 1000000000L ||
        (uint64_t)timeout->tv_sec > (UINT64_MAX - (uint64_t)timeout->tv_nsec) /
            UINT64_C(1000000000)) {
        errno = EINVAL;
        return -1;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    uint64_t now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec;
    uint64_t duration = (uint64_t)timeout->tv_sec * UINT64_C(1000000000) +
        (uint64_t)timeout->tv_nsec;
    if (UINT64_MAX - now_ns < duration) { errno = EOVERFLOW; return -1; }
    *deadline = now_ns + duration;
    return 0;
}

static int ff_kqueue_wait_slice(uint64_t deadline, int infinite)
{
    if (infinite) return KER_FF_KQUEUE_WAIT_SLICE_MS;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    uint64_t now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec;
    if (now_ns >= deadline) return 0;
    uint64_t remaining = deadline - now_ns;
    uint64_t milliseconds = (remaining + UINT64_C(999999)) / UINT64_C(1000000);
    return milliseconds > KER_FF_KQUEUE_WAIT_SLICE_MS ?
        KER_FF_KQUEUE_WAIT_SLICE_MS : (int)milliseconds;
}

static int ff_kqueue_retry_pause(uint64_t deadline, int infinite)
{
    int milliseconds = ff_kqueue_wait_slice(deadline, infinite);
    if (milliseconds <= 0) return milliseconds;
    struct timespec pause = {.tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000L};
    return nanosleep(&pause, NULL) < 0 ? -1 : 1;
}

static int ff_kqueue_emit_watch(struct ff_kqueue_context *context,
    const struct epoll_event *ready, struct kevent *output)
{
    struct ff_kqueue_watch snapshot_watch;
    size_t index = (uint32_t)ready->data.u64;
    pthread_mutex_lock(&context->lock);
    struct ff_kqueue_watch *watch = NULL;
    bool valid = ff_kqueue_token_decode(context, ready->data.u64, &watch);
    if (valid) snapshot_watch = *watch;
    pthread_mutex_unlock(&context->lock);
    if (!valid) return 0;

    uint64_t cookie = 0;
    if (ff_kqueue_socket_cookie(snapshot_watch.fd, &cookie) < 0 ||
        cookie != snapshot_watch.socket_cookie) return 0;
    struct ker_socket_event_snapshot state = {0};
    if (ker_sb_preload_ff_event_snapshot(snapshot_watch.fd, &state) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 2;
        return errno == EBADF || errno == ESTALE ? 0 : -1;
    }
    if (state.version != KER_SOCKET_EVENT_SNAPSHOT_VERSION ||
        state.size != sizeof(state)) { errno = EPROTO; return -1; }
    if (state.flags & KER_SOCKET_EVENT_ERROR_QUEUE_ONLY) {
        errno = EOPNOTSUPP;
        return -1;
    }
    bool read_filter = snapshot_watch.filter == EVFILT_READ;
    bool read_shutdown = (state.flags & KER_SOCKET_EVENT_READ_SHUTDOWN) != 0;
    bool write_shutdown = (state.flags & KER_SOCKET_EVENT_WRITE_SHUTDOWN) != 0;
    bool listener_error = read_filter &&
        (state.flags & KER_SOCKET_EVENT_LISTENER) &&
        (state.events & EPOLLERR);
    bool filter_eof = read_filter ? (read_shutdown || listener_error) :
        write_shutdown;
    uint32_t readiness = state.events;
    if (read_filter) {
        readiness &= EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    } else {
        readiness &= EPOLLOUT | EPOLLERR | EPOLLHUP;
    }
    bool ready_filter = readiness != 0;
    if (!filter_eof && !ready_filter) return 0;
    if (snapshot_watch.filter == EVFILT_READ &&
        !(state.validity & KER_SOCKET_EVENT_READ_AVAILABLE_VALID)) {
        errno = EPROTO; return -1;
    }
    if (snapshot_watch.filter == EVFILT_WRITE &&
        !(state.validity & KER_SOCKET_EVENT_WRITE_ACCOUNTING_VALID)) {
        errno = EPROTO; return -1;
    }
    struct kevent result_event = {
        .ident = (uintptr_t)snapshot_watch.fd,
        .filter = snapshot_watch.filter,
        .flags = filter_eof ? EV_EOF : 0,
        .fflags = filter_eof ? (unsigned int)state.pending_hard_error : 0,
        .data = snapshot_watch.filter == EVFILT_READ ?
            state.read_available : state.write_accounting_space,
        .udata = snapshot_watch.udata
    };
    if (snapshot_watch.flags & EV_ONESHOT) {
        /* Keep the global lock before the per-queue lock, the same order as
         * close/reuse notification. */
        ker_sb_preload_lock();
        pthread_mutex_lock(&context->lock);
        watch = NULL;
        valid = ff_kqueue_token_decode(context, ready->data.u64, &watch) &&
            watch->fd == snapshot_watch.fd &&
            watch->capability_fd == snapshot_watch.capability_fd &&
            watch->socket_cookie == snapshot_watch.socket_cookie &&
            watch->filter == snapshot_watch.filter &&
            watch->flags == snapshot_watch.flags &&
            watch->udata == snapshot_watch.udata && watch->enabled;
        if (!valid) {
            pthread_mutex_unlock(&context->lock);
            ker_sb_preload_unlock();
            return 0;
        }
        int status = ff_kqueue_watch_ctl_locked(context, watch, false);
        int saved_errno = errno;
        *watch = (struct ff_kqueue_watch){0};
        pthread_mutex_unlock(&context->lock);
        ker_sb_preload_unlock();
        if (status < 0 && saved_errno != ENOENT) { errno = saved_errno; return -1; }
    } else {
        pthread_mutex_lock(&context->lock);
        watch = NULL;
        valid = ff_kqueue_token_decode(context, ready->data.u64, &watch) &&
            watch->fd == snapshot_watch.fd &&
            watch->capability_fd == snapshot_watch.capability_fd &&
            watch->socket_cookie == snapshot_watch.socket_cookie &&
            watch->filter == snapshot_watch.filter &&
            watch->flags == snapshot_watch.flags &&
            watch->udata == snapshot_watch.udata && watch->enabled;
        pthread_mutex_unlock(&context->lock);
        if (!valid) return 0;
    }
    *output = result_event;
    (void)index;
    return 1;
}

static int ff_kqueue_emit_user(struct ff_kqueue_context *context,
    const struct epoll_event *ready, struct kevent *output)
{
    struct ff_kqueue_user user;
    pthread_mutex_lock(&context->lock);
    user = context->users[0];
    if (!user.present || !user.enabled ||
        (uint32_t)ready->data.u64 != KER_FF_KQUEUE_WATCH_MAX || user.generation !=
            (uint32_t)(ready->data.u64 >> 32)) {
        pthread_mutex_unlock(&context->lock);
        return 0;
    }
    uint64_t value;
    if (syscall(SYS_read, user.event_fd, &value, sizeof(value)) < 0) {
        if (errno == EAGAIN) { pthread_mutex_unlock(&context->lock); return 0; }
        pthread_mutex_unlock(&context->lock);
        return -1;
    }
    *output = (struct kevent){.ident = user.ident, .filter = EVFILT_USER,
        .flags = EV_CLEAR, .fflags = NOTE_FFNOP | user.fflags,
        .data = user.data, .udata = user.udata};
    pthread_mutex_unlock(&context->lock);
    return 1;
}

static int ff_kqueue_process_ready(struct ff_kqueue_context *context,
    int queue_index, const struct epoll_event *ready, struct kevent *output)
{
    return queue_index == 2 ? ff_kqueue_emit_user(context, ready, output) :
        ff_kqueue_emit_watch(context, ready, output);
}

static int ff_kqueue_collect(struct ff_kqueue_context *context,
    struct kevent *events, int maximum, int initial_queue,
    const struct epoll_event *initial_event)
{
    int queues[3] = {context->read_epfd, context->write_epfd,
        context->user_epfd};
    unsigned int start;
    pthread_mutex_lock(&context->lock);
    start = context->next_wait_queue++ % 3;
    pthread_mutex_unlock(&context->lock);
    int count = 0;
    struct epoll_event pending;
    int pending_queue = -1;
    pthread_mutex_lock(&context->lock);
    int deferred_error = context->pending_error;
    context->pending_error = 0;
    if (!deferred_error && context->pending_ready) {
        pending = context->pending_event;
        pending_queue = context->pending_queue;
        context->pending_ready = false;
    }
    pthread_mutex_unlock(&context->lock);
    if (deferred_error) { errno = deferred_error; return -1; }
    if (pending_queue >= 0 && pending_queue < 3) {
        int emitted = ff_kqueue_process_ready(context, pending_queue, &pending,
            &events[count]);
        if (emitted == 2) {
            pthread_mutex_lock(&context->lock);
            context->pending_event = pending;
            context->pending_queue = pending_queue;
            context->pending_ready = true;
            pthread_mutex_unlock(&context->lock);
            errno = EAGAIN;
            return count ? count : -2;
        }
        if (emitted < 0) {
            int error = errno;
            if (count) {
                pthread_mutex_lock(&context->lock);
                context->pending_error = error;
                pthread_mutex_unlock(&context->lock);
                return count;
            }
            errno = error;
            return -1;
        }
        count += emitted;
        if (count >= maximum) return count;
    }
    if (initial_event && initial_queue >= 0 && initial_queue < 3) {
        int emitted = ff_kqueue_process_ready(context, initial_queue,
            initial_event, &events[count]);
        if (emitted == 2) {
            pthread_mutex_lock(&context->lock);
            context->pending_event = *initial_event;
            context->pending_queue = initial_queue;
            context->pending_ready = true;
            pthread_mutex_unlock(&context->lock);
            errno = EAGAIN;
            return count ? count : -2;
        }
        if (emitted < 0) {
            int error = errno;
            if (count) {
                pthread_mutex_lock(&context->lock);
                context->pending_error = error;
                pthread_mutex_unlock(&context->lock);
                return count;
            }
            errno = error;
            return -1;
        }
        count += emitted;
        if (count >= maximum) return count;
    }
    for (unsigned int n = 0; n < 3 && count < maximum; ++n) {
        int queue_index = (int)((start + n) % 3);
        struct epoll_event ready;
        int got = ker_sb_posix_epoll_wait(queues[queue_index], &ready, 1, 0);
        if (got < 0) return -1;
        if (!got) continue;
        if (initial_event && queue_index == initial_queue &&
            ready.data.u64 == initial_event->data.u64) continue;
        int emitted = ff_kqueue_process_ready(context, queue_index, &ready,
            &events[count]);
        if (emitted == 2) {
            pthread_mutex_lock(&context->lock);
            context->pending_event = ready;
            context->pending_queue = queue_index;
            context->pending_ready = true;
            pthread_mutex_unlock(&context->lock);
            errno = EAGAIN;
            return count ? count : -2;
        }
        if (emitted < 0) {
            int error = errno;
            if (count) {
                pthread_mutex_lock(&context->lock);
                context->pending_error = error;
                pthread_mutex_unlock(&context->lock);
                return count;
            }
            errno = error;
            return -1;
        }
        count += emitted;
    }
    return count;
}

int ff_kevent(int queue, const struct kevent *changes, int change_count,
    struct kevent *events, int event_count, const struct timespec *timeout)
{
    if (!FF_IO_ALLOWED()) { errno = EPERM; return -1; }
    if (change_count < 0 || change_count > KER_FF_KQUEUE_CHANGE_MAX ||
        event_count < 0 || event_count > KER_FF_KQUEUE_WATCH_MAX ||
        (size_t)change_count > SIZE_MAX / sizeof(struct kevent) ||
        (size_t)event_count > SIZE_MAX / sizeof(struct kevent)) {
        errno = EINVAL; return -1;
    }
    struct kevent copied_changes[KER_FF_KQUEUE_CHANGE_MAX];
    if (change_count && ker_sb_preload_usercopy_in(copied_changes, changes,
            (size_t)change_count * sizeof(*copied_changes)) < 0) return -1;
    struct timespec copied_timeout;
    if (FF_POLL_KEVENT()) {
        /* Original ff_kevent_do_each polls with a zero timeout. Its owning
         * Nginx loop must return to service reload control and heartbeats. */
        copied_timeout = (struct timespec){0};
        timeout = &copied_timeout;
    } else if (timeout && ker_sb_preload_usercopy_in(&copied_timeout, timeout,
            sizeof(copied_timeout)) < 0) {
        return -1;
    }
    struct kevent *copied_events = event_count ? calloc((size_t)event_count,
        sizeof(*copied_events)) : NULL;
    if (event_count && !copied_events) return -1;
    for (int i = 0; i < change_count; ++i)
        if (ff_kqueue_validate_change(&copied_changes[i]) < 0) {
            free(copied_events);
            return -1;
        }
    uint64_t deadline;
    if (ff_kqueue_timeout_ms(timeout ? &copied_timeout : NULL, &deadline) < 0) {
        free(copied_events);
        return -1;
    }

    struct ker_sb_preload_epoll_context_ref *reference = NULL;
    void *opaque = NULL;
    uint64_t context_generation = 0;
    if (ker_sb_preload_epoll_context_acquire(queue, &reference, &opaque,
            &context_generation) < 0) {
        free(copied_events);
        return -1;
    }
    struct ff_kqueue_context *context = opaque;
    (void)context_generation;
    bool wait_locked = false;
    if (event_count) {
        /* The source caller profile has one event-loop collector per kqueue.
         * Bound concurrent collectors instead of blocking behind an infinite
         * wait or allowing them to overwrite a retained edge. */
        int lock_error = pthread_mutex_trylock(&context->wait_lock);
        if (lock_error) {
            ker_sb_preload_epoll_context_release(reference);
            free(copied_events);
            errno = EBUSY;
            return -1;
        }
        wait_locked = true;
    }
    if (change_count) {
        uint64_t cookies[KER_FF_KQUEUE_CHANGE_MAX] = {0};
        int capabilities[KER_FF_KQUEUE_CHANGE_MAX];
        for (int i = 0; i < change_count; ++i) capabilities[i] = -1;
        ker_sb_preload_lock();
        int status = 0;
        int error = 0;
        for (int i = 0; i < change_count; ++i) {
            const struct kevent *change = &copied_changes[i];
            if ((change->filter != EVFILT_READ && change->filter != EVFILT_WRITE) ||
                !(change->flags & (EV_ADD | EV_ENABLE))) continue;
            if (ff_kqueue_socket_cookie((int)change->ident, &cookies[i]) < 0) {
                status = -1; error = errno; break;
            }
            int native = ker_sb_preload_network_fd_locked((int)change->ident,
                &capabilities[i]);
            if (native != 1) {
                status = -1; error = native < 0 ? errno : EOPNOTSUPP; break;
            }
        }
        if (status < 0) {
            ker_sb_preload_unlock();
            if (wait_locked) pthread_mutex_unlock(&context->wait_lock);
            ker_sb_preload_epoll_context_release(reference);
            free(copied_events);
            errno = error;
            return -1;
        }
        pthread_mutex_lock(&context->lock);
        status = 0;
        for (int i = 0; i < change_count; ++i) {
            if (ff_kqueue_apply_change_locked(context, &copied_changes[i],
                    cookies[i], capabilities[i]) < 0) {
                status = -1;
                break;
            }
        }
        error = errno;
        pthread_mutex_unlock(&context->lock);
        ker_sb_preload_unlock();
        if (status < 0) {
            if (wait_locked) pthread_mutex_unlock(&context->wait_lock);
            ker_sb_preload_epoll_context_release(reference);
            free(copied_events);
            errno = error;
            return -1;
        }
    }
    if (!event_count) {
        ker_sb_preload_epoll_context_release(reference);
        free(copied_events);
        FF_PROGRESS();
        return 0;
    }
    int infinite = timeout == NULL;
    int count = 0;
    for (;;) {
        count = ff_kqueue_collect(context, copied_events, event_count, -1, NULL);
        if (count == -2) {
            int paused = ff_kqueue_retry_pause(deadline, infinite);
            if (paused < 0) { count = -1; break; }
            if (!paused) { count = 0; break; }
            continue;
        }
        if (count < 0 || count > 0) break;
        int slice = ff_kqueue_wait_slice(deadline, infinite);
        if (slice < 0) { count = -1; break; }
        if (slice == 0) { count = 0; break; }
        int queues[3] = {context->read_epfd, context->write_epfd,
            context->user_epfd};
        pthread_mutex_lock(&context->lock);
        unsigned int wait_index = context->next_wait_queue++ % 3;
        pthread_mutex_unlock(&context->lock);
        struct epoll_event waited;
        int got = ker_sb_posix_epoll_wait(queues[wait_index], &waited, 1,
            slice);
        if (got < 0) { count = -1; break; }
        if (got) {
            count = ff_kqueue_collect(context, copied_events, event_count,
                (int)wait_index, &waited);
            if (count == -2) {
                int paused = ff_kqueue_retry_pause(deadline, infinite);
                if (paused < 0) { count = -1; break; }
                if (!paused) { count = 0; break; }
                continue;
            }
            if (count < 0 || count > 0) break;
        }
    }
    int error = errno;
    if (wait_locked) pthread_mutex_unlock(&context->wait_lock);
    ker_sb_preload_epoll_context_release(reference);
    /* A faulting output buffer can follow readiness consumption (including
     * one-shot removal); this adapter does not promise event retention. */
    if (count > 0 && ker_sb_preload_usercopy_out(events, copied_events,
            (size_t)count * sizeof(*copied_events)) < 0) {
        error = errno;
        count = -1;
    }
    free(copied_events);
    FF_PROGRESS();
    if (count < 0) errno = error;
    return count;
}

int ff_dup2(int old_fd, int new_fd)
{ (void)old_fd; (void)new_fd; return unsupported(); }

#undef FF_DISPATCH_RETURN
#undef FF_POLL_KEVENT
