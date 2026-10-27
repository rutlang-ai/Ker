#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <lkl.h>

_Static_assert(sizeof(struct pollfd) == sizeof(struct lkl_pollfd), "native poll ABI");
_Static_assert(sizeof(struct epoll_event) == sizeof(struct lkl_epoll_event), "native epoll ABI");
_Static_assert(offsetof(struct epoll_event, data) == offsetof(struct lkl_epoll_event, data), "epoll data ABI");

static int64_t now_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}
/* Saturate very large timeouts without signed arithmetic overflow. */
static int64_t deadline_ns(int64_t duration)
{
    int64_t now = now_ns();
    return duration > INT64_MAX - now ? INT64_MAX : now + duration;
}
static int duration_ns(const struct timespec *value, int64_t *result)
{
    if (!value) { *result = -1; return 0; }
    if (value->tv_sec < 0 || value->tv_nsec < 0 || value->tv_nsec >= 1000000000) {
        errno = EINVAL; return -1;
    }
    *result = value->tv_sec > (INT64_MAX - value->tv_nsec) / 1000000000 ?
        INT64_MAX : (int64_t)value->tv_sec * 1000000000 + value->tv_nsec;
    return 0;
}
static int host_poll(struct pollfd *fds, nfds_t count, int64_t timeout, const sigset_t *mask)
{
    struct timespec value = {.tv_sec = timeout < 0 ? 0 : timeout / INT64_C(1000000000),
        .tv_nsec = timeout < 0 ? 0 : timeout % INT64_C(1000000000)};
    return syscall(SYS_ppoll, fds, count, timeout < 0 ? NULL : &value, mask, _NSIG / 8);
}
static int poll_ns(struct pollfd *fds, nfds_t count, int64_t timeout, const sigset_t *mask)
{
    if (count > KER_FD_LIMIT) { errno = EINVAL; return -1; }
    if (count && !fds) { errno = EFAULT; return -1; }
    struct ker_fd **pinned = calloc(count ? count : 1, sizeof(*pinned));
    int *host_snapshot = malloc((count ? count : 1) * sizeof(*host_snapshot));
    struct pollfd *host = calloc(count ? count : 1, sizeof(*host));
    struct lkl_pollfd *native = calloc(count ? count : 1, sizeof(*native));
    if (!pinned || !host_snapshot || !host || !native) {
        free(pinned); free(host_snapshot); free(host); free(native); errno = ENOMEM; return -1;
    }
    bool has_native = false;
    for (nfds_t i = 0; i < count; ++i) {
        host_snapshot[i] = -1;
        pinned[i] = ker_fd_get(fds[i].fd);
        host[i] = fds[i];
        native[i].fd = -1;
        if (pinned[i]) {
            has_native = true;
            native[i].fd = pinned[i]->native;
            native[i].events = fds[i].events;
            host[i].fd = -1;
            if (pinned[i]->kind == KER_FD_EPOLL) host_snapshot[i] = -2;
        }
    }
    int result = 0, saved = 0;
    int64_t deadline = timeout < 0 ? INT64_MAX : deadline_ns(timeout);
    for (;;) {
        long n = has_native ? lkl_sys_poll(native, count, 0) : 0;
        if (n < 0) { result = -1; saved = (int)-n; break; }
        int64_t remaining = timeout < 0 ? -1 : deadline - now_ns();
        if (remaining < 0 && timeout >= 0) remaining = 0;
        int64_t wait = !has_native ? remaining : (n || timeout == 0 ? 0 :
            (remaining < 0 || remaining > INT64_C(1000000) ? INT64_C(1000000) : remaining));
        for (nfds_t i = 0; i < count; ++i) {
            if (host_snapshot[i] == -2) {
                host_snapshot[i] = ker_fd_host_dup(pinned[i]);
                if (host_snapshot[i] < 0) { result = -1; saved = errno; break; }
                host[i].fd = host_snapshot[i];
            }
        }
        if (result < 0) {
            for (nfds_t i = 0; i < count; ++i) if (host_snapshot[i] >= 0) {
                ker_fd_host_put(host_snapshot[i]); host_snapshot[i] = -2;
            }
            break;
        }
        int h = host_poll(host, count, wait, mask);
        for (nfds_t i = 0; i < count; ++i) {
            if (host_snapshot[i] >= 0) {
                ker_fd_host_put(host_snapshot[i]); host_snapshot[i] = -2;
            }
        }
        if (h < 0) { result = -1; saved = errno; break; }
        for (nfds_t i = 0; i < count; ++i) {
            fds[i].revents = host[i].revents | native[i].revents;
            result += fds[i].revents != 0;
        }
        if (result || timeout == 0 || (timeout >= 0 && now_ns() >= deadline)) break;
    }
    for (nfds_t i = 0; i < count; ++i) ker_fd_put(pinned[i]);
    free(pinned); free(host_snapshot); free(host); free(native);
    if (result < 0) errno = saved;
    return result;
}
int poll(struct pollfd *fds, nfds_t count, int timeout)
{
    return poll_ns(fds, count, timeout < 0 ? -1 : (int64_t)timeout * 1000000, NULL);
}
int __poll(struct pollfd *, nfds_t, int) __attribute__((alias("poll")));

/* Block signals while inspecting readiness, then atomically install the caller's
 * mask in the host wait. This closes the signal/check/sleep race for mixed fds.
 * The native kernel runs on independent host threads and retains its own timers. */
static int mask_enter(const sigset_t *mask, sigset_t *old)
{
    if (!mask) return 0;
    sigset_t all;
    sigfillset(&all);
    int error = pthread_sigmask(SIG_SETMASK, &all, old);
    if (error) { errno = error; return -1; }
    return 0;
}
static int mask_leave(const sigset_t *mask, const sigset_t *old, int result)
{
    int saved = errno;
    if (mask) pthread_sigmask(SIG_SETMASK, old, NULL);
    errno = saved;
    return result;
}
int ppoll(struct pollfd *fds, nfds_t count, const struct timespec *timeout, const sigset_t *mask)
{
    int64_t duration;
    if (duration_ns(timeout, &duration)) return -1;
    sigset_t old;
    if (mask_enter(mask, &old)) return -1;
    return mask_leave(mask, &old, poll_ns(fds, count, duration, mask));
}

int epoll_create1(int flags)
{
    if (!ker_native_ready()) return syscall(SYS_epoll_create1, flags);
    long native = lkl_sys_epoll_create1(flags);
    if (native < 0) { errno = (int)-native; return -1; }
    int host = ker_fd_epoll_host_create(flags);
    if (host < 0) { int saved = errno; lkl_sys_close(native); errno = saved; return -1; }
    return ker_fd_export(native, KER_FD_EPOLL, host, flags & EPOLL_CLOEXEC, 0, -1);
}
int epoll_create(int size)
{
    if (size <= 0) { errno = EINVAL; return -1; }
    return epoll_create1(0);
}
int epoll_ctl(int fd, int operation, int target, struct epoll_event *event)
{
    struct ker_fd *ep = ker_fd_get(fd), *entry = ker_fd_get(target);
    long result;
    bool native_call = false;
    if (ep && ep->kind != KER_FD_EPOLL) { errno = EINVAL; result = -1; }
    else if (entry && (!ep || entry->kind == KER_FD_EPOLL)) {
        /* Nested mixed-domain epoll requires a union-readiness object. */
        errno = ep == entry ? EINVAL : EOPNOTSUPP;
        result = -1;
    } else if (entry) {
        native_call = true;
        /* LKL shares this address space, so reject NULL before its user-copy
         * path can dereference it. Linux does not read event for DEL. */
        result = !event && operation != EPOLL_CTL_DEL ? -EFAULT :
            lkl_sys_epoll_ctl(ep->native, operation, entry->native, (void *)event);
    } else if (ep) {
        int host = ker_fd_host_dup(ep);
        if (host < 0) result = -1;
        else { result = syscall(SYS_epoll_ctl, host, operation, target, event); ker_fd_host_put(host); }
    } else result = syscall(SYS_epoll_ctl, fd, operation, target, event);
    int saved = errno;
    ker_fd_put(entry); ker_fd_put(ep);
    if (result < 0) errno = native_call ? (int)-result : saved;
    return result < 0 ? -1 : (int)result;
}
static int host_epoll_wait_ns(int fd, struct epoll_event *events, int maximum,
    int64_t timeout, const sigset_t *mask, bool precise)
{
    if (!precise) {
        int milliseconds = timeout < 0 ? -1 : (int)(timeout / 1000000);
        return syscall(SYS_epoll_pwait, fd, events, maximum, milliseconds, mask, _NSIG / 8);
    }
#ifdef SYS_epoll_pwait2
    struct timespec value = { .tv_sec = timeout < 0 ? 0 : timeout / 1000000000,
        .tv_nsec = timeout < 0 ? 0 : timeout % 1000000000 };
    return syscall(SYS_epoll_pwait2, fd, events, maximum,
        timeout < 0 ? NULL : &value, mask, _NSIG / 8);
#else
    (void)fd; (void)events; (void)maximum; (void)timeout; (void)mask;
    errno = ENOSYS;
    return -1;
#endif
}
static int epoll_wait_ns(int fd, struct epoll_event *events, int maximum,
    int64_t timeout, const sigset_t *mask, bool precise)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) {
        return host_epoll_wait_ns(fd, events, maximum, timeout, mask, precise);
    }
    if (entry->kind != KER_FD_EPOLL || maximum <= 0 || maximum > KER_FD_LIMIT) {
        ker_fd_put(entry); errno = EINVAL; return -1;
    }
    int64_t deadline = timeout < 0 ? INT64_MAX : deadline_ns(timeout);
    bool native_first = atomic_fetch_add_explicit(&entry->turn, 1, memory_order_relaxed) & 1;
    int result = 0, saved = 0;
    for (;;) {
        for (unsigned int pass = 0; pass < 2 && result < maximum; ++pass) {
            bool native = pass == (native_first ? 0U : 1U);
            int host = native ? -1 : ker_fd_host_dup(entry);
            long count;
            if (native && !events) {
                /* LKL user copies share our address space. Probe the epoll
                 * file without delivering events: Linux faults only when it
                 * tries to copy a ready event, and must retain ET/ONESHOT
                 * readiness after that fault. Empty waits still time out. */
                struct lkl_pollfd probe = {.fd = entry->native, .events = POLLIN};
                count = lkl_sys_poll(&probe, 1, 0);
                if (count > 0) count = -EFAULT;
            } else if (native) {
                count = lkl_sys_epoll_wait(entry->native,
                    (void *)(events + result), maximum - result, 0);
            } else {
                count = host < 0 ? -1 : syscall(SYS_epoll_pwait, host,
                    events ? events + result : NULL, maximum - result, 0, NULL, 0);
            }
            if (!native && host >= 0) ker_fd_host_put(host);
            if (count < 0) { saved = native ? (int)-count : errno; result = -1; break; }
            result += (int)count;
        }
        if (result || timeout == 0 || (timeout >= 0 && now_ns() >= deadline)) break;
        int64_t remaining = timeout < 0 ? INT64_C(1000000) : deadline - now_ns();
        if (remaining > INT64_C(1000000)) remaining = INT64_C(1000000);
        if (remaining < 0) remaining = 0;
        int hostfd = ker_fd_host_dup(entry);
        if (hostfd < 0) { saved = errno; result = -1; break; }
        struct pollfd host = {hostfd, POLLIN, 0};
        int polled = host_poll(&host, 1, remaining, mask);
        saved = errno;
        ker_fd_host_put(hostfd);
        if (polled < 0) { result = -1; break; }
    }
    ker_fd_put(entry);
    if (result < 0) errno = saved;
    return result;
}
int epoll_wait(int fd, struct epoll_event *events, int maximum, int timeout)
{
    return epoll_wait_ns(fd, events, maximum, timeout < 0 ? -1 : (int64_t)timeout * 1000000, NULL, false);
}
int epoll_pwait(int fd, struct epoll_event *events, int maximum, int timeout, const sigset_t *mask)
{
    sigset_t old;
    if (mask_enter(mask, &old)) return -1;
    return mask_leave(mask, &old, epoll_wait_ns(fd, events, maximum,
        timeout < 0 ? -1 : (int64_t)timeout * 1000000, mask, false));
}
int epoll_pwait2(int fd, struct epoll_event *events, int maximum, const struct timespec *timeout, const sigset_t *mask)
{
    int64_t duration;
    if (duration_ns(timeout, &duration)) return -1;
    sigset_t old;
    if (mask_enter(mask, &old)) return -1;
    return mask_leave(mask, &old, epoll_wait_ns(fd, events, maximum, duration, mask, true));
}
static int select_ns(int maximum, fd_set *reads, fd_set *writes, fd_set *errors, int64_t duration, const sigset_t *mask)
{
    if (maximum < 0 || maximum > FD_SETSIZE) {
        errno = EINVAL; return -1;
    }
    struct pollfd fds[FD_SETSIZE];
    nfds_t count = 0;
    for (int fd = 0; fd < maximum; ++fd) {
        short events = (reads && FD_ISSET(fd, reads) ? POLLIN : 0) |
            (writes && FD_ISSET(fd, writes) ? POLLOUT : 0) |
            (errors && FD_ISSET(fd, errors) ? POLLPRI : 0);
        if (events) fds[count++] = (struct pollfd){fd, events, 0};
    }
    int ready = poll_ns(fds, count, duration, mask);
    if (ready < 0) return -1;
    if (reads) FD_ZERO(reads);
    if (writes) FD_ZERO(writes);
    if (errors) FD_ZERO(errors);
    int result = 0;
    for (nfds_t i = 0; i < count; ++i) {
        if (fds[i].revents & POLLNVAL) { errno = EBADF; return -1; }
        if (reads && (fds[i].events & POLLIN) && (fds[i].revents & (POLLIN | POLLHUP | POLLERR))) {
            FD_SET(fds[i].fd, reads); result++;
        }
        if (writes && (fds[i].events & POLLOUT) && (fds[i].revents & (POLLOUT | POLLERR))) {
            FD_SET(fds[i].fd, writes); result++;
        }
        if (errors && (fds[i].events & POLLPRI) && (fds[i].revents & POLLPRI)) {
            FD_SET(fds[i].fd, errors); result++;
        }
    }
    return result;
}
int select(int maximum, fd_set *reads, fd_set *writes, fd_set *errors, struct timeval *timeout)
{
    if (timeout && (timeout->tv_sec < 0 || timeout->tv_usec < 0 || timeout->tv_usec >= 1000000)) {
        errno = EINVAL; return -1;
    }
    struct timespec value = {timeout ? timeout->tv_sec : 0, timeout ? timeout->tv_usec * 1000 : 0};
    int64_t duration;
    if (duration_ns(timeout ? &value : NULL, &duration)) return -1;
    int64_t start = now_ns();
    int result = select_ns(maximum, reads, writes, errors, duration, NULL);
    if (timeout) {
        int64_t left = duration - (now_ns() - start);
        if (left < 0) left = 0;
        timeout->tv_sec = left / INT64_C(1000000000);
        timeout->tv_usec = left % INT64_C(1000000000) / 1000;
    }
    return result;
}
int pselect(int maximum, fd_set *reads, fd_set *writes, fd_set *errors,
    const struct timespec *timeout, const sigset_t *mask)
{
    int64_t duration;
    if (duration_ns(timeout, &duration)) return -1;
    sigset_t old;
    if (mask_enter(mask, &old)) return -1;
    return mask_leave(mask, &old, select_ns(maximum, reads, writes, errors, duration, mask));
}
