#define _GNU_SOURCE
/* Keep the application's fortify checks while routing owned descriptors. */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#ifndef KER_FORTIFY_BOUNDS_STANDALONE
#include "fd-table.h"
#include "syscall-result.h"
#endif
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#ifndef KER_FORTIFY_BOUNDS_STANDALONE
#include <lkl.h>
#endif
extern void __chk_fail(void) __attribute__((noreturn));

typedef ssize_t (*read_chk_fn)(int, void *, size_t, size_t);
typedef ssize_t (*pread_chk_fn)(int, void *, size_t, off_t, size_t);
typedef ssize_t (*recv_chk_fn)(int, void *, size_t, size_t, int);
typedef ssize_t (*recvfrom_chk_fn)(int, void *, size_t, size_t, int, struct sockaddr *, socklen_t *);
typedef int (*poll_chk_fn)(struct pollfd *, nfds_t, int, size_t);
typedef int (*ppoll_chk_fn)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *, size_t);
static pthread_once_t libc_checked_once = PTHREAD_ONCE_INIT;
static read_chk_fn libc_read_chk;
static pread_chk_fn libc_pread_chk;
static recv_chk_fn libc_recv_chk;
static recvfrom_chk_fn libc_recvfrom_chk;
static poll_chk_fn libc_poll_chk;
static ppoll_chk_fn libc_ppoll_chk;
static int libc_checked_error;

static void resolve_libc_checked(void)
{
    libc_read_chk = (read_chk_fn)dlsym(RTLD_NEXT, "__read_chk");
    libc_pread_chk = (pread_chk_fn)dlsym(RTLD_NEXT, "__pread_chk");
    libc_recv_chk = (recv_chk_fn)dlsym(RTLD_NEXT, "__recv_chk");
    libc_recvfrom_chk = (recvfrom_chk_fn)dlsym(RTLD_NEXT, "__recvfrom_chk");
    libc_poll_chk = (poll_chk_fn)dlsym(RTLD_NEXT, "__poll_chk");
    libc_ppoll_chk = (ppoll_chk_fn)dlsym(RTLD_NEXT, "__ppoll_chk");
    if (!libc_read_chk || !libc_pread_chk || !libc_recv_chk || !libc_recvfrom_chk ||
        !libc_poll_chk || !libc_ppoll_chk) libc_checked_error = ENOSYS;
}
static int ensure_libc_checked(void)
{
    int error = pthread_once(&libc_checked_once, resolve_libc_checked);
    if (!error) error = libc_checked_error;
    if (error) { errno = error; return -1; }
    return 0;
}
static ssize_t host_read_chk(int fd, void *bytes, size_t count, size_t capacity)
{
    if (ensure_libc_checked()) return -1;
    return libc_read_chk(fd, bytes, count, capacity);
}
static ssize_t host_pread_chk(int fd, void *bytes, size_t count, off_t offset, size_t capacity)
{
    if (ensure_libc_checked()) return -1;
    return libc_pread_chk(fd, bytes, count, offset, capacity);
}
static ssize_t host_recv_chk(int fd, void *bytes, size_t count, size_t capacity, int flags)
{
    if (ensure_libc_checked()) return -1;
    return libc_recv_chk(fd, bytes, count, capacity, flags);
}
static ssize_t host_recvfrom_chk(int fd, void *bytes, size_t count, size_t capacity, int flags,
    struct sockaddr *address, socklen_t *length)
{
    if (ensure_libc_checked()) return -1;
    return libc_recvfrom_chk(fd, bytes, count, capacity, flags, address, length);
}
static int host_poll_chk(struct pollfd *fds, nfds_t count, int timeout, size_t capacity)
{
    if (ensure_libc_checked()) return -1;
    return libc_poll_chk(fds, count, timeout, capacity);
}
static int host_ppoll_chk(struct pollfd *fds, nfds_t count, const struct timespec *timeout,
    const sigset_t *mask, size_t capacity)
{
    if (ensure_libc_checked()) return -1;
    return libc_ppoll_chk(fds, count, timeout, mask, capacity);
}

/* Host descriptors must reach libc's cancellation-point implementation. Native
 * entries stay in LKL while pinned, matching the ordinary POSIX wrappers. */
ssize_t __read_chk(int fd, void *bytes, size_t count, size_t capacity)
{
    if (count > capacity) __chk_fail();
#ifdef KER_FORTIFY_BOUNDS_STANDALONE
    return host_read_chk(fd, bytes, count, capacity);
#else
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return host_read_chk(fd, bytes, count, capacity);
    long value = lkl_sys_read(entry->native, bytes, count);
    ker_fd_put(entry);
    return ker_native_result(value);
#endif
}
ssize_t __pread_chk(int fd, void *bytes, size_t count, off_t offset, size_t capacity)
{
    if (count > capacity) __chk_fail();
#ifdef KER_FORTIFY_BOUNDS_STANDALONE
    return host_pread_chk(fd, bytes, count, offset, capacity);
#else
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return host_pread_chk(fd, bytes, count, offset, capacity);
    long value = lkl_sys_pread64(entry->native, bytes, count, offset);
    ker_fd_put(entry);
    return ker_native_result(value);
#endif
}
_Static_assert(sizeof(off_t) == sizeof(off64_t), "Linux fortified offset ABI");
ssize_t __pread64_chk(int fd, void *bytes, size_t count, off64_t offset, size_t capacity)
    __attribute__((alias("__pread_chk")));
ssize_t __recv_chk(int fd, void *bytes, size_t count, size_t capacity, int flags)
{
    if (count > capacity) __chk_fail();
#ifdef KER_FORTIFY_BOUNDS_STANDALONE
    return host_recv_chk(fd, bytes, count, capacity, flags);
#else
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return host_recv_chk(fd, bytes, count, capacity, flags);
    long value = lkl_sys_recvfrom(entry->native, bytes, count, flags, NULL, NULL);
    ker_fd_put(entry);
    return ker_native_result(value);
#endif
}
ssize_t __recvfrom_chk(int fd, void *bytes, size_t count, size_t capacity, int flags,
    struct sockaddr *address, socklen_t *length)
{
    if (count > capacity) __chk_fail();
#ifdef KER_FORTIFY_BOUNDS_STANDALONE
    return host_recvfrom_chk(fd, bytes, count, capacity, flags, address, length);
#else
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return host_recvfrom_chk(fd, bytes, count, capacity, flags, address, length);
    long value = lkl_sys_recvfrom(entry->native, bytes, count, flags, (void *)address, (void *)length);
    ker_fd_put(entry);
    return ker_native_result(value);
#endif
}

#ifndef KER_FORTIFY_BOUNDS_STANDALONE
static int copy_pollfds(struct pollfd *destination, const struct pollfd *source, size_t length)
{
    if (!length) return 0;
    struct iovec local = {destination, length};
    struct iovec remote = {(void *)source, length};
    ssize_t copied = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
    if (copied == (ssize_t)length) return 0;
    errno = EFAULT;
    return -1;
}
static int checked_poll_dispatch(struct pollfd *fds, nfds_t count, int timeout,
    const struct timespec *timespec, const sigset_t *mask, size_t capacity, int is_ppoll)
{
    /* Preserve the existing Ker limit/error order without reading an oversized
     * array. The unfortified wrapper validates the limit first. */
    if (count > KER_FD_LIMIT) return is_ppoll ? ppoll(fds, count, timespec, mask) : poll(fds, count, timeout);
    if (count && !fds) return is_ppoll ? host_ppoll_chk(fds, count, timespec, mask, capacity) :
        host_poll_chk(fds, count, timeout, capacity);
    struct pollfd *snapshot = calloc(count ? count : 1, sizeof(*snapshot));
    struct ker_fd **pins = calloc(count ? count : 1, sizeof(*pins));
    if (!snapshot || !pins) {
        free(snapshot); free(pins); errno = ENOMEM; return -1;
    }
    size_t bytes = (size_t)count * sizeof(*snapshot);
    if (copy_pollfds(snapshot, fds, bytes)) {
        free(snapshot); free(pins);
        /* An inaccessible pollfd array cannot identify a native descriptor;
         * let libc provide the checked host EFAULT behavior. */
        return is_ppoll ? host_ppoll_chk(fds, count, timespec, mask, capacity) :
            host_poll_chk(fds, count, timeout, capacity);
    }
    bool native = false;
    for (nfds_t i = 0; i < count; ++i) {
        pins[i] = ker_fd_get(snapshot[i].fd);
        native |= pins[i] != NULL;
    }
    int result;
    if (native) result = is_ppoll ? ppoll(fds, count, timespec, mask) : poll(fds, count, timeout);
    else result = is_ppoll ? host_ppoll_chk(fds, count, timespec, mask, capacity) :
        host_poll_chk(fds, count, timeout, capacity);
    for (nfds_t i = 0; i < count; ++i) ker_fd_put(pins[i]);
    free(snapshot); free(pins);
    return result;
}
#endif
int __poll_chk(struct pollfd *fds, nfds_t count, int timeout, size_t capacity)
{
    if (count > capacity / sizeof(*fds)) __chk_fail();
#ifdef KER_FORTIFY_BOUNDS_STANDALONE
    return host_poll_chk(fds, count, timeout, capacity);
#else
    return checked_poll_dispatch(fds, count, timeout, NULL, NULL, capacity, 0);
#endif
}
int __ppoll_chk(struct pollfd *fds, nfds_t count, const struct timespec *timeout,
    const sigset_t *mask, size_t capacity)
{
    if (count > capacity / sizeof(*fds)) __chk_fail();
#ifdef KER_FORTIFY_BOUNDS_STANDALONE
    return host_ppoll_chk(fds, count, timeout, mask, capacity);
#else
    return checked_poll_dispatch(fds, count, 0, timeout, mask, capacity, 1);
#endif
}
