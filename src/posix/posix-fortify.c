#define _GNU_SOURCE
/* These checked entry points must call the unfortified public wrappers. */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
extern void __chk_fail(void) __attribute__((noreturn));

/* Fortified libc entry points otherwise use internal syscalls that bypass the
 * public interposers. Keep the bounds check, then use the same owner routing. */
ssize_t __read_chk(int fd, void *bytes, size_t count, size_t capacity)
{
    if (count > capacity) __chk_fail();
    return read(fd, bytes, count);
}
ssize_t __pread_chk(int fd, void *bytes, size_t count, off_t offset, size_t capacity)
{
    if (count > capacity) __chk_fail();
    return pread(fd, bytes, count, offset);
}
_Static_assert(sizeof(off_t) == sizeof(off64_t), "Linux fortified offset ABI");
ssize_t __pread64_chk(int fd, void *bytes, size_t count, off64_t offset, size_t capacity)
    __attribute__((alias("__pread_chk")));
ssize_t __recv_chk(int fd, void *bytes, size_t count, size_t capacity, int flags)
{
    if (count > capacity) __chk_fail();
    return recv(fd, bytes, count, flags);
}
ssize_t __recvfrom_chk(int fd, void *bytes, size_t count, size_t capacity, int flags,
    struct sockaddr *address, socklen_t *length)
{
    if (count > capacity) __chk_fail();
    return recvfrom(fd, bytes, count, flags, address, length);
}
int __poll_chk(struct pollfd *fds, nfds_t count, int timeout, size_t capacity)
{
    if (count > capacity / sizeof(*fds)) __chk_fail();
    return poll(fds, count, timeout);
}
int __ppoll_chk(struct pollfd *fds, nfds_t count, const struct timespec *timeout,
    const sigset_t *mask, size_t capacity)
{
    if (count > capacity / sizeof(*fds)) __chk_fail();
    return ppoll(fds, count, timeout, mask);
}
