#define _GNU_SOURCE
#include <ff_api.h>
#include <ker/socket-broker.h>
#include "socket-broker-preload-internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
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
#define FF_TRACE(fd, result) ker_fstack_runtime_trace_leaf(__func__, (fd), (long)(result))
#else
#define FF_TRACE(fd, result) ((void)0)
#endif

#define FF_DISPATCH_RETURN(type, expression) do { \
    if (ker_sb_preload_ff_dispatch_begin(fd)) return (type)-1; \
    type result = (expression); \
    int saved_errno = errno; \
    FF_TRACE(fd, result); \
    ker_sb_preload_ff_dispatch_end(); \
    errno = saved_errno; \
    return result; \
} while (0)

int ff_socket(int domain, int type, int protocol)
{
    int family = domain == AF_INET6_LINUX ? AF_INET6 : domain;
    if (family != AF_INET && family != AF_INET6) return unsupported();
    int base = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (base != SOCK_STREAM || (protocol && protocol != IPPROTO_TCP))
        return unsupported();
    int fd = ker_sb_posix_socket(family, type, protocol);
    FF_TRACE(-1, fd);
    return fd;
}

int ff_bind(int fd, const struct linux_sockaddr *address, socklen_t length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_bind(fd, (const struct sockaddr *)address, length)); }

int ff_connect(int fd, const struct linux_sockaddr *address, socklen_t length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_connect(fd, (const struct sockaddr *)address, length)); }

int ff_listen(int fd, int backlog)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_listen(fd, backlog)); }

int ff_accept4(int fd, struct linux_sockaddr *address, socklen_t *length, int flags)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_accept4(fd, (struct sockaddr *)address, length, flags)); }

int ff_accept(int fd, struct linux_sockaddr *address, socklen_t *length)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_accept4(fd, (struct sockaddr *)address, length, 0)); }

int ff_close(int fd)
{ FF_DISPATCH_RETURN(int, ker_sb_posix_close(fd)); }

int ff_socket_drain_count(void)
{
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
    return count;
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

int ff_kqueue(void)
{ return unsupported(); }

int ff_kevent(int queue, const struct kevent *changes, int change_count,
    struct kevent *events, int event_count, const struct timespec *timeout)
{ (void)queue; (void)changes; (void)change_count; (void)events; (void)event_count; (void)timeout; return unsupported(); }

int ff_dup2(int old_fd, int new_fd)
{ (void)old_fd; (void)new_fd; return unsupported(); }

#undef FF_DISPATCH_RETURN
