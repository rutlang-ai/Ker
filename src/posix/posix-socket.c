#define _GNU_SOURCE
#include "fd-table.h"
#include "lkl-overlay/arch/lkl/include/asm/ker-host-usercopy.h"
#include <ker/posix.h>
#include "native-buffer.h"
#include "mtu-control.h"
#include "syscall-result.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

int ker_posix_descriptor_kind(int fd)
{
    if (fd < 0) { errno = EBADF; return -1; }
    struct ker_fd *entry = ker_fd_get(fd);
    if (entry) {
        int kind = KER_POSIX_DESCRIPTOR_OTHER_NATIVE;
        if (entry->kind == KER_FD_SOCKET) kind = KER_POSIX_DESCRIPTOR_SOCKET;
        else if (entry->kind == KER_FD_EPOLL) kind = KER_POSIX_DESCRIPTOR_EPOLL;
        ker_fd_put(entry);
        return kind;
    }
    if (syscall(SYS_fcntl, fd, F_GETFD) < 0) return -1;
    return KER_POSIX_DESCRIPTOR_HOST;
}
#include <lkl.h>
#include <lkl/linux/capability.h>

long ker_native_write_result(long value, int flags)
{
    if (value == -EPIPE && !(flags & MSG_NOSIGNAL)) pthread_kill(pthread_self(), SIGPIPE);
    return ker_native_result(value);
}
static long sent(struct ker_fd *entry, long value, int flags)
{
    ker_fd_put(entry);
    return ker_native_write_result(value, flags);
}

/* Netlink authorization checks both the sender's current credentials and the
 * immutable credentials captured when the socket file is created. Keep route
 * dumps available while ensuring every send API remains unable to mutate
 * administrative state outside Ker's coordinated adapters. */
struct netlink_cap_guard {
    struct __lkl__user_cap_header_struct header;
    struct __lkl__user_cap_data_struct original[2];
    bool restore;
};

static long netlink_cap_drop(struct netlink_cap_guard *guard)
{
    memset(guard, 0, sizeof(*guard));
    guard->header.version = _LKL_LINUX_CAPABILITY_VERSION_3;
    long result = lkl_sys_capget(&guard->header, guard->original);
    if (result < 0) return result;
    unsigned int word = LKL_CAP_NET_ADMIN / 32;
    unsigned int mask = 1U << (LKL_CAP_NET_ADMIN % 32);
    if (!(guard->original[word].effective & mask)) return 0;
    struct __lkl__user_cap_data_struct restricted[2] = {
        guard->original[0], guard->original[1]};
    restricted[word].effective &= ~mask;
    result = lkl_sys_capset(&guard->header, restricted);
    if (result >= 0) guard->restore = true;
    return result;
}

static long netlink_cap_restore(struct netlink_cap_guard *guard)
{
    if (!guard->restore) return 0;
    guard->restore = false;
    return lkl_sys_capset(&guard->header, guard->original);
}

static long netlink_socket_without_admin(int type, int protocol)
{
    struct netlink_cap_guard guard;
    long result = netlink_cap_drop(&guard);
    if (result < 0) return result;
    long fd = lkl_sys_socket(AF_NETLINK, type, protocol);
    long restored = netlink_cap_restore(&guard);
    if (restored < 0) {
        if (fd >= 0) lkl_sys_close((int)fd);
        return restored;
    }
    return fd;
}

static long netlink_send_begin(const struct ker_fd *entry, struct netlink_cap_guard *guard)
{
    memset(guard, 0, sizeof(*guard));
    if (entry->kind != KER_FD_NETLINK) return 0;
    return netlink_cap_drop(guard);
}

static long netlink_send_end(struct netlink_cap_guard *guard)
{
    return netlink_cap_restore(guard);
}

int socket(int domain, int type, int protocol)
{
    if (domain != AF_INET && domain != AF_INET6 && domain != AF_NETLINK && domain != AF_PACKET) return syscall(SYS_socket, domain, type, protocol);
    if (!ker_native_ready()) { errno = ENETDOWN; return -1; }
    long fd = domain == AF_NETLINK ? netlink_socket_without_admin(type, protocol) :
        lkl_sys_socket(domain, type, protocol);
    if (fd < 0) return ker_native_result(fd);
    enum ker_fd_kind kind = KER_FD_SOCKET;
    if (domain == AF_NETLINK) kind = KER_FD_NETLINK;
    else if (domain == AF_PACKET) kind = KER_FD_PACKET;
    return ker_fd_export(fd, kind, -1, type & SOCK_CLOEXEC, 0, -1);
}
int close(int fd) { return ker_fd_close(fd); }

/* Native calls retain the entry through completion, so a concurrent close
 * cannot recycle the imported kernel fd into an unrelated socket operation. */
#define ARGS(...) __VA_ARGS__
#define FD_CALL(name, signature, host_args, native_args) \
    int name signature { \
        struct ker_fd *entry = ker_fd_get(fd); \
        if (!entry) return syscall(SYS_##name, ARGS host_args); \
        long call_result = lkl_sys_##name native_args; \
        ker_fd_put(entry); return ker_native_result(call_result); \
    }
FD_CALL(bind, (int fd, const struct sockaddr *address, socklen_t length),
    (fd, address, length), (entry->native, (void *)address, length))
FD_CALL(connect, (int fd, const struct sockaddr *address, socklen_t length),
    (fd, address, length), (entry->native, (void *)address, length))
FD_CALL(listen, (int fd, int backlog), (fd, backlog), (entry->native, backlog))
FD_CALL(shutdown, (int fd, int how), (fd, how), (entry->native, how))
FD_CALL(getsockname, (int fd, struct sockaddr *address, socklen_t *length),
    (fd, address, length), (entry->native, (void *)address, (void *)length))
FD_CALL(getpeername, (int fd, struct sockaddr *address, socklen_t *length),
    (fd, address, length), (entry->native, (void *)address, (void *)length))
int setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_setsockopt, fd, level, option, value, length);
    if (entry->kind != KER_FD_EPOLL && level == SOL_SOCKET &&
        (option == SO_ATTACH_BPF || option == SO_ATTACH_REUSEPORT_EBPF)) {
        /* These arguments are host program descriptors. There is no imported
         * BPF-program ownership bridge; never reinterpret their numbers. */
        ker_fd_put(entry);
        errno = EOPNOTSUPP;
        return -1;
    }
    struct ker_native_option_guard *guard = NULL;
    int token = level == SOL_SOCKET && option == SO_ZEROCOPY ? ker_native_buffer_option_begin(entry->native, &guard) : 0;
    long result;
    if (token < 0) result = token;
    else if (guard && length >= sizeof(int) && !value) result = -EFAULT;
    else result = lkl_sys_setsockopt(entry->native, level, option, (void *)value, length);
    ker_native_buffer_send_end(guard);
    ker_fd_put(entry);
    return (int)ker_native_result(result);
}
FD_CALL(getsockopt, (int fd, int level, int option, void *value, socklen_t *length),
    (fd, level, option, value, length), (entry->native, level, option, value, (void *)length))

int accept4(int fd, struct sockaddr *address, socklen_t *length, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_accept4, fd, address, length, flags);
    long child = lkl_sys_accept4(entry->native, (void *)address, (void *)length, flags);
    ker_fd_put(entry);
    if (child < 0) return ker_native_result(child);
    return ker_fd_export(child, KER_FD_SOCKET, -1, flags & SOCK_CLOEXEC, 0, -1);
}
int accept(int fd, struct sockaddr *address, socklen_t *length)
{
    return accept4(fd, address, length, 0);
}
#define IO_CALL(name, signature, host_args, native_args, signal_flags) \
    ssize_t name signature { \
        struct ker_fd *entry = ker_fd_get(fd); \
        if (!entry) return syscall(SYS_##name, ARGS host_args); \
        long call_result = lkl_sys_##name native_args; \
        return sent(entry, call_result, signal_flags); \
    }
#define NETLINK_IO_CALL(name, signature, host_args, native_args) \
    ssize_t name signature { \
        struct ker_fd *entry = ker_fd_get(fd); \
        if (!entry) return syscall(SYS_##name, ARGS host_args); \
        struct netlink_cap_guard guard; \
        long call_result = netlink_send_begin(entry, &guard); \
        if (call_result >= 0) call_result = lkl_sys_##name native_args; \
        long restored = netlink_send_end(&guard); \
        if (call_result >= 0 && restored < 0) call_result = restored; \
        return sent(entry, call_result, 0); \
    }
IO_CALL(read, (int fd, void *bytes, size_t length), (fd, bytes, length),
    (entry->native, bytes, length), MSG_NOSIGNAL)
NETLINK_IO_CALL(write, (int fd, const void *bytes, size_t length), (fd, bytes, length),
    (entry->native, (void *)bytes, length))
IO_CALL(readv, (int fd, const struct iovec *iov, int count), (fd, iov, count),
    (entry->native, (void *)iov, count), MSG_NOSIGNAL)
NETLINK_IO_CALL(writev, (int fd, const struct iovec *iov, int count), (fd, iov, count),
    (entry->native, (void *)iov, count))
/* Shared by POSIX sendto and the explicit owned-payload entry point. */
static ssize_t native_sendto(struct ker_fd *entry, const void *bytes, size_t length, int flags,
    const struct sockaddr *address, socklen_t address_length)
{
    struct iovec vector = {(void *)bytes, length};
    struct ker_native_option_guard *guard = NULL;
    int token = ker_native_buffer_send_begin(entry->native, &vector, 1, flags, &guard);
    struct netlink_cap_guard cap_guard;
    long result = token < 0 ? token : netlink_send_begin(entry, &cap_guard);
    if (result >= 0) result = lkl_sys_sendto(entry->native, (void *)bytes,
        length, flags, (void *)address, address_length);
    long restored = token < 0 ? 0 : netlink_send_end(&cap_guard);
    if (result >= 0 && restored < 0) result = restored;
    ker_native_buffer_send_end(guard);
    return sent(entry, result, flags);
}
ssize_t sendto(int fd, const void *bytes, size_t length, int flags,
    const struct sockaddr *address, socklen_t address_length)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_sendto, fd, bytes, length, flags, address, address_length);
    return native_sendto(entry, bytes, length, flags, address, address_length);
}
int ker_posix_buffer_writer_send(struct ker_posix_buffer_writer *writer, int fd,
    size_t offset, size_t length, int flags)
{
    struct iovec single, *vectors;
    size_t count;
    int error = ker_native_writer_range(writer, offset, length, &single, &vectors, &count);
    if (error) { errno = -error; return -1; }
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) { if (vectors != &single) free(vectors); errno = EBADF; return -1; }
    if (entry->kind != KER_FD_SOCKET) {
        ker_fd_put(entry); if (vectors != &single) free(vectors); errno = ENOTSOCK; return -1;
    }
    struct ker_native_option_guard *guard = NULL;
    int token = ker_native_buffer_send_begin(entry->native, vectors, count, flags, &guard);
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = count};
    long result = token < 0 ? token : lkl_sys_sendmsg(entry->native, (void *)&message, flags);
    ker_native_buffer_send_end(guard);
    if (vectors != &single) free(vectors);
    return (int)sent(entry, result, flags);
}
IO_CALL(recvfrom, (int fd, void *bytes, size_t length, int flags,
    struct sockaddr *address, socklen_t *address_length),
    (fd, bytes, length, flags, address, address_length),
    (entry->native, bytes, length, flags, (void *)address, (void *)address_length), MSG_NOSIGNAL)
ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_sendmsg, fd, message, flags);
    if (entry->kind == KER_FD_EPOLL)
        return sent(entry, lkl_sys_sendmsg(entry->native, (void *)message, flags), flags);
    struct ker_native_option_guard *guard = NULL;
    struct msghdr copied;
    int token = 0;
    if (flags & MSG_ZEROCOPY) {
        if (ker_host_usercopy(&copied, message, sizeof(copied), 0))
            return sent(entry, -EFAULT, flags);
        token = ker_native_buffer_send_begin(entry->native,
            copied.msg_iov, copied.msg_iovlen, flags, &guard);
    }
    struct netlink_cap_guard cap_guard;
    long result = token < 0 ? token : netlink_send_begin(entry, &cap_guard);
    if (result >= 0) result = lkl_sys_sendmsg(entry->native, (void *)message, flags);
    long restored = token < 0 ? 0 : netlink_send_end(&cap_guard);
    if (result >= 0 && restored < 0) result = restored;
    ker_native_buffer_send_end(guard);
    return sent(entry, result, flags);
}
IO_CALL(recvmsg, (int fd, struct msghdr *message, int flags), (fd, message, flags),
    (entry->native, (void *)message, flags), MSG_NOSIGNAL)
ssize_t send(int fd, const void *bytes, size_t length, int flags)
{
    return sendto(fd, bytes, length, flags, NULL, 0);
}
ssize_t recv(int fd, void *bytes, size_t length, int flags)
{
    return recvfrom(fd, bytes, length, flags, NULL, NULL);
}
int sendmmsg(int fd, struct mmsghdr *messages, unsigned int count, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_sendmmsg, fd, messages, count, flags);
    if (entry->kind == KER_FD_EPOLL)
        return (int)sent(entry, lkl_sys_sendmmsg(entry->native, (void *)messages, count, flags), flags);
    if (!(flags & MSG_ZEROCOPY) || !count) {
        struct netlink_cap_guard guard;
        long value = netlink_send_begin(entry, &guard);
        if (value >= 0) value = lkl_sys_sendmmsg(entry->native, (void *)messages, count, flags);
        long restored = netlink_send_end(&guard);
        if (value >= 0 && restored < 0) value = restored;
        return (int)sent(entry, value, flags);
    }
    /* Validate each original Linux operation just before execution, so a late
     * bad buffer retains sendmmsg's accepted-prefix and msg_len semantics. */
    if (count > IOV_MAX) count = IOV_MAX;
    if (count && !messages) return (int)sent(entry, -EFAULT, flags);
    unsigned int done = 0;
    long value = 0;
    while (done < count) {
        uintptr_t address = (uintptr_t)messages;
        size_t offset = (size_t)done * sizeof(*messages);
        if (address > UINTPTR_MAX - offset) { value = -EFAULT; break; }
        struct mmsghdr *current = (void *)(address + offset);
        struct msghdr message;
        if (ker_host_usercopy(&message, current, sizeof(message), 0)) {
            value = -EFAULT;
            break;
        }
        struct ker_native_option_guard *guard = NULL;
        int token = ker_native_buffer_send_begin(entry->native,
            message.msg_iov, message.msg_iovlen, flags, &guard);
        struct netlink_cap_guard cap_guard;
        value = token < 0 ? token : netlink_send_begin(entry, &cap_guard);
        if (value >= 0) value = lkl_sys_sendmmsg(entry->native,
            (void *)current, 1, flags | (done + 1 < count ? MSG_BATCH : 0));
        long restored = token < 0 ? 0 : netlink_send_end(&cap_guard);
        if (value >= 0 && restored < 0) value = restored;
        ker_native_buffer_send_end(guard);
        if (value <= 0) break;
        done++;

        /* Linux stops the original sendmmsg batch when a stream message is
         * only partly accepted. The zerocopy adapter submits messages one at
         * a time to guard each buffer, so reproduce that accepted-prefix rule
         * from the successful msg_len and original iovec lengths. */
        /* Inspect metadata only after Linux accepted the message: invalid
         * vectors must keep the syscall's normal EFAULT path. As with the
         * syscall, callers must keep the mmsghdr and iovecs stable until this
         * sendmmsg call returns. */
        size_t payload = 0;
        bool payload_overflow = false;
        for (size_t i = 0; i < message.msg_iovlen; i++) {
            struct iovec vector;
            uintptr_t vectors = (uintptr_t)message.msg_iov;
            if (i > (UINTPTR_MAX - vectors) / sizeof(vector) ||
                ker_host_usercopy(&vector, (void *)(vectors + i * sizeof(vector)), sizeof(vector), 0)) {
                payload_overflow = true;
                break;
            }
            size_t length = vector.iov_len;
            if (length > SIZE_MAX - payload) {
                payload_overflow = true;
                break;
            }
            payload += length;
        }
        unsigned int accepted;
        if (payload_overflow || ker_host_usercopy(&accepted,
                (void *)((uintptr_t)current + offsetof(struct mmsghdr, msg_len)), sizeof(accepted), 0) ||
            accepted < payload) break;
    }
    return (int)sent(entry, done ? (long)done : value, flags);
}
int recvmmsg(int fd, struct mmsghdr *messages, unsigned int count, int flags, struct timespec *timeout)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_recvmmsg, fd, messages, count, flags, timeout);
    long value = lkl_sys_recvmmsg(entry->native, (void *)messages, count, flags, (void *)timeout);
    ker_fd_put(entry);
    return ker_native_result(value);
}
static int duplicate(struct ker_fd *entry, int flags, int minimum, int fixed)
{
    long native = lkl_sys_dup(entry->native);
    int host = -1;
    if (native < 0) return ker_native_result(native);
    if (flags & O_CLOEXEC) {
        long error = lkl_sys_fcntl(native, F_SETFD, FD_CLOEXEC);
        if (error < 0) { lkl_sys_close(native); return ker_native_result(error); }
    }
    if (entry->kind == KER_FD_EPOLL) {
        host = ker_fd_host_dup(entry);
        if (host < 0) { int saved = errno; lkl_sys_close(native); errno = saved; return -1; }
    }
    return ker_fd_export(native, entry->kind, host, flags, minimum, fixed);
}
int dup(int fd)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_dup, fd);
    int value = duplicate(entry, 0, 0, -1);
    ker_fd_put(entry);
    return value;
}
int dup3(int oldfd, int newfd, int flags)
{
    if (oldfd == newfd || (flags & ~O_CLOEXEC)) { errno = EINVAL; return -1; }
    if (newfd < 0) { errno = EBADF; return -1; }
    struct ker_fd *entry = ker_fd_get(oldfd);
    if (!entry) return ker_fd_dup_host(oldfd, newfd, flags);
    int value = duplicate(entry, flags, 0, newfd);
    ker_fd_put(entry);
    return value;
}
int dup2(int oldfd, int newfd)
{
    if (oldfd == newfd) {
        struct ker_fd *entry = ker_fd_get(oldfd);
        if (entry) { ker_fd_put(entry); return oldfd; }
        return syscall(SYS_fcntl, oldfd, F_GETFD) < 0 ? -1 : oldfd;
    }
    return dup3(oldfd, newfd, 0);
}
int fcntl(int fd, int command, ...)
{
    unsigned long argument = 0;
    switch (command) {
    case F_GETFD: case F_GETFL: case F_GETOWN: case F_GETSIG: case F_GETLEASE:
    case F_GETPIPE_SZ: case F_GET_SEALS: break;
    default: {
        va_list args;
        va_start(args, command);
        argument = va_arg(args, unsigned long);
        va_end(args);
    }
    }
    if (command == KER_F_DUPFD_QUERY) return ker_fd_same_file(fd, (int)argument);
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fcntl, fd, command, argument);
    int value;
    if (command == F_GETFD || command == F_SETFD) {
        /* exec closes host reservations; the private kernel never execs. */
        value = syscall(SYS_fcntl, fd, command, argument);
    } else if (command == F_SETOWN || command == F_SETOWN_EX || command == F_SETSIG ||
        (command == F_SETFL && (argument & O_ASYNC))) {
        /* Native kernel task IDs cannot designate host signal recipients. */
        errno = EOPNOTSUPP; value = -1;
    } else if (command == F_DUPFD || command == F_DUPFD_CLOEXEC) {
        if (argument >= KER_FD_LIMIT) { errno = EINVAL; value = -1; }
        else value = duplicate(entry, command == F_DUPFD_CLOEXEC ? O_CLOEXEC : 0, (int)argument, -1);
    } else value = ker_native_result(lkl_sys_fcntl(entry->native, command, argument));
    ker_fd_put(entry);
    return value;
}
int fcntl64(int, int, ...) __attribute__((alias("fcntl")));
int ioctl(int fd, unsigned long request, ...)
{
    if (request == FIOCLEX || request == FIONCLEX) {
        int descriptor_flags = syscall(SYS_fcntl, fd, F_GETFD);
        if (descriptor_flags < 0) return -1;
        if (request == FIOCLEX) descriptor_flags |= FD_CLOEXEC;
        else descriptor_flags &= ~FD_CLOEXEC;
        return syscall(SYS_fcntl, fd, F_SETFD, descriptor_flags);
    }
    va_list args;
    va_start(args, request);
    unsigned long argument = va_arg(args, unsigned long);
    va_end(args);
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_ioctl, fd, request, argument);
    if (request == FIOASYNC || request == FIOSETOWN || request == SIOCSPGRP) {
        ker_fd_put(entry); errno = EOPNOTSUPP; return -1;
    }
    /* These socket operations unconditionally transfer an integer. LKL's
     * in-process uaccess cannot recover a host NULL dereference. */
    if (!argument && (request == FIONBIO || ((entry->kind == KER_FD_SOCKET || entry->kind == KER_FD_PACKET) &&
        (request == FIONREAD || request == SIOCOUTQ)))) {
        ker_fd_put(entry); errno = EFAULT; return -1;
    }
    long value = ker_mtu_ioctl(entry->native, request, argument);
    ker_fd_put(entry);
    return ker_native_result(value);
}

int sockatmark(int fd)
{
    /* libc's internal ioctl bypasses interposition on native reservations. */
    int value;
    if (ioctl(fd, SIOCATMARK, &value) < 0) return -1;
    return value;
}
