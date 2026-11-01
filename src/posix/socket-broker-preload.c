#define _GNU_SOURCE
#include "socket-broker-preload-internal.h"
#include "lkl-overlay/arch/lkl/include/asm/ker-host-usercopy.h"
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define KER_SB_MAX_IOV 64
#define KER_SB_IO_MAX 4096

extern char **environ;

struct host_libc_functions {
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

int ker_sb_preload_resolve_host_functions(void)
{
#define RESOLVE_HOST_FUNCTION(member, symbol) do { \
    host_libc.member = (__typeof__(host_libc.member))dlsym(RTLD_NEXT, symbol); \
    if (!host_libc.member) { errno = ENOSYS; return -1; } \
} while (0)
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
    return 0;
}

int ker_sb_preload_host_epoll_pwait(int epfd, struct epoll_event *events,
    int maximum, int timeout, const sigset_t *mask)
{
    return host_libc.epoll_pwait(epfd, events, maximum, timeout, mask);
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
    if (domain != AF_INET && domain != AF_INET6)
        return (int)syscall(SYS_socket, domain, type, protocol);
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
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
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
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : host_libc.connect(fd, address, length);
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
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : (int)syscall(SYS_listen, fd, backlog);
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_listen(client, cap, backlog) : -1;
    ker_sb_preload_unlock(); return result;
}

int accept4(int fd, struct sockaddr *address, socklen_t *length, int flags)
{
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
#ifdef SYS_accept4
        return native < 0 ? -1 : host_libc.accept4(fd, address, length, flags);
#else
        if (flags) { errno = EINVAL; return -1; }
        return native < 0 ? -1 : host_libc.accept(fd, address, length);
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
    int accepted = client ? ker_socket_client_accept4(client, cap,
        address ? (struct sockaddr *)&local : NULL,
        address ? &local_length : NULL, flags) : -1;
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
    ker_sb_preload_lock();
    int native = ker_sb_preload_any_native_locked(fd);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : host_libc.close(fd);
    }
    int result = ker_sb_preload_close_locked(fd);
    ker_sb_preload_unlock(); return result;
}

int shutdown(int fd, int how)
{
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : (int)syscall(SYS_shutdown, fd, how);
    }
    struct ker_socket_client *client = ker_sb_preload_client_locked();
    int result = client ? ker_socket_client_shutdown(client, cap, how) : -1;
    ker_sb_preload_unlock(); return result;
}

static int name_query(int fd, struct sockaddr *address, socklen_t *length,
    bool peer)
{
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
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
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
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
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
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
    if (!descriptor_may_be_broker_capability(fd))
        return writing ? host_libc.write(fd, buffer, length) :
            host_libc.read(fd, buffer, length);
    ker_sb_preload_lock();
    int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : writing ? host_libc.write(fd, buffer, length) :
            host_libc.read(fd, buffer, length);
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
    ker_sb_preload_lock(); int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : host_libc.send(fd, buffer, length, flags);
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
    ker_sb_preload_lock(); int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : host_libc.recv(fd, buffer, length, flags);
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
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) {
        if (address || address_length) { errno = EOPNOTSUPP; return -1; }
        return send(fd, buffer, length, flags);
    }
    return host_libc.sendto(fd, buffer, length, flags, address, address_length);
}

ssize_t recvfrom(int fd, void *buffer, size_t length, int flags,
    struct sockaddr *address, socklen_t *address_length)
{
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) {
        if (address || address_length) { errno = EOPNOTSUPP; return -1; }
        return recv(fd, buffer, length, flags);
    }
    return host_libc.recvfrom(fd, buffer, length, flags, address, address_length);
}

ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) { errno = EOPNOTSUPP; return -1; }
    return host_libc.sendmsg(fd, message, flags);
}

ssize_t recvmsg(int fd, struct msghdr *message, int flags)
{
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    ker_sb_preload_unlock();
    if (native < 0) return -1;
    if (native) { errno = EOPNOTSUPP; return -1; }
    return host_libc.recvmsg(fd, message, flags);
}

static ssize_t vector_io(int fd, const struct iovec *user_iov, int count, bool writing)
{
    ker_sb_preload_lock(); int cap = -1, native = native_socket_fd(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : writing ? host_libc.writev(fd, user_iov, count) :
            host_libc.readv(fd, user_iov, count);
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
    if (maximum <= 0 || maximum > 4096) { errno = EINVAL; return -1; }
    struct epoll_event local[4096];
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
        return host_libc.epoll_pwait(epfd, user_events, maximum, timeout, mask);
    }
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
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    if (native < 0) { ker_sb_preload_unlock(); return -1; }
    if (!native) {
        int epoll_cap = -1;
        int composite = ker_sb_preload_composite_epoll_locked(fd, &epoll_cap);
        if (composite < 0) { ker_sb_preload_unlock(); return -1; }
        if (composite && (command == F_DUPFD || command == F_DUPFD_CLOEXEC)) {
            int result = ker_sb_preload_epoll_duplicate_locked(fd, (int)argument,
                command == F_DUPFD_CLOEXEC);
            ker_sb_preload_unlock(); return result;
        }
        if (composite && (command == F_GETFL || command == F_SETFL)) {
            ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
        }
        ker_sb_preload_unlock();
        if (!fcntl_command_has_argument(command)) return host_libc.fcntl(fd, command);
        if (fcntl_command_argument_is_pointer(command))
            return host_libc.fcntl(fd, command, pointer_argument);
        return host_libc.fcntl(fd, command, argument);
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
        result = ker_sb_preload_duplicate_network_locked(fd, (int)argument,
            command == F_DUPFD_CLOEXEC);
        break;
    default: errno = EOPNOTSUPP; result = -1; break;
    }
    ker_sb_preload_unlock(); return result;
}

extern __typeof(fcntl) fcntl64 __attribute__((alias("fcntl")));

int ioctl(int fd, unsigned long request, ...)
{
    va_list ap; va_start(ap, request); void *user_argument = va_arg(ap, void *); va_end(ap);
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
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
    ker_sb_preload_lock();
    if (ker_sb_preload_has_exec_unsafe_epoll_locked()) {
        ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
    }
    ker_sb_preload_unlock();
    return 0;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
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
    ker_sb_preload_lock(); int cap = -1;
    int native = ker_sb_preload_network_fd_locked(out_fd, &cap);
    if (native <= 0) {
        ker_sb_preload_unlock();
        return native < 0 ? -1 : host_libc.sendfile(out_fd, in_fd,
            user_offset, count);
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
