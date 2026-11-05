#define _GNU_SOURCE
#include "linux-mptcp-socket-wire.h"
#include <errno.h>
#include <linux/mptcp.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* Only linked into the unchanged upstream helpers. Host fork, pipe, waitpid,
 * AF_UNIX synchronization, files and alarms retain their original semantics.
 * Each network fd owns one channel to a socket in the resident Linux kernel.
 * Upstream creates every network fd after fork; inheriting network fds is not
 * supported by this deliberately narrow fixture. There is no host IP fallback. */
static unsigned char network_fds[4096];
static int is_network(int fd) { return fd >= 0 && fd < 4096 && network_fds[fd]; }
static int remember(int fd)
{
    if (fd < 0) return -1;
    if (fd >= 4096) { syscall(SYS_close, fd); errno = EMFILE; return -1; }
    network_fds[fd] = 1;
    return fd;
}
static long exchange(int fd, struct ms_message *m, void *bytes, int *received_fd)
{
    struct { struct ms_message h; unsigned char data[MS_MAX]; } packet;
    if (m->length > MS_MAX) { errno = EMSGSIZE; return -1; }
    m->magic = MS_MAGIC; packet.h = *m;
    memcpy(packet.data, bytes, m->length);
    size_t size = sizeof(packet.h) + m->length;
    if (syscall(SYS_sendto, fd, &packet, size, MSG_NOSIGNAL, NULL, 0) != (ssize_t)size) return -1;
    struct iovec iov = {&packet, sizeof(packet)};
    union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.data, .msg_controllen = sizeof(control.data)};
    ssize_t n = syscall(SYS_recvmsg, fd, &msg, MSG_CMSG_CLOEXEC | MSG_TRUNC);
    if (n < 0) return -1;
    int newfd = -1;
    int bad_control = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS || c->cmsg_len < CMSG_LEN(0)) {
            bad_control = 1; continue;
        }
        size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < count; i++) {
            int passed; memcpy(&passed, (char *)CMSG_DATA(c) + i * sizeof(int), sizeof(passed));
            if (newfd < 0) newfd = passed;
            else { syscall(SYS_close, passed); bad_control = 1; }
        }
    }
    if (n < (ssize_t)sizeof(packet.h) || n > (ssize_t)sizeof(packet) ||
        bad_control || (msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) || packet.h.magic != MS_MAGIC ||
        packet.h.operation != m->operation || packet.h.length != (size_t)n - sizeof(packet.h) ||
        (newfd >= 0 && !received_fd)) {
        if (newfd >= 0) syscall(SYS_close, newfd);
        errno = EPROTO; return -1;
    }
    *m = packet.h;
    memcpy(bytes, packet.data, m->length);
    if (received_fd) *received_fd = newfd;
    if (m->result < 0) { errno = (int)-m->result; return -1; }
    return m->result;
}
int __wrap_socket(int domain, int type, int protocol)
{
    if ((domain != AF_INET && domain != AF_INET6) || type != SOCK_STREAM ||
        (protocol != IPPROTO_MPTCP && protocol != IPPROTO_TCP)) { errno = EOPNOTSUPP; return -1; }
    const char *path = getenv("KER_MPTCP_SOCKET_CHANNEL");
    if (!path || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) { errno = ENOTCONN; return -1; }
    int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, path);
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_SOCKET, .a = domain, .b = type, .c = protocol};
    if (syscall(SYS_connect, fd, &address, sizeof(address)) || exchange(fd, &m, data, NULL) < 0) {
        int error = errno; syscall(SYS_close, fd); errno = error; return -1;
    }
    return remember(fd);
}
static int address_call(int fd, unsigned op, const struct sockaddr *address, socklen_t length)
{
    if (!is_network(fd)) { errno = EBADF; return -1; }
    if (!address || length > sizeof(struct sockaddr_storage)) { errno = EINVAL; return -1; }
    unsigned char data[MS_MAX]; memcpy(data, address, length);
    struct ms_message m = {.operation = op, .length = length};
    return (int)exchange(fd, &m, data, NULL);
}
int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length)
{ return address_call(fd, MS_BIND, address, length); }
int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length)
{ return address_call(fd, MS_CONNECT, address, length); }
static int name_call(int fd, unsigned op, struct sockaddr *address, socklen_t *length)
{
    if (!is_network(fd) || !address || !length) { errno = EINVAL; return -1; }
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = op};
    long result = exchange(fd, &m, data, NULL);
    if (result < 0) return -1;
    if (m.length > sizeof(struct sockaddr_storage)) { errno = EPROTO; return -1; }
    memcpy(address, data, *length < m.length ? *length : m.length); *length = m.length;
    return (int)result;
}
int __wrap_getsockname(int fd, struct sockaddr *address, socklen_t *length)
{ return name_call(fd, MS_NAME, address, length); }
int __wrap_getpeername(int fd, struct sockaddr *address, socklen_t *length)
{ return name_call(fd, MS_PEER, address, length); }
int __wrap_listen(int fd, int backlog)
{
    if (!is_network(fd)) { errno = EBADF; return -1; }
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_LISTEN, .a = backlog};
    return (int)exchange(fd, &m, data, NULL);
}
int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    if (!is_network(fd)) { errno = EBADF; return -1; }
    if (address || length) { errno = EOPNOTSUPP; return -1; }
    unsigned char data[MS_MAX]; int accepted = -1;
    struct ms_message m = {.operation = MS_ACCEPT};
    if (exchange(fd, &m, data, &accepted) < 0) return -1;
    if (accepted < 0) { errno = EPROTO; return -1; }
    return remember(accepted);
}
int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    if (!is_network(fd)) { errno = EBADF; return -1; }
    if (length > MS_MAX) { errno = EOPNOTSUPP; return -1; }
    unsigned char data[MS_MAX]; memcpy(data, value, length);
    struct ms_message m = {.operation = MS_SETOPT, .length = length, .a = level, .b = option};
    return (int)exchange(fd, &m, data, NULL);
}
int __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{
    if (!is_network(fd) || !length) { errno = EINVAL; return -1; }
    unsigned char data[MS_MAX];
    size_t capacity = (int)*length < 0 ? 0 : *length;
    if (capacity > MS_MAX) { errno = EOPNOTSUPP; return -1; }
    memcpy(data, value, capacity);
    struct mptcp_full_info original = {0};
    size_t sf = 0, tcp = 0;
    int full = level == SOL_MPTCP && option == MPTCP_FULL_INFO;
    if (full) {
        if (capacity < offsetof(struct mptcp_full_info, mptcp_info) || capacity > sizeof(original)) {
            errno = EOPNOTSUPP; return -1;
        }
        memcpy(&original, value, capacity);
        if (original.size_arrays_user > 2 || original.size_sfinfo_user > sizeof(struct mptcp_subflow_info) ||
            original.size_tcpinfo_user > sizeof(struct tcp_info) || !original.subflow_info || !original.tcp_info) {
            errno = EOPNOTSUPP; return -1;
        }
        sf = original.size_arrays_user * original.size_sfinfo_user;
        tcp = original.size_arrays_user * original.size_tcpinfo_user;
        memcpy(data + capacity, (void *)(uintptr_t)original.subflow_info, sf);
        memcpy(data + capacity + sf, (void *)(uintptr_t)original.tcp_info, tcp);
        ((struct mptcp_full_info *)(void *)data)->subflow_info = 0;
        ((struct mptcp_full_info *)(void *)data)->tcp_info = 0;
    }
    struct ms_message m = {.operation = MS_GETOPT, .length = (uint32_t)(capacity + sf + tcp),
        .a = level, .b = option, .c = *length};
    long result = exchange(fd, &m, data, NULL);
    int error = errno;
    if (m.length != capacity + sf + tcp || ((int)m.c >= 0 && m.c > capacity)) { errno = EPROTO; return -1; }
    if (full) {
        ((struct mptcp_full_info *)(void *)data)->subflow_info = original.subflow_info;
        ((struct mptcp_full_info *)(void *)data)->tcp_info = original.tcp_info;
        memcpy((void *)(uintptr_t)original.subflow_info, data + capacity, sf);
        memcpy((void *)(uintptr_t)original.tcp_info, data + capacity + sf, tcp);
    }
    memcpy(value, data, capacity); *length = m.c;
    errno = error; return (int)result;
}
ssize_t __wrap_read(int fd, void *buffer, size_t length)
{
    if (!is_network(fd)) return syscall(SYS_read, fd, buffer, length);
    if (length > MS_MAX) { errno = EOPNOTSUPP; return -1; }
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_READ, .a = (uint32_t)length};
    long result = exchange(fd, &m, data, NULL);
    if (result >= 0) {
        if ((size_t)result > length || m.length != (size_t)result) { errno = EPROTO; return -1; }
        memcpy(buffer, data, (size_t)result);
    }
    return result;
}
ssize_t __wrap_write(int fd, const void *buffer, size_t length)
{
    if (!is_network(fd)) return syscall(SYS_write, fd, buffer, length);
    if (length > MS_MAX) { errno = EOPNOTSUPP; return -1; }
    unsigned char data[MS_MAX]; memcpy(data, buffer, length);
    struct ms_message m = {.operation = MS_WRITE, .length = (uint32_t)length};
    return exchange(fd, &m, data, NULL);
}
int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list ap; va_start(ap, request); void *value = va_arg(ap, void *); va_end(ap);
    if (!is_network(fd)) return (int)syscall(SYS_ioctl, fd, request, value);
    if (request != FIONREAD && request != TIOCOUTQ && request != 0x894b /* SIOCOUTQNSD */) {
        errno = EOPNOTSUPP; return -1;
    }
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_IOCTL, .a = (uint32_t)request};
    long result = exchange(fd, &m, data, NULL);
    if (result >= 0) {
        if (m.length != sizeof(int)) { errno = EPROTO; return -1; }
        memcpy(value, data, sizeof(int));
    }
    return (int)result;
}
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags)
{
    if (!is_network(fd)) return syscall(SYS_recvmsg, fd, message, flags);
    if (!message || message->msg_iovlen != 1 || message->msg_name || message->msg_iov[0].iov_len > MS_MAX / 2 ||
        message->msg_controllen > MS_MAX / 2) { errno = EOPNOTSUPP; return -1; }
    unsigned char data[MS_MAX];
    size_t capacity = message->msg_iov[0].iov_len, control = message->msg_controllen;
    struct ms_message m = {.operation = MS_RECVMSG, .a = (uint32_t)capacity,
        .b = (uint32_t)control, .c = flags};
    long result = exchange(fd, &m, data, NULL);
    if (result >= 0) {
        if ((size_t)result > capacity || m.b > control || m.length != (size_t)result + m.b) { errno = EPROTO; return -1; }
        memcpy(message->msg_iov[0].iov_base, data, (size_t)result);
        memcpy(message->msg_control, data + result, m.b);
        message->msg_controllen = m.b; message->msg_flags = m.c;
    }
    return result;
}
int __wrap_close(int fd)
{
    if (is_network(fd)) network_fds[fd] = 0;
    return (int)syscall(SYS_close, fd);
}
