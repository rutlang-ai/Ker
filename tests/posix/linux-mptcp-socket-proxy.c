#define _GNU_SOURCE
#include <netinet/in.h>
#include <net/if.h>
#include "linux-mptcp-socket-wire.h"
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <linux/mptcp.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef KER_NETLINK_DUMPS_SELFTEST
#include <linux/mqueue.h>
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
#include <sys/epoll.h>
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NET_DEVICE_SELFTEST)
#include <linux/sockios.h>
#include <linux/if_tun.h>
#endif
#ifdef KER_PACKETDRILL_SELFTEST
#include <sys/wait.h>
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_SOCKET_FILTER_SELFTEST)
#include <linux/filter.h>
#endif

/* Only linked into the unchanged upstream helpers. Host fork, pipe, waitpid,
 * AF_UNIX synchronization, files and alarms retain their original semantics.
 * Each network fd owns one channel to a socket in the resident Linux kernel.
 * Upstream creates every network fd after fork; inheriting network fds is not
 * supported by this deliberately narrow fixture. There is no host IP fallback. */
static unsigned char network_fds[4096];
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
static int remote_epoll[4096];
#endif
static struct stat imported_inputs[4096];
static unsigned char has_input[4096];
static int interrupted;
static ssize_t write_result(ssize_t result, int flags)
{
    if (result < 0 && errno == EPIPE && !(flags & MSG_NOSIGNAL)) {
        raise(SIGPIPE); errno = EPIPE;
    }
    return result;
}
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
    ssize_t n;
    do {
        n = syscall(SYS_recvmsg, fd, &msg, MSG_CMSG_CLOEXEC | MSG_TRUNC);
        if (n < 0 && errno == EINTR) interrupted = 1;
    } while (n < 0 && errno == EINTR);
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
static int open_channel(void)
{
    const char *path = getenv("KER_MPTCP_SOCKET_CHANNEL");
    if (!path || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) { errno = ENOTCONN; return -1; }
    int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, path);
    if (syscall(SYS_connect, fd, &address, sizeof(address))) {
        int error = errno; syscall(SYS_close, fd); errno = error; return -1;
    }
    return fd;
}
#ifdef KER_NETLINK_DUMPS_SELFTEST
/* Only the upstream helper is compiled with syscall=ker_netlink_syscall.
 * The transport's host syscalls retain their ordinary libc implementation. */
long ker_netlink_syscall(long operation, ...)
{
    va_list ap; va_start(ap, operation);
    unsigned char data[MS_MAX];
    if (operation == SYS_mq_open) {
        const char *name = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        unsigned mode = (unsigned)va_arg(ap, int);
        int attributes = va_arg(ap, int); /* original syscall passes literal 0 */
        va_end(ap);
        if (!name || strlen(name) >= 256 || attributes) { errno = EOPNOTSUPP; return -1; }
        int fd = open_channel(); if (fd < 0) return -1;
        strcpy((char *)data, name);
        struct ms_message m = {.operation = MS_MQ_OPEN, .a = (unsigned)flags, .b = mode,
                              .length = (uint32_t)strlen(name) + 1};
        if (exchange(fd, &m, data, NULL) < 0) {
            int error = errno; syscall(SYS_close, fd); errno = error; return -1;
        }
        return remember(fd);
    }
    if (operation == SYS_mq_notify) {
        int fd = va_arg(ap, int);
        const struct sigevent *event = va_arg(ap, const struct sigevent *);
        va_end(ap);
        if (!is_network(fd) || !event || event->sigev_notify != SIGEV_THREAD ||
            !is_network(event->sigev_signo) || !event->sigev_value.sival_ptr) {
            errno = EOPNOTSUPP; return -1;
        }
        struct ms_message handle = {.operation = MS_NETLINK_HANDLE};
        long target = exchange(event->sigev_signo, &handle, data, NULL);
        if (target < 0) return -1;
        memcpy(data, event->sigev_value.sival_ptr, NOTIFY_COOKIE_LEN);
        struct ms_message m = {.operation = MS_MQ_NOTIFY, .a = (uint32_t)target,
                              .length = NOTIFY_COOKIE_LEN};
        return exchange(fd, &m, data, NULL);
    }
    va_end(ap); errno = EOPNOTSUPP; return -1;
}
#endif
int __wrap_socket(int domain, int type, int protocol)
{
    int packet = 0;
#ifdef KER_PACKETDRILL_SELFTEST
    packet = domain == AF_PACKET && type == SOCK_RAW;
#endif
    int netlink = domain == AF_NETLINK && ((type & ~SOCK_CLOEXEC) == SOCK_RAW || (type & ~SOCK_CLOEXEC) == SOCK_DGRAM) &&
                  (protocol == NETLINK_SOCK_DIAG || protocol == NETLINK_ROUTE || protocol == NETLINK_GENERIC || protocol == NETLINK_NETFILTER);
    int raw = (domain == AF_INET || domain == AF_INET6) &&
              (((type & ~SOCK_CLOEXEC) == SOCK_RAW &&
                 (protocol == IPPROTO_RAW || (domain == AF_INET && protocol == IPPROTO_ICMP) ||
                  (domain == AF_INET6 && protocol == IPPROTO_ICMPV6))) ||
               ((type & ~SOCK_CLOEXEC) == SOCK_DGRAM &&
                 (protocol == 0 || (domain == AF_INET && protocol == IPPROTO_ICMP) ||
                  (domain == AF_INET6 && protocol == IPPROTO_ICMPV6))));
    int udp = 0;
#ifdef KER_NETWORK_SELFTEST
    udp = (domain == AF_INET || domain == AF_INET6) && type == SOCK_DGRAM &&
          (protocol == 0 || protocol == IPPROTO_UDP);
    if (udp) raw = 0;
#endif
    int dccp = 0;
#ifdef KER_NET_DEVICE_SELFTEST
    dccp = (domain == AF_INET || domain == AF_INET6) && type == SOCK_DCCP &&
           (protocol == 0 || protocol == IPPROTO_DCCP);
#endif
    int creation = 0;
#ifdef KER_SOCKET_CREATION_SELFTEST
    creation = domain == AF_INET || (domain == AF_MAX && type == 0 && protocol == 0);
#endif
    if (!creation && !dccp && !udp && !packet && !netlink && !raw && ((domain != AF_INET && domain != AF_INET6) || type != SOCK_STREAM ||
        (protocol != IPPROTO_MPTCP && protocol != IPPROTO_TCP && protocol != 0))) { errno = EOPNOTSUPP; return -1; }
    int fd = open_channel();
    if (fd < 0) return -1;
    const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE");
    if (!ns) ns = "";
    if (strlen(ns) >= 64) { syscall(SYS_close, fd); errno = EINVAL; return -1; }
    unsigned char data[MS_MAX]; strcpy((char *)data, ns);
    struct ms_message m = {.operation = MS_SOCKET, .a = domain, .b = type, .c = protocol,
                           .length = (uint32_t)strlen(ns) + 1};
    if (exchange(fd, &m, data, NULL) < 0) {
        int error = errno; syscall(SYS_close, fd); errno = error; return -1;
    }
#ifdef KER_FORWARDING_SELFTEST
    /* ip vrf exec normally attaches a cgroup socket-create BPF program. The
     * host cgroup cannot address resident Linux devices. Apply the same
     * sk_bound_dev_if operation through native SO_BINDTODEVICE before exposing
     * each IP socket; routing and VRF isolation remain entirely in Linux. */
    const char *vrf = getenv("KER_FORWARDING_VRF");
    if (vrf && (domain == AF_INET || domain == AF_INET6)) {
        if (!*vrf || strlen(vrf) >= IFNAMSIZ) {
            syscall(SYS_close, fd); errno = EINVAL; return -1;
        }
        strcpy((char *)data, vrf);
        m = (struct ms_message){.operation = MS_SETOPT, .a = SOL_SOCKET,
            .b = SO_BINDTODEVICE, .length = (uint32_t)strlen(vrf) + 1};
        if (exchange(fd, &m, data, NULL) < 0) {
            int error = errno; syscall(SYS_close, fd); errno = error; return -1;
        }
    }
#endif
    return remember(fd);
}
unsigned __wrap_if_nametoindex(const char *name)
{
    const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE"); if (!ns) ns = "";
    if (!name || strlen(name) >= IFNAMSIZ || strlen(ns) >= 64) { errno = EINVAL; return 0; }
    int fd = open_channel(); if (fd < 0) return 0;
    unsigned char data[MS_MAX]; strcpy((char *)data, ns); strcpy((char *)data + strlen(ns) + 1, name);
    struct ms_message m = {.operation = MS_IFINDEX, .length = (uint32_t)(strlen(ns) + strlen(name) + 2)};
    long result = exchange(fd, &m, data, NULL); int error = errno; syscall(SYS_close, fd); errno = error;
    return result < 0 ? 0 : (unsigned)result;
}
char *__wrap_if_indextoname(unsigned index, char name[IF_NAMESIZE])
{
    const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE"); if (!ns) ns = "";
    if (!name || strlen(ns) >= 64) { errno = EINVAL; return NULL; }
    int fd = open_channel(); if (fd < 0) return NULL;
    unsigned char data[MS_MAX]; strcpy((char *)data, ns);
    struct ms_message m = {.operation = MS_IFNAME, .a = index, .length = (uint32_t)strlen(ns) + 1};
    long result = exchange(fd, &m, data, NULL); int error = errno; syscall(SYS_close, fd); errno = error;
    if (result < 0) return NULL;
    if (m.length < 2 || m.length > IF_NAMESIZE || data[m.length - 1] || strlen((char *)data) + 1 != m.length) {
        errno = EPROTO; return NULL;
    }
    memcpy(name, data, m.length); return name;
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
    if (address && !length) { errno = EFAULT; return -1; }
    unsigned char data[MS_MAX]; int accepted = -1;
    struct ms_message m = {.operation = MS_ACCEPT};
    if (exchange(fd, &m, data, &accepted) < 0) return -1;
    if (accepted < 0) { errno = EPROTO; return -1; }
    accepted = remember(accepted);
    if (accepted >= 0 && address && name_call(accepted, MS_PEER, address, length)) {
        int e = errno; network_fds[accepted] = 0; syscall(SYS_close, accepted); errno = e; return -1;
    }
    return accepted;
}
int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    if (!is_network(fd)) { errno = EBADF; return -1; }
    if (length > MS_MAX) { errno = EOPNOTSUPP; return -1; }
    unsigned char data[MS_MAX]; memcpy(data, value, length);
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_SOCKET_FILTER_SELFTEST)
    if (level == SOL_SOCKET && option == SO_ATTACH_FILTER) {
        if (length != sizeof(struct sock_fprog)) { errno = EINVAL; return -1; }
        struct sock_fprog program; memcpy(&program, value, sizeof(program));
        size_t bytes = (size_t)program.len * sizeof(struct sock_filter);
        if (!program.filter || bytes > MS_MAX - sizeof(program)) { errno = EINVAL; return -1; }
        memcpy(data + sizeof(program), program.filter, bytes); program.filter = NULL;
        memcpy(data, &program, sizeof(program));
        struct ms_message m = {.operation = MS_SETOPT, .length = (uint32_t)(sizeof(program) + bytes), .a = level, .b = option};
        return (int)exchange(fd, &m, data, NULL);
    }
#endif
    int replace = (level == IPPROTO_IP || level == IPPROTO_IPV6) && option == IPT_SO_SET_REPLACE;
    struct xt_counters *counters = NULL;
    size_t count = 0;
    if (replace) {
        size_t offset = level == IPPROTO_IP ? offsetof(struct ipt_replace, counters) : offsetof(struct ip6t_replace, counters);
        size_t number = level == IPPROTO_IP ? offsetof(struct ipt_replace, num_counters) : offsetof(struct ip6t_replace, num_counters);
        if (length < offset + sizeof(counters)) { errno = EINVAL; return -1; }
        unsigned n; memcpy(&n, data + number, sizeof(n)); count = n;
        if (count > (MS_MAX - length) / sizeof(*counters)) { errno = EMSGSIZE; return -1; }
        memcpy(&counters, data + offset, sizeof(counters));
        if (count && !counters) { errno = EFAULT; return -1; }
        memset(data + offset, 0, sizeof(counters));
    }
    struct ms_message m = {.operation = MS_SETOPT, .length = length, .a = level, .b = option};
    int result = (int)exchange(fd, &m, data, NULL);
    if (result >= 0 && replace) {
        if (m.length != count * sizeof(*counters)) { errno = EPROTO; return -1; }
        if (count) memcpy(counters, data, m.length);
    }
    return result;
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
    /* The original mmap helper writes the whole mapped file at once. A
     * bounded native short write preserves normal stream syscall semantics. */
    if (length > MS_MAX) length = MS_MAX;
    unsigned char data[MS_MAX]; memcpy(data, buffer, length);
    struct ms_message m = {.operation = MS_WRITE, .length = (uint32_t)length};
    return write_result(exchange(fd, &m, data, NULL), 0);
}
int __wrap_ioctl(int fd, unsigned long request, ...)
{
#ifdef KER_PACKETDRILL_SELFTEST
    if (is_network(fd) && request == TUNSETOFFLOAD) {
        va_list ap; va_start(ap, request); unsigned long flags = va_arg(ap, unsigned long); va_end(ap);
        unsigned char data[MS_MAX];
        struct ms_message m = {.operation = MS_IOCTL, .a = (uint32_t)request, .b = (uint32_t)flags};
        return (int)exchange(fd, &m, data, NULL);
    }
#endif
    va_list ap; va_start(ap, request); void *value = va_arg(ap, void *); va_end(ap);
    if (!is_network(fd)) return (int)syscall(SYS_ioctl, fd, request, value);
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NET_DEVICE_SELFTEST)
    if (request == TUNSETIFF || request == TUNSETQUEUE || request == SIOCGIFFLAGS || request == SIOCSIFFLAGS ||
        request == SIOCGIFADDR || request == SIOCSIFADDR || request == SIOCSIFNETMASK ||
        request == SIOCGIFMTU || request == SIOCSIFMTU) {
        unsigned char data[MS_MAX]; memcpy(data, value, sizeof(struct ifreq));
        struct ms_message m = {.operation = MS_IOCTL, .a = (uint32_t)request, .length = sizeof(struct ifreq)};
        int result = (int)exchange(fd, &m, data, NULL);
        if (result >= 0) {
            if (m.length != sizeof(struct ifreq)) { errno = EPROTO; return -1; }
            memcpy(value, data, sizeof(struct ifreq));
        }
        return result;
    }
    if (request == SIOCGSTAMP) {
        unsigned char data[MS_MAX];
        struct ms_message m = {.operation = MS_IOCTL, .a = (uint32_t)request};
        int result = (int)exchange(fd, &m, data, NULL);
        if (result >= 0) {
            if (m.length != sizeof(struct timeval)) { errno = EPROTO; return -1; }
            memcpy(value, data, sizeof(struct timeval));
        }
        return result;
    }
#endif
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
static ssize_t message_call(int fd, struct msghdr *message, int flags, int sending)
{
    if (!is_network(fd)) return syscall(sending ? SYS_sendmsg : SYS_recvmsg, fd, message, flags);
#ifdef KER_PACKETDRILL_SELFTEST
    if (sending) {
        if (!message || message->msg_iovlen > 64 || message->msg_namelen > sizeof(struct sockaddr_storage)) { errno = EOPNOTSUPP; return -1; }
        size_t prefix = sizeof(struct ms_io) + message->msg_iovlen * sizeof(uint32_t);
        size_t total = 0, control = message->msg_controllen, name = message->msg_namelen;
        for (size_t i = 0; i < message->msg_iovlen; i++) {
            if (message->msg_iov[i].iov_len > MS_MAX - total) { errno = EMSGSIZE; return -1; }
            total += message->msg_iov[i].iov_len;
        }
        if (control > MS_MAX || prefix + total + control + name > MS_MAX) { errno = EMSGSIZE; return -1; }
        unsigned char data[MS_MAX];
        struct ms_io io = {(uint32_t)total, (uint32_t)control, (uint32_t)name, (uint32_t)flags};
        memcpy(data, &io, sizeof(io));
        size_t offset = prefix;
        for (size_t i = 0; i < message->msg_iovlen; i++) {
            uint32_t length = (uint32_t)message->msg_iov[i].iov_len;
            memcpy(data + sizeof(io) + i * sizeof(length), &length, sizeof(length));
            if (length) memcpy(data + offset, message->msg_iov[i].iov_base, length);
            offset += length;
        }
        if (control) memcpy(data + offset, message->msg_control, control);
        if (name) memcpy(data + offset + control, message->msg_name, name);
        struct ms_message m = {.operation = MS_PACKET_SENDV, .length = (uint32_t)(prefix + total + control + name), .a = (uint32_t)message->msg_iovlen};
        return write_result(exchange(fd, &m, data, NULL), flags);
    }
#endif
    if (!message || message->msg_iovlen > 16 || message->msg_namelen > sizeof(struct sockaddr_storage)) {
        errno = EOPNOTSUPP; return -1;
    }
    size_t capacity = 0, control = message->msg_controllen, name = message->msg_namelen;
    for (size_t i = 0; i < message->msg_iovlen; i++) {
        if (message->msg_iov[i].iov_len > MS_MAX - capacity) { errno = EMSGSIZE; return -1; }
        capacity += message->msg_iov[i].iov_len;
    }
    if (control > MS_MAX || sizeof(struct ms_io) + capacity + control + name > MS_MAX) { errno = EMSGSIZE; return -1; }
    unsigned char data[MS_MAX];
    struct ms_io io = {(uint32_t)capacity, (uint32_t)control, (uint32_t)name, (uint32_t)flags};
    memcpy(data, &io, sizeof(io));
    if (sending) {
        size_t offset = sizeof(io);
        for (size_t i = 0; i < message->msg_iovlen; i++) {
            memcpy(data + offset, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len);
            offset += message->msg_iov[i].iov_len;
        }
        if (control) memcpy(data + offset, message->msg_control, control);
        if (name) memcpy(data + offset + control, message->msg_name, name);
    }
    struct ms_message m = {.operation = sending ? MS_SENDMSG : MS_RECVMSG,
        .length = (uint32_t)(sizeof(io) + (sending ? capacity + control + name : 0))};
    long result = exchange(fd, &m, data, NULL);
    if (sending) return write_result(result, flags);
    if (result < 0) return result;
    if (m.length < sizeof(io)) { errno = EPROTO; return -1; }
    memcpy(&io, data, sizeof(io));
    if (io.data > capacity || io.control > control || io.name > name ||
        ((size_t)result > capacity && !(io.flags & MSG_TRUNC)) ||
        m.length != sizeof(io) + io.data + io.control + io.name) { errno = EPROTO; return -1; }
    size_t offset = sizeof(io), remaining = io.data;
    for (size_t i = 0; i < message->msg_iovlen && remaining; i++) {
        size_t copy = message->msg_iov[i].iov_len < remaining ? message->msg_iov[i].iov_len : remaining;
        memcpy(message->msg_iov[i].iov_base, data + offset, copy); offset += copy; remaining -= copy;
    }
    if (io.control) memcpy(message->msg_control, data + sizeof(io) + io.data, io.control);
    if (io.name) memcpy(message->msg_name, data + sizeof(io) + io.data + io.control, io.name);
    message->msg_controllen = io.control; message->msg_namelen = io.name; message->msg_flags = io.flags;
    return result;
}
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags)
{ return message_call(fd, message, flags, 0); }
ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags)
{ return message_call(fd, (struct msghdr *)message, flags, 1); }
ssize_t __wrap_recvfrom(int fd, void *bytes, size_t length, int flags, struct sockaddr *address, socklen_t *addrlen)
{
    struct iovec vector = {bytes, length};
    struct msghdr msg = {.msg_iov = &vector, .msg_iovlen = 1, .msg_name = address,
                         .msg_namelen = address && addrlen ? *addrlen : 0};
    ssize_t result = __wrap_recvmsg(fd, &msg, flags);
    if (result >= 0 && address && addrlen) *addrlen = msg.msg_namelen;
    return result;
}
ssize_t __wrap_recv(int fd, void *bytes, size_t length, int flags)
{ return __wrap_recvfrom(fd, bytes, length, flags, NULL, NULL); }
#ifdef KER_RPATH_SELFTEST
__attribute__((visibility("hidden")))
int ker_rpath_gettimeofday_impl(struct timeval *tv, void *tz)
{
    if (!getenv("KER_MPTCP_NATIVE_REALTIME") || tv == NULL)
        return (int)syscall(SYS_gettimeofday, tv, tz);

    /* Keep the legacy timezone output on the host ABI while sourcing time
     * from the same Linux instance that produces SO_TIMESTAMP for this test. */
    if (tz) {
        struct timeval ignored;
        if (syscall(SYS_gettimeofday, &ignored, tz)) return -1;
    }
    int fd = -1;
    for (int candidate = 0; candidate < (int)(sizeof(network_fds) / sizeof(network_fds[0])); candidate++)
        if (network_fds[candidate]) { fd = candidate; break; }
    if (fd < 0) { errno = ENOTCONN; return -1; }

    unsigned char response[MS_MAX];
    struct ms_message m = {.operation = MS_REALTIME_GET};
    long result = exchange(fd, &m, response, NULL);
    if (result < 0) return -1;
    if (result || m.length != sizeof(struct timeval)) {
        errno = EPROTO; return -1;
    }
    struct timeval native;
    memcpy(&native, response, sizeof(native));
    if (native.tv_usec < 0 || native.tv_usec >= 1000000) { errno = EPROTO; return -1; }
    const char *log = getenv("KER_MPTCP_NATIVE_TIME_LOG");
    if (log && *log) {
        int out = (int)syscall(SYS_openat, AT_FDCWD, log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (out < 0) return -1;
        static const char marker = '1';
        long written = syscall(SYS_write, out, &marker, 1);
        int saved = errno;
        syscall(SYS_close, out);
        if (written != 1) { errno = written < 0 ? saved : EIO; return -1; }
    }
    *tv = native;
    return 0;
}
int __wrap_gettimeofday(struct timeval *tv, void *tz)
{ return ker_rpath_gettimeofday_impl(tv, tz); }
#endif
ssize_t __wrap_sendto(int fd, const void *bytes, size_t length, int flags, const struct sockaddr *address, socklen_t addrlen)
{
    struct iovec vector = {(void *)bytes, length};
    struct msghdr msg = {.msg_iov = &vector, .msg_iovlen = 1, .msg_name = (void *)address, .msg_namelen = addrlen};
    return __wrap_sendmsg(fd, &msg, flags);
}
ssize_t __wrap_send(int fd, const void *bytes, size_t length, int flags)
{ return __wrap_sendto(fd, bytes, length, flags, NULL, 0); }
int __wrap_fcntl(int fd, int command, ...)
{
    int administrative = 0;
#ifdef KER_PACKETDRILL_SELFTEST
    administrative = is_network(fd) && network_fds[fd] == 2;
#endif
    if (is_network(fd) && command != F_GETFL && command != F_SETFL && command != F_GETFD && command != F_SETFD &&
        !(administrative && (command == F_DUPFD || command == F_DUPFD_CLOEXEC))) {
        errno = EOPNOTSUPP; return -1;
    }
    long argument = 0;
    if (command != F_GETFL && command != F_GETFD && command != F_GETOWN && command != F_GETSIG &&
        command != F_GETLEASE && command != F_GETPIPE_SZ && command != F_GET_SEALS) {
        va_list ap; va_start(ap, command);
        if (command == F_GETLK || command == F_SETLK || command == F_SETLKW ||
            command == F_OFD_GETLK || command == F_OFD_SETLK || command == F_OFD_SETLKW)
            argument = (long)va_arg(ap, void *);
        else argument = va_arg(ap, int);
        va_end(ap);
    }
    if (!is_network(fd)) return (int)syscall(SYS_fcntl, fd, command, argument);
#ifdef KER_PACKETDRILL_SELFTEST
    if (administrative && (command == F_DUPFD || command == F_DUPFD_CLOEXEC || command == F_GETFD || command == F_SETFD)) {
        int result = (int)syscall(SYS_fcntl, fd, command, argument);
        if (result >= 0 && (command == F_DUPFD || command == F_DUPFD_CLOEXEC)) {
            if (result >= 4096) { syscall(SYS_close, result); errno = EMFILE; return -1; }
            network_fds[result] = 2;
        }
        return result;
    }
#endif
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_FCNTL, .a = command, .b = (uint32_t)argument};
    return (int)exchange(fd, &m, data, NULL);
}
int __wrap_shutdown(int fd, int how)
{
    if (!is_network(fd)) return (int)syscall(SYS_shutdown, fd, how);
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_SHUTDOWN, .a = how};
    return (int)exchange(fd, &m, data, NULL);
}
static long long milliseconds(void)
{
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
#ifdef KER_MIXED_POLL_SELFTEST
/* The RPC channel's host readiness is unrelated to its resident socket.
 * Query each resident socket through native poll and ordinary descriptors
 * through host poll. Bounded host waits keep both sources observable while
 * preserving the caller's overall timeout and native error/hangup events. */
static int mixed_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (count > 64) { errno = EOPNOTSUPP; return -1; }
    struct pollfd host[64];
    long long deadline = milliseconds() + timeout;
    for (;;) {
        for (nfds_t i = 0; i < count; i++) {
            host[i] = fds[i]; host[i].revents = 0;
            if (is_network(host[i].fd)) host[i].fd = -1;
        }
        if (syscall(SYS_poll, host, count, 0) < 0) return -1;
        int ready = 0;
        for (nfds_t i = 0; i < count; i++) {
            fds[i].revents = host[i].revents;
            if (is_network(fds[i].fd)) {
                unsigned char data[MS_MAX];
                struct ms_message m = {.operation = MS_POLL, .a = 0, .b = (uint32_t)fds[i].events};
                interrupted = 0;
                if (exchange(fds[i].fd, &m, data, NULL) < 0) return -1;
                if (interrupted) { errno = EINTR; return -1; }
                fds[i].revents = (short)m.b;
            }
            if (fds[i].revents) ready++;
        }
        if (ready) return ready;
        long long remaining = deadline - milliseconds();
        if (timeout >= 0 && remaining <= 0) return 0;
        int slice = timeout < 0 || remaining > 5 ? 5 : (int)remaining;
        if (syscall(SYS_poll, host, count, slice) < 0) return -1;
    }
}
#endif
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    int native = 0;
    for (nfds_t i = 0; i < count; i++) native += is_network(fds[i].fd);
    if (!native) return (int)syscall(SYS_poll, fds, count, timeout);
#ifdef KER_MIXED_POLL_SELFTEST
    if (count != 1 || native != 1) return mixed_poll(fds, count, timeout);
#endif
    if (count != 1 || native != 1) { errno = EOPNOTSUPP; return -1; }
    long long deadline = milliseconds() + timeout;
    for (;;) {
        int slice = timeout < 0 ? 50 : (int)(deadline - milliseconds());
        if (slice < 0) slice = 0;
        if (slice > 50) slice = 50;
        unsigned char data[MS_MAX];
        struct ms_message m = {.operation = MS_POLL, .a = (uint32_t)slice, .b = (uint32_t)fds[0].events};
        interrupted = 0;
        long result = exchange(fds[0].fd, &m, data, NULL);
        if (interrupted) { errno = EINTR; return -1; }
        if (result < 0) return -1;
        fds[0].revents = (short)m.b;
        if (result || (timeout >= 0 && milliseconds() >= deadline)) return (int)result;
    }
}
/* pm_nl_ctl's single-reader event wait. Readiness belongs to the native
 * netlink socket, never the host RPC channel. Finite poll slices also let
 * terminated event readers release their resident sockets promptly. */
#ifdef KER_MIXED_POLL_SELFTEST
static int mixed_select(int nfds, fd_set *reads, fd_set *writes, fd_set *excepts, struct timeval *timeout)
{
    struct pollfd fds[64]; nfds_t count = 0;
    fd_set wanted_reads, wanted_writes, wanted_excepts;
    FD_ZERO(&wanted_reads); FD_ZERO(&wanted_writes); FD_ZERO(&wanted_excepts);
    if (reads) wanted_reads = *reads;
    if (writes) wanted_writes = *writes;
    if (excepts) wanted_excepts = *excepts;
    for (int fd = 0; fd < nfds; fd++) {
        short events = (FD_ISSET(fd, &wanted_reads) ? POLLIN : 0) |
                       (FD_ISSET(fd, &wanted_writes) ? POLLOUT : 0) |
                       (FD_ISSET(fd, &wanted_excepts) ? POLLPRI : 0);
        if (!events) continue;
        if (count == 64) { errno = EOPNOTSUPP; return -1; }
        fds[count++] = (struct pollfd){.fd = fd, .events = events};
    }
    int wait = -1; long long budget = 0;
    struct timespec before, after;
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_usec < 0 || timeout->tv_usec >= 1000000) { errno = EINVAL; return -1; }
        if (timeout->tv_sec > (INT_MAX - 999) / 1000) { errno = EOPNOTSUPP; return -1; }
        budget = (long long)timeout->tv_sec * 1000000 + timeout->tv_usec;
        wait = (int)((budget + 999) / 1000);
        clock_gettime(CLOCK_MONOTONIC, &before);
    }
    int result = __wrap_poll(fds, count, wait);
    if (timeout) {
        clock_gettime(CLOCK_MONOTONIC, &after);
        long long used = (after.tv_sec - before.tv_sec) * 1000000LL + (after.tv_nsec - before.tv_nsec) / 1000;
        long long remaining = budget > used ? budget - used : 0;
        timeout->tv_sec = remaining / 1000000; timeout->tv_usec = remaining % 1000000;
    }
    if (result < 0) return -1;
    for (nfds_t i = 0; i < count; i++) if (fds[i].revents & POLLNVAL) { errno = EBADF; return -1; }
    if (reads) FD_ZERO(reads);
    if (writes) FD_ZERO(writes);
    if (excepts) FD_ZERO(excepts);
    result = 0;
    for (nfds_t i = 0; i < count; i++) {
        int fd = fds[i].fd; short ready = fds[i].revents;
        if (reads && FD_ISSET(fd, &wanted_reads) && (ready & (POLLIN | POLLHUP | POLLERR))) { FD_SET(fd, reads); result++; }
        if (writes && FD_ISSET(fd, &wanted_writes) && (ready & (POLLOUT | POLLERR))) { FD_SET(fd, writes); result++; }
        if (excepts && FD_ISSET(fd, &wanted_excepts) && (ready & POLLPRI)) { FD_SET(fd, excepts); result++; }
    }
    return result;
}
#endif
int __wrap_select(int nfds, fd_set *reads, fd_set *writes, fd_set *excepts, struct timeval *timeout)
{
    if (nfds < 0 || nfds > FD_SETSIZE) { errno = EINVAL; return -1; }
    int native = 0, count = 0, selected = -1;
    for (int fd = 0; fd < nfds; fd++) {
        if (reads && FD_ISSET(fd, reads)) { count++; selected = fd; native += is_network(fd); }
        if (is_network(fd) && ((writes && FD_ISSET(fd, writes)) || (excepts && FD_ISSET(fd, excepts)))) native++;
    }
    if (!native) return (int)syscall(SYS_select, nfds, reads, writes, excepts, timeout);
#ifdef KER_MIXED_POLL_SELFTEST
    return mixed_select(nfds, reads, writes, excepts, timeout);
#endif
    if (native != 1 || count != 1 || writes || excepts || timeout) { errno = EOPNOTSUPP; return -1; }
    struct pollfd p = {.fd = selected, .events = POLLIN};
    int result = __wrap_poll(&p, 1, -1);
    if (result < 0) return -1;
    if (p.revents & POLLNVAL) { errno = EBADF; return -1; }
    FD_ZERO(reads);
    if (p.revents & (POLLIN | POLLHUP | POLLERR)) { FD_SET(selected, reads); return 1; }
    errno = EIO; return -1;
}

/* Import the unchanged input through bounded host-only chunks. The resident
 * kernel owns a sealed native file and executes every sendfile operation. */
static int same_input(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
ssize_t __wrap_sendfile(int out, int in, off_t *offset, size_t count)
{
    if (!is_network(out)) return syscall(SYS_sendfile, out, in, offset, count);
    if (is_network(in)) { errno = EOPNOTSUPP; return -1; }
    struct stat st;
    if (syscall(SYS_fstat, in, &st)) return -1;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > MS_INPUT_MAX || count > UINT32_MAX) {
        errno = EOPNOTSUPP; return -1;
    }
    off_t position = offset ? *offset : (off_t)syscall(SYS_lseek, in, 0, SEEK_CUR);
    if (position < 0) { errno = EINVAL; return -1; }
    unsigned char data[MS_MAX];
    if (!has_input[out] || !same_input(&st, &imported_inputs[out])) {
        has_input[out] = 0;
        struct ms_message start = {.operation = MS_INPUT_START, .a = (uint32_t)st.st_size};
        if (exchange(out, &start, data, NULL) < 0) return -1;
        for (off_t done = 0; done < st.st_size;) {
            size_t chunk = (size_t)(st.st_size - done);
            if (chunk > MS_MAX) chunk = MS_MAX;
            ssize_t got = syscall(SYS_pread64, in, data, chunk, done);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) { if (!got) errno = EIO; return -1; }
            struct ms_message write = {.operation = MS_INPUT_WRITE, .length = (uint32_t)got};
            if (exchange(out, &write, data, NULL) < 0) return -1;
            done += got;
        }
        struct stat after;
        if (syscall(SYS_fstat, in, &after)) return -1;
        if (!same_input(&st, &after)) { errno = ESTALE; return -1; }
        struct ms_message finish = {.operation = MS_INPUT_END};
        if (exchange(out, &finish, data, NULL) < 0) return -1;
        imported_inputs[out] = st; has_input[out] = 1;
    }
    int64_t wire_offset = position; memcpy(data, &wire_offset, sizeof(wire_offset));
    struct ms_message m = {.operation = MS_SENDFILE, .length = sizeof(wire_offset), .a = (uint32_t)count, .b = 1};
    long result = exchange(out, &m, data, NULL);
    if (result < 0) return write_result(result, 0);
    if (m.length != sizeof(wire_offset)) { errno = EPROTO; return -1; }
    memcpy(&wire_offset, data, sizeof(wire_offset));
    if (offset) *offset = (off_t)wire_offset;
    else if (syscall(SYS_lseek, in, (off_t)wire_offset, SEEK_SET) < 0) return -1;
    return result;
}

static int proc_file(const char *path)
{
    const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE");
    if (!ns) ns = "";
    if (strlen(ns) >= 64 || strlen(path) > 128) { errno = EINVAL; return -1; }
    int channel = open_channel();
    if (channel < 0) return -1;
    unsigned char data[MS_MAX]; strcpy((char *)data, ns); strcpy((char *)data + strlen(ns) + 1, path);
    struct ms_message m = {.operation = MS_FILE, .length = (uint32_t)(strlen(ns) + strlen(path) + 2)};
    long result = exchange(channel, &m, data, NULL);
    int error = errno; syscall(SYS_close, channel);
    if (result < 0) { errno = error; return -1; }
    int fd = (int)syscall(SYS_memfd_create, "native-proc", 1);
    if (fd < 0) return -1;
    if (syscall(SYS_write, fd, data, m.length) != m.length || syscall(SYS_lseek, fd, 0, SEEK_SET) < 0) {
        error = errno; syscall(SYS_close, fd); errno = error; return -1;
    }
    return fd;
}
int __wrap_open(const char *path, int flags, ...)
{
    int mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
#ifdef KER_PACKETDRILL_SELFTEST
    if (!strncmp(path, "/proc/sys/net/", 14)) {
        if ((flags & O_ACCMODE) == O_RDONLY) return proc_file(path);
        const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE"); if (!ns) ns = "";
        if (strlen(ns) >= 64 || strlen(path) > 128) { errno = EINVAL; return -1; }
        int fd = open_channel(); if (fd < 0) return -1;
        unsigned char data[MS_MAX]; strcpy((char *)data, ns); strcpy((char *)data + strlen(ns) + 1, path);
        struct ms_message m = {.operation = MS_PROC_OPEN, .a = (uint32_t)flags,
            .length = (uint32_t)(strlen(ns) + strlen(path) + 2)};
        if (exchange(fd, &m, data, NULL) < 0) { int e = errno; syscall(SYS_close, fd); errno = e; return -1; }
        int result = remember(fd);
        /* Bash duplicates this administrative transport onto stdout. Its
         * native proc file belongs to the last host channel reference, not
         * to the first close of the original pre-dup descriptor. */
        if (result >= 0) network_fds[result] = 2;
        return result;
    }
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NET_DEVICE_SELFTEST)
#ifdef KER_MACVTAP_SELFTEST
    if (!strncmp(path, "/dev/tap", 8)) {
        unsigned index; char trailing;
        if (sscanf(path, "/dev/tap%u%c", &index, &trailing) != 1 || !index ||
            flags != (O_RDWR | O_NONBLOCK)) { errno = EINVAL; return -1; }
        const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE"); if (!ns) ns = "";
        if (strlen(ns) >= 64) { errno = EINVAL; return -1; }
        int fd = open_channel(); if (fd < 0) return -1;
        unsigned char data[MS_MAX]; strcpy((char *)data, ns);
        struct ms_message m = {.operation = MS_MACVTAP_OPEN, .a = index,
            .length = (uint32_t)strlen(ns) + 1};
        if (exchange(fd, &m, data, NULL) < 0) {
            int error = errno; syscall(SYS_close, fd); errno = error; return -1;
        }
        return remember(fd);
    }
#endif
    if (!strcmp(path, "/dev/net/tun")) {
        if (flags != O_RDWR) { errno = EOPNOTSUPP; return -1; }
        const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE"); if (!ns) ns = "";
        if (strlen(ns) >= 64) { errno = EINVAL; return -1; }
        int fd = open_channel(); if (fd < 0) return -1;
        unsigned char data[MS_MAX]; strcpy((char *)data, ns);
        struct ms_message m = {.operation = MS_TUN_OPEN, .length = (uint32_t)strlen(ns) + 1};
        if (exchange(fd, &m, data, NULL) < 0) { int e = errno; syscall(SYS_close, fd); errno = e; return -1; }
        return remember(fd);
    }
#endif
    if (!strncmp(path, "/proc/net/", 10) || !strcmp(path, "/proc/sys/net/mptcp/enabled")) {
        if ((flags & O_ACCMODE) != O_RDONLY) { errno = EOPNOTSUPP; return -1; }
        return proc_file(path);
    }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}
FILE *__wrap_fopen(const char *path, const char *mode)
{
    if (!strncmp(path, "/proc/net/", 10) || !strcmp(path, "/proc/sys/net/mptcp/enabled")
#ifdef KER_PACKETDRILL_SELFTEST
        || !strncmp(path, "/proc/sys/net/", 14)
#endif
    ) {
        if (strcmp(mode, "r") && strcmp(mode, "re")) { errno = EOPNOTSUPP; return NULL; }
        int fd = proc_file(path);
        if (fd < 0) return NULL;
        FILE *stream = fdopen(fd, "r");
        if (!stream) { int e = errno; syscall(SYS_close, fd); errno = e; }
        return stream;
    }
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen) { errno = ENOSYS; return NULL; }
    return real_fopen(path, mode);
}
int __wrap_close(int fd)
{
#ifdef KER_PACKETDRILL_SELFTEST
    if (is_network(fd) && network_fds[fd] == 2) {
        network_fds[fd] = 0; has_input[fd] = 0;
        return (int)syscall(SYS_close, fd);
    }
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
    if (is_network(fd)) remote_epoll[fd] = 0;
#endif
    if (is_network(fd)) {
        /* Preserve original close ordering, including the native FIN and
         * TIME_WAIT transition, before releasing its host RPC transport. */
        unsigned char data[MS_MAX];
        struct ms_message m = {.operation = MS_CLOSE};
        long result = exchange(fd, &m, data, NULL);
        int error = errno;
        network_fds[fd] = 0; has_input[fd] = 0;
        syscall(SYS_close, fd); errno = error;
        return (int)result;
    }
    return (int)syscall(SYS_close, fd);
}
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
int __wrap_epoll_create(int size)
{
    const char *ns = getenv("KER_MPTCP_SOCKET_NAMESPACE"); if (!ns) ns = "";
    if (strlen(ns) >= 64) { errno = EINVAL; return -1; }
    int fd = open_channel(); if (fd < 0) return -1;
    unsigned char data[MS_MAX]; strcpy((char *)data, ns);
    struct ms_message m = {.operation = MS_EPOLL_OPEN, .a = (uint32_t)size, .length = (uint32_t)strlen(ns) + 1};
    long result = exchange(fd, &m, data, NULL);
    if (result < 0) { int error = errno; syscall(SYS_close, fd); errno = error; return -1; }
    if (remember(fd) < 0) return -1;
    remote_epoll[fd] = (int)result; return fd;
}
int __wrap_epoll_ctl(int epoll, int operation, int target, struct epoll_event *event)
{
    if (!is_network(epoll) && !is_network(target)) return (int)syscall(SYS_epoll_ctl, epoll, operation, target, event);
    if (!is_network(epoll) || !remote_epoll[epoll] || !is_network(target)) { errno = EBADF; return -1; }
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_EPOLL_CTL, .a = (uint32_t)remote_epoll[epoll], .b = (uint32_t)operation};
    if (event) { memcpy(data, event, sizeof(*event)); m.length = sizeof(*event); }
    return (int)exchange(target, &m, data, NULL);
}
int __wrap_epoll_wait(int epoll, struct epoll_event *events, int maximum, int timeout)
{
    if (!is_network(epoll)) return (int)syscall(SYS_epoll_wait, epoll, events, maximum, timeout);
    if (!remote_epoll[epoll] || maximum <= 0 || maximum > 64 || timeout < -1 || timeout > 1000) { errno = EOPNOTSUPP; return -1; }
    unsigned char data[MS_MAX];
    struct ms_message m = {.operation = MS_EPOLL_WAIT, .a = (uint32_t)maximum, .b = (uint32_t)timeout};
    long result = exchange(epoll, &m, data, NULL);
    if (result >= 0) {
        if (result > maximum || m.length != (size_t)result * sizeof(*events)) { errno = EPROTO; return -1; }
        memcpy(events, data, m.length);
    }
    return (int)result;
}
#endif
#ifdef KER_MPTCP_DIAG_PRELOAD
#ifdef KER_PACKETDRILL_SELFTEST
/* The original sysctl helper emits simple echo redirections and a bash
 * restore script. Bash's fixture echo function writes their exact bytes
 * through the native proc fd and propagates the real write result. */
int system(const char *command)
{
    if (!command || !strstr(command, "/proc/sys/net/") || !strchr(command, '>')) {
        int (*original)(const char *) = dlsym(RTLD_NEXT, "system");
        if (!original) { errno = ENOSYS; return -1; }
        return original(command);
    }
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) { execl("/bin/bash", "bash", "-c", command, (char *)NULL); _exit(127); }
    int status;
    while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) return -1; }
    return status;
}
ssize_t writev(int fd, const struct iovec *vectors, int count)
{
    if (!is_network(fd)) return syscall(SYS_writev, fd, vectors, count);
    if (count < 0 || count > IOV_MAX) { errno = EINVAL; return -1; }
    unsigned char bytes[MS_MAX]; size_t total = 0;
    for (int i = 0; i < count; i++) {
        if (vectors[i].iov_len > sizeof(bytes) - total) { errno = EMSGSIZE; return -1; }
        memcpy(bytes + total, vectors[i].iov_base, vectors[i].iov_len); total += vectors[i].iov_len;
    }
    return __wrap_write(fd, bytes, total);
}
#endif
FILE *fopen64(const char *path, const char *mode) { return __wrap_fopen(path, mode); }
int open64(const char *path, int flags, ...)
{
    int mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    return __wrap_open(path, flags, mode);
}
#endif
