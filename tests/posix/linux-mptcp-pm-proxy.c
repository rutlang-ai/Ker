#define _GNU_SOURCE
#include "linux-mptcp-pm-wire.h"
#include <errno.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* Linked only into the original pm_nl_ctl selftest, never a production preload.
 * Only the transport/namespace changes: original Netlink requests and kernel
 * responses cross the channel byte-for-byte, including NLMSG_ERROR replies. */
static int proxy_fd = -1;
static long exchange(int fd, struct pm_message *message, void *data)
{
    struct { struct pm_message header; char bytes[PM_MAX]; } packet;
    if (message->length > PM_MAX) { errno = EMSGSIZE; return -1; }
    message->magic = PM_MAGIC;
    packet.header = *message;
    memcpy(packet.bytes, data, message->length);
    size_t size = sizeof(packet.header) + message->length;
    if (syscall(SYS_sendto, fd, &packet, size, MSG_NOSIGNAL, NULL, 0) != (ssize_t)size) return -1;
    ssize_t got = syscall(SYS_recvfrom, fd, &packet, sizeof(packet), MSG_TRUNC, NULL, NULL);
    if (got < 0) return -1;
    if (got < (ssize_t)sizeof(packet.header) || got > (ssize_t)sizeof(packet) ||
        packet.header.magic != PM_MAGIC || packet.header.operation != message->operation ||
        packet.header.length != (size_t)got - sizeof(packet.header)) { errno = EPROTO; return -1; }
    *message = packet.header;
    if (message->result < 0) { errno = (int)-message->result; return -1; }
    memcpy(data, packet.bytes, message->length);
    return message->result;
}
int __wrap_socket(int domain, int type, int protocol)
{
    if (domain != AF_NETLINK || type != SOCK_RAW || protocol != NETLINK_GENERIC || proxy_fd >= 0) {
        errno = EOPNOTSUPP; return -1;
    }
    const char *path = getenv("KER_MPTCP_PM_SOCKET");
    const char *ns = getenv("KER_MPTCP_PM_NAMESPACE");
    if (!path || !ns || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path) || strlen(ns) >= 64) {
        errno = EINVAL; return -1;
    }
    int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, path);
    if (syscall(SYS_connect, fd, &address, sizeof(address))) { int e = errno; syscall(SYS_close, fd); errno = e; return -1; }
    char data[PM_MAX];
    strcpy(data, ns);
    struct pm_message message = {.operation = PM_SOCKET, .length = (uint32_t)strlen(ns) + 1,
                                 .flags = type, .argument = protocol};
    if (exchange(fd, &message, data) < 0) { int e = errno; syscall(SYS_close, fd); errno = e; return -1; }
    proxy_fd = fd;
    return fd;
}
ssize_t __wrap_sendto(int fd, const void *bytes, size_t length, int flags,
                      const struct sockaddr *address, socklen_t address_length)
{
    if (fd != proxy_fd) { errno = EBADF; return -1; }
    if (!address || address_length != sizeof(struct sockaddr_nl) ||
        length > PM_MAX - sizeof(struct sockaddr_nl)) { errno = EMSGSIZE; return -1; }
    char data[PM_MAX];
    memcpy(data, address, address_length);
    memcpy(data + address_length, bytes, length);
    struct pm_message message = {.operation = PM_SEND, .length = (uint32_t)(length + address_length),
                                 .flags = flags, .argument = address_length};
    return exchange(fd, &message, data);
}
ssize_t __wrap_recvfrom(int fd, void *bytes, size_t length, int flags,
                        struct sockaddr *address, socklen_t *address_length)
{
    if (fd != proxy_fd) { errno = EBADF; return -1; }
    if (length > PM_MAX - sizeof(struct sockaddr_nl) || (address && !address_length)) { errno = EINVAL; return -1; }
    char data[PM_MAX];
    struct pm_message message = {.operation = PM_RECV, .argument = (uint32_t)length, .flags = flags};
    long result = exchange(fd, &message, data);
    if (result < 0) return -1;
    if ((size_t)result > length || message.length != (size_t)result + sizeof(struct sockaddr_nl) ||
        message.argument > sizeof(struct sockaddr_nl)) { errno = EPROTO; return -1; }
    memcpy(bytes, data + sizeof(struct sockaddr_nl), (size_t)result);
    if (address) {
        size_t copy = *address_length < message.argument ? *address_length : message.argument;
        memcpy(address, data, copy); *address_length = message.argument;
    }
    return result;
}
unsigned __wrap_if_nametoindex(const char *name)
{
    if (proxy_fd < 0 || strlen(name) >= IF_NAMESIZE) { errno = ENODEV; return 0; }
    char data[PM_MAX]; strcpy(data, name);
    struct pm_message message = {.operation = PM_NAMEINDEX, .length = (uint32_t)strlen(name) + 1};
    long result = exchange(proxy_fd, &message, data);
    return result < 0 ? 0 : (unsigned)result;
}
char *__wrap_if_indextoname(unsigned index, char *name)
{
    if (proxy_fd < 0) { errno = ENOTCONN; return NULL; }
    char data[PM_MAX];
    struct pm_message message = {.operation = PM_INDEXNAME, .argument = index};
    if (exchange(proxy_fd, &message, data) < 0) return NULL;
    if (!message.length || message.length > IF_NAMESIZE || data[message.length - 1]) { errno = EPROTO; return NULL; }
    memcpy(name, data, message.length); return name;
}
int __wrap_close(int fd)
{
    if (fd == proxy_fd) proxy_fd = -1;
    return (int)syscall(SYS_close, fd);
}
