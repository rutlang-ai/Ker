#define _GNU_SOURCE
#include "linux-mptcp-pm-wire.h"
#include "linux-selftest-runtime.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

struct namespace { char name[64]; int fd; };
struct client { int host, native, ns; pid_t pid; };
static struct namespace namespaces[16];
static struct client clients[64];
static unsigned created, deleted, sockets_created, sends, receives, sysctls, link_ups;
static int root_ns;
static long (*native_call)(unsigned, const unsigned long[6]);

static long call(unsigned operation, unsigned long a, unsigned long b, unsigned long c)
{
    unsigned long arguments[6] = {a, b, c, 0, 0, 0};
    long result = native_call(operation, arguments);
    if (result < 0) { errno = (int)-result; return -1; }
    return result;
}
static int select_ns(int fd) { return (int)call(KER_TEST_SETNS, fd, CLONE_NEWNET, 0); }
static int open_native(const char *name, int flags)
{
    return (int)call(KER_TEST_OPEN, (unsigned long)name, flags, 0);
}
static int find_ns(const char *name)
{
    for (unsigned i = 0; i < 16; i++)
        if (namespaces[i].fd >= 0 && !strcmp(namespaces[i].name, name)) return (int)i;
    errno = ENOENT;
    return -1;
}
static int named_ns(const char *name)
{
    if (!*name) return root_ns;
    int index = find_ns(name);
    return index < 0 ? -1 : namespaces[index].fd;
}
static void drop_client(struct client *client)
{
    if (client->native >= 0) close(client->native);
    if (client->ns >= 0) close(client->ns);
    if (client->host >= 0) close(client->host);
    *client = (struct client){-1, -1, -1, 0};
}
static char *string_argument(char *data, size_t length)
{
    if (!length || data[length - 1] || strlen(data) + 1 != length) { errno = EINVAL; return NULL; }
    return data;
}
static int create_namespace(const char *name)
{
    if (!*name || strlen(name) >= sizeof(namespaces[0].name)) { errno = EINVAL; return -1; }
    if (find_ns(name) >= 0) { errno = EEXIST; return -1; }
    unsigned slot;
    for (slot = 0; slot < 16 && namespaces[slot].fd >= 0; slot++);
    if (slot == 16) { errno = ENOSPC; return -1; }
    if (select_ns(root_ns) || call(KER_TEST_UNSHARE, CLONE_NEWNET, 0, 0)) return -1;
    int fd = open_native("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    int saved = errno;
    if (select_ns(root_ns)) { if (fd >= 0) close(fd); return -1; }
    if (fd < 0) { errno = saved; return -1; }
    strcpy(namespaces[slot].name, name);
    namespaces[slot].fd = fd;
    created++;
    return 0;
}
static int write_sysctl(char *text)
{
    char *equals = strchr(text, '=');
    if (!equals || strncmp(text, "net.", 4)) { errno = EINVAL; return -1; }
    *equals++ = 0;
    if (!*equals || strlen(text) > 128 || strlen(equals) > 128) { errno = EINVAL; return -1; }
    char path[160];
    snprintf(path, sizeof(path), "/proc/sys/%s", text);
    for (char *p = path + 10; *p; p++) {
        if (*p == '.') *p = '/';
        else if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')) {
            errno = EINVAL; return -1;
        }
    }
    int fd = open_native(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t result = write(fd, equals, strlen(equals));
    int error = errno;
    close(fd);
    if (result != (ssize_t)strlen(equals)) { errno = result < 0 ? error : EIO; return -1; }
    sysctls++;
    return 0;
}
static long dispatch(struct client *client, struct pm_message *m, char *data, size_t *output)
{
    char *name;
    *output = 0;
    switch (m->operation) {
    case PM_NEWNS:
    case PM_DELNS:
    case PM_UP:
    case PM_SOCKET:
        name = string_argument(data, m->length);
        if (!name) return -1;
        if (m->operation == PM_NEWNS) return create_namespace(name);
        if (m->operation == PM_DELNS) {
            int index = find_ns(name);
            if (index < 0) return -1;
            int result = close(namespaces[index].fd);
            if (!result) { namespaces[index].fd = -1; deleted++; }
            return result;
        }
        {
            int ns = named_ns(name);
            if (ns < 0 || select_ns(ns)) return -1;
            if (m->operation == PM_UP) {
                unsigned index = if_nametoindex("lo");
                if (!index || call(KER_TEST_IF_UP, index, 0, 0)) return -1;
                link_ups++; return 0;
            }
            if (client->native >= 0 || m->argument != NETLINK_GENERIC || m->flags != SOCK_RAW) {
                errno = EOPNOTSUPP; return -1;
            }
            client->ns = dup(ns);
            if (client->ns < 0) return -1;
            client->native = (int)call(KER_TEST_NETLINK, m->flags, m->argument, 0);
            if (client->native < 0) return -1;
            int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
            if (!kind || kind(client->native) != 3) { errno = ENOTSUP; return -1; }
            sockets_created++; return 0;
        }
    case PM_LISTNS:
        for (unsigned i = 0; i < 16; i++) if (namespaces[i].fd >= 0)
            *output += (size_t)snprintf(data + *output, PM_MAX - *output, "%s\n", namespaces[i].name);
        return 0;
    case PM_SYSCTL:
        name = memchr(data, 0, m->length);
        if (!name || name == data + m->length - 1 || data[m->length - 1]) { errno = EINVAL; return -1; }
        {
            int ns = named_ns(data);
            if (ns < 0 || select_ns(ns)) return -1;
            return write_sysctl(name + 1);
        }
    case PM_PROBE: {
        if (select_ns(root_ns)) return -1;
        int fd = open_native("/proc/sys/net/mptcp/enabled", O_RDONLY);
        if (fd < 0) return -1;
        ssize_t result = read(fd, data, PM_MAX);
        int error = errno;
        close(fd);
        if (result < 0) { errno = error; return -1; }
        *output = (size_t)result; return 0;
    }
    case PM_SEND:
    case PM_RECV:
    case PM_NAMEINDEX:
    case PM_INDEXNAME:
        if (client->native < 0 || client->ns < 0) { errno = ENOTCONN; return -1; }
        if (select_ns(client->ns)) return -1;
        if (m->operation == PM_NAMEINDEX) {
            if (!string_argument(data, m->length)) return -1;
            unsigned index = if_nametoindex(data);
            return index ? (long)index : -1;
        }
        if (m->operation == PM_INDEXNAME) {
            if (!if_indextoname(m->argument, data)) return -1;
            *output = strlen(data) + 1; return 0;
        }
        if (m->operation == PM_SEND) {
            if (m->length < sizeof(struct sockaddr_nl) || m->argument != sizeof(struct sockaddr_nl)) {
                errno = EINVAL; return -1;
            }
            struct sockaddr_nl address;
            memcpy(&address, data, sizeof(address));
            long result = sendto(client->native, data + sizeof(address), m->length - sizeof(address),
                                 (int)m->flags, (void *)&address, sizeof(address));
            if (result >= 0) sends++;
            return result;
        } else {
            struct sockaddr_nl address = {0};
            socklen_t length = sizeof(address);
            if (m->argument > PM_MAX - sizeof(address)) { errno = EMSGSIZE; return -1; }
            long result = recvfrom(client->native, data + sizeof(address), m->argument,
                                   (int)m->flags, (void *)&address, &length);
            if (result < 0) return -1;
            memcpy(data, &address, sizeof(address));
            m->argument = length;
            *output = sizeof(address) + (size_t)result;
            receives++;
            return result;
        }
    case PM_STOP:
    case PM_STATUS: {
        unsigned live_ns = 0, live_netlink = 0;
        for (unsigned i = 0; i < 16; i++) live_ns += namespaces[i].fd >= 0;
        for (unsigned i = 0; i < 64; i++) live_netlink += clients[i].native >= 0;
        *output = (size_t)snprintf(data, PM_MAX,
            "{\"created\":%u,\"deleted\":%u,\"live_namespaces\":%u,\"live_netlink\":%u,"
            "\"netlink_sockets\":%u,\"sends\":%u,\"receives\":%u,\"sysctls\":%u,\"link_ups\":%u}",
            created, deleted, live_ns, live_netlink, sockets_created, sends, receives, sysctls, link_ups);
        return 0;
    }
    default: errno = EOPNOTSUPP; return -1;
    }
}
int main(int argc, char **argv)
{
    if (argc != 2 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    native_call = dlsym(RTLD_DEFAULT, "ker_linux_selftest_call");
    if (!native_call) return 3;
    for (unsigned i = 0; i < 16; i++) namespaces[i].fd = -1;
    for (unsigned i = 0; i < 64; i++) clients[i] = (struct client){-1, -1, -1, 0};
    root_ns = open_native("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    if (root_ns < 0) { perror("root native namespace"); return 4; }
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, argv[1]);
    if (listener < 0 || bind(listener, (void *)&address, sizeof(address)) || chmod(argv[1], 0600) || listen(listener, 16)) {
        perror("PM test listener"); return 5;
    }
    int stopping = 0, failed = 0;
    while (!stopping) {
        struct pollfd fds[65] = {{listener, POLLIN, 0}};
        for (unsigned i = 0; i < 64; i++) fds[i + 1] = (struct pollfd){clients[i].host, POLLIN, 0};
        if (poll(fds, 65, -1) < 0) { if (errno == EINTR) continue; failed = 1; break; }
        if (fds[0].revents & POLLIN) {
            int fd = accept(listener, NULL, NULL);
            if (fd < 0) { failed = 1; break; }
            struct ucred cred;
            socklen_t size = sizeof(cred);
            unsigned slot;
            for (slot = 0; slot < 64 && clients[slot].host >= 0; slot++);
            if (slot == 64 || getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &size) || cred.uid != getuid()) close(fd);
            else clients[slot] = (struct client){fd, -1, -1, cred.pid};
        }
        for (unsigned i = 0; i < 64; i++) if (fds[i + 1].revents) {
            struct { struct pm_message header; char bytes[PM_MAX]; } packet;
            ssize_t size = recv(clients[i].host, &packet, sizeof(packet), MSG_TRUNC);
            if (!size) { drop_client(&clients[i]); continue; }
            if (size < (ssize_t)sizeof(packet.header) || size > (ssize_t)sizeof(packet) ||
                packet.header.magic != PM_MAGIC || packet.header.extra || packet.header.result || packet.header.length != (size_t)size - sizeof(packet.header)) {
                drop_client(&clients[i]); continue;
            }
            size_t length = 0;
            long result = dispatch(&clients[i], &packet.header, packet.bytes, &length);
            int error = errno;
            if (select_ns(root_ns)) { failed = 1; stopping = 1; break; }
            packet.header.result = result < 0 ? -error : result;
            packet.header.length = (uint32_t)length;
            if (send(clients[i].host, &packet, sizeof(packet.header) + length, MSG_NOSIGNAL) != (ssize_t)(sizeof(packet.header) + length))
                drop_client(&clients[i]);
            if (packet.header.operation == PM_STOP) stopping = 1;
        }
    }
    for (unsigned i = 0; i < 64; i++) drop_client(&clients[i]);
    for (unsigned i = 0; i < 16; i++) if (namespaces[i].fd >= 0) close(namespaces[i].fd);
    select_ns(root_ns);
    close(root_ns); close(listener); unlink(argv[1]);
    return failed;
}
