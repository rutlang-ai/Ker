#define _GNU_SOURCE
#include "socket-broker-server.h"
#include "socket-broker-protocol.h"
#include <ker/posix.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include "tcp-observer-diag-wire.h"
#include "member-census-diag-wire.h"
#include "member-census-diag.h"
#include "member-census-runtime.h"

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

struct sb_group {
    bool live;
    uint16_t port;
    int base_fd[2];
    uint32_t member_mark[2];
    uint64_t member_cookie[2];
    size_t handles;
};
struct sb_object {
    bool live;
    enum ker_socket_broker_kind kind;
    uint32_t rights;
    dev_t capability_dev;
    ino_t capability_ino;
    int capability_read_fd;
    int native_fd;
    int group_slot;
    uint8_t group_index;
    uint64_t observer_cookie;
    uint32_t observer_source;
    uint32_t observer_destination;
    uint16_t observer_source_port;
    uint16_t observer_destination_port;
    uint32_t census_mark;
    uint16_t census_local_port;
    uint64_t census_listener_cookie;
};
struct sb_client {
    int fd;
    int pidfd;
    pid_t pid;
    struct ucred credential;
    uint64_t sequence;
    int census_job;
};

#define KER_SB_CENSUS_JOBS 4
struct sb_census_job {
    bool live;
    int client_slot;
    int client_fd;
    struct ker_sb_header request;
    uint64_t ticket;
};
struct ker_socket_broker_server {
    int listener;
    char path[KER_SB_PATH_MAX + 1];
    dev_t path_dev;
    ino_t path_ino;
    bool path_bound;
    bool running;
    bool stop_when_empty;
    int failure;
    uint64_t runtime_lease;
    bool runtime_lease_live;
    struct sb_object objects[KER_SB_OBJECTS];
    struct sb_group groups[KER_SB_OBJECTS];
    struct sb_client clients[KER_SB_CLIENTS];
    struct sb_census_job census_jobs[KER_SB_CENSUS_JOBS];
};


static int host_close(int fd)
{
    if (fd >= 0) return (int)syscall(SYS_close, fd);
    return 0;
}
static void release_runtime_lease(struct ker_socket_broker_server *server)
{
    if (server && server->runtime_lease_live) {
        if (ker_member_census_server_release(server->runtime_lease)) abort();
        server->runtime_lease_live = false;
    }
}
static int host_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{ return (int)syscall(SYS_getsockopt, fd, level, option, value, length); }
static int fail(int error) { errno = error; return -1; }

/* Socket options are copied as flat bytes in the broker protocol. Keep the
 * surface explicit: options containing pointers or descriptor values need a
 * dedicated translation and must never be forwarded as opaque client bytes. */
static bool socket_option_supported(int level, int option, bool setting)
{
    if (level == SOL_SOCKET) {
        switch (option) {
        case SO_REUSEADDR:
        case SO_REUSEPORT:
        case SO_KEEPALIVE:
        case SO_RCVBUF:
        case SO_SNDBUF:
        case SO_RCVLOWAT:
        case SO_SNDLOWAT:
        case SO_LINGER:
        case SO_RCVTIMEO:
        case SO_SNDTIMEO:
            return true;
        case SO_TYPE:
        case SO_ERROR:
        case SO_DOMAIN:
        case SO_PROTOCOL:
        case SO_ACCEPTCONN:
            return !setting;
#ifdef SO_COOKIE
        case SO_COOKIE:
            return !setting;
#endif
        default:
            return false;
        }
    }
    if (level == IPPROTO_TCP) {
        switch (option) {
        case TCP_NODELAY:
        case TCP_CORK:
        case TCP_DEFER_ACCEPT:
        case TCP_KEEPIDLE:
        case TCP_KEEPINTVL:
        case TCP_KEEPCNT:
        case TCP_FASTOPEN:
            return true;
        default:
            return false;
        }
    }
    if (level == IPPROTO_IPV6 && option == IPV6_V6ONLY) return true;
    return false;
}

static bool socket_linger_is_nonblocking(const void *value, uint32_t length)
{
    /* Original Linux consumes the structure prefix when optlen is larger. */
    if (length < sizeof(struct linger)) return true;
    struct linger linger_value;
    memcpy(&linger_value, value, sizeof(linger_value));
    return !linger_value.l_onoff || linger_value.l_linger == 0;
}

static uint32_t required_right(uint16_t operation)
{
    switch (operation) {
    case KER_SB_TCP_OBSERVER_CREATE:
        return KER_SOCKET_BROKER_NAME | KER_SOCKET_BROKER_OPTION;
    case KER_SB_TCP_OBSERVER_SNAPSHOT: return KER_SOCKET_BROKER_READ;
    case KER_SB_READ: return KER_SOCKET_BROKER_READ;
    case KER_SB_WRITE: return KER_SOCKET_BROKER_WRITE;
    case KER_SB_GETSOCKNAME: case KER_SB_GETPEERNAME: return KER_SOCKET_BROKER_NAME;
    case KER_SB_GETSOCKOPT: return KER_SOCKET_BROKER_OPTION;
    case KER_SB_EPOLL_WAIT: return KER_SOCKET_BROKER_WAIT;
    case KER_SB_DUP: case KER_SB_SETFL: case KER_SB_FIONBIO:
    case KER_SB_BIND: case KER_SB_CONNECT: case KER_SB_LISTEN: case KER_SB_ACCEPT4:
    case KER_SB_SHUTDOWN: case KER_SB_SETSOCKOPT: case KER_SB_EPOLL_CTL:
        return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_FIONREAD: case KER_SB_RECV: return KER_SOCKET_BROKER_READ;
    case KER_SB_SEND: return KER_SOCKET_BROKER_WRITE;
    case KER_SB_REUSEPORT_GROUP_CREATE: case KER_SB_REUSEPORT_GROUP_MEMBER:
    case KER_SB_REUSEPORT_GROUP_SELECT: return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_MEMBER_CENSUS_CREATE: return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_MEMBER_CENSUS_SNAPSHOT: return KER_SOCKET_BROKER_READ;
    default: return 0;
    }
}

static void close_client(struct ker_socket_broker_server *server, struct sb_client *client)
{
    if (client->census_job >= 0 && client->census_job < KER_SB_CENSUS_JOBS) {
        struct sb_census_job *job = &server->census_jobs[client->census_job];
        if (job->live) (void)ker_member_census_query_cancel(job->ticket);
    }
    (void)host_close(client->fd);
    (void)host_close(client->pidfd);
    *client = (struct sb_client){.fd = -1, .pidfd = -1, .census_job = -1};
}

static void close_object(struct ker_socket_broker_server *server, struct sb_object *object)
{
    if (!object->live) return;
    /* Do not retain the adopted descriptor through epoll metadata. The final
     * capability close is the final userspace fd close; original Linux applies
     * its own epoll/OFD close semantics. */
    if (object->native_fd >= 0) (void)close(object->native_fd);
    if (object->group_slot >= 0) {
        struct sb_group *group = &server->groups[object->group_slot];
        if (group && group->live && group->handles && --group->handles == 0) {
            (void)close(group->base_fd[0]);
            (void)close(group->base_fd[1]);
            *group = (struct sb_group){.base_fd = {-1, -1}};
        }
    }
    (void)host_close(object->capability_read_fd);
    *object = (struct sb_object){.capability_read_fd = -1, .native_fd = -1, .group_slot = -1};
}

static size_t object_count(const struct ker_socket_broker_server *server)
{
    size_t result = 0;
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) result += server->objects[i].live;
    return result;
}
static size_t client_count(const struct ker_socket_broker_server *server)
{
    size_t result = 0;
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) result += server->clients[i].fd >= 0;
    return result;
}

static struct sb_object *lookup_cap(struct ker_socket_broker_server *server, int fd)
{
    struct stat identity = {0};
    int flags = (int)syscall(SYS_fcntl, fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY ||
        syscall(SYS_fstat, fd, &identity) || !S_ISFIFO(identity.st_mode)) return NULL;
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        if (server->objects[i].live && server->objects[i].capability_dev == identity.st_dev &&
            server->objects[i].capability_ino == identity.st_ino) return &server->objects[i];
    return NULL;
}

static int make_capability(struct ker_socket_broker_server *server, int native_fd,
    enum ker_socket_broker_kind kind, uint32_t rights, size_t *slot_out)
{
    size_t slot = KER_SB_OBJECTS;
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) if (!server->objects[i].live) { slot = i; break; }
    if (slot == KER_SB_OBJECTS) return fail(EMFILE);
    int pair[2] = {-1, -1};
    if (syscall(SYS_pipe2, pair, O_CLOEXEC | O_NONBLOCK)) return -1;
    struct stat identity = {0};
    int flags = (int)syscall(SYS_fcntl, pair[1], F_GETFL);
    if (flags < 0 || syscall(SYS_fstat, pair[1], &identity) || !S_ISFIFO(identity.st_mode) ||
        (flags & O_ACCMODE) != O_WRONLY) {
        int error = errno ? errno : EOPNOTSUPP;
        (void)host_close(pair[0]); (void)host_close(pair[1]);
        return fail(error);
    }
    server->objects[slot] = (struct sb_object){.live = true, .kind = kind,
        .rights = rights, .capability_dev = identity.st_dev, .capability_ino = identity.st_ino,
        .capability_read_fd = pair[0], .native_fd = native_fd, .group_slot = -1};
    if (slot_out) *slot_out = slot;
    return pair[1];
}

static int group_handle(struct ker_socket_broker_server *server, int group_slot,
    int native_fd, enum ker_socket_broker_kind kind, uint32_t rights, unsigned index)
{
    size_t object_slot = KER_SB_OBJECTS;
    int capability = make_capability(server, native_fd, kind, rights, &object_slot);
    if (capability < 0) return -1;
    struct sb_object *object = &server->objects[object_slot];
    object->group_slot = group_slot;
    object->group_index = (uint8_t)index;
    server->groups[group_slot].handles++;
    return capability;
}

static int member_census_capability(struct ker_socket_broker_server *server,
    struct sb_object *group_object, unsigned index)
{
    if (!group_object || group_object->kind != KER_SOCKET_BROKER_REUSEPORT_GROUP ||
        group_object->group_slot < 0 || index > 1) return fail(ENOTSOCK);
    struct sb_group *group = &server->groups[group_object->group_slot];
    if (!group->live || !group->member_mark[index] || !group->member_cookie[index])
        return fail(EBADF);
    size_t slot = KER_SB_OBJECTS;
    int capability = make_capability(server, -1, KER_SOCKET_BROKER_MEMBER_CENSUS,
        KER_SOCKET_BROKER_READ, &slot);
    if (capability < 0) return -1;
    /* Metadata only: deliberately keep group_slot=-1 and native_fd=-1 so
     * census capabilities neither retain the listener group nor any TCP fd. */
    struct sb_object *object = &server->objects[slot];
    object->census_mark = group->member_mark[index];
    object->census_local_port = group->port;
    object->census_listener_cookie = group->member_cookie[index];
    return capability;
}

static int reuseport_filter(int fd, unsigned index)
{
    struct sock_filter instruction = BPF_STMT(BPF_RET | BPF_K, index);
    struct sock_fprog program = {.len = 1, .filter = &instruction};
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &program, sizeof(program));
}

static int native_net_admin_present(void)
{
    return ker_member_census_diag_require_net_admin();
}

static int allocate_member_mark(uint32_t *mark)
{
    return ker_member_census_mark_allocate(mark);
}

static int set_member_mark(int fd, uint32_t mark)
{
    if (!mark) return fail(EINVAL);
    return setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
}

static int socket_cookie(int fd, uint64_t *cookie)
{
    socklen_t length = sizeof(*cookie);
    *cookie = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, cookie, &length)) return -1;
    if (length != sizeof(*cookie) || !*cookie) return fail(EPROTO);
    return 0;
}

static bool group_port_reserved(const struct ker_socket_broker_server *server, uint16_t port)
{
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        if (server->groups[i].live && server->groups[i].port == port) return true;
    return false;
}

static bool any_live_group(const struct ker_socket_broker_server *server)
{
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        if (server->groups[i].live) return true;
    return false;
}

static int broker_has_binding(const struct ker_socket_broker_server *server, uint16_t port,
    bool *found)
{
    *found = false;
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) {
        const struct sb_object *object = &server->objects[i];
        if (!object->live || object->kind != KER_SOCKET_BROKER_SOCKET || object->group_slot >= 0)
            continue;
        struct sockaddr_storage address = {0};
        socklen_t length = sizeof(address);
        if (getsockname(object->native_fd, (struct sockaddr *)&address, &length)) return -1;
        uint16_t current = address.ss_family == AF_INET ?
            ((struct sockaddr_in *)&address)->sin_port :
            address.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&address)->sin6_port : 0;
        if (current == htons(port) && current) { *found = true; return 0; }
    }
    return 0;
}

static bool requested_port_reserved(const struct ker_socket_broker_server *server,
    const void *address, socklen_t length)
{
    if (!address || length < sizeof(sa_family_t)) return false;
    const struct sockaddr *sa = address;
    uint16_t port = 0;
    if (sa->sa_family == AF_INET && length >= sizeof(struct sockaddr_in))
        port = ntohs(((const struct sockaddr_in *)address)->sin_port);
    else if (sa->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6))
        port = ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
    return port && group_port_reserved(server, port);
}

static int socket_reuseport_enabled(int fd, bool *enabled)
{
    int value = 0;
    socklen_t length = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, &length)) return -1;
    if (length != sizeof(value)) return fail(EPROTO);
    *enabled = value != 0;
    return 0;
}

static int construct_reuseport_group(struct ker_socket_broker_server *server,
    const struct sockaddr_in *address, int backlog, uint32_t rights)
{
    if (!server || !address || server->listener < 0 ||
        address->sin_family != AF_INET || !address->sin_port || backlog < 0 ||
        !rights || (rights & ~KER_SOCKET_BROKER_ALL)) return fail(EINVAL);
    int authority = native_net_admin_present();
    if (authority < 0) return fail(-authority);
    uint16_t port = ntohs(address->sin_port);
    if (group_port_reserved(server, port)) return fail(EADDRINUSE);
    bool existing_binding = false;
    if (broker_has_binding(server, port, &existing_binding)) return -1;
    if (existing_binding) return fail(EADDRINUSE);
    size_t slot = KER_SB_OBJECTS;
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        if (!server->groups[i].live) { slot = i; break; }
    if (slot == KER_SB_OBJECTS) return fail(EMFILE);
    uint32_t marks[2] = {0};
    int mark_status = allocate_member_mark(&marks[0]);
    if (!mark_status) mark_status = allocate_member_mark(&marks[1]);
    if (mark_status) return fail(-mark_status);
    int listener0 = -1, listener1 = -1;
    int one = 1;
    listener0 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener0 < 0) goto error;
    if (setsockopt(listener0, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) ||
        set_member_mark(listener0, marks[0]) ||
        bind(listener0, (const struct sockaddr *)address, sizeof(*address)) ||
        listen(listener0, backlog) || reuseport_filter(listener0, 0)) goto error;
    uint64_t cookies[2] = {0};
    if (socket_cookie(listener0, &cookies[0])) goto error;
    /* Selector zero is live before member one joins; traffic cannot target
     * an unpublished listener during group construction. */
    listener1 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener1 < 0) goto error;
    if (setsockopt(listener1, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) ||
        set_member_mark(listener1, marks[1]) ||
        bind(listener1, (const struct sockaddr *)address, sizeof(*address)) ||
        listen(listener1, backlog)) goto error;
    if (socket_cookie(listener1, &cookies[1])) goto error;
    server->groups[slot] = (struct sb_group){.live = true, .port = port,
        .base_fd = {listener0, listener1}, .member_mark = {marks[0], marks[1]},
        .member_cookie = {cookies[0], cookies[1]}, .handles = 0};
    int capability = group_handle(server, (int)slot, -1,
        KER_SOCKET_BROKER_REUSEPORT_GROUP, rights, 0);
    if (capability < 0) {
        int saved = errno;
        (void)close(listener0); (void)close(listener1);
        server->groups[slot] = (struct sb_group){.base_fd = {-1, -1}};
        errno = saved;
        return -1;
    }
    return capability;
error: {
        int saved = errno;
        if (listener1 >= 0) (void)close(listener1);
        if (listener0 >= 0) (void)close(listener0);
        errno = saved;
        return -1;
    }
}

int ker_socket_broker_server_reuseport_group_create(struct ker_socket_broker_server *server,
    const struct sockaddr_in *address, int backlog, uint32_t rights)
{
    if (!server || server->running) return fail(server ? EBUSY : EINVAL);
    return construct_reuseport_group(server, address, backlog, rights);
}

int ker_socket_broker_server_adopt(struct ker_socket_broker_server *server,
    int native_fd, enum ker_socket_broker_kind kind, uint32_t rights)
{
    if (!server || server->listener < 0 || native_fd < 0 ||
        (kind != KER_SOCKET_BROKER_SOCKET && kind != KER_SOCKET_BROKER_EPOLL) ||
        !rights || (rights & ~KER_SOCKET_BROKER_ALL)) return fail(EINVAL);
    if (server->running) return fail(EBUSY);
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        if (server->objects[i].live && server->objects[i].native_fd == native_fd) return fail(EALREADY);
    int descriptor_kind = ker_posix_descriptor_kind(native_fd);
    if (descriptor_kind < 0) return -1;
    int expected_kind = kind == KER_SOCKET_BROKER_SOCKET ?
        KER_POSIX_DESCRIPTOR_SOCKET : KER_POSIX_DESCRIPTOR_EPOLL;
    if (descriptor_kind != expected_kind) return fail(descriptor_kind == KER_POSIX_DESCRIPTOR_HOST ? EBADF : ENOTSOCK);
    int original_flags = -1;
    bool added_nonblock = false;
    if (kind == KER_SOCKET_BROKER_SOCKET) {
        int domain = -1, type = -1;
        socklen_t length = sizeof(domain);
        if (getsockopt(native_fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) ||
            length != sizeof(domain) || (domain != AF_INET && domain != AF_INET6)) {
            return fail(ENOTSOCK);
        }
        length = sizeof(type);
        if (getsockopt(native_fd, SOL_SOCKET, SO_TYPE, &type, &length) ||
            length != sizeof(type) || (type != SOCK_STREAM && type != SOCK_DGRAM)) {
            return fail(EPROTONOSUPPORT);
        }
        struct linger linger_value = {0};
        length = sizeof(linger_value);
        if (getsockopt(native_fd, SOL_SOCKET, SO_LINGER, &linger_value, &length)) return -1;
        if (length != sizeof(linger_value)) return fail(EPROTO);
        if (linger_value.l_onoff && linger_value.l_linger != 0)
            return fail(EOPNOTSUPP);
        original_flags = fcntl(native_fd, F_GETFL);
        if (original_flags < 0) return -1;
        if (!(original_flags & O_NONBLOCK) && fcntl(native_fd, F_SETFL, original_flags | O_NONBLOCK) < 0) {
            return -1;
        }
        added_nonblock = !(original_flags & O_NONBLOCK);
    }
    /* A successful adoption transfers this fd-table entry to the broker.
     * The caller must not use or close native_fd after success. */
    int capability = make_capability(server, native_fd, kind, rights, NULL);
    if (capability < 0 && added_nonblock) {
        int error = errno;
        (void)fcntl(native_fd, F_SETFL, original_flags);
        errno = error;
    }
    return capability;
}

static int receive_request(struct sb_client *client, struct ker_sb_header *header,
    unsigned char *payload, size_t *payload_length, int fds[KER_SB_MAX_RIGHTS], size_t *fd_count)
{
    unsigned char packet[KER_SB_MAX_PACKET];
    char control[CMSG_SPACE(sizeof(int) * KER_SB_MAX_RIGHTS) + CMSG_SPACE(sizeof(struct ucred))] = {0};
    struct iovec iov = {.iov_base = packet, .iov_len = sizeof(packet)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t amount = syscall(SYS_recvmsg, client->fd, &message,
        MSG_DONTWAIT | MSG_CMSG_CLOEXEC | MSG_TRUNC);
    if (amount < 0) return errno == EAGAIN || errno == EINTR ? 1 : -1;
    size_t found = 0;
    unsigned credential_count = 0;
    struct ucred sender = {0};
    bool malformed = amount == 0 || !!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET) { malformed = true; continue; }
        if (cmsg->cmsg_type == SCM_CREDENTIALS) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(sender)) || ++credential_count != 1) {
                malformed = true; continue;
            }
            memcpy(&sender, CMSG_DATA(cmsg), sizeof(sender));
            continue;
        }
        if (cmsg->cmsg_type != SCM_RIGHTS) { malformed = true; continue; }
        if (cmsg->cmsg_len < CMSG_LEN(0)) { malformed = true; continue; }
        if (cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
            (cmsg->cmsg_len - CMSG_LEN(0)) % sizeof(int)) malformed = true;
        size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        int *received = (int *)CMSG_DATA(cmsg);
        for (size_t i = 0; i < count; ++i) {
            if (found < KER_SB_MAX_RIGHTS) fds[found] = received[i];
            else (void)host_close(received[i]);
            found++;
        }
    }
    if (malformed || credential_count != 1 || sender.pid != client->credential.pid ||
        sender.uid != client->credential.uid || sender.gid != client->credential.gid ||
        (size_t)amount < sizeof(*header)) goto invalid;
    memcpy(header, packet, sizeof(*header));
    if (header->magic != KER_SB_MAGIC || header->version != KER_SB_VERSION ||
        header->flags || header->result || header->payload_length > KER_SB_MAX_REQUEST ||
        (size_t)amount != sizeof(*header) + header->payload_length ||
        client->sequence == UINT64_MAX || header->sequence != client->sequence + 1 ||
        header->rights_count != found ||
        found > KER_SB_MAX_RIGHTS) goto invalid;
    memcpy(payload, packet + sizeof(*header), header->payload_length);
    *payload_length = header->payload_length;
    *fd_count = found;
    client->sequence = header->sequence;
    return 0;
invalid:
    for (size_t i = 0; i < found && i < KER_SB_MAX_RIGHTS; ++i) (void)host_close(fds[i]);
    return -2;
}

static int send_reply(struct sb_client *client, const struct ker_sb_header *request,
    int64_t result, const void *payload, size_t payload_length, int passed_fd)
{
    struct ker_sb_header reply = {.magic = KER_SB_MAGIC, .version = KER_SB_VERSION,
        .operation = request->operation, .payload_length = (uint32_t)payload_length,
        .rights_count = passed_fd >= 0 ? 1 : 0, .sequence = request->sequence, .result = result};
    struct iovec iov[2] = {{&reply, sizeof(reply)}, {(void *)payload, payload_length}};
    struct msghdr message = {.msg_iov = iov, .msg_iovlen = payload_length ? 2u : 1u};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    if (passed_fd >= 0) {
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));
    }
    ssize_t sent;
    do {
        sent = syscall(SYS_sendmsg, client->fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)(sizeof(reply) + payload_length) ? 0 : -1;
}

static int make_native_object(struct ker_socket_broker_server *server, int native_fd,
    enum ker_socket_broker_kind kind, uint32_t rights, int *client_fd)
{
    int fd = make_capability(server, native_fd, kind, rights, NULL);
    if (fd < 0) return -errno;
    *client_fd = fd;
    return 0;
}

static int object_for_request(struct ker_socket_broker_server *server, int cap_fd,
    uint16_t operation, enum ker_socket_broker_kind kind, struct sb_object **out)
{
    struct sb_object *object = lookup_cap(server, cap_fd);
    if (!object) return -EBADF;
    if (object->kind != kind) return -ENOTSOCK;
    uint32_t right = required_right(operation);
    if (right && (object->rights & right) != right) return -EACCES;
    *out = object;
    return 0;
}

static int managed_member_status(struct sb_object *object, int operation)
{
    if (object->group_slot < 0) return 0;
    switch (operation) {
    case KER_SB_BIND: case KER_SB_CONNECT: case KER_SB_LISTEN:
    case KER_SB_SHUTDOWN: case KER_SB_SETSOCKOPT:
        return -EOPNOTSUPP;
    default:
        return 0;
    }
}

static uint32_t diag_sequence;

static int observer_query(const struct sb_object *object,
    struct ker_sb_tcp_observer_snapshot *snapshot)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
        KER_TCP_OBSERVER_NETLINK_PROTOCOL);
    if (fd < 0) return -errno;
    int status = 0;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    uint32_t sequence = ++diag_sequence;
    if (!sequence) sequence = ++diag_sequence;
    struct {
        struct ker_nlmsghdr header;
        struct ker_inet_diag_req_v2 request;
    } __attribute__((packed)) request = {
        .header = {.length = sizeof(request), .type = KER_TCP_OBSERVER_SOCK_DIAG_BY_FAMILY,
            .flags = KER_TCP_OBSERVER_NLM_F_REQUEST, .sequence = sequence},
        .request = {.family = AF_INET, .protocol = KER_TCP_OBSERVER_PROTOCOL_TCP,
            .states = UINT32_MAX, .id = {.sport = object->observer_source_port,
                .dport = object->observer_destination_port,
                .src = {object->observer_source}, .dst = {object->observer_destination},
                .cookie = {(uint32_t)object->observer_cookie,
                    (uint32_t)(object->observer_cookie >> 32)}}}
    };
    ssize_t sent = sendto(fd, &request, sizeof(request), 0,
        (void *)&kernel, sizeof(kernel));
    if (sent < 0) { status = -errno; goto out; }
    if (sent != (ssize_t)sizeof(request)) { status = -EIO; goto out; }

    struct sockaddr_nl local = {0};
    socklen_t local_length = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_length)) { status = -errno; goto out; }
    if (local_length != sizeof(local) || local.nl_family != AF_NETLINK || !local.nl_pid) {
        status = -EPROTO; goto out;
    }
    unsigned char response[1024] = {0};
    struct sockaddr_nl sender = {0};
    socklen_t sender_length = sizeof(sender);
    ssize_t received = recvfrom(fd, response, sizeof(response),
        MSG_DONTWAIT | MSG_TRUNC, (void *)&sender, &sender_length);
    if (received < 0) { status = -errno; goto out; }
    if (received > (ssize_t)sizeof(response) || received < (ssize_t)sizeof(struct ker_nlmsghdr) ||
        sender_length < sizeof(sender) || sender.nl_family != AF_NETLINK ||
        sender.nl_pid != 0 || sender.nl_groups != 0) { status = -EPROTO; goto out; }
    status = ker_tcp_observer_parse_reply(response, (size_t)received,
        sender.nl_pid, local.nl_pid, &request, sizeof(request), &request.request.id, snapshot);
out:
    (void)close(fd);
    return status;
}

static int observer_create(struct ker_socket_broker_server *server,
    struct sb_object *source, int *passed_fd)
{
    int domain = -1, type = -1, protocol = -1, accepting = -1;
    socklen_t length = sizeof(int);
    if (getsockopt(source->native_fd, SOL_SOCKET, SO_DOMAIN, &domain, &length)) return -errno;
    if (length != sizeof(domain)) return -EPROTO;
    if (domain != AF_INET) return -EAFNOSUPPORT;
    length = sizeof(type);
    if (getsockopt(source->native_fd, SOL_SOCKET, SO_TYPE, &type, &length)) return -errno;
    if (length != sizeof(type)) return -EPROTO;
    if (type != SOCK_STREAM) return -EPROTOTYPE;
    length = sizeof(protocol);
    if (getsockopt(source->native_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &length)) return -errno;
    if (length != sizeof(protocol)) return -EPROTO;
    if (protocol != IPPROTO_TCP) return -EPROTONOSUPPORT;
    length = sizeof(accepting);
    if (getsockopt(source->native_fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &length)) return -errno;
    if (length != sizeof(accepting)) return -EPROTO;
    if (accepting) return -EINVAL;
    struct sockaddr_in local = {0}, peer = {0};
    length = sizeof(local);
    if (getsockname(source->native_fd, (struct sockaddr *)&local, &length)) return -errno;
    if (length != sizeof(local) || local.sin_family != AF_INET) return -EPROTO;
    length = sizeof(peer);
    if (getpeername(source->native_fd, (struct sockaddr *)&peer, &length)) return -errno;
    if (length != sizeof(peer) || peer.sin_family != AF_INET) return -ENOTCONN;
    uint64_t cookie = 0;
    length = sizeof(cookie);
    if (getsockopt(source->native_fd, SOL_SOCKET, SO_COOKIE, &cookie, &length)) return -errno;
    if (length != sizeof(cookie) || cookie == 0) return -EPROTO;
    size_t observer_slot = KER_SB_OBJECTS;
    int capability = make_capability(server, -1, KER_SOCKET_BROKER_TCP_OBSERVER,
        KER_SOCKET_BROKER_READ, &observer_slot);
    if (capability < 0) return -errno;
    struct sb_object *observer = &server->objects[observer_slot];
    observer->observer_cookie = cookie;
    observer->observer_source = local.sin_addr.s_addr;
    observer->observer_destination = peer.sin_addr.s_addr;
    observer->observer_source_port = local.sin_port;
    observer->observer_destination_port = peer.sin_port;
    *passed_fd = capability;
    return 0;

}

static int dispatch_request(struct ker_socket_broker_server *server,
    const struct ker_sb_header *request, const unsigned char *input, size_t input_length,
    int *fds, size_t fd_count, unsigned char *output, size_t *output_length,
    int *passed_fd, int64_t *result)
{
    *output_length = 0; *passed_fd = -1; *result = -EINVAL;
    size_t expected_rights = request->operation == KER_SB_SOCKET ||
        request->operation == KER_SB_EPOLL_CREATE1 ||
        request->operation == KER_SB_REUSEPORT_GROUP_CREATE ? 0 :
        request->operation == KER_SB_EPOLL_CTL ? 2 : 1;
    if (fd_count != expected_rights) return -EPROTO;
    if (expected_rights && request->operation != KER_SB_EPOLL_CTL) {
        struct sb_object *object;
        enum ker_socket_broker_kind expected_kind = KER_SOCKET_BROKER_SOCKET;
        if (request->operation == KER_SB_EPOLL_WAIT) expected_kind = KER_SOCKET_BROKER_EPOLL;
        else if (request->operation == KER_SB_REUSEPORT_GROUP_MEMBER ||
            request->operation == KER_SB_REUSEPORT_GROUP_SELECT)
            expected_kind = KER_SOCKET_BROKER_REUSEPORT_GROUP;
        else if (request->operation == KER_SB_MEMBER_CENSUS_CREATE)
            expected_kind = KER_SOCKET_BROKER_REUSEPORT_GROUP;
        else if (request->operation == KER_SB_MEMBER_CENSUS_SNAPSHOT)
            expected_kind = KER_SOCKET_BROKER_MEMBER_CENSUS;
        else if (request->operation == KER_SB_TCP_OBSERVER_SNAPSHOT)
            expected_kind = KER_SOCKET_BROKER_TCP_OBSERVER;
        else if (request->operation == KER_SB_DESCRIBE || request->operation == KER_SB_DUP ||
            request->operation == KER_SB_GETFL) expected_kind = 0;
        int status;
        if (!expected_kind) {
            object = lookup_cap(server, fds[0]);
            status = object ? 0 : -EBADF;
            if (!status && object->kind == KER_SOCKET_BROKER_REUSEPORT_GROUP &&
                request->operation == KER_SB_DUP) return -EOPNOTSUPP;
            if (!status && object->kind == KER_SOCKET_BROKER_MEMBER_CENSUS &&
                request->operation == KER_SB_DUP) return -EOPNOTSUPP;
            uint32_t right = required_right(request->operation);
            if (!status && request->operation == KER_SB_DUP &&
                object->kind == KER_SOCKET_BROKER_TCP_OBSERVER) status = -EOPNOTSUPP;
            if (!status && right && (object->rights & right) != right) status = -EACCES;
            if (!status && request->operation == KER_SB_TCP_OBSERVER_SNAPSHOT &&
                object->kind != KER_SOCKET_BROKER_TCP_OBSERVER) status = -ENOTSOCK;
            if (!status && request->operation == KER_SB_TCP_OBSERVER_CREATE &&
                object->kind != KER_SOCKET_BROKER_SOCKET) status = -ENOTSOCK;
        } else {
            status = object_for_request(server, fds[0], request->operation, expected_kind, &object);
        }
        if (status) return status;
    }
    struct sb_object *first = NULL, *second = NULL;
    int status;
    switch (request->operation) {
    case KER_SB_REUSEPORT_GROUP_CREATE: {
        if (input_length != sizeof(struct ker_sb_reuseport_group_create)) return -EPROTO;
        struct ker_sb_reuseport_group_create args;
        memcpy(&args, input, sizeof(args));
        struct sockaddr_in address;
        memcpy(&address, args.address, sizeof(address));
        if (address.sin_family != AF_INET || !address.sin_port || args.backlog < 0)
            return -EINVAL;
        int capability = construct_reuseport_group(server, &address, args.backlog,
            KER_SOCKET_BROKER_CONTROL);
        if (capability < 0) return -errno;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_REUSEPORT_GROUP_MEMBER: {
        if (input_length != sizeof(struct ker_sb_reuseport_group_member)) return -EPROTO;
        struct ker_sb_reuseport_group_member args;
        memcpy(&args, input, sizeof(args));
        if (args.index > 1) return -EINVAL;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        if (object->kind != KER_SOCKET_BROKER_REUSEPORT_GROUP || object->group_slot < 0)
            return -ENOTSOCK;
        struct sb_group *group = &server->groups[object->group_slot];
        if (!group->live) return -EBADF;
        int native_fd = fcntl(group->base_fd[args.index], F_DUPFD_CLOEXEC, 0);
        if (native_fd < 0) return -errno;
        int capability = group_handle(server, object->group_slot, native_fd,
            KER_SOCKET_BROKER_SOCKET, KER_SOCKET_BROKER_ALL, args.index);
        if (capability < 0) { int error = errno; (void)close(native_fd); return -error; }
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_REUSEPORT_GROUP_SELECT: {
        if (input_length != sizeof(struct ker_sb_reuseport_group_member)) return -EPROTO;
        struct ker_sb_reuseport_group_member args;
        memcpy(&args, input, sizeof(args));
        if (args.index > 1) return -EINVAL;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        if (object->kind != KER_SOCKET_BROKER_REUSEPORT_GROUP || object->group_slot < 0)
            return -ENOTSOCK;
        struct sb_group *group = &server->groups[object->group_slot];
        if (!group->live) return -EBADF;
        if (reuseport_filter(group->base_fd[0], args.index)) return -errno;
        *result = 0; return 0;
    }
    case KER_SB_MEMBER_CENSUS_CREATE: {
        if (input_length != sizeof(struct ker_sb_member_census_create)) return -EPROTO;
        struct ker_sb_member_census_create args;
        memcpy(&args, input, sizeof(args));
        if (args.index > 1) return -EINVAL;
        struct sb_object *group_object = lookup_cap(server, fds[0]);
        if (!group_object) return -EBADF;
        int capability = member_census_capability(server, group_object, args.index);
        if (capability < 0) return -errno;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_DESCRIBE: {
        if (input_length) return -EPROTO;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        int flags = 0;
        if (object->kind != KER_SOCKET_BROKER_REUSEPORT_GROUP &&
            object->kind != KER_SOCKET_BROKER_MEMBER_CENSUS &&
            object->kind != KER_SOCKET_BROKER_TCP_OBSERVER &&
            object->kind != KER_SOCKET_BROKER_MEMBER_CENSUS) {
            flags = fcntl(object->native_fd, F_GETFL);
            if (flags < 0) return -errno;
        }
        struct ker_sb_describe description = {.kind = object->kind, .flags = flags};
        memcpy(output, &description, sizeof(description));
        *output_length = sizeof(description); *result = 0; return 0;
    }
    case KER_SB_DUP: {
        if (input_length) return -EPROTO;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        if (object->kind == KER_SOCKET_BROKER_REUSEPORT_GROUP) return -EOPNOTSUPP;
        if (object->kind == KER_SOCKET_BROKER_MEMBER_CENSUS) return -EOPNOTSUPP;

        if (object->kind == KER_SOCKET_BROKER_TCP_OBSERVER) return -EOPNOTSUPP;

        if (object->kind == KER_SOCKET_BROKER_MEMBER_CENSUS) return -EOPNOTSUPP;

        int native_fd = fcntl(object->native_fd, F_DUPFD_CLOEXEC, 0);
        if (native_fd < 0) return -errno;
        if (object->group_slot >= 0) {
            int capability = group_handle(server, object->group_slot, native_fd,
                KER_SOCKET_BROKER_SOCKET, object->rights, object->group_index);
            if (capability < 0) { int error = errno; (void)close(native_fd); return -error; }
            *passed_fd = capability;
            status = 0;
        } else {
            status = make_native_object(server, native_fd, object->kind, object->rights, passed_fd);
        }
        if (status) { (void)close(native_fd); return status; }
        *result = 1; return 0;
    }
    case KER_SB_GETFL: {
        if (input_length) return -EPROTO;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        if (object->kind != KER_SOCKET_BROKER_SOCKET && object->kind != KER_SOCKET_BROKER_EPOLL)
            return -ENOTSOCK;
        struct ker_sb_integer flags = {.value = fcntl(object->native_fd, F_GETFL)};
        if (flags.value < 0) return -errno;
        memcpy(output, &flags, sizeof(flags));
        *output_length = sizeof(flags); *result = 0; return 0;
    }
    case KER_SB_SETFL: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        if (object->kind != KER_SOCKET_BROKER_SOCKET) return -ENOTSOCK;
        status = managed_member_status(object, request->operation);
        if (status) return status;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        int current = fcntl(object->native_fd, F_GETFL);
        if (current < 0) return -errno;
        if (!(args.value & O_NONBLOCK) || ((args.value ^ current) & ~O_NONBLOCK))
            return -EOPNOTSUPP;
        int call_result = fcntl(object->native_fd, F_SETFL, args.value);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_FIONBIO: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        if (args.value != 1) return -EOPNOTSUPP;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        if (object->kind != KER_SOCKET_BROKER_SOCKET) return -ENOTSOCK;
        int enabled = 1;
        int call_result = ioctl(object->native_fd, FIONBIO, &enabled);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_FIONREAD: {
        if (input_length) return -EPROTO;
        int available = 0;
        int call_result = ioctl(lookup_cap(server, fds[0])->native_fd, FIONREAD, &available);
        if (call_result < 0) return -errno;
        struct ker_sb_integer output_value = {.value = available};
        memcpy(output, &output_value, sizeof(output_value));
        *output_length = sizeof(output_value); *result = 0; return 0;
    }
    case KER_SB_SEND: {
        if (input_length < sizeof(struct ker_sb_io)) return -EPROTO;
        struct ker_sb_io args; memcpy(&args, input, sizeof(args));
        if (args.length != input_length - sizeof(args)) return -EPROTO;
        if (args.flags & ~(MSG_DONTWAIT | MSG_MORE | MSG_NOSIGNAL)) return -EOPNOTSUPP;
        ssize_t count = send(lookup_cap(server, fds[0])->native_fd,
            input + sizeof(args), args.length, args.flags | MSG_NOSIGNAL);
        *result = count < 0 ? -errno : count; return 0;
    }
    case KER_SB_RECV: {
        if (input_length != sizeof(struct ker_sb_io)) return -EPROTO;
        struct ker_sb_io args; memcpy(&args, input, sizeof(args));
        if (args.length > KER_SOCKET_BROKER_IO_MAX) return -EINVAL;
        if (args.flags & ~(MSG_PEEK | MSG_DONTWAIT)) return -EOPNOTSUPP;
        ssize_t count = recv(lookup_cap(server, fds[0])->native_fd, output,
            args.length, args.flags);
        if (count < 0) return -errno;
        *output_length = (size_t)count; *result = count; return 0;
    }
    case KER_SB_SOCKET: {
        if (input_length != sizeof(struct ker_sb_socket_args)) return -EPROTO;
        struct ker_sb_socket_args args; memcpy(&args, input, sizeof(args));
        int base_type = args.type & 0xf;
        if ((args.domain != AF_INET && args.domain != AF_INET6) ||
            (base_type != SOCK_STREAM && base_type != SOCK_DGRAM) ||
            (args.type & ~(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC))) return -EAFNOSUPPORT;
        int native_fd = socket(args.domain, args.type | SOCK_NONBLOCK | SOCK_CLOEXEC, args.protocol);
        if (native_fd < 0) return -errno;
        status = make_native_object(server, native_fd, KER_SOCKET_BROKER_SOCKET,
            KER_SOCKET_BROKER_ALL, passed_fd);
        if (status) { (void)close(native_fd); return status; }
        *result = 1; return 0;
    }
    case KER_SB_EPOLL_CREATE1: {
        if (input_length != sizeof(struct ker_sb_epoll_create)) return -EPROTO;
        struct ker_sb_epoll_create args; memcpy(&args, input, sizeof(args));
        if (args.flags & ~EPOLL_CLOEXEC) return -EINVAL;
        int native_fd = epoll_create1(args.flags | EPOLL_CLOEXEC);
        if (native_fd < 0) return -errno;
        status = make_native_object(server, native_fd, KER_SOCKET_BROKER_EPOLL,
            KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_WAIT, passed_fd);
        if (status) { (void)close(native_fd); return status; }
        *result = 1; return 0;
    }
    case KER_SB_EPOLL_CTL: {
        if (input_length != sizeof(struct ker_sb_epoll_ctl)) return -EPROTO;
        status = object_for_request(server, fds[0], request->operation,
            KER_SOCKET_BROKER_EPOLL, &first); if (status) return status;
        status = object_for_request(server, fds[1], request->operation,
            KER_SOCKET_BROKER_SOCKET, &second); if (status) return status;
        struct ker_sb_epoll_ctl args; memcpy(&args, input, sizeof(args));
        if (args.operation != EPOLL_CTL_ADD && args.operation != EPOLL_CTL_MOD && args.operation != EPOLL_CTL_DEL) return -EINVAL;
        if (args.has_event > 1) return -EINVAL;
        struct epoll_event *event = args.has_event ? &args.event : NULL;
        int call_result = epoll_ctl(first->native_fd, args.operation, second->native_fd, event);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_EPOLL_WAIT: {
        if (input_length != sizeof(struct ker_sb_epoll_wait)) return -EPROTO;
        struct ker_sb_epoll_wait args; memcpy(&args, input, sizeof(args));
        if (args.maxevents < 1 || args.maxevents > KER_SOCKET_BROKER_EVENTS_MAX) return -EINVAL;
        struct epoll_event events[KER_SOCKET_BROKER_EVENTS_MAX];
        int count = epoll_wait(lookup_cap(server, fds[0])->native_fd,
            events, args.maxevents, 0);
        if (count < 0) return -errno;
        uint32_t n = (uint32_t)count;
        memcpy(output, &n, sizeof(n));
        memcpy(output + sizeof(n), events, (size_t)count * sizeof(*events));
        *output_length = sizeof(n) + (size_t)count * sizeof(*events);
        *result = count; return 0;
    }
    case KER_SB_BIND: case KER_SB_CONNECT: {
        if (input_length != sizeof(struct ker_sb_address)) return -EPROTO;
        struct ker_sb_address args; memcpy(&args, input, sizeof(args));
        if (!args.length || args.length > sizeof(args.bytes)) return -EINVAL;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        status = managed_member_status(object, request->operation);
        if (status) return status;
        if (request->operation == KER_SB_BIND && requested_port_reserved(server,
                args.bytes, (socklen_t)args.length)) return -EADDRINUSE;
        int call_result = request->operation == KER_SB_BIND ?
            bind(object->native_fd,
                (const struct sockaddr *)args.bytes, args.length) :
            connect(object->native_fd,
                (const struct sockaddr *)args.bytes, args.length);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_LISTEN: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        status = managed_member_status(object, request->operation);
        if (status) return status;
        struct sockaddr_storage local = {0}; socklen_t local_length = sizeof(local);
        if (getsockname(object->native_fd, (struct sockaddr *)&local, &local_length)) return -errno;
        if (requested_port_reserved(server, &local, local_length)) return -EADDRINUSE;
        /* An unbound SO_REUSEPORT socket could otherwise autojoin a broker
         * group when original Linux chooses its ephemeral port. */
        bool unbound = (local.ss_family == AF_INET &&
                ((struct sockaddr_in *)&local)->sin_port == 0) ||
            (local.ss_family == AF_INET6 && ((struct sockaddr_in6 *)&local)->sin6_port == 0);
        if (unbound) {
            bool reuseport = false;
            if (socket_reuseport_enabled(object->native_fd, &reuseport)) return -errno;
            if (reuseport && any_live_group(server)) return -EOPNOTSUPP;
        }
        int call_result = listen(object->native_fd, args.value);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_ACCEPT4: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        if (args.value & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) return -EINVAL;
        struct ker_sb_address address = {0};
        socklen_t length = sizeof(address.bytes);
        int native_fd = accept4(lookup_cap(server, fds[0])->native_fd,
            (struct sockaddr *)address.bytes, &length, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (native_fd < 0) return -errno;
        if (length > sizeof(address.bytes)) { (void)close(native_fd); return -EOVERFLOW; }
        address.length = length;
        memcpy(output, &address, sizeof(address));
        *output_length = sizeof(address);
        status = make_native_object(server, native_fd, KER_SOCKET_BROKER_SOCKET,
            KER_SOCKET_BROKER_ALL, passed_fd);
        if (status) { (void)close(native_fd); return status; }
        *result = 1; return 0;
    }
    case KER_SB_READ: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        if (args.value < 0 || args.value > KER_SOCKET_BROKER_IO_MAX) return -EINVAL;
        ssize_t count = read(lookup_cap(server, fds[0])->native_fd, output, (size_t)args.value);
        if (count < 0) return -errno;
        *output_length = (size_t)count; *result = count; return 0;
    }
    case KER_SB_WRITE: {
        if (input_length > KER_SOCKET_BROKER_IO_MAX) return -EINVAL;
        ssize_t count = send(lookup_cap(server, fds[0])->native_fd, input, input_length, MSG_NOSIGNAL);
        *result = count < 0 ? -errno : count; return 0;
    }
    case KER_SB_SHUTDOWN: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        status = managed_member_status(object, request->operation);
        if (status) return status;
        int call_result = shutdown(object->native_fd, args.value);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_GETSOCKNAME: case KER_SB_GETPEERNAME: {
        if (input_length) return -EPROTO;
        struct ker_sb_address address = {0}; socklen_t length = sizeof(address.bytes);
        int call_result = request->operation == KER_SB_GETSOCKNAME ?
            getsockname(lookup_cap(server, fds[0])->native_fd,
                (struct sockaddr *)address.bytes, &length) :
            getpeername(lookup_cap(server, fds[0])->native_fd,
                (struct sockaddr *)address.bytes, &length);
        if (call_result < 0) return -errno;
        if (length > sizeof(address.bytes)) return -EOVERFLOW;
        address.length = length; memcpy(output, &address, sizeof(address));
        *output_length = sizeof(address); *result = 0; return 0;
    }
    case KER_SB_SETSOCKOPT: {
        if (input_length < sizeof(struct ker_sb_option)) return -EPROTO;
        struct ker_sb_option args; memcpy(&args, input, sizeof(args));
        if (args.length != input_length - sizeof(args)) return -EPROTO;
        struct sb_object *object = lookup_cap(server, fds[0]);
        if (!object) return -EBADF;
        status = managed_member_status(object, request->operation);
        if (status) return status;
        if (!socket_option_supported(args.level, args.option, true)) return -EOPNOTSUPP;
        if (args.level == SOL_SOCKET && args.option == SO_LINGER &&
            !socket_linger_is_nonblocking(input + sizeof(args), args.length)) return -EOPNOTSUPP;
        if (args.level == SOL_SOCKET && args.option == SO_COOKIE) return -EOPNOTSUPP;
        int call_result = setsockopt(object->native_fd,
            args.level, args.option, input + sizeof(args), args.length);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_GETSOCKOPT: {
        if (input_length != sizeof(struct ker_sb_option)) return -EPROTO;
        struct ker_sb_option args; memcpy(&args, input, sizeof(args));
        if (args.length > KER_SOCKET_BROKER_IO_MAX - sizeof(uint32_t)) return -EINVAL;
        if (!socket_option_supported(args.level, args.option, false)) return -EOPNOTSUPP;
        if (args.level == SOL_SOCKET && args.option == SO_COOKIE &&
            args.length != sizeof(uint64_t)) return -EINVAL;
        socklen_t length = args.length;
        int call_result = getsockopt(lookup_cap(server, fds[0])->native_fd,
            args.level, args.option, output + sizeof(uint32_t), &length);
        if (call_result < 0) return -errno;
        if (length > args.length) return -EOVERFLOW;
        if (args.level == SOL_SOCKET && args.option == SO_COOKIE &&
            length != sizeof(uint64_t)) return -EPROTO;
        uint32_t wire_length = length; memcpy(output, &wire_length, sizeof(wire_length));
        *output_length = sizeof(wire_length) + length; *result = 0; return 0;
    }
    case KER_SB_TCP_OBSERVER_CREATE: {
        if (input_length) return -EPROTO;
        struct sb_object *source = lookup_cap(server, fds[0]);
        if (!source) return -EBADF;
        status = observer_create(server, source, passed_fd);
        if (status) return status;
        *result = 1; return 0;
    }
    case KER_SB_TCP_OBSERVER_SNAPSHOT: {
        if (input_length) return -EPROTO;
        struct sb_object *observer = lookup_cap(server, fds[0]);
        if (!observer) return -EBADF;
        struct ker_sb_tcp_observer_snapshot snapshot = {0};
        status = observer_query(observer, &snapshot);
        if (status) return status;
        memcpy(output, &snapshot, sizeof(snapshot));
        *output_length = sizeof(snapshot); *result = 0; return 0;
    }
    case KER_SB_MEMBER_CENSUS_SNAPSHOT:
        /* The broker pump starts these in a dedicated LKL query task and
         * sends the response only after a complete validated NLMSG_DONE. */
        return -EINPROGRESS;
    default: return -EOPNOTSUPP;
    }
}

static size_t expected_rights(uint16_t operation)
{
    if (operation == KER_SB_SOCKET || operation == KER_SB_EPOLL_CREATE1 ||
        operation == KER_SB_REUSEPORT_GROUP_CREATE) return 0;
    return operation == KER_SB_EPOLL_CTL ? 2 : 1;
}

static int start_member_census_job(struct ker_socket_broker_server *server,
    struct sb_client *client, const struct ker_sb_header *request, int census_cap)
{
    struct sb_object *object = lookup_cap(server, census_cap);
    if (!object) return -EBADF;
    if (object->kind != KER_SOCKET_BROKER_MEMBER_CENSUS || object->native_fd >= 0 ||
        object->group_slot >= 0) return -ENOTSOCK;
    if ((object->rights & KER_SOCKET_BROKER_READ) != KER_SOCKET_BROKER_READ) return -EACCES;
    if (!object->census_mark || !object->census_local_port ||
        !object->census_listener_cookie) return -EPROTO;
    if (client->census_job >= 0) return -EBUSY;
    size_t slot = KER_SB_CENSUS_JOBS;
    for (size_t i = 0; i < KER_SB_CENSUS_JOBS; ++i)
        if (!server->census_jobs[i].live) { slot = i; break; }
    if (slot == KER_SB_CENSUS_JOBS) return -EAGAIN;
    struct sb_census_job *job = &server->census_jobs[slot];
    struct ker_member_census_identity identity = {
        .mark = object->census_mark, .local_port = object->census_local_port,
        .listener_cookie = object->census_listener_cookie};
    uint64_t ticket = 0;
    int submitted = ker_member_census_query_submit(&identity, &ticket);
    if (submitted) return submitted;
    *job = (struct sb_census_job){.live = true,
        .client_slot = (int)(client - server->clients), .client_fd = client->fd,
        .request = *request, .ticket = ticket};
    client->census_job = (int)slot;
    return 0;
}

static void finish_member_census_jobs(struct ker_socket_broker_server *server)
{
    for (size_t i = 0; i < KER_SB_CENSUS_JOBS; ++i) {
        struct sb_census_job *job = &server->census_jobs[i];
        if (!job->live) continue;
        struct ker_socket_member_census_snapshot snapshot = {0};
        int query_status = 0;
        int ready = ker_member_census_query_poll(job->ticket, &query_status, &snapshot);
        if (!ready) continue;
        if (ready < 0) {
            if (job->client_slot >= 0 && job->client_slot < KER_SB_CLIENTS) {
                struct sb_client *client = &server->clients[job->client_slot];
                if (client->fd == job->client_fd && client->census_job == (int)i)
                    close_client(server, client);
            }
            job->live = false;
            continue;
        }
        if (job->client_slot >= 0 && job->client_slot < KER_SB_CLIENTS) {
            struct sb_client *client = &server->clients[job->client_slot];
            if (client->fd == job->client_fd && client->census_job == (int)i) {
                client->census_job = -1;
                const void *output = query_status ? NULL : &snapshot;
                size_t output_length = query_status ? 0 : sizeof(snapshot);
                if (send_reply(client, &job->request, query_status, output,
                        output_length, -1)) close_client(server, client);
            }
        }
        job->live = false;
    }
}

static void service_client(struct ker_socket_broker_server *server, struct sb_client *client)
{
    struct ker_sb_header request = {0};
    unsigned char input[KER_SB_MAX_REQUEST] = {0};
    size_t input_length = 0, fd_count = 0;
    int fds[KER_SB_MAX_RIGHTS] = {-1, -1};
    int receive_result = receive_request(client, &request, input, &input_length, fds, &fd_count);
    if (receive_result == 1) return;
    if (receive_result) { close_client(server, client); return; }
    if (fd_count != expected_rights(request.operation)) {
        for (size_t i = 0; i < fd_count; ++i) (void)host_close(fds[i]);
        close_client(server, client); return;
    }
    if (client->census_job >= 0) {
        for (size_t i = 0; i < fd_count; ++i) (void)host_close(fds[i]);
        close_client(server, client);
        return;
    }
    unsigned char output[KER_SOCKET_BROKER_IO_MAX] = {0};
    size_t output_length = 0;
    int passed_fd = -1;
    int64_t result = 0;
    int dispatch;
    bool deferred = false;
    if (request.operation == KER_SB_MEMBER_CENSUS_SNAPSHOT) {
        struct sb_object *object = fd_count == 1 ? lookup_cap(server, fds[0]) : NULL;
        uint32_t right = required_right(request.operation);
        if (input_length) dispatch = -EPROTO;
        else if (!object) dispatch = -EBADF;
        else if (object->kind != KER_SOCKET_BROKER_MEMBER_CENSUS) dispatch = -ENOTSOCK;
        else if ((object->rights & right) != right) dispatch = -EACCES;
        else dispatch = start_member_census_job(server, client, &request, fds[0]);
        if (!dispatch) deferred = true;
    } else {
        dispatch = dispatch_request(server, &request, input, input_length, fds, fd_count,
            output, &output_length, &passed_fd, &result);
    }
    for (size_t i = 0; i < fd_count; ++i) (void)host_close(fds[i]);
    if (deferred) return;
    if (dispatch) {
        if (passed_fd >= 0) (void)host_close(passed_fd);
        passed_fd = -1; output_length = 0; result = dispatch;
    }
    if (send_reply(client, &request, result, output, output_length, passed_fd)) {
        if (passed_fd >= 0) (void)host_close(passed_fd);
        close_client(server, client); return;
    }
    if (passed_fd >= 0) (void)host_close(passed_fd);
}

static int accept_clients(struct ker_socket_broker_server *server)
{
    for (unsigned accepted = 0; accepted < 8; ++accepted) {
        int fd = (int)syscall(SYS_accept4, server->listener, NULL, NULL,
            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -errno;
        struct ucred credential = {0}; socklen_t length = sizeof(credential);
        if (host_getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential, &length) ||
            length != sizeof(credential) || credential.uid != geteuid()) {
            (void)host_close(fd); continue;
        }
        int pass_credentials = 1;
        if (syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_PASSCRED,
                &pass_credentials, sizeof(pass_credentials))) {
            (void)host_close(fd); continue;
        }
        int pidfd = -1; length = sizeof(pidfd);
        int pidfd_result = host_getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &length);
        if (pidfd_result || length != sizeof(pidfd)) {
            int error = pidfd_result ? errno : EPROTO;
            if (pidfd >= 0) (void)host_close(pidfd);
            (void)host_close(fd); return -error;
        }
        size_t slot = KER_SB_CLIENTS;
        for (size_t i = 0; i < KER_SB_CLIENTS; ++i)
            if (server->clients[i].fd < 0) { slot = i; break; }
        if (slot == KER_SB_CLIENTS) { (void)host_close(pidfd); (void)host_close(fd); continue; }
        server->clients[slot] = (struct sb_client){.fd = fd, .pidfd = pidfd,
            .pid = credential.pid, .credential = credential, .census_job = -1};
    }
    return 0;
}

static void reap_dead(struct ker_socket_broker_server *server)
{
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) {
        struct sb_object *object = &server->objects[i];
        if (!object->live) continue;
        struct pollfd pfd = {.fd = object->capability_read_fd, .events = POLLIN | POLLHUP | POLLERR};
        if (syscall(SYS_poll, &pfd, 1, 0) <= 0) continue;
        if (pfd.revents & POLLIN) {
            char discard[256];
            for (unsigned drain = 0; drain < 8; ++drain) {
                ssize_t count = syscall(SYS_read, object->capability_read_fd, discard, sizeof(discard));
                if (count <= 0) break;
            }
        }
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) close_object(server, object);
    }
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_client *client = &server->clients[i];
        if (client->fd < 0) continue;
        struct pollfd pfd[2] = {{.fd = client->fd, .events = POLLIN | POLLHUP | POLLERR},
            {.fd = client->pidfd, .events = POLLIN}};
        if (syscall(SYS_poll, pfd, 2, 0) > 0 &&
            ((pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) || pfd[1].revents)) close_client(server, client);
    }
}

static int broker_pump(void *argument)
{
    struct ker_socket_broker_server *server = argument;
    int accepted = accept_clients(server);
    if (accepted) server->failure = -accepted;
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_client *client = &server->clients[i];
        if (client->fd < 0) continue;
        struct pollfd pfd = {.fd = client->fd, .events = POLLIN | POLLHUP | POLLERR};
        if (syscall(SYS_poll, &pfd, 1, 0) <= 0) continue;
        if (pfd.revents & POLLIN) {
            if (client->census_job >= 0) close_client(server, client);
            else service_client(server, client);
        }
        else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) close_client(server, client);
    }
    reap_dead(server);
    finish_member_census_jobs(server);
    if (server->failure || (server->stop_when_empty && !object_count(server) && !client_count(server))) {
        for (size_t i = 0; i < KER_SB_CLIENTS; ++i) close_client(server, &server->clients[i]);
        for (size_t i = 0; i < KER_SB_OBJECTS; ++i) close_object(server, &server->objects[i]);
        ker_posix_stop_run();
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    (void)syscall(SYS_nanosleep, &pause, NULL);
    return 0;
}

struct ker_socket_broker_server *ker_socket_broker_server_create(const char *path)
{
    if (!path) { errno = EINVAL; return NULL; }
    size_t length = strnlen(path, KER_SB_PATH_MAX + 1);
    if (!length || length > KER_SB_PATH_MAX) { errno = ENAMETOOLONG; return NULL; }
    struct ker_socket_broker_server *server = calloc(1, sizeof(*server));
    if (!server) return NULL;
    server->listener = -1;
    int lease_status = ker_member_census_server_claim(&server->runtime_lease);
    if (lease_status) {
        free(server);
        errno = -lease_status;
        return NULL;
    }
    server->runtime_lease_live = true;
    memcpy(server->path, path, length + 1);
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i)
        server->clients[i] = (struct sb_client){.fd = -1, .pidfd = -1, .census_job = -1};
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) server->objects[i] = (struct sb_object){.capability_read_fd = -1, .native_fd = -1};
    struct stat existing;
    if (!lstat(path, &existing)) {
        release_runtime_lease(server); free(server); errno = EADDRINUSE; return NULL;
    }
    if (errno != ENOENT) {
        int error = errno; release_runtime_lease(server); free(server); errno = error; return NULL;
    }
    int listener = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        int error = errno; release_runtime_lease(server); free(server); errno = error; return NULL;
    }
    int pass_credentials = 1;
    if (syscall(SYS_setsockopt, listener, SOL_SOCKET, SO_PASSCRED,
            &pass_credentials, sizeof(pass_credentials))) {
        int error = errno; (void)host_close(listener); release_runtime_lease(server);
        free(server); errno = error; return NULL;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, length + 1);
    if (syscall(SYS_bind, listener, &address, sizeof(address))) {
        int error = errno; (void)host_close(listener); release_runtime_lease(server);
        free(server); errno = error; return NULL;
    }
    struct stat identity;
    if (lstat(path, &identity)) {
        int error = errno; (void)host_close(listener); release_runtime_lease(server);
        free(server); errno = error; return NULL;
    }
    server->path_dev = identity.st_dev;
    server->path_ino = identity.st_ino;
    server->path_bound = true;
    if (syscall(SYS_chmod, path, 0600) || syscall(SYS_listen, listener, KER_SB_CLIENTS)) {
        int error = errno;
        if (!lstat(path, &identity) && identity.st_dev == server->path_dev &&
            identity.st_ino == server->path_ino) (void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
        (void)host_close(listener); release_runtime_lease(server);
        free(server); errno = error; return NULL;
    }
    server->listener = listener;
    return server;
}

int ker_socket_broker_server_run(struct ker_socket_broker_server *server, int stop_when_empty)
{
    if (!server || server->listener < 0 || server->running) return fail(EINVAL);
    if (stop_when_empty && !object_count(server)) return fail(EINVAL);
    server->running = true;
    server->stop_when_empty = !!stop_when_empty;
    int result = ker_posix_run(broker_pump, server);
    server->running = false;
    if (result < 0) return -1;
    if (server->failure) return fail(server->failure);
    return 0;
}

void ker_socket_broker_server_destroy(struct ker_socket_broker_server *server)
{
    if (!server) return;
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) close_client(server, &server->clients[i]);
    for (size_t i = 0; i < KER_SB_CENSUS_JOBS; ++i) {
        struct sb_census_job *job = &server->census_jobs[i];
        if (!job->live) continue;
        (void)ker_member_census_query_cancel(job->ticket);
        job->live = false;
    }
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) close_object(server, &server->objects[i]);
    (void)host_close(server->listener);
    if (server->path_bound) {
        struct stat identity;
        if (!lstat(server->path, &identity) && identity.st_dev == server->path_dev &&
            identity.st_ino == server->path_ino) (void)syscall(SYS_unlinkat, AT_FDCWD, server->path, 0);
    }
    release_runtime_lease(server);
    free(server);
}
