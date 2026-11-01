#define _GNU_SOURCE
#include "socket-broker-server.h"
#include "socket-broker-protocol.h"
#include <ker/posix.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

struct sb_object {
    bool live;
    enum ker_socket_broker_kind kind;
    uint32_t rights;
    dev_t capability_dev;
    ino_t capability_ino;
    int capability_read_fd;
    int native_fd;
};
struct sb_client {
    int fd;
    int pidfd;
    pid_t pid;
    struct ucred credential;
    uint64_t sequence;
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
    struct sb_object objects[KER_SB_OBJECTS];
    struct sb_client clients[KER_SB_CLIENTS];
};

static int host_close(int fd)
{
    if (fd >= 0) return (int)syscall(SYS_close, fd);
    return 0;
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
    case KER_SB_READ: return KER_SOCKET_BROKER_READ;
    case KER_SB_WRITE: return KER_SOCKET_BROKER_WRITE;
    case KER_SB_GETSOCKNAME: case KER_SB_GETPEERNAME: return KER_SOCKET_BROKER_NAME;
    case KER_SB_GETSOCKOPT: return KER_SOCKET_BROKER_OPTION;
    case KER_SB_EPOLL_WAIT: return KER_SOCKET_BROKER_WAIT;
    case KER_SB_BIND: case KER_SB_CONNECT: case KER_SB_LISTEN: case KER_SB_ACCEPT4:
    case KER_SB_SHUTDOWN: case KER_SB_SETSOCKOPT: case KER_SB_EPOLL_CTL:
        return KER_SOCKET_BROKER_CONTROL;
    default: return 0;
    }
}

static void close_client(struct sb_client *client)
{
    (void)host_close(client->fd);
    (void)host_close(client->pidfd);
    *client = (struct sb_client){.fd = -1, .pidfd = -1};
}

static void close_object(struct sb_object *object)
{
    if (!object->live) return;
    /* Do not retain the adopted descriptor through epoll metadata. The final
     * capability close is the final userspace fd close; original Linux applies
     * its own epoll/OFD close semantics. */
    (void)close(object->native_fd);
    (void)host_close(object->capability_read_fd);
    *object = (struct sb_object){.capability_read_fd = -1, .native_fd = -1};
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
    enum ker_socket_broker_kind kind, uint32_t rights)
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
        .capability_read_fd = pair[0], .native_fd = native_fd};
    return pair[1];
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
    int capability = make_capability(server, native_fd, kind, rights);
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
        header->flags || header->result || header->payload_length > KER_SOCKET_BROKER_IO_MAX ||
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
    int fd = make_capability(server, native_fd, kind, rights);
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
    if (right && !(object->rights & right)) return -EACCES;
    *out = object;
    return 0;
}

static int dispatch_request(struct ker_socket_broker_server *server,
    const struct ker_sb_header *request, const unsigned char *input, size_t input_length,
    int *fds, size_t fd_count, unsigned char *output, size_t *output_length,
    int *passed_fd, int64_t *result)
{
    *output_length = 0; *passed_fd = -1; *result = -EINVAL;
    size_t expected_rights = request->operation == KER_SB_SOCKET ||
        request->operation == KER_SB_EPOLL_CREATE1 ? 0 :
        request->operation == KER_SB_EPOLL_CTL ? 2 : 1;
    if (fd_count != expected_rights) return -EPROTO;
    if (expected_rights && request->operation != KER_SB_EPOLL_CTL) {
        struct sb_object *object;
        int status = object_for_request(server, fds[0], request->operation,
            request->operation == KER_SB_EPOLL_WAIT ? KER_SOCKET_BROKER_EPOLL : KER_SOCKET_BROKER_SOCKET,
            &object);
        if (status) return status;
    }
    struct sb_object *first = NULL, *second = NULL;
    int status;
    switch (request->operation) {
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
        int call_result = request->operation == KER_SB_BIND ?
            bind(lookup_cap(server, fds[0])->native_fd,
                (const struct sockaddr *)args.bytes, args.length) :
            connect(lookup_cap(server, fds[0])->native_fd,
                (const struct sockaddr *)args.bytes, args.length);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_LISTEN: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        int call_result = listen(lookup_cap(server, fds[0])->native_fd, args.value);
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
        int call_result = shutdown(lookup_cap(server, fds[0])->native_fd, args.value);
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
        if (!socket_option_supported(args.level, args.option, true)) return -EOPNOTSUPP;
        if (args.level == SOL_SOCKET && args.option == SO_LINGER &&
            !socket_linger_is_nonblocking(input + sizeof(args), args.length)) return -EOPNOTSUPP;
        int call_result = setsockopt(lookup_cap(server, fds[0])->native_fd,
            args.level, args.option, input + sizeof(args), args.length);
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_GETSOCKOPT: {
        if (input_length != sizeof(struct ker_sb_option)) return -EPROTO;
        struct ker_sb_option args; memcpy(&args, input, sizeof(args));
        if (args.length > KER_SOCKET_BROKER_IO_MAX - sizeof(uint32_t)) return -EINVAL;
        if (!socket_option_supported(args.level, args.option, false)) return -EOPNOTSUPP;
        socklen_t length = args.length;
        int call_result = getsockopt(lookup_cap(server, fds[0])->native_fd,
            args.level, args.option, output + sizeof(uint32_t), &length);
        if (call_result < 0) return -errno;
        if (length > args.length) return -EOVERFLOW;
        uint32_t wire_length = length; memcpy(output, &wire_length, sizeof(wire_length));
        *output_length = sizeof(wire_length) + length; *result = 0; return 0;
    }
    default: return -EOPNOTSUPP;
    }
}

static size_t expected_rights(uint16_t operation)
{
    if (operation == KER_SB_SOCKET || operation == KER_SB_EPOLL_CREATE1) return 0;
    return operation == KER_SB_EPOLL_CTL ? 2 : 1;
}

static void service_client(struct ker_socket_broker_server *server, struct sb_client *client)
{
    struct ker_sb_header request = {0};
    unsigned char input[KER_SOCKET_BROKER_IO_MAX] = {0};
    size_t input_length = 0, fd_count = 0;
    int fds[KER_SB_MAX_RIGHTS] = {-1, -1};
    int receive_result = receive_request(client, &request, input, &input_length, fds, &fd_count);
    if (receive_result == 1) return;
    if (receive_result) { close_client(client); return; }
    if (fd_count != expected_rights(request.operation)) {
        for (size_t i = 0; i < fd_count; ++i) (void)host_close(fds[i]);
        close_client(client); return;
    }
    unsigned char output[KER_SOCKET_BROKER_IO_MAX] = {0};
    size_t output_length = 0;
    int passed_fd = -1;
    int64_t result = 0;
    int dispatch = dispatch_request(server, &request, input, input_length, fds, fd_count,
        output, &output_length, &passed_fd, &result);
    for (size_t i = 0; i < fd_count; ++i) (void)host_close(fds[i]);
    if (dispatch) {
        if (passed_fd >= 0) (void)host_close(passed_fd);
        passed_fd = -1; output_length = 0; result = dispatch;
    }
    if (send_reply(client, &request, result, output, output_length, passed_fd)) {
        if (passed_fd >= 0) (void)host_close(passed_fd);
        close_client(client); return;
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
            .pid = credential.pid, .credential = credential};
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
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) close_object(object);
    }
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_client *client = &server->clients[i];
        if (client->fd < 0) continue;
        struct pollfd pfd[2] = {{.fd = client->fd, .events = POLLIN | POLLHUP | POLLERR},
            {.fd = client->pidfd, .events = POLLIN}};
        if (syscall(SYS_poll, pfd, 2, 0) > 0 &&
            ((pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) || pfd[1].revents)) close_client(client);
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
        if (pfd.revents & POLLIN) service_client(server, client);
        else if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) close_client(client);
    }
    reap_dead(server);
    if (server->failure || (server->stop_when_empty && !object_count(server) && !client_count(server))) {
        for (size_t i = 0; i < KER_SB_CLIENTS; ++i) close_client(&server->clients[i]);
        for (size_t i = 0; i < KER_SB_OBJECTS; ++i) close_object(&server->objects[i]);
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
    memcpy(server->path, path, length + 1);
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) server->clients[i] = (struct sb_client){.fd = -1, .pidfd = -1};
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) server->objects[i] = (struct sb_object){.capability_read_fd = -1, .native_fd = -1};
    struct stat existing;
    if (!lstat(path, &existing)) { free(server); errno = EADDRINUSE; return NULL; }
    if (errno != ENOENT) { int error = errno; free(server); errno = error; return NULL; }
    int listener = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) { int error = errno; free(server); errno = error; return NULL; }
    int pass_credentials = 1;
    if (syscall(SYS_setsockopt, listener, SOL_SOCKET, SO_PASSCRED,
            &pass_credentials, sizeof(pass_credentials))) {
        int error = errno; (void)host_close(listener); free(server); errno = error; return NULL;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, length + 1);
    if (syscall(SYS_bind, listener, &address, sizeof(address))) {
        int error = errno; (void)host_close(listener); free(server); errno = error; return NULL;
    }
    struct stat identity;
    if (lstat(path, &identity)) {
        int error = errno; (void)host_close(listener); free(server); errno = error; return NULL;
    }
    server->path_dev = identity.st_dev;
    server->path_ino = identity.st_ino;
    server->path_bound = true;
    if (syscall(SYS_chmod, path, 0600) || syscall(SYS_listen, listener, KER_SB_CLIENTS)) {
        int error = errno;
        if (!lstat(path, &identity) && identity.st_dev == server->path_dev &&
            identity.st_ino == server->path_ino) (void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
        (void)host_close(listener); free(server); errno = error; return NULL;
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
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) close_client(&server->clients[i]);
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) close_object(&server->objects[i]);
    (void)host_close(server->listener);
    if (server->path_bound) {
        struct stat identity;
        if (!lstat(server->path, &identity) && identity.st_dev == server->path_dev &&
            identity.st_ino == server->path_ino) (void)syscall(SYS_unlinkat, AT_FDCWD, server->path, 0);
    }
    free(server);
}
