#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include "socket-broker-protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

static int fail(int error)
{
    errno = error;
    return -1;
}

static int valid_capability_fd(int fd)
{
    struct stat identity = {0};
    int flags = (int)syscall(SYS_fcntl, fd, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == O_WRONLY &&
        !syscall(SYS_fstat, fd, &identity) && S_ISFIFO(identity.st_mode);
}

static int connect_session(struct ker_socket_client *client)
{
    if (!client || !client->path[0]) return fail(EINVAL);
    if (client->owner_pid != getpid()) {
        if (client->session_fd >= 0) (void)syscall(SYS_close, client->session_fd);
        client->session_fd = -1;
        client->sequence = 0;
        client->owner_pid = getpid();
    }
    if (client->session_fd >= 0) return 0;
    int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t path_length = strlen(client->path);
    if (!path_length || path_length > sizeof(address.sun_path) - 1) {
        (void)syscall(SYS_close, fd);
        return fail(ENAMETOOLONG);
    }
    memcpy(address.sun_path, client->path, path_length + 1);
    if (syscall(SYS_connect, fd, &address, sizeof(address))) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        return fail(error);
    }
    struct ucred credential = {0};
    socklen_t size = sizeof(credential);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERCRED, &credential, &size)) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        return fail(error);
    }
    if (size != sizeof(credential) || credential.uid != geteuid()) {
        (void)syscall(SYS_close, fd);
        return fail(EACCES);
    }
    int peer_pidfd = -1;
    size = sizeof(peer_pidfd);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERPIDFD, &peer_pidfd, &size) ||
        size != sizeof(peer_pidfd)) {
        int error = errno ? errno : EOPNOTSUPP;
        if (peer_pidfd >= 0) (void)syscall(SYS_close, peer_pidfd);
        (void)syscall(SYS_close, fd);
        return fail(error);
    }
    (void)syscall(SYS_close, peer_pidfd);
    client->session_fd = fd;
    client->owner_pid = getpid();
    client->sequence = 0;
    return 0;
}

int ker_socket_client_open(struct ker_socket_client *client, const char *path)
{
    if (!client || !path) return fail(EINVAL);
    size_t length = strnlen(path, KER_SOCKET_BROKER_PATH_MAX + 1);
    if (!length || length > KER_SOCKET_BROKER_PATH_MAX) return fail(ENAMETOOLONG);
    memset(client, 0, sizeof(*client));
    memcpy(client->path, path, length + 1);
    client->session_fd = -1;
    client->owner_pid = getpid();
    return connect_session(client);
}

void ker_socket_client_close(struct ker_socket_client *client)
{
    if (!client) return;
    if (client->session_fd >= 0) (void)syscall(SYS_close, client->session_fd);
    client->session_fd = -1;
    client->sequence = 0;
    client->owner_pid = getpid();
}

static int receive_packet(int fd, struct ker_sb_header *reply, void *payload,
    size_t capacity, int *received_fds, size_t expected_fds, size_t *actual_fds)
{
    char control[CMSG_SPACE(sizeof(int) * KER_SB_MAX_RIGHTS)] = {0};
    struct iovec iov[2] = {{reply, sizeof(*reply)}, {payload, capacity}};
    struct msghdr message = {.msg_iov = iov, .msg_iovlen = capacity ? 2u : 1u,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t count;
    do {
        message.msg_controllen = sizeof(control);
        message.msg_flags = 0;
        count = syscall(SYS_recvmsg, fd, &message, MSG_CMSG_CLOEXEC | MSG_TRUNC);
    } while (count < 0 && errno == EINTR);
    if (count < 0) return -1;
    size_t found = 0;
    int malformed = !!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            malformed = 1;
            continue;
        }
        if (cmsg->cmsg_len < CMSG_LEN(0)) { malformed = 1; continue; }
        if (cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
            (cmsg->cmsg_len - CMSG_LEN(0)) % sizeof(int)) malformed = 1;
        size_t count_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        const int *fds = (const int *)CMSG_DATA(cmsg);
        for (size_t i = 0; i < count_fds; ++i) {
            if (found < KER_SB_MAX_RIGHTS) received_fds[found] = fds[i];
            else (void)syscall(SYS_close, fds[i]);
            found++;
        }
    }
    if ((size_t)count < sizeof(*reply) || malformed ||
        (expected_fds != SIZE_MAX && found != expected_fds) || found > KER_SB_MAX_RIGHTS ||
        reply->payload_length > capacity ||
        (size_t)count != sizeof(*reply) + reply->payload_length) {
        for (size_t i = 0; i < found && i < KER_SB_MAX_RIGHTS; ++i)
            (void)syscall(SYS_close, received_fds[i]);
        return fail(EPROTO);
    }
    *actual_fds = found;
    return 0;
}

static int rpc(struct ker_socket_client *client, uint16_t operation,
    const void *payload, size_t payload_length, const int *fds, size_t fd_count,
    void *reply_payload, size_t reply_capacity, size_t expected_reply_fds,
    int *reply_fds, int64_t *result, size_t *actual_reply_length)
{
    if (!client || payload_length > KER_SB_MAX_REQUEST ||
        reply_capacity > KER_SOCKET_BROKER_IO_MAX || fd_count > KER_SB_MAX_RIGHTS ||
        (expected_reply_fds != SIZE_MAX && expected_reply_fds > KER_SB_MAX_RIGHTS)) return fail(EINVAL);
    if (connect_session(client)) return -1;
    if (client->sequence == UINT64_MAX) {
        ker_socket_client_close(client);
        return fail(EOVERFLOW);
    }
    struct ker_sb_header request = {.magic = KER_SB_MAGIC, .version = KER_SB_VERSION,
        .operation = operation, .payload_length = (uint32_t)payload_length,
        .rights_count = (uint16_t)fd_count, .sequence = ++client->sequence};
    char control[CMSG_SPACE(sizeof(int) * KER_SB_MAX_RIGHTS)] = {0};
    struct iovec iov[2] = {{&request, sizeof(request)}, {(void *)payload, payload_length}};
    struct msghdr message = {.msg_iov = iov, .msg_iovlen = payload_length ? 2u : 1u};
    if (fd_count) {
        message.msg_control = control;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * fd_count);
    }
    ssize_t sent;
    do {
        sent = syscall(SYS_sendmsg, client->session_fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)(sizeof(request) + payload_length)) {
        int error = sent < 0 ? errno : EIO;
        ker_socket_client_close(client);
        return fail(error);
    }
    struct ker_sb_header reply = {0};
    int received[KER_SB_MAX_RIGHTS] = {-1, -1};
    size_t actual_fds = 0;
    if (receive_packet(client->session_fd, &reply, reply_payload, reply_capacity,
            received, expected_reply_fds, &actual_fds)) {
        int error = errno;
        ker_socket_client_close(client);
        return fail(error);
    }
    size_t required_reply_fds = expected_reply_fds == SIZE_MAX ? (reply.result < 0 ? 0u : 1u) : expected_reply_fds;
    if (reply.magic != KER_SB_MAGIC || reply.version != KER_SB_VERSION ||
        reply.operation != operation || reply.sequence != request.sequence ||
        reply.flags || reply.rights_count != actual_fds || actual_fds != required_reply_fds ||
        (reply.result < 0 && (reply.result < -4095 || reply.payload_length)) ||
        reply.result > KER_SOCKET_BROKER_IO_MAX) {
        for (size_t i = 0; i < actual_fds && i < KER_SB_MAX_RIGHTS; ++i) (void)syscall(SYS_close, received[i]);
        ker_socket_client_close(client);
        return fail(EPROTO);
    }
    if (result) *result = reply.result;
    if (actual_reply_length) *actual_reply_length = reply.payload_length;
    if (reply_fds) for (size_t i = 0; i < actual_fds; ++i) reply_fds[i] = received[i];
    else for (size_t i = 0; i < actual_fds; ++i) (void)syscall(SYS_close, received[i]);
    return 0;
}

static int finish_int(int transport, int64_t result)
{
    if (transport) return -1;
    if (result < 0) return fail(result >= -4095 ? (int)-result : EPROTO);
    if (result > INT32_MAX) return fail(EPROTO);
    return (int)result;
}

static int socket_call(struct ker_socket_client *client, int cap_fd,
    uint16_t operation, const void *input, size_t input_length,
    void *output, size_t output_capacity, int *new_cap, int *received_count)
{
    int rights[1] = {cap_fd}, reply_rights[1] = {-1};
    int64_t result = 0;
    size_t reply_length = 0;
    int transport = rpc(client, operation, input, input_length,
        cap_fd >= 0 ? rights : NULL, cap_fd >= 0 ? 1u : 0u,
        output, output_capacity, new_cap ? SIZE_MAX : 0u, reply_rights, &result, &reply_length);
    if (transport) return -1;
    if (result < 0) {
        if (new_cap && reply_rights[0] >= 0) (void)syscall(SYS_close, reply_rights[0]);
        return fail(result >= -4095 ? (int)-result : EPROTO);
    }
    if (result > INT32_MAX) {
        if (new_cap && reply_rights[0] >= 0) (void)syscall(SYS_close, reply_rights[0]);
        return fail(EPROTO);
    }
    bool requires_cap = operation == KER_SB_SOCKET || operation == KER_SB_ACCEPT4 ||
        operation == KER_SB_EPOLL_CREATE1 || operation == KER_SB_DUP ||
        operation == KER_SB_REUSEPORT_GROUP_CREATE ||
        operation == KER_SB_REUSEPORT_GROUP_MEMBER ||
        operation == KER_SB_TCP_OBSERVER_CREATE ||
        operation == KER_SB_MEMBER_CENSUS_CREATE ||
        operation == KER_SB_FF_OWNER_CREATE ||
        operation == KER_SB_FF_OWNER_SOCKET;
    bool requires_zero = operation == KER_SB_BIND || operation == KER_SB_CONNECT ||
        operation == KER_SB_LISTEN || operation == KER_SB_SHUTDOWN ||
        operation == KER_SB_GETSOCKNAME || operation == KER_SB_GETPEERNAME ||
        operation == KER_SB_SETSOCKOPT || operation == KER_SB_GETSOCKOPT ||
        operation == KER_SB_EPOLL_CTL || operation == KER_SB_DESCRIBE ||
        operation == KER_SB_GETFL || operation == KER_SB_SETFL ||
        operation == KER_SB_FIONBIO || operation == KER_SB_FIONREAD;
    requires_zero = requires_zero || operation == KER_SB_REUSEPORT_GROUP_SELECT ||
        operation == KER_SB_TCP_OBSERVER_SNAPSHOT ||
        operation == KER_SB_MEMBER_CENSUS_SNAPSHOT ||
        operation == KER_SB_MEMBER_PAYLOAD_SNAPSHOT ||
        operation == KER_SB_FF_OWNER_PAYLOAD;
    if ((requires_cap && (!new_cap || result != 1)) || (requires_zero && result != 0)) {
        if (reply_rights[0] >= 0) (void)syscall(SYS_close, reply_rights[0]);
        ker_socket_client_close(client);
        return fail(EPROTO);
    }
    if (new_cap && (result != 1 || reply_rights[0] < 0 ||
        !valid_capability_fd(reply_rights[0]))) {
        if (reply_rights[0] >= 0) (void)syscall(SYS_close, reply_rights[0]);
        ker_socket_client_close(client);
        return fail(EPROTO);
    }
    if (new_cap) *new_cap = reply_rights[0];
    if (received_count) *received_count = (int)reply_length;
    return (int)result;
}

static int pack_address(struct ker_sb_address *wire, const struct sockaddr *address,
    socklen_t length)
{
    if (!address || !length || length > sizeof(wire->bytes)) return fail(EINVAL);
    memset(wire, 0, sizeof(*wire));
    wire->length = length;
    memcpy(wire->bytes, address, length);
    return 0;
}

int ker_socket_client_socket(struct ker_socket_client *client, int domain, int type, int protocol)
{
    struct ker_sb_socket_args args = {.domain = domain, .type = type, .protocol = protocol};
    int fd = -1;
    if (socket_call(client, -1, KER_SB_SOCKET, &args, sizeof(args), NULL, 0, &fd, NULL) < 0) return -1;
    int flags = (type & SOCK_CLOEXEC) ? FD_CLOEXEC : 0;
    if (syscall(SYS_fcntl, fd, F_SETFD, flags) < 0) {
        int error = errno; (void)syscall(SYS_close, fd); return fail(error);
    }
    return fd;
}

int ker_socket_client_bind(struct ker_socket_client *client, int cap_fd,
    const struct sockaddr *address, socklen_t length)
{
    struct ker_sb_address wire;
    if (pack_address(&wire, address, length)) return -1;
    return socket_call(client, cap_fd, KER_SB_BIND, &wire, sizeof(wire), NULL, 0, NULL, NULL);
}
int ker_socket_client_connect(struct ker_socket_client *client, int cap_fd,
    const struct sockaddr *address, socklen_t length)
{
    struct ker_sb_address wire;
    if (pack_address(&wire, address, length)) return -1;
    return socket_call(client, cap_fd, KER_SB_CONNECT, &wire, sizeof(wire), NULL, 0, NULL, NULL);
}
int ker_socket_client_listen(struct ker_socket_client *client, int cap_fd, int backlog)
{
    struct ker_sb_integer value = {.value = backlog};
    return socket_call(client, cap_fd, KER_SB_LISTEN, &value, sizeof(value), NULL, 0, NULL, NULL);
}
int ker_socket_client_accept4(struct ker_socket_client *client, int cap_fd,
    struct sockaddr *address, socklen_t *length, int flags)
{
    struct ker_sb_integer input = {.value = flags};
    struct ker_sb_address output = {0};
    int new_cap = -1, received = 0;
    int result = socket_call(client, cap_fd, KER_SB_ACCEPT4, &input, sizeof(input),
        &output, sizeof(output), &new_cap, &received);
    if (result < 0) return -1;
    if (result != 1 || received != sizeof(output) || output.length > sizeof(output.bytes)) {
        (void)syscall(SYS_close, new_cap); return fail(EPROTO);
    }
    int descriptor_flags = (flags & SOCK_CLOEXEC) ? FD_CLOEXEC : 0;
    if (syscall(SYS_fcntl, new_cap, F_SETFD, descriptor_flags) < 0) {
        int error = errno; (void)syscall(SYS_close, new_cap); return fail(error);
    }
    if (address && length) {
        socklen_t copy = *length < output.length ? *length : (socklen_t)output.length;
        memcpy(address, output.bytes, copy);
        *length = (socklen_t)output.length;
    }
    return new_cap;
}

ssize_t ker_socket_client_read(struct ker_socket_client *client, int cap_fd, void *buffer, size_t length)
{
    if ((!buffer && length) || length > KER_SOCKET_BROKER_IO_MAX) return fail(EINVAL);
    int received = 0;
    int result = socket_call(client, cap_fd, KER_SB_READ, &((struct ker_sb_integer){.value = (int32_t)length}),
        sizeof(struct ker_sb_integer), buffer, length, NULL, &received);
    if (result < 0) return -1;
    if ((size_t)received != (size_t)result || (size_t)result > length) return fail(EPROTO);
    return result;
}
ssize_t ker_socket_client_write(struct ker_socket_client *client, int cap_fd, const void *buffer, size_t length)
{
    if ((!buffer && length) || length > KER_SOCKET_BROKER_IO_MAX) return fail(EINVAL);
    int rights[1] = {cap_fd};
    int64_t result = 0;
    if (rpc(client, KER_SB_WRITE, buffer, length, rights, 1, NULL, 0, 0, NULL, &result, NULL)) return -1;
    if (result < 0) return fail(result >= -4095 ? (int)-result : EPROTO);
    return (size_t)result <= length ? (ssize_t)result : fail(EPROTO);
}
int ker_socket_client_shutdown(struct ker_socket_client *client, int cap_fd, int how)
{
    struct ker_sb_integer value = {.value = how};
    return socket_call(client, cap_fd, KER_SB_SHUTDOWN, &value, sizeof(value), NULL, 0, NULL, NULL);
}

static int name_call(struct ker_socket_client *client, int cap_fd, uint16_t operation,
    struct sockaddr *address, socklen_t *length)
{
    if (!address || !length) return fail(EINVAL);
    struct ker_sb_address output = {0};
    int received = 0;
    int result = socket_call(client, cap_fd, operation, NULL, 0, &output, sizeof(output), NULL, &received);
    if (result < 0) return -1;
    if (received != sizeof(output) || output.length > sizeof(output.bytes)) return fail(EPROTO);
    socklen_t copy = *length < output.length ? *length : (socklen_t)output.length;
    memcpy(address, output.bytes, copy);
    *length = (socklen_t)output.length;
    return 0;
}
int ker_socket_client_getsockname(struct ker_socket_client *client, int cap_fd,
    struct sockaddr *address, socklen_t *length)
{ return name_call(client, cap_fd, KER_SB_GETSOCKNAME, address, length); }
int ker_socket_client_getpeername(struct ker_socket_client *client, int cap_fd,
    struct sockaddr *address, socklen_t *length)
{ return name_call(client, cap_fd, KER_SB_GETPEERNAME, address, length); }

int ker_socket_client_setsockopt(struct ker_socket_client *client, int cap_fd,
    int level, int option, const void *value, socklen_t length)
{
    if ((!value && length) || length > KER_SOCKET_BROKER_IO_MAX - sizeof(struct ker_sb_option)) return fail(EINVAL);
    unsigned char payload[KER_SOCKET_BROKER_IO_MAX];
    struct ker_sb_option header = {.level = level, .option = option, .length = length};
    memcpy(payload, &header, sizeof(header));
    if (length) memcpy(payload + sizeof(header), value, length);
    return socket_call(client, cap_fd, KER_SB_SETSOCKOPT, payload, sizeof(header) + length,
        NULL, 0, NULL, NULL);
}
int ker_socket_client_getsockopt(struct ker_socket_client *client, int cap_fd,
    int level, int option, void *value, socklen_t *length)
{
    if (!length || (!value && *length) || *length > KER_SOCKET_BROKER_IO_MAX - sizeof(uint32_t)) return fail(EINVAL);
    struct ker_sb_option input = {.level = level, .option = option, .length = *length};
    unsigned char output[KER_SOCKET_BROKER_IO_MAX] = {0};
    int received = 0;
    int result = socket_call(client, cap_fd, KER_SB_GETSOCKOPT, &input, sizeof(input),
        output, *length + sizeof(uint32_t), NULL, &received);
    if (result < 0) return -1;
    if (received < (int)sizeof(uint32_t)) return fail(EPROTO);
    uint32_t actual; memcpy(&actual, output, sizeof(actual));
    if (actual > *length || actual != (uint32_t)(received - sizeof(uint32_t))) return fail(EPROTO);
    if (actual) memcpy(value, output + sizeof(actual), actual);
    *length = actual;
    return 0;
}

int ker_socket_client_epoll_create1(struct ker_socket_client *client, int flags)
{
    struct ker_sb_epoll_create input = {.flags = flags};
    int cap = -1;
    if (socket_call(client, -1, KER_SB_EPOLL_CREATE1, &input, sizeof(input), NULL, 0, &cap, NULL) < 0) return -1;
    if (syscall(SYS_fcntl, cap, F_SETFD,
            (flags & EPOLL_CLOEXEC) ? FD_CLOEXEC : 0) < 0) {
        int error = errno; (void)syscall(SYS_close, cap); return fail(error);
    }
    return cap;
}
int ker_socket_client_epoll_ctl(struct ker_socket_client *client, int epoll_cap,
    int operation, int socket_cap, const struct epoll_event *event)
{
    struct ker_sb_epoll_ctl input = {.operation = operation, .has_event = event != NULL};
    if (event) input.event = *event;
    int rights[2] = {epoll_cap, socket_cap};
    int64_t result = 0;
    if (rpc(client, KER_SB_EPOLL_CTL, &input, sizeof(input), rights, 2,
            NULL, 0, 0, NULL, &result, NULL)) return -1;
    return finish_int(0, result);
}
int ker_socket_client_epoll_wait(struct ker_socket_client *client, int epoll_cap,
    struct epoll_event *events, int maxevents)
{
    if (!events || maxevents < 1 || maxevents > KER_SOCKET_BROKER_EVENTS_MAX) return fail(EINVAL);
    struct ker_sb_epoll_wait input = {.maxevents = maxevents};
    struct { uint32_t count; struct epoll_event events[KER_SOCKET_BROKER_EVENTS_MAX]; } output = {0};
    int received = 0;
    int result = socket_call(client, epoll_cap, KER_SB_EPOLL_WAIT, &input, sizeof(input),
        &output, sizeof(output), NULL, &received);
    if (result < 0) return -1;
    if ((size_t)received != sizeof(output.count) + sizeof(struct epoll_event) * output.count ||
        output.count > (uint32_t)maxevents || result != (int)output.count) return fail(EPROTO);
    memcpy(events, output.events, output.count * sizeof(*events));
    return result;
}

int ker_socket_client_describe(struct ker_socket_client *client, int cap_fd,
    enum ker_socket_broker_kind *kind, int *status_flags)
{
    if (!kind || !status_flags) return fail(EINVAL);
    struct ker_sb_describe output = {0};
    int received = 0;
    int result = socket_call(client, cap_fd, KER_SB_DESCRIBE, NULL, 0,
        &output, sizeof(output), NULL, &received);
    if (result < 0) return -1;
    if (received != sizeof(output) || output.flags < 0 ||
        (output.kind != KER_SOCKET_BROKER_SOCKET && output.kind != KER_SOCKET_BROKER_EPOLL &&
         output.kind != KER_SOCKET_BROKER_REUSEPORT_GROUP &&
         output.kind != KER_SOCKET_BROKER_TCP_OBSERVER &&
         output.kind != KER_SOCKET_BROKER_MEMBER_CENSUS))
        return fail(EPROTO);
    *kind = (enum ker_socket_broker_kind)output.kind;
    *status_flags = output.flags;
    return 0;
}

int ker_socket_client_tcp_observer_create(struct ker_socket_client *client,
    int socket_cap)
{
    int observer_cap = -1;
    if (socket_call(client, socket_cap, KER_SB_TCP_OBSERVER_CREATE, NULL, 0,
            NULL, 0, &observer_cap, NULL) < 0) return -1;
    return observer_cap;
}

int ker_socket_client_tcp_observer_snapshot(struct ker_socket_client *client,
    int observer_cap, struct ker_socket_tcp_observer_snapshot *snapshot)
{
    if (!snapshot) return fail(EINVAL);
    struct ker_sb_tcp_observer_snapshot wire = {0};
    int received = 0;
    if (socket_call(client, observer_cap, KER_SB_TCP_OBSERVER_SNAPSHOT, NULL, 0,
            &wire, sizeof(wire), NULL, &received) < 0) return -1;
    if (received != sizeof(wire) || wire.reserved[0] || wire.reserved[1] ||
        !wire.cookie || wire.present > 1 ||
        (wire.present && (!wire.state || wire.state > 13)) ||
        (!wire.present && (wire.state || wire.receive_queue || wire.send_queue)))
        return fail(EPROTO);
    snapshot->cookie = wire.cookie;
    snapshot->present = wire.present;
    snapshot->state = wire.state;
    snapshot->receive_queue = wire.receive_queue;
    snapshot->send_queue = wire.send_queue;
    return 0;
}

int ker_socket_client_dup(struct ker_socket_client *client, int cap_fd)
{
    int duplicate = -1;
    if (socket_call(client, cap_fd, KER_SB_DUP, NULL, 0, NULL, 0,
            &duplicate, NULL) < 0) return -1;
    if (syscall(SYS_fcntl, duplicate, F_SETFD, 0) < 0) {
        int error = errno;
        (void)syscall(SYS_close, duplicate);
        return fail(error);
    }
    return duplicate;
}

int ker_socket_client_getfl(struct ker_socket_client *client, int cap_fd)
{
    struct ker_sb_integer output = {0};
    int received = 0;
    int result = socket_call(client, cap_fd, KER_SB_GETFL, NULL, 0,
        &output, sizeof(output), NULL, &received);
    if (result < 0) return -1;
    if (received != sizeof(output) || output.value < 0) return fail(EPROTO);
    return output.value;
}

int ker_socket_client_setfl(struct ker_socket_client *client, int cap_fd, int flags)
{
    struct ker_sb_integer input = {.value = flags};
    return socket_call(client, cap_fd, KER_SB_SETFL, &input, sizeof(input), NULL, 0, NULL, NULL);
}

int ker_socket_client_ioctl(struct ker_socket_client *client, int cap_fd,
    unsigned long request, void *argument)
{
    if (request == FIONBIO) {
        if (!argument) return fail(EFAULT);
        int enabled = *(int *)argument;
        struct ker_sb_integer input = {.value = enabled};
        return socket_call(client, cap_fd, KER_SB_FIONBIO, &input, sizeof(input), NULL, 0, NULL, NULL);
    }
    if (request == FIONREAD) {
        if (!argument) return fail(EFAULT);
        struct ker_sb_integer output = {0};
        int received = 0;
        int result = socket_call(client, cap_fd, KER_SB_FIONREAD, NULL, 0,
            &output, sizeof(output), NULL, &received);
        if (result < 0) return -1;
        if (received != sizeof(output) || output.value < 0) return fail(EPROTO);
        *(int *)argument = output.value;
        return 0;
    }
    return fail(EOPNOTSUPP);
}

int ker_socket_client_fionbio(struct ker_socket_client *client, int cap_fd, int enabled)
{
    return ker_socket_client_ioctl(client, cap_fd, FIONBIO, &enabled);
}

int ker_socket_client_fionread(struct ker_socket_client *client, int cap_fd, int *available)
{
    return ker_socket_client_ioctl(client, cap_fd, FIONREAD, available);
}

ssize_t ker_socket_client_send(struct ker_socket_client *client, int cap_fd,
    const void *buffer, size_t length, int flags)
{
    if ((!buffer && length) || length > KER_SOCKET_BROKER_IO_MAX)
        return fail(EINVAL);
    unsigned char payload[KER_SB_MAX_REQUEST];
    struct ker_sb_io input = {.flags = flags, .length = (uint32_t)length};
    memcpy(payload, &input, sizeof(input));
    if (length) memcpy(payload + sizeof(input), buffer, length);
    int rights[1] = {cap_fd};
    int64_t result = 0;
    if (rpc(client, KER_SB_SEND, payload, sizeof(input) + length,
            rights, 1, NULL, 0, 0, NULL, &result, NULL)) return -1;
    if (result < 0) return fail(result >= -4095 ? (int)-result : EPROTO);
    return (size_t)result <= length ? (ssize_t)result : fail(EPROTO);
}

ssize_t ker_socket_client_recv(struct ker_socket_client *client, int cap_fd,
    void *buffer, size_t length, int flags)
{
    if ((!buffer && length) || length > KER_SOCKET_BROKER_IO_MAX) return fail(EINVAL);
    struct ker_sb_io input = {.flags = flags, .length = (uint32_t)length};
    int rights[1] = {cap_fd};
    int64_t result = 0;
    size_t received = 0;
    if (rpc(client, KER_SB_RECV, &input, sizeof(input), rights, 1,
            buffer, length, 0, NULL, &result, &received)) return -1;
    if (result < 0) return fail(result >= -4095 ? (int)-result : EPROTO);
    if ((uint64_t)result != received || received > length) return fail(EPROTO);
    return (ssize_t)result;
}

int ker_socket_client_reuseport_group_create(struct ker_socket_client *client,
    const struct sockaddr_in *address, int backlog)
{
    if (!address || address->sin_family != AF_INET || !address->sin_port || backlog < 0)
        return fail(EINVAL);
    struct ker_sb_reuseport_group_create input = {.backlog = backlog};
    memcpy(input.address, address, sizeof(*address));
    int capability = -1;
    if (socket_call(client, -1, KER_SB_REUSEPORT_GROUP_CREATE, &input, sizeof(input),
            NULL, 0, &capability, NULL) < 0) return -1;
    return capability;
}

int ker_socket_client_reuseport_group_member(struct ker_socket_client *client,
    int group_cap, unsigned index)
{
    if (index > 1) return fail(EINVAL);
    struct ker_sb_reuseport_group_member input = {.index = index};
    int member = -1;
    if (socket_call(client, group_cap, KER_SB_REUSEPORT_GROUP_MEMBER, &input,
            sizeof(input), NULL, 0, &member, NULL) < 0) return -1;
    return member;
}

int ker_socket_client_reuseport_group_select(struct ker_socket_client *client,
    int group_cap, unsigned index)
{
    if (index > 1) return fail(EINVAL);
    struct ker_sb_reuseport_group_member input = {.index = index};
    return socket_call(client, group_cap, KER_SB_REUSEPORT_GROUP_SELECT,
        &input, sizeof(input), NULL, 0, NULL, NULL);
}

int ker_socket_client_member_census_create(struct ker_socket_client *client,
    int group_cap, unsigned index)
{
    if (index > 1) return fail(EINVAL);
    struct ker_sb_member_census_create input = {.index = index};
    int census_cap = -1;
    if (socket_call(client, group_cap, KER_SB_MEMBER_CENSUS_CREATE, &input,
            sizeof(input), NULL, 0, &census_cap, NULL) < 0) return -1;
    return census_cap;
}

int ker_socket_client_member_census_snapshot(struct ker_socket_client *client,
    int census_cap, struct ker_socket_member_census_snapshot *snapshot)
{
    if (!snapshot) return fail(EINVAL);
    struct ker_sb_member_census_snapshot wire = {0};
    int received = 0;
    if (socket_call(client, census_cap, KER_SB_MEMBER_CENSUS_SNAPSHOT, NULL, 0,
            &wire, sizeof(wire), NULL, &received) < 0) return -1;
    if (received != sizeof(wire) || !wire.listener_cookie || wire.state_counts[0])
        return fail(EPROTO);
    uint64_t total = 0;
    for (size_t i = 0; i < KER_SOCKET_BROKER_TCP_STATES; ++i) {
        if (UINT64_MAX - total < wire.state_counts[i]) return fail(EPROTO);
        total += wire.state_counts[i];
    }
    if (total != wire.total) return fail(EPROTO);
    snapshot->total = wire.total;
    memcpy(snapshot->state_counts, wire.state_counts, sizeof(snapshot->state_counts));
    snapshot->listener_cookie = wire.listener_cookie;
    return 0;
}

int ker_socket_client_member_payload_snapshot(struct ker_socket_client *client,
    int census_cap, struct ker_socket_member_payload_snapshot *snapshot)
{
    if (!snapshot) return fail(EINVAL);
    struct ker_sb_member_payload_snapshot wire = {0};
    int received = 0;
    if (socket_call(client, census_cap, KER_SB_MEMBER_PAYLOAD_SNAPSHOT, NULL, 0,
            &wire, sizeof(wire), NULL, &received) < 0) return -1;
    if (received != sizeof(wire) || wire.sampled_sockets > 4096 ||
        (wire.payload_bytes && !wire.sampled_sockets)) return fail(EPROTO);
    struct ker_socket_member_payload_snapshot completed = {
        .payload_bytes = wire.payload_bytes,
        .sampled_sockets = wire.sampled_sockets};
    *snapshot = completed;
    return 0;
}

int ker_socket_client_ff_owner_create(struct ker_socket_client *client)
{
    int owner_cap = -1;
    if (socket_call(client, -1, KER_SB_FF_OWNER_CREATE, NULL, 0,
            NULL, 0, &owner_cap, NULL) < 0) return -1;
    return owner_cap;
}

int ker_socket_client_ff_owner_socket(struct ker_socket_client *client,
    int owner_cap, int domain, int type, int protocol)
{
    struct ker_sb_socket_args args = {.domain = domain, .type = type, .protocol = protocol};
    int fd = -1;
    if (socket_call(client, owner_cap, KER_SB_FF_OWNER_SOCKET, &args,
            sizeof(args), NULL, 0, &fd, NULL) < 0) return -1;
    int descriptor_flags = (type & SOCK_CLOEXEC) ? FD_CLOEXEC : 0;
    if (syscall(SYS_fcntl, fd, F_SETFD, descriptor_flags) < 0) {
        int error = errno; (void)syscall(SYS_close, fd); return fail(error);
    }
    return fd;
}

int ker_socket_client_ff_owner_match(struct ker_socket_client *client,
    int owner_cap, int socket_cap)
{
    int rights[2] = {owner_cap, socket_cap};
    int64_t result = 0;
    size_t reply_length = 0;
    if (rpc(client, KER_SB_FF_OWNER_MATCH, NULL, 0, rights, 2, NULL, 0, 0,
            NULL, &result, &reply_length)) return -1;
    if (reply_length) return fail(EPROTO);
    if (result < 0) return fail(result >= -4095 ? (int)-result : EPROTO);
    if (result > 1) return fail(EPROTO);
    return (int)result;
}

int ker_socket_client_ff_owner_payload_snapshot(struct ker_socket_client *client,
    int owner_cap, struct ker_socket_member_payload_snapshot *snapshot)
{
    if (!snapshot) return fail(EINVAL);
    struct ker_sb_member_payload_snapshot wire = {0};
    int received = 0;
    if (socket_call(client, owner_cap, KER_SB_FF_OWNER_PAYLOAD, NULL, 0,
            &wire, sizeof(wire), NULL, &received) < 0) return -1;
    if (received != sizeof(wire) || wire.sampled_sockets > 4096 ||
        (wire.payload_bytes && !wire.sampled_sockets)) return fail(EPROTO);
    struct ker_socket_member_payload_snapshot completed = {
        .payload_bytes = wire.payload_bytes, .sampled_sockets = wire.sampled_sockets};
    *snapshot = completed;
    return 0;
}
