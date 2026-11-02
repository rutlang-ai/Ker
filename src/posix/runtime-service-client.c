#define _GNU_SOURCE
#include "runtime-service-client.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

#define RESPONSE_MAX (sizeof(struct ker_runtime_service_header) + \
    sizeof(struct ker_runtime_service_claim_result))
/* One monotonic bound covers connect, send and receive for each RPC. */
#ifdef KER_RUNTIME_SERVICE_CLIENT_TESTING
static uint64_t rpc_timeout_ns = UINT64_C(2000000000);
static unsigned test_post_receive_delay_ms;
void ker_runtime_service_client_test_configure(uint64_t timeout_ns,
    unsigned post_receive_delay_ms)
{
    rpc_timeout_ns = timeout_ns;
    test_post_receive_delay_ms = post_receive_delay_ms;
}
#else
#define RPC_TIMEOUT_NS UINT64_C(2000000000)
#endif

struct rpc_deadline { uint64_t at_ns; };

static int monotonic_ns(uint64_t *value)
{
    struct timespec now;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now)) return -1;
    if (now.tv_sec < 0 || (uint64_t)now.tv_sec > UINT64_MAX / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        return -1;
    }
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    return 0;
}

static int start_deadline(struct rpc_deadline *deadline)
{
    uint64_t now;
    if (monotonic_ns(&now)) return -1;
    uint64_t timeout =
#ifdef KER_RUNTIME_SERVICE_CLIENT_TESTING
        rpc_timeout_ns;
#else
        RPC_TIMEOUT_NS;
#endif
    if (UINT64_MAX - now < timeout) { errno = EOVERFLOW; return -1; }
    deadline->at_ns = now + timeout;
    return 0;
}

/* 0 means readiness before deadline, 1 means late readiness, and -1 means
 * timeout/error without readiness. rpc() may drain a late readable reply so a
 * completed CLAIM's lease ID is not lost. */
static int wait_ready(int fd, short events, const struct rpc_deadline *deadline)
{
    for (;;) {
        uint64_t now;
        if (monotonic_ns(&now)) return -1;
        bool expired = now >= deadline->at_ns;
        uint64_t remaining = expired ? 0 : deadline->at_ns - now;
        uint64_t milliseconds = (remaining + UINT64_C(999999)) / UINT64_C(1000000);
        int timeout = milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
        struct pollfd descriptor = {.fd = fd, .events = events};
        int ready = (int)syscall(SYS_poll, &descriptor, 1, timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (!ready) {
            if (expired) { errno = ETIMEDOUT; return -1; }
            continue;
        }
        if (descriptor.revents & POLLNVAL) { errno = EBADF; return -1; }
        if (descriptor.revents & (events | POLLERR | POLLHUP)) {
            if (monotonic_ns(&now)) return -1;
            return now >= deadline->at_ns ? 1 : 0;
        }
    }
}

static bool bytes_nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t value = 0;
    for (size_t i = 0; i < length; ++i) value |= bytes[i];
    return value != 0;
}

/* Read field 22 from a process stat file without using stdio or a path that
 * can be redirected through the preload interposer. Field 2 is parenthesized and
 * may contain spaces or ')' characters, so begin after its final ')'. */
static int process_start_time(pid_t pid, uint64_t *result)
{
    char buffer[4096];
    char path[64];
    int path_length = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (path_length <= 0 || (size_t)path_length >= sizeof(path)) {
        errno = EOVERFLOW;
        return -1;
    }
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    ssize_t length = (ssize_t)syscall(SYS_read, fd, buffer, sizeof(buffer) - 1);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    errno = saved;
    if (length <= 0 || (size_t)length >= sizeof(buffer) - 1) {
        errno = EPROTO;
        return -1;
    }
    buffer[length] = '\0';
    char *cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ') { errno = EPROTO; return -1; }
    cursor += 2; /* field 3 */
    for (unsigned field = 3; field < 22; ++field) {
        char *space = strchr(cursor, ' ');
        if (!space) { errno = EPROTO; return -1; }
        cursor = space + 1;
    }
    if (*cursor < '0' || *cursor > '9') { errno = EPROTO; return -1; }
    uint64_t value = 0;
    do {
        unsigned digit = (unsigned)(*cursor - '0');
        if (value > (UINT64_MAX - digit) / 10) { errno = EOVERFLOW; return -1; }
        value = value * 10 + digit;
        ++cursor;
    } while (*cursor >= '0' && *cursor <= '9');
    if (*cursor != ' ' && *cursor != '\n' && *cursor != '\0') {
        errno = EPROTO;
        return -1;
    }
    *result = value;
    return 0;
}

static int current_start_time(uint64_t *result)
{
    return process_start_time(getpid(), result);
}

static int process_executable_identity(pid_t pid, uint8_t digest[32],
    struct stat *identity, const struct rpc_deadline *deadline)
{
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) { errno = EOVERFLOW; return -1; }
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct stat before;
    if (syscall(SYS_fstat, fd, &before)) {
        int error = errno; (void)syscall(SYS_close, fd); errno = error; return -1;
    }
    if (before.st_size < 0 || (uint64_t)before.st_size > UINT64_C(67108864)) {
        (void)syscall(SYS_close, fd); errno = EFBIG; return -1;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) { (void)syscall(SYS_close, fd); errno = ENOMEM; return -1; }
    int result = -1;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        errno = EIO;
        goto done;
    }
    uint8_t buffer[16384];
    uint64_t total = 0;
    for (;;) {
        uint64_t now;
        if (monotonic_ns(&now)) goto done;
        if (now >= deadline->at_ns) { errno = ETIMEDOUT; goto done; }
        ssize_t count = (ssize_t)syscall(SYS_read, fd, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        if (!count) break;
        if (total > UINT64_C(67108864) - (uint64_t)count) {
            errno = EFBIG;
            goto done;
        }
        total += (uint64_t)count;
        if (EVP_DigestUpdate(context, buffer, (size_t)count) != 1) {
            errno = EIO;
            goto done;
        }
    }
    unsigned digest_length = 0;
    if (EVP_DigestFinal_ex(context, digest, &digest_length) != 1 || digest_length != 32) {
        errno = EIO;
        goto done;
    }
    struct stat after;
    if (syscall(SYS_fstat, fd, &after)) goto done;
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || total != (uint64_t)before.st_size) {
        errno = ESTALE;
        goto done;
    }
    if (identity) *identity = after;
    result = 0;
done: {
        int error = errno;
        EVP_MD_CTX_free(context);
        (void)syscall(SYS_close, fd);
        errno = error;
        return result;
    }
}

static int process_executable_still_same(pid_t pid, const struct stat *identity)
{
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) { errno = EOVERFLOW; return -1; }
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct stat current;
    int result = (int)syscall(SYS_fstat, fd, &current);
    int error = errno;
    (void)syscall(SYS_close, fd);
    if (result) { errno = error; return -1; }
    if (current.st_dev != identity->st_dev || current.st_ino != identity->st_ino) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static void forget_fd(struct ker_runtime_service_client *client)
{
    client->fd = -1;
    client->fd_identity_valid = 0;
    client->sequence = 0;
}

static bool fd_is_ours(const struct ker_runtime_service_client *client)
{
    struct stat value;
    if (client->fd < 0 || !client->fd_identity_valid ||
        syscall(SYS_fstat, client->fd, &value)) return false;
    if ((uint64_t)value.st_dev != client->fd_device ||
        (uint64_t)value.st_ino != client->fd_inode || !S_ISSOCK(value.st_mode))
        return false;
    int type = 0, domain = 0;
    uint64_t cookie = 0;
    socklen_t length = sizeof(type);
    if (syscall(SYS_getsockopt, client->fd, SOL_SOCKET, SO_TYPE, &type, &length) ||
        length != sizeof(type) || type != SOCK_SEQPACKET) return false;
    length = sizeof(domain);
    if (syscall(SYS_getsockopt, client->fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) ||
        length != sizeof(domain) || domain != AF_UNIX) return false;
    length = sizeof(cookie);
    if (syscall(SYS_getsockopt, client->fd, SOL_SOCKET, SO_COOKIE, &cookie, &length) ||
        length != sizeof(cookie)) return false;
    return cookie == client->fd_cookie;
}

static void close_owned_fd(struct ker_runtime_service_client *client)
{
    if (fd_is_ours(client)) (void)syscall(SYS_close, client->fd);
    forget_fd(client);
}

static int open_channel(struct ker_runtime_service_client *client,
    const struct rpc_deadline *deadline)
{
    if (client->path[0] != '/') { errno = EINVAL; return -1; }
    size_t path_length = strnlen(client->path, sizeof(client->path));
    if (!path_length || path_length > KER_RUNTIME_SERVICE_PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = (int)syscall(SYS_socket, AF_UNIX,
        SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    int receive_credentials = 1;
    if (syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_PASSCRED,
            &receive_credentials, sizeof(receive_credentials))) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, client->path, path_length + 1);
    socklen_t address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
        path_length + 1);
    if (syscall(SYS_connect, fd, &address, address_length)) {
        if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR &&
            errno != EAGAIN) {
            int error = errno;
            (void)syscall(SYS_close, fd);
            errno = error;
            return -1;
        }
        int ready = wait_ready(fd, POLLOUT, deadline);
        if (ready < 0 || ready > 0) {
            if (ready > 0) errno = ETIMEDOUT;
            int error = errno;
            (void)syscall(SYS_close, fd);
            errno = error;
            return -1;
        }
        int socket_error = 0;
        socklen_t error_length = sizeof(socket_error);
        if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR,
                &socket_error, &error_length)) {
            int error = errno;
            (void)syscall(SYS_close, fd);
            errno = error;
            return -1;
        }
        if (error_length != sizeof(socket_error) || socket_error) {
            int error = socket_error ? socket_error : EPROTO;
            (void)syscall(SYS_close, fd);
            errno = error;
            return -1;
        }
    }
    struct ucred peer = {0};
    socklen_t peer_length = sizeof(peer);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERCRED,
            &peer, &peer_length)) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    if (peer_length != sizeof(peer) || peer.uid != geteuid() || peer.gid != getegid()) {
        (void)syscall(SYS_close, fd);
        errno = EACCES;
        return -1;
    }
    if (!client->supervisor_pid || peer.pid != client->supervisor_pid ||
        peer.pid != getppid()) {
        (void)syscall(SYS_close, fd);
        errno = EACCES;
        return -1;
    }
    uint64_t peer_start_time;
    if (process_start_time(peer.pid, &peer_start_time)) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    if (peer_start_time != client->supervisor_start_time) {
        (void)syscall(SYS_close, fd);
        errno = ESTALE;
        return -1;
    }
    int peer_pidfd = -1;
    socklen_t pidfd_length = sizeof(peer_pidfd);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERPIDFD,
            &peer_pidfd, &pidfd_length)) {
        int error = errno;
        if (peer_pidfd >= 0) (void)syscall(SYS_close, peer_pidfd);
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    if (pidfd_length != sizeof(peer_pidfd) || peer_pidfd < 0) {
        if (peer_pidfd >= 0) (void)syscall(SYS_close, peer_pidfd);
        (void)syscall(SYS_close, fd);
        errno = EPROTO;
        return -1;
    }
    struct pollfd peer_liveness = {.fd = peer_pidfd, .events = POLLIN};
    int peer_exited = (int)syscall(SYS_poll, &peer_liveness, 1, 0);
    int peer_error = errno;
    if (peer_exited != 0) {
        (void)syscall(SYS_close, peer_pidfd);
        (void)syscall(SYS_close, fd);
        errno = peer_exited < 0 ? peer_error : ESTALE;
        return -1;
    }
    uint8_t peer_executable_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    struct stat peer_executable_identity;
    if (process_executable_identity(peer.pid, peer_executable_hash,
            &peer_executable_identity, deadline)) {
        int error = errno;
        (void)syscall(SYS_close, peer_pidfd);
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    uint64_t peer_start_after_hash;
    int identity_error = 0;
    if (memcmp(peer_executable_hash, client->supervisor_exe_sha256,
            sizeof(peer_executable_hash))) identity_error = EACCES;
    else if (process_executable_still_same(peer.pid, &peer_executable_identity))
        identity_error = errno;
    else if (process_start_time(peer.pid, &peer_start_after_hash))
        identity_error = errno;
    else if (peer_start_after_hash != client->supervisor_start_time)
        identity_error = ESTALE;
    if (identity_error) {
        (void)syscall(SYS_close, peer_pidfd);
        (void)syscall(SYS_close, fd);
        errno = identity_error;
        return -1;
    }
    peer_exited = (int)syscall(SYS_poll, &peer_liveness, 1, 0);
    peer_error = errno;
    (void)syscall(SYS_close, peer_pidfd);
    if (peer_exited != 0) {
        (void)syscall(SYS_close, fd);
        errno = peer_exited < 0 ? peer_error : ESTALE;
        return -1;
    }
    struct stat value;
    if (syscall(SYS_fstat, fd, &value)) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    uint64_t cookie = 0;
    socklen_t cookie_length = sizeof(cookie);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_COOKIE, &cookie, &cookie_length)) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    if (cookie_length != sizeof(cookie)) {
        (void)syscall(SYS_close, fd);
        errno = EPROTO;
        return -1;
    }
    uint64_t completed_at;
    if (monotonic_ns(&completed_at)) {
        int error = errno;
        (void)syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    if (completed_at >= deadline->at_ns) {
        (void)syscall(SYS_close, fd);
        errno = ETIMEDOUT;
        return -1;
    }
    client->fd = fd;
    client->fd_identity_valid = 1;
    client->fd_device = (uint64_t)value.st_dev;
    client->fd_inode = (uint64_t)value.st_ino;
    client->fd_cookie = cookie;
    client->supervisor_uid = (uint32_t)peer.uid;
    client->supervisor_gid = (uint32_t)peer.gid;
    client->sequence = 0;
    return 0;
}

static void initialize_header(struct ker_runtime_service_client *client,
    struct ker_runtime_service_header *header, uint16_t operation,
    const uint8_t lease_id[KER_RUNTIME_SERVICE_LEASE_BYTES], uint32_t packet_length)
{
    memset(header, 0, sizeof(*header));
    header->magic = KER_RUNTIME_SERVICE_MAGIC;
    header->version = KER_RUNTIME_SERVICE_VERSION;
    header->operation = operation;
    header->packet_length = packet_length;
    header->sequence = client->sequence + 1;
    header->service_epoch = client->service_epoch;
    memcpy(header->run_nonce, client->run_nonce, sizeof(header->run_nonce));
    if (lease_id) memcpy(header->lease_id, lease_id, sizeof(header->lease_id));
}

static int rpc(struct ker_runtime_service_client *client, uint16_t operation,
    const uint8_t lease_id[KER_RUNTIME_SERVICE_LEASE_BYTES],
    const void *body, size_t body_length, bool claim_response,
    uint8_t response_lease[KER_RUNTIME_SERVICE_LEASE_BYTES],
    int *late_reply,
    const struct rpc_deadline *deadline)
{
    if (late_reply) *late_reply = 0;
    if (client->fd < 0 || !fd_is_ours(client)) { errno = ENOTCONN; return -1; }
    if (client->sequence == UINT64_MAX) { errno = EOVERFLOW; return -1; }
    struct ker_runtime_service_header request;
    uint32_t request_length = (uint32_t)(sizeof(request) + body_length);
    initialize_header(client, &request, operation, lease_id, request_length);
    struct iovec vectors[2] = {
        {.iov_base = &request, .iov_len = sizeof(request)},
        {.iov_base = (void *)body, .iov_len = body_length}
    };
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = body_length ? 2 : 1};
    ssize_t sent;
    for (;;) {
        int ready = wait_ready(client->fd, POLLOUT, deadline);
        if (ready < 0 || ready > 0) {
            client->failed = 1;
            if (ready > 0) errno = ETIMEDOUT;
            return -1;
        }
        uint64_t send_at;
        if (monotonic_ns(&send_at)) { client->failed = 1; return -1; }
        if (send_at >= deadline->at_ns) {
            client->failed = 1;
            errno = ETIMEDOUT;
            return -1;
        }
        sent = (ssize_t)syscall(SYS_sendmsg, client->fd, &message,
            MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        break;
    }
    if (sent != (ssize_t)request_length) {
        int error = sent < 0 ? errno : EIO;
        client->failed = 1;
        errno = error;
        return -1;
    }
    client->sequence = request.sequence;

    uint8_t packet[RESPONSE_MAX];
    struct iovec response_vector = {.iov_base = packet, .iov_len = sizeof(packet)};
    char control[CMSG_SPACE(sizeof(int) * 32)];
    struct msghdr response_message = {.msg_iov = &response_vector, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t received;
    for (;;) {
        int ready = wait_ready(client->fd, POLLIN, deadline);
        if (ready < 0) {
            client->failed = 1;
            return -1;
        }
        response_message.msg_controllen = sizeof(control);
        response_message.msg_flags = 0;
        received = (ssize_t)syscall(SYS_recvmsg, client->fd, &response_message,
            MSG_CMSG_CLOEXEC | MSG_TRUNC | MSG_DONTWAIT);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (ready > 0) { client->failed = 1; errno = ETIMEDOUT; return -1; }
            continue;
        }
        break;
    }
    if (received < 0) { client->failed = 1; return -1; }
#ifdef KER_RUNTIME_SERVICE_CLIENT_TESTING
    if (test_post_receive_delay_ms) {
        unsigned delay = test_post_receive_delay_ms;
        test_post_receive_delay_ms = 0;
        struct timespec pause = {
            .tv_sec = (time_t)(delay / 1000),
            .tv_nsec = (long)(delay % 1000) * 1000000L
        };
        while (syscall(SYS_nanosleep, &pause, &pause) && errno == EINTR) {}
    }
#endif
    bool bad_ancillary = false;
    bool saw_credentials = false;
    struct ucred response_credential = {0};
    for (struct cmsghdr *control_header = CMSG_FIRSTHDR(&response_message);
         control_header; control_header = CMSG_NXTHDR(&response_message, control_header)) {
        if (control_header->cmsg_level == SOL_SOCKET &&
            control_header->cmsg_type == SCM_RIGHTS &&
            control_header->cmsg_len >= CMSG_LEN(0)) {
            bad_ancillary = true;
            size_t bytes = control_header->cmsg_len - CMSG_LEN(0);
            size_t descriptor_count = bytes / sizeof(int);
            const int *descriptors = (const int *)CMSG_DATA(control_header);
            for (size_t i = 0; i < descriptor_count; ++i)
                if (descriptors[i] >= 0) (void)syscall(SYS_close, descriptors[i]);
        } else if (control_header->cmsg_level == SOL_SOCKET &&
            control_header->cmsg_type == SCM_CREDENTIALS &&
            control_header->cmsg_len == CMSG_LEN(sizeof(response_credential)) &&
            !saw_credentials) {
            memcpy(&response_credential, CMSG_DATA(control_header),
                sizeof(response_credential));
            saw_credentials = true;
        } else {
            bad_ancillary = true;
        }
    }
    if ((response_message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        bad_ancillary || !saw_credentials ||
        response_credential.pid != client->supervisor_pid ||
        response_credential.uid != (uid_t)client->supervisor_uid ||
        response_credential.gid != (gid_t)client->supervisor_gid ||
        (size_t)received < sizeof(struct ker_runtime_service_header) ||
        (size_t)received > sizeof(packet)) {
        client->failed = 1; errno = EPROTO; return -1;
    }
    struct ker_runtime_service_header reply;
    memcpy(&reply, packet, sizeof(reply));
    size_t expected_body = claim_response && reply.status == 0 ?
        sizeof(struct ker_runtime_service_claim_result) : 0;
    if (reply.magic != KER_RUNTIME_SERVICE_MAGIC ||
        reply.version != KER_RUNTIME_SERVICE_VERSION ||
        reply.operation != operation || reply.packet_length != (uint32_t)received ||
        reply.sequence != request.sequence ||
        reply.service_epoch != client->service_epoch ||
        memcmp(reply.run_nonce, client->run_nonce, sizeof(reply.run_nonce)) ||
        (lease_id && memcmp(reply.lease_id, lease_id, sizeof(reply.lease_id))) ||
        (size_t)received != sizeof(reply) + expected_body || reply.status < 0) {
        client->failed = 1; errno = EPROTO; return -1;
    }
    uint64_t completed_at;
    if (monotonic_ns(&completed_at)) { client->failed = 1; return -1; }
    bool late = completed_at >= deadline->at_ns;
    if (late && late_reply) *late_reply = 1;
    if (claim_response && reply.status > 0 &&
        bytes_nonzero(reply.lease_id, sizeof(reply.lease_id))) {
        client->failed = 1; errno = EPROTO; return -1;
    }
    if (reply.status > 0) { errno = late ? ETIMEDOUT : reply.status; return -1; }
    if (claim_response) {
        if (!bytes_nonzero(reply.lease_id, sizeof(reply.lease_id))) {
            client->failed = 1; errno = EPROTO; return -1;
        }
        if (response_lease) memcpy(response_lease, reply.lease_id, sizeof(reply.lease_id));
        memcpy(client->worker_profile_hash, packet + sizeof(reply),
            sizeof(client->worker_profile_hash));
    }
    return 0;
}

void ker_runtime_service_client_init(struct ker_runtime_service_client *client)
{
    if (!client) return;
    memset(client, 0, sizeof(*client));
    client->fd = -1;
    client->initialized = 1;
}

static int validate_owner(struct ker_runtime_service_client *client)
{
    if (!client || !client->initialized) { errno = EINVAL; return -1; }
    if (client->owner_pid != (int32_t)getpid()) {
        /* Do not close the inherited number: close-all may have reused it. */
        forget_fd(client);
        client->failed = 1;
        errno = ECHILD;
        return -1;
    }
    uint64_t start_time;
    if (current_start_time(&start_time)) return -1;
    if (start_time != client->owner_start_time) { errno = ESTALE; return -1; }
    return 0;
}

int ker_runtime_service_claim(struct ker_runtime_service_client *client,
    const char *path, const uint8_t run_nonce[KER_RUNTIME_SERVICE_NONCE_BYTES],
    uint64_t service_epoch, const uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES],
    const uint8_t role_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES],
    const uint8_t expected_worker_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES],
    int32_t supervisor_pid, uint64_t supervisor_start_time,
    const uint8_t supervisor_exe_sha256[KER_RUNTIME_SERVICE_PROFILE_BYTES])
{
    if (!client || !path || !run_nonce || !ticket || !role_profile_hash ||
        !expected_worker_profile_hash || !supervisor_exe_sha256 || supervisor_pid <= 0 ||
        !bytes_nonzero(run_nonce, KER_RUNTIME_SERVICE_NONCE_BYTES) ||
        !service_epoch || !bytes_nonzero(ticket, KER_RUNTIME_SERVICE_TICKET_BYTES) ||
        !bytes_nonzero(role_profile_hash, KER_RUNTIME_SERVICE_PROFILE_BYTES) ||
        !bytes_nonzero(expected_worker_profile_hash, KER_RUNTIME_SERVICE_PROFILE_BYTES) ||
        !supervisor_start_time) {
        errno = EINVAL; return -1;
    }
    if (!client->initialized) { errno = EINVAL; return -1; }
    if (client->lease_valid) { errno = EALREADY; return -1; }
    client->cleanup_only = 0;
    size_t path_length = strnlen(path, KER_RUNTIME_SERVICE_PATH_MAX + 1);
    if (!path_length || path_length > KER_RUNTIME_SERVICE_PATH_MAX || path[0] != '/') {
        errno = EINVAL; return -1;
    }
    uint64_t start_time;
    if (current_start_time(&start_time)) return -1;
    memcpy(client->path, path, path_length + 1);
    memcpy(client->run_nonce, run_nonce, sizeof(client->run_nonce));
    memcpy(client->ticket, ticket, sizeof(client->ticket));
    memcpy(client->role_profile_hash, role_profile_hash,
        sizeof(client->role_profile_hash));
    memcpy(client->expected_worker_profile_hash, expected_worker_profile_hash,
        sizeof(client->expected_worker_profile_hash));
    client->service_epoch = service_epoch;
    client->owner_pid = (int32_t)getpid();
    client->owner_start_time = start_time;
    client->supervisor_pid = supervisor_pid;
    client->supervisor_start_time = supervisor_start_time;
    memcpy(client->supervisor_exe_sha256, supervisor_exe_sha256,
        sizeof(client->supervisor_exe_sha256));
    client->failed = 0;
    struct rpc_deadline deadline;
    if (start_deadline(&deadline) || open_channel(client, &deadline)) return -1;
    struct ker_runtime_service_claim body;
    memcpy(body.ticket, ticket, sizeof(body.ticket));
    memcpy(body.profile_hash, role_profile_hash, sizeof(body.profile_hash));
    uint8_t lease[KER_RUNTIME_SERVICE_LEASE_BYTES];
    int late_reply = 0;
    if (rpc(client, KER_RUNTIME_SERVICE_CLAIM, NULL, &body, sizeof(body), true,
            lease, &late_reply, &deadline)) {
        close_owned_fd(client);
        return -1;
    }
    memcpy(client->lease_id, lease, sizeof(client->lease_id));
    client->lease_valid = 1;
    if (memcmp(client->worker_profile_hash, client->expected_worker_profile_hash,
            sizeof(client->worker_profile_hash))) {
        struct rpc_deadline release_deadline;
        int release_late = 0;
        if (!start_deadline(&release_deadline) &&
            !rpc(client, KER_RUNTIME_SERVICE_RELEASE, client->lease_id, NULL, 0,
                false, NULL, &release_late, &release_deadline)) {
            client->lease_valid = 0;
            memset(client->lease_id, 0, sizeof(client->lease_id));
            close_owned_fd(client);
        } else {
            client->cleanup_only = 1;
            client->failed = 1;
            close_owned_fd(client);
        }
        errno = EPROTO;
        return -1;
    }
    if (late_reply) { errno = ETIMEDOUT; return -1; }
    return 0;
}

int ker_runtime_service_check(struct ker_runtime_service_client *client)
{
    if (validate_owner(client)) return -1;
    if (client->cleanup_only) { errno = EACCES; return -1; }
    if (!client->lease_valid || client->failed) { errno = ENOTCONN; return -1; }
    struct rpc_deadline deadline;
    if (start_deadline(&deadline)) return -1;
    int late_reply = 0;
    int result = rpc(client, KER_RUNTIME_SERVICE_CHECK, client->lease_id, NULL, 0,
        false, NULL, &late_reply, &deadline);
    if (!result && late_reply) { errno = ETIMEDOUT; return -1; }
    return result;
}

int ker_runtime_service_release(struct ker_runtime_service_client *client)
{
    if (validate_owner(client)) return -1;
    if (!client->lease_valid || client->failed) { errno = ENOTCONN; return -1; }
    struct rpc_deadline deadline;
    if (start_deadline(&deadline)) return -1;
    int late_reply = 0;
    if (rpc(client, KER_RUNTIME_SERVICE_RELEASE, client->lease_id, NULL, 0,
            false, NULL, &late_reply, &deadline)) return -1;
    client->lease_valid = 0;
    memset(client->lease_id, 0, sizeof(client->lease_id));
    close_owned_fd(client);
    if (late_reply) { errno = ETIMEDOUT; return -1; }
    return 0;
}

int ker_runtime_service_reconnect(struct ker_runtime_service_client *client)
{
    if (validate_owner(client)) return -1;
    if (!client->lease_valid) { errno = EINVAL; return -1; }
    /* This API is for a caller that has already closed inherited descriptors.
     * Forget, never close, the old number because it may now name another fd. */
    forget_fd(client);
    client->failed = 0;
    struct rpc_deadline deadline;
    if (start_deadline(&deadline) || open_channel(client, &deadline)) return -1;
    if (client->cleanup_only) return 0;
    int late_reply = 0;
    int result = rpc(client, KER_RUNTIME_SERVICE_CHECK, client->lease_id, NULL, 0,
        false, NULL, &late_reply, &deadline);
    if (!result && late_reply) { errno = ETIMEDOUT; return -1; }
    return result;
}

void ker_runtime_service_client_close(struct ker_runtime_service_client *client)
{
    if (!client || !client->initialized) return;
    if (client->owner_pid == (int32_t)getpid()) close_owned_fd(client);
    else forget_fd(client);
    /* Closing only the channel does not release the supervisor-owned lease.
     * Retain its identity so the same process can reconnect and CHECK/RELEASE. */
}
