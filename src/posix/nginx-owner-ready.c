#define _GNU_SOURCE
#include "nginx-owner-ready.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

static int same_identity(int fd, const struct stat *expected)
{
    struct stat value;
    if (syscall(SYS_fstat, fd, &value)) return -errno;
    return value.st_dev == expected->st_dev && value.st_ino == expected->st_ino &&
        (value.st_mode & S_IFMT) == (expected->st_mode & S_IFMT) ? 0 : -ESTALE;
}
static int endpoint_matches(const struct ker_nginx_owner_ready_sender *sender)
{
    int status = same_identity(sender->fd, &sender->endpoint_identity);
    if (status) return status;
    uint64_t cookie = 0;
    socklen_t length = sizeof(cookie);
    if (syscall(SYS_getsockopt, sender->fd, SOL_SOCKET, SO_COOKIE, &cookie, &length)) return -errno;
    return length == sizeof(cookie) && cookie == sender->cookie ? 0 : -ESTALE;
}
static int start_ticks(uint64_t *ticks)
{
    char bytes[4096];
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -errno;
    ssize_t amount = syscall(SYS_read, fd, bytes, sizeof(bytes) - 1);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    if (amount < 0) return -saved;
    if (!amount || amount == (ssize_t)sizeof(bytes) - 1) return -EPROTO;
    bytes[amount] = '\0';
    char *cursor = strrchr(bytes, ')');
    if (!cursor || cursor[1] != ' ') return -EPROTO;
    cursor += 2;
    for (unsigned field = 3; field <= 22; ++field) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) return -EPROTO;
        char *end = cursor;
        while (*end && *end != ' ') ++end;
        if (field == 22) {
            char saved_char = *end;
            *end = '\0';
            char *parsed = NULL;
            errno = 0;
            unsigned long long value = strtoull(cursor, &parsed, 10);
            int error = errno;
            *end = saved_char;
            if (error || parsed != end || cursor == end || !value) return -EPROTO;
            *ticks = (uint64_t)value;
            return 0;
        }
        cursor = end;
    }
    return -EPROTO;
}
int ker_nginx_owner_ready_sender_init(struct ker_nginx_owner_ready_sender *sender,
    int fd, pid_t expected_peer)
{
    if (!sender || fd < 3 || expected_peer <= 0) return -EINVAL;
    if (sender->initialized) return -EALREADY;
    struct ker_nginx_owner_ready_sender value = {.fd = fd, .peer_pidfd = -1};
    if (syscall(SYS_fstat, fd, &value.endpoint_identity)) return -errno;
    int type = 0, domain = 0;
    socklen_t length = sizeof(type);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &length)) return -errno;
    if (length != sizeof(type) || type != SOCK_SEQPACKET) return -EPROTOTYPE;
    length = sizeof(domain);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_DOMAIN, &domain, &length)) return -errno;
    if (length != sizeof(domain) || domain != AF_UNIX) return -EAFNOSUPPORT;
    struct ucred peer;
    length = sizeof(peer);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERCRED, &peer, &length)) return -errno;
    if (length != sizeof(peer) || peer.pid != expected_peer ||
        peer.uid != getuid() || peer.gid != getgid()) return -EACCES;
    length = sizeof(value.cookie);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_COOKIE, &value.cookie, &length)) return -errno;
    if (length != sizeof(value.cookie) || !value.cookie) return -EPROTO;
    length = sizeof(value.peer_pidfd);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERPIDFD, &value.peer_pidfd, &length)) return -errno;
    int status = 0;
    if (length != sizeof(value.peer_pidfd) || value.peer_pidfd < 0) status = -EPROTO;
    else if (syscall(SYS_fstat, value.peer_pidfd, &value.pidfd_identity)) status = -errno;
    int flags = (int)syscall(SYS_fcntl, fd, F_GETFD, 0);
    if (!status && flags < 0) status = -errno;
    if (!status && syscall(SYS_fcntl, fd, F_SETFD, flags | FD_CLOEXEC)) status = -errno;
    if (status) {
        if (value.peer_pidfd >= 0) (void)syscall(SYS_close, value.peer_pidfd);
        return status;
    }
    value.master_pid = getpid(); value.initialized = true;
    *sender = value;
    return 0;
}
int ker_nginx_owner_ready_sender_bind(struct ker_nginx_owner_ready_sender *sender,
    int slot_fd, unsigned role)
{
    if (!sender || !sender->initialized || role > 1 || slot_fd < 0) return -EINVAL;
    if (sender->bound_pid) return -EALREADY;
    if (sender->master_pid == getpid()) return -EPERM;
    struct stat slot;
    if (syscall(SYS_fstat, slot_fd, &slot)) return -errno;
    int flags = (int)syscall(SYS_fcntl, slot_fd, F_GETFL, 0);
    if (flags < 0) return -errno;
    if (!S_ISFIFO(slot.st_mode) || (flags & O_ACCMODE) != O_WRONLY) return -ENOTSOCK;
    uint64_t ticks = 0;
    int status = start_ticks(&ticks);
    if (status) return status;
    sender->record = (struct ker_nginx_owner_ready_record){
        .magic = KER_NGINX_OWNER_READY_MAGIC, .version = KER_NGINX_OWNER_READY_VERSION,
        .length = sizeof(sender->record), .role = role,
        .slot_device = (uint64_t)slot.st_dev, .slot_inode = (uint64_t)slot.st_ino,
        .worker_pid = (uint32_t)getpid(), .worker_start_time = ticks,
        .endpoint_cookie = sender->cookie};
    sender->bound_pid = getpid();
    return 0;
}
int ker_nginx_owner_ready_sender_send(struct ker_nginx_owner_ready_sender *sender)
{
    if (!sender || !sender->initialized || !sender->bound_pid) return -EINVAL;
    if (sender->bound_pid != getpid()) return -EXDEV;
    if (sender->sent) return 0;
    struct timespec now;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now)) return -errno;
    uint64_t ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    if (!sender->deadline_ns) sender->deadline_ns = ns + UINT64_C(5000000000);
    if (ns >= sender->deadline_ns) return -ETIMEDOUT;
    int status = endpoint_matches(sender);
    if (!status) status = same_identity(sender->peer_pidfd, &sender->pidfd_identity);
    if (status) return status == -EINTR ? -EAGAIN : status;
    struct pollfd fds[] = {{.fd = sender->peer_pidfd, .events = POLLIN},
        {.fd = sender->fd, .events = POLLHUP}};
    if (syscall(SYS_poll, fds, 2, 0) < 0) return errno == EINTR ? -EAGAIN : -errno;
    if (fds[0].revents || (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL))) return -ECONNRESET;
    ssize_t amount = syscall(SYS_sendto, sender->fd, &sender->record, sizeof(sender->record),
        MSG_NOSIGNAL | MSG_DONTWAIT, NULL, 0);
    if (amount < 0) return errno == EINTR || errno == EAGAIN ? -EAGAIN : -errno;
    if (amount != sizeof(sender->record)) return -EPROTO;
    sender->sent = true;
    ker_nginx_owner_ready_sender_close(sender);
    return 0;
}
void ker_nginx_owner_ready_sender_close(struct ker_nginx_owner_ready_sender *sender)
{
    if (!sender || !sender->initialized) return;
    if (sender->fd >= 0 && !endpoint_matches(sender)) (void)syscall(SYS_close, sender->fd);
    if (sender->peer_pidfd >= 0 && !same_identity(sender->peer_pidfd, &sender->pidfd_identity))
        (void)syscall(SYS_close, sender->peer_pidfd);
    sender->fd = sender->peer_pidfd = -1;
}
