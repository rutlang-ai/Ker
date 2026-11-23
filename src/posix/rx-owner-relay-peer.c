#define _GNU_SOURCE
#include "rx-owner-relay-peer.h"
#include "rx-decision-wire.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static uint32_t frame_hash(const unsigned char *frame, size_t bytes)
{
    uint32_t hash = UINT32_C(2166136261);
    for (size_t i = 0; i < bytes; ++i) { hash ^= frame[i]; hash *= UINT32_C(16777619); }
    return hash;
}

static int owner_live(const struct ker_rx_owner_relay_peer *peer)
{
    /* A live unrelated pidfd is not authority for this channel's owner. */
    char path[64], contents[1024];
    int length = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", peer->pidfd);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -EINVAL;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -errno;
    long count = syscall(SYS_read, fd, contents, sizeof(contents) - 1);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    if (count < 0) return -saved;
    if (!count || (size_t)count == sizeof(contents) - 1) return -EPROTO;
    contents[count] = 0;
    char *pid = strstr(contents, "\nPid:\t");
    if (!pid) return -EPROTO;
    char *end = NULL;
    errno = 0;
    long value = strtol(pid + 6, &end, 10);
    if (errno || end == pid + 6 || (*end != '\n' && *end != 0) ||
        value != (long)peer->identity.owner_pid) return -ESTALE;
    struct pollfd pfd = {.fd = peer->pidfd, .events = POLLIN};
    long ready = syscall(SYS_poll, &pfd, 1, 0);
    if (ready < 0) return -errno;
    if (ready || pfd.revents) return -ESRCH;
    length = snprintf(path, sizeof(path), "/proc/%u/stat", peer->identity.owner_pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -EINVAL;
    fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -errno;
    count = syscall(SYS_read, fd, contents, sizeof(contents) - 1);
    saved = errno;
    (void)syscall(SYS_close, fd);
    if (count < 0) return -saved;
    if (!count || (size_t)count == sizeof(contents) - 1) return -EPROTO;
    contents[count] = 0;
    char *cursor = strrchr(contents, ')');
    if (!cursor || cursor[1] != ' ') return -EPROTO;
    cursor += 2;
    for (unsigned field = 3; field < 22; ++field) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) return -EPROTO;
        while (*cursor && *cursor != ' ') ++cursor;
    }
    while (*cursor == ' ') ++cursor;
    errno = 0;
    unsigned long long ticks = strtoull(cursor, &end, 10);
    if (errno || end == cursor || (*end && *end != ' ') ||
        ticks != peer->identity.owner_start_ticks) return -ESTALE;
    return 0;
}

static int receive_reply(struct ker_rx_owner_relay_peer *peer,
    const struct ker_rx_owner_relay_header *request, const unsigned char *frame,
    size_t bytes, int *action, bool blocking)
{
    unsigned char packet[sizeof(*request) + KER_RX_OWNER_RELAY_MAX_FRAME];
    unsigned char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(4 * sizeof(int))];
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now >= request->deadline_ns) return -ETIMEDOUT;
        int live = owner_live(peer);
        if (live) return live;
        struct pollfd fds[] = {{.fd = peer->fd, .events = POLLIN},
            {.fd = peer->pidfd, .events = POLLIN}};
        int timeout = (int)((request->deadline_ns - now + 999999) / 1000000);
        long ready = syscall(SYS_poll, fds, 2, blocking ? timeout : 0);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -errno;
        if (fds[1].revents) return -ESRCH;
        if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) return -ENOTCONN;
        if (!ready) { if (!blocking) return -EAGAIN; continue; }
        struct iovec iov = {.iov_base = packet, .iov_len = sizeof(packet)};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control)};
        long count = syscall(SYS_recvmsg, peer->fd, &message,
            MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!blocking) return -EAGAIN;
            continue;
        }
        if (count < 0) return -errno;
        unsigned credentials = 0;
        bool malformed = false;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
                cmsg = CMSG_NXTHDR(&message, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                if (cmsg->cmsg_len < CMSG_LEN(0)) { malformed = true; continue; }
                size_t size = cmsg->cmsg_len - CMSG_LEN(0);
                for (size_t offset = 0; offset + sizeof(int) <= size; offset += sizeof(int)) {
                    int received_fd;
                    memcpy(&received_fd, (unsigned char *)CMSG_DATA(cmsg) + offset, sizeof(int));
                    (void)syscall(SYS_close, received_fd);
                }
                malformed = true;
            } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                struct ucred cred;
                memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
                ++credentials;
                if (cred.pid != (pid_t)peer->identity.owner_pid ||
                    cred.uid != peer->uid || cred.gid != peer->gid) malformed = true;
            } else malformed = true;
        }
        if (malformed || credentials != 1 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            count != (long)(sizeof(*request) + bytes)) return -EPROTO;
        struct ker_rx_owner_relay_header reply, expected = *request;
        memcpy(&reply, packet, sizeof(reply));
        expected.type = KER_RX_OWNER_RELAY_REPLY;
        expected.dispatcher_result = reply.dispatcher_result;
        expected.frame_hash32 = frame_hash(frame, bytes);
        expected.frame_unchanged = 1;
        if (reply.dispatcher_result < -3 || memcmp(&reply, &expected, sizeof(reply)) ||
            memcmp(packet + sizeof(reply), frame, bytes)) return -EPROTO;
        live = owner_live(peer);
        if (live) return live;
        now = now_ns();
        if (!now || now >= request->deadline_ns) return -ETIMEDOUT;
        *action = reply.dispatcher_result == request->queue_id ?
            KER_RX_DECISION_LOCAL : KER_RX_DECISION_DROP;
        return 0;
    }
}

int ker_rx_owner_relay_peer_begin(struct ker_rx_owner_relay_peer *peer,
    const struct ker_rx_owner_relay_header *source, const void *frame,
    size_t bytes)
{
    if (!peer || peer->fd < 0 || peer->pidfd < 0) return -ENOTCONN;
    if (peer->pending_active) return -EBUSY;
    if (!source || !frame || bytes < 14 || bytes > KER_RX_OWNER_RELAY_MAX_FRAME ||
        source->magic != KER_RX_OWNER_RELAY_MAGIC || source->version != KER_RX_OWNER_RELAY_VERSION ||
        source->type != KER_RX_OWNER_RELAY_REPLY || source->dispatcher_result != -3 ||
        !source->packet_id || !source->queue_count || source->queue_id >= source->queue_count ||
        source->frame_bytes != bytes || source->frame_unchanged != 1 || source->action || source->reserved ||
        source->frame_hash32 != frame_hash(frame, bytes)) return -EINVAL;
    const struct ker_rx_owner_relay_header *identity = &peer->identity;
    if (!identity->owner_pid || !identity->owner_tid || !identity->owner_start_ticks ||
        source->app_pid != (uint32_t)getpid() || !source->app_start_ticks ||
        !source->supervisor_pid || !source->supervisor_start_ticks || !source->worker_epoch ||
        identity->owner_pid == source->owner_pid ||
        identity->app_pid != source->app_pid || identity->app_start_ticks != source->app_start_ticks ||
        identity->supervisor_pid != source->supervisor_pid ||
        identity->supervisor_start_ticks != source->supervisor_start_ticks ||
        identity->worker_epoch != source->worker_epoch ||
        memcmp(identity->run_nonce, source->run_nonce, sizeof(source->run_nonce))) return -ESTALE;
    uint64_t now = now_ns();
    if (!now || now >= source->deadline_ns) return -ETIMEDOUT;
    if (source->deadline_ns - now > KER_RX_DECISION_DEADLINE_NS) return -EINVAL;
    if (source->packet_id <= peer->last_packet_id) return -EALREADY;
    int live = owner_live(peer);
    if (live) return live;
    int type = 0, enabled = 1;
    socklen_t size = sizeof(type);
    if (syscall(SYS_getsockopt, peer->fd, SOL_SOCKET, SO_TYPE, &type, &size) ||
        type != SOCK_SEQPACKET) return -EPROTOTYPE;
    if (syscall(SYS_setsockopt, peer->fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) return -errno;
    struct ker_rx_owner_relay_header request = *source;
    request.type = KER_RX_OWNER_RELAY_REQUEST;
    request.owner_pid = identity->owner_pid;
    request.owner_tid = identity->owner_tid;
    request.owner_start_ticks = identity->owner_start_ticks;
    request.dispatcher_result = 0;
    request.frame_hash32 = 0;
    request.frame_unchanged = 0;
    struct iovec vectors[] = {{.iov_base = &request, .iov_len = sizeof(request)},
        {.iov_base = (void *)frame, .iov_len = bytes}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    peer->last_packet_id = source->packet_id;
    long sent = syscall(SYS_sendmsg, peer->fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != (long)(sizeof(request) + bytes)) return sent < 0 ? -errno : -EIO;
    peer->pending = request;
    peer->pending_active = true;
    return 0;
}

int ker_rx_owner_relay_peer_poll(struct ker_rx_owner_relay_peer *peer,
    const void *frame, size_t bytes, int *action)
{
    if (!peer || !peer->pending_active || !frame || !action ||
        bytes != peer->pending.frame_bytes) return -EINVAL;
    int status = receive_reply(peer, &peer->pending, frame, bytes, action, false);
    if (status != -EAGAIN) peer->pending_active = false;
    return status;
}

int ker_rx_owner_relay_peer_forward(struct ker_rx_owner_relay_peer *peer,
    const struct ker_rx_owner_relay_header *source, const void *frame,
    size_t bytes, int *action)
{
    if (!action) return -EINVAL;
    int status = ker_rx_owner_relay_peer_begin(peer, source, frame, bytes);
    if (status) return status;
    status = receive_reply(peer, &peer->pending, frame, bytes, action, true);
    peer->pending_active = false;
    return status;
}
