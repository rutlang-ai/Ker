#define _GNU_SOURCE
#include "nginx-source-bootstrap.h"
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <ff_reload.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec now;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int observation_expired(uint64_t deadline)
{
    uint64_t now = now_ns();
    if (now && now < deadline) return 0;
    errno = ETIMEDOUT;
    return 1;
}

static int read_host(const char *path, char *text, size_t size, uint64_t deadline)
{
    int fd;
    do {
        if (observation_expired(deadline)) return -ETIMEDOUT;
        fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    }
    while (fd < 0 && errno == EINTR);
    if (fd < 0) return -errno;
    ssize_t n;
    do {
        if (observation_expired(deadline)) {
            (void)syscall(SYS_close, fd);
            return -ETIMEDOUT;
        }
        n = syscall(SYS_read, fd, text, size - 1);
    }
    while (n < 0 && errno == EINTR);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    if (n <= 0 || (size_t)n >= size - 1) return n < 0 ? -saved : -EPROTO;
    text[n] = 0;
    return 0;
}

/* Nginx's original timer-resolution alarm may interrupt host observation.
 * An interrupted observation says nothing about the actor's authority. */
static long poll_now(struct pollfd *fd, uint64_t deadline)
{
    long result;
    do {
        if (observation_expired(deadline)) return -1;
        result = syscall(SYS_poll, fd, 1, 0);
    }
    while (result < 0 && errno == EINTR);
    return result;
}

static int start_ticks_until(uint32_t pid, uint64_t *result, uint64_t deadline)
{
    char path[64], text[4096];
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    int status = read_host(path, text, sizeof(text), deadline);
    if (status) return status;
    char *cursor = strrchr(text, ')');
    if (!cursor || cursor[1] != ' ') return -EPROTO;
    cursor += 2;
    for (unsigned field = 3; field < 22; ++field) {
        while (*cursor == ' ') ++cursor;
        while (*cursor && *cursor != ' ') ++cursor;
        if (!*cursor) return -EPROTO;
    }
    while (*cursor == ' ') ++cursor;
    char *end;
    errno = 0;
    unsigned long long value = strtoull(cursor, &end, 10);
    if (errno || end == cursor || (*end && *end != ' ') || !value) return -EPROTO;
    *result = value;
    return 0;
}

static int start_ticks(uint32_t pid, uint64_t *result)
{
    return start_ticks_until(pid, result, now_ns() + UINT64_C(5000000000));
}

static int live_pidfd(int fd, uint32_t pid, uint64_t start, uint64_t deadline)
{
    if (fd < 0 || !pid || !start) return -EINVAL;
    char path[64], text[1024];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    int status = read_host(path, text, sizeof(text), deadline);
    if (status) return status;
    char *line = strstr(text, "\nPid:\t"), *end;
    if (!line) return -EPROTO;
    errno = 0;
    long value = strtol(line + 6, &end, 10);
    if (errno || end == line + 6 || (*end && *end != '\n') || value != (long)pid)
        return -ESTALE;
    struct pollfd pollfd = {.fd = fd, .events = POLLIN | POLLHUP | POLLERR};
    long ready = poll_now(&pollfd, deadline);
    if (ready < 0) return -errno;
    if (ready || pollfd.revents) return -ESRCH;
    uint64_t actual;
    status = start_ticks_until(pid, &actual, deadline);
    return status ? status : actual == start ? 0 : -ESTALE;
}

void ker_nginx_source_bootstrap_close(struct ker_nginx_source_bootstrap *binding)
{
    if (!binding) return;
    int *fds[] = {&binding->channel, &binding->supervisor_pidfd,
        &binding->runtime_pidfd, &binding->io_pidfd, &binding->slot_fd, &binding->relay_fd,
        &binding->ready_fd};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); ++i) {
        if (*fds[i] >= 0) (void)syscall(SYS_close, *fds[i]);
        *fds[i] = -1;
    }
    memset(&binding->record, 0, sizeof(binding->record));
}

static uint64_t binding_deadline(const struct ker_nginx_source_bootstrap *binding)
{
    return binding->record.role == KER_NGINX_SOURCE_ROLE_MASTER ?
        binding->record.control_deadline_ns : binding->record.deadline_ns;
}

static int live_actors(const struct ker_nginx_source_bootstrap *binding)
{
    if (!binding || binding->channel < 0) return -ENOTCONN;
    const struct ker_nginx_source_bootstrap_record *r = &binding->record;
    uint64_t deadline = binding_deadline(binding);
    uint64_t now = now_ns();
    if (!now || now >= deadline) return -ETIMEDOUT;
    int status = live_pidfd(binding->supervisor_pidfd, r->supervisor_pid, r->supervisor_start_ticks, deadline);
    if (!status) status = live_pidfd(binding->runtime_pidfd, r->runtime_pid, r->runtime_start_ticks, deadline);
    if (!status) status = live_pidfd(binding->io_pidfd, r->io_pid, r->io_start_ticks, deadline);
    now = now_ns();
    if (!status && (!now || now >= deadline)) status = -ETIMEDOUT;
    return status;
}

int ker_nginx_source_bootstrap_live(const struct ker_nginx_source_bootstrap *binding)
{
    int status = live_actors(binding);
    if (status) return status;
    struct pollfd channel = {.fd = binding->channel, .events = POLLIN};
    if (!status && poll_now(&channel, binding_deadline(binding)) < 0) status = -errno;
    /* A credentialed control record can queue between the owner's command
     * poll and this observation. Readability is not identity loss; the owner
     * loop must parse queued commands before its next pass. */
    if (!status && (channel.revents & (POLLHUP | POLLERR | POLLNVAL)))
        status = -ENOTCONN;
    return status;
}

static int poll_command(const struct ker_nginx_source_bootstrap *binding, uint16_t type)
{
    int status = live_actors(binding);
    if (status) return status;
    struct pollfd channel = {.fd = binding->channel, .events = POLLIN};
    long ready = poll_now(&channel, binding_deadline(binding));
    if (ready < 0) return -errno;
    if (!ready) return 0;
    if (channel.revents & (POLLHUP | POLLERR | POLLNVAL)) return -ENOTCONN;
    if (!(channel.revents & POLLIN)) return -ENOTCONN;
    struct ker_nginx_source_bootstrap_record record;
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(8 * sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    long count = syscall(SYS_recvmsg, binding->channel, &message,
        MSG_TRUNC | MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (count < 0) return errno == EINTR ? 0 : -errno;
    int credentials = 0, malformed = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
            cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
                cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
            struct ucred cred;
            memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
            ++credentials;
            if (cred.pid != (pid_t)binding->record.supervisor_pid ||
                cred.uid != getuid() || cred.gid != getgid()) malformed = 1;
        } else {
            malformed = 1;
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
                    cmsg->cmsg_len >= CMSG_LEN(0)) {
                size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
                for (size_t i = 0; i + sizeof(int) <= bytes; i += sizeof(int)) {
                    int fd;
                    memcpy(&fd, (char *)CMSG_DATA(cmsg) + i, sizeof(fd));
                    (void)syscall(SYS_close, fd);
                }
            }
        }
    }
    struct ker_nginx_source_bootstrap_record expected = binding->record;
    expected.type = type;
    if (!count && !credentials && !malformed && !message.msg_controllen)
        return -ENOTCONN;
    if (malformed || credentials != 1 || count != sizeof(record) ||
        message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
        memcmp(&expected, &record, sizeof(record))) return -EPROTO;
    return live_actors(binding) ? -ESTALE : 1;
}

int ker_nginx_source_bootstrap_poll_stop(const struct ker_nginx_source_bootstrap *binding)
{
    return poll_command(binding, KER_NGINX_SOURCE_BOOTSTRAP_STOP);
}

int ker_nginx_source_bootstrap_poll_activate(const struct ker_nginx_source_bootstrap *binding)
{
    if (!binding || binding->record.flags != KER_NGINX_SOURCE_WORKER_CANDIDATE)
        return -EPERM;
    return poll_command(binding, KER_NGINX_SOURCE_BOOTSTRAP_ACTIVATE);
}

static int wait_channel(int fd, int supervisor_pidfd, short events, uint64_t deadline)
{
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        struct pollfd fds[] = {{.fd = fd, .events = events},
            {.fd = supervisor_pidfd, .events = POLLIN}};
        int timeout = (int)((deadline - now + 999999) / 1000000);
        long n = syscall(SYS_poll, fds, 2, timeout);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -errno;
        if (fds[1].revents || (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))) {
            fprintf(stderr, "ker source bootstrap: channel failed pid=%ld fd=%d events=%x revents=%x supervisor_fd=%d revents=%x\n",
                (long)getpid(), fd, (unsigned)events, (unsigned)fds[0].revents,
                supervisor_pidfd, (unsigned)fds[1].revents);
            return -ENOTCONN;
        }
        if (fds[0].revents & events) return 0;
    }
}

int ker_nginx_source_bootstrap_connect(const char *path,
    const struct ker_nginx_source_bootstrap_record *request,
    uint32_t expected_supervisor, uint64_t expected_supervisor_start,
    struct ker_nginx_source_bootstrap *binding)
{
    if (!binding) return -EINVAL;
    *binding = (struct ker_nginx_source_bootstrap){.channel = -1,
        .supervisor_pidfd = -1, .runtime_pidfd = -1, .io_pidfd = -1,
        .slot_fd = -1, .relay_fd = -1, .ready_fd = -1};
    if (!path || !request || !expected_supervisor || !expected_supervisor_start ||
        strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return -EINVAL;
    uint64_t now = now_ns(), actual = 0;
    uint64_t observation_deadline = request->role == KER_NGINX_SOURCE_ROLE_MASTER ?
        request->control_deadline_ns : request->deadline_ns;
    uint8_t nonce = 0;
    for (size_t i = 0; i < sizeof(request->run_nonce); ++i) nonce |= request->run_nonce[i];
    if (request->magic != KER_NGINX_SOURCE_BOOTSTRAP_MAGIC ||
        request->version != KER_NGINX_SOURCE_BOOTSTRAP_VERSION ||
        ((request->role == KER_NGINX_SOURCE_ROLE_MASTER) ?
            (request->type != KER_NGINX_SOURCE_MASTER_PARK &&
             request->type != KER_NGINX_SOURCE_MASTER_COMMIT &&
             request->type != KER_NGINX_SOURCE_MASTER_ABORT) :
            request->type != KER_NGINX_SOURCE_BOOTSTRAP_REQUEST) ||
        request->record_bytes != sizeof(*request) || request->role > KER_NGINX_SOURCE_ROLE_MASTER ||
        request->generation > 1 || request->reserved || !request->launch_epoch || !nonce ||
        request->actor_pid != (uint32_t)getpid() || request->actor_tid != (uint32_t)syscall(SYS_gettid) ||
        !request->master_pid ||
        ((request->master_pid == request->actor_pid) != (request->role == KER_NGINX_SOURCE_ROLE_MASTER)) ||
        !request->source_block_address || request->supervisor_pid || request->runtime_pid ||
        request->io_pid || request->flags || request->supervisor_start_ticks ||
        request->runtime_start_ticks || request->io_start_ticks || request->slot_device ||
        request->slot_inode || request->relay_cookie || request->ready_cookie || !now || request->deadline_ns <= now ||
        (request->role == KER_NGINX_SOURCE_ROLE_MASTER ?
            (!request->control_deadline_ns || request->control_deadline_ns <= now ||
                request->control_deadline_ns > request->deadline_ns ||
                request->control_deadline_ns - now >
                    (uint64_t)FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT * UINT64_C(1000000)) :
            request->control_deadline_ns != 0) ||
        request->deadline_ns - now > KER_NGINX_SOURCE_BOOTSTRAP_MAX_NS ||
        start_ticks_until(request->actor_pid, &actual, observation_deadline) || actual != request->actor_start_ticks ||
        start_ticks_until(request->master_pid, &actual, observation_deadline) || actual != request->master_start_ticks)
        return -EINVAL;
    binding->supervisor_pidfd = (int)syscall(SYS_pidfd_open, expected_supervisor, 0);
    int status = live_pidfd(binding->supervisor_pidfd, expected_supervisor, expected_supervisor_start, observation_deadline);
    if (status) goto fail;
    binding->channel = (int)syscall(SYS_socket, AF_UNIX,
        SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (binding->channel < 0) { status = -errno; goto fail; }
    int enabled = 1;
    if (syscall(SYS_setsockopt, binding->channel, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) {
        status = -errno; goto fail;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (syscall(SYS_connect, binding->channel, &address,
            offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1)) {
        status = -errno; goto fail;
    }
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (syscall(SYS_getsockopt, binding->channel, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
        size != sizeof(peer) || peer.pid != (pid_t)expected_supervisor ||
        peer.uid != getuid() || peer.gid != getgid()) { status = -EACCES; goto fail; }
    uint64_t handshake_deadline = request->role == KER_NGINX_SOURCE_ROLE_MASTER ?
        request->control_deadline_ns : now_ns() + UINT64_C(5000000000);
    if (handshake_deadline > request->deadline_ns) handshake_deadline = request->deadline_ns;
    status = wait_channel(binding->channel, binding->supervisor_pidfd, POLLOUT, handshake_deadline);
    if (status) goto fail;
    long sent = syscall(SYS_sendto, binding->channel, request, sizeof(*request), MSG_NOSIGNAL, NULL, 0);
    if (sent != sizeof(*request)) {
        status = sent < 0 ? -errno : -EIO; goto fail;
    }
    status = wait_channel(binding->channel, binding->supervisor_pidfd, POLLIN, handshake_deadline);
    if (status) goto fail;
    struct ker_nginx_source_bootstrap_record response;
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(8 * sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &response, .iov_len = sizeof(response)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    long count = syscall(SYS_recvmsg, binding->channel, &message, MSG_TRUNC | MSG_CMSG_CLOEXEC);
    if (count < 0) { status = -errno; goto fail; }
    int fds[8], fd_count = 0, credentials = 0;
    status = -EPROTO;
    int malformed = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
            if (bytes % sizeof(int)) malformed = 1;
            for (size_t i = 0; i + sizeof(int) <= bytes; i += sizeof(int)) {
                int fd;
                memcpy(&fd, (char *)CMSG_DATA(cmsg) + i, sizeof(fd));
                if (fd_count < 8) fds[fd_count++] = fd;
                else { (void)syscall(SYS_close, fd); malformed = 1; }
            }
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
                cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
            struct ucred cred;
            memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
            ++credentials;
            if (memcmp(&cred, &peer, sizeof(cred))) malformed = 1;
        } else malformed = 1;
    }
    int expected_fds = request->role == KER_NGINX_SOURCE_ROLE_WORKER ? 5 : 2;
    if (!malformed && count == sizeof(response) && credentials == 1 && fd_count == expected_fds &&
        !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        struct ker_nginx_source_bootstrap_record expected = *request;
        expected.type = request->role == KER_NGINX_SOURCE_ROLE_MASTER ?
            request->type + 2 : KER_NGINX_SOURCE_BOOTSTRAP_REPLY;
        expected.supervisor_pid = expected_supervisor;
        expected.supervisor_start_ticks = expected_supervisor_start;
        expected.runtime_pid = response.runtime_pid;
        expected.runtime_start_ticks = response.runtime_start_ticks;
        expected.io_pid = response.io_pid;
        expected.io_start_ticks = response.io_start_ticks;
        if (request->role == KER_NGINX_SOURCE_ROLE_MASTER && response.flags <= 4095)
            expected.flags = response.flags;
        if (request->role == KER_NGINX_SOURCE_ROLE_SLIM &&
            response.flags == KER_NGINX_SOURCE_SLIM_CONTROL_ONLY)
            expected.flags = response.flags;
        if (request->role == KER_NGINX_SOURCE_ROLE_WORKER) {
            if (response.flags == KER_NGINX_SOURCE_WORKER_INITIAL ||
                response.flags == KER_NGINX_SOURCE_WORKER_CANDIDATE)
                expected.flags = response.flags;
            expected.slot_device = response.slot_device;
            expected.slot_inode = response.slot_inode;
            expected.relay_cookie = response.relay_cookie;
            expected.ready_cookie = response.ready_cookie;
        }
        if ((request->role != KER_NGINX_SOURCE_ROLE_WORKER || expected.flags != 0) &&
            !memcmp(&expected, &response, sizeof(expected)) &&
            response.runtime_pid != response.io_pid && response.runtime_pid != expected_supervisor &&
            response.io_pid != expected_supervisor &&
            !live_pidfd(fds[0], response.runtime_pid, response.runtime_start_ticks, observation_deadline) &&
            !live_pidfd(fds[1], response.io_pid, response.io_start_ticks, observation_deadline)) {
            status = 0;
            if (request->role == KER_NGINX_SOURCE_ROLE_WORKER) {
                struct stat slot;
                uint64_t cookie = 0;
                socklen_t length = sizeof(cookie);
                int type = 0, domain = 0;
                socklen_t type_bytes = sizeof(type);
                int slot_flags = (int)syscall(SYS_fcntl, fds[2], F_GETFL, 0);
                if (syscall(SYS_fstat, fds[2], &slot) || !S_ISFIFO(slot.st_mode) ||
                    slot_flags < 0 || (slot_flags & O_ACCMODE) != O_WRONLY ||
                    (uint64_t)slot.st_dev != response.slot_device ||
                    (uint64_t)slot.st_ino != response.slot_inode || !response.relay_cookie ||
                    syscall(SYS_getsockopt, fds[3], SOL_SOCKET, SO_COOKIE, &cookie, &length) ||
                    length != sizeof(cookie) || cookie != response.relay_cookie ||
                    syscall(SYS_getsockopt, fds[3], SOL_SOCKET, SO_TYPE, &type, &type_bytes) ||
                    type_bytes != sizeof(type) || type != SOCK_SEQPACKET) status = -ESTALE;
                type_bytes = sizeof(domain);
                if (!status && (syscall(SYS_getsockopt, fds[3], SOL_SOCKET, SO_DOMAIN,
                        &domain, &type_bytes) || type_bytes != sizeof(domain) || domain != AF_UNIX))
                    status = -EAFNOSUPPORT;
                struct ucred grant_peer;
                type_bytes = sizeof(grant_peer);
                if (!status && (syscall(SYS_getsockopt, fds[3], SOL_SOCKET, SO_PEERCRED,
                        &grant_peer, &type_bytes) || type_bytes != sizeof(grant_peer) ||
                        grant_peer.pid != (pid_t)expected_supervisor ||
                        grant_peer.uid != getuid() || grant_peer.gid != getgid())) status = -EACCES;
                length = sizeof(cookie);
                type_bytes = sizeof(type);
                if (!status && (!response.ready_cookie || response.ready_cookie == response.relay_cookie ||
                    syscall(SYS_getsockopt, fds[4], SOL_SOCKET, SO_COOKIE, &cookie, &length) ||
                    length != sizeof(cookie) || cookie != response.ready_cookie ||
                    syscall(SYS_getsockopt, fds[4], SOL_SOCKET, SO_TYPE, &type, &type_bytes) ||
                    type_bytes != sizeof(type) || type != SOCK_SEQPACKET)) status = -EPROTO;
                type_bytes = sizeof(domain);
                if (!status && (syscall(SYS_getsockopt, fds[4], SOL_SOCKET, SO_DOMAIN,
                        &domain, &type_bytes) || type_bytes != sizeof(domain) || domain != AF_UNIX)) status = -EPROTO;
                type_bytes = sizeof(grant_peer);
                if (!status && (syscall(SYS_getsockopt, fds[4], SOL_SOCKET, SO_PEERCRED,
                        &grant_peer, &type_bytes) || type_bytes != sizeof(grant_peer) ||
                        grant_peer.pid != (pid_t)expected_supervisor ||
                        grant_peer.uid != getuid() || grant_peer.gid != getgid())) status = -EACCES;
            }
        }
    }
    if (!status) {
        binding->record = response;
        binding->runtime_pidfd = fds[0]; binding->io_pidfd = fds[1];
        if (fd_count == 5) {
            binding->slot_fd = fds[2]; binding->relay_fd = fds[3]; binding->ready_fd = fds[4];
        }
        fd_count = 0;
        status = ker_nginx_source_bootstrap_live(binding);
    }
    for (int i = 0; i < fd_count; ++i) (void)syscall(SYS_close, fds[i]);
    if (!status) return 0;
fail:
    ker_nginx_source_bootstrap_close(binding);
    return status;
}

/* Constructor state is inherited through the original fork/double-fork path;
 * it is not an inherited FD and survives the slim primary's close loop. */
static uint32_t source_master_pid;
static uint64_t source_master_start;
static uint64_t source_master_handover_deadline[3];
static int environment_consumed;
static int source_intermediate;
static int source_detached;
static int (*source_forget_inherited)(void);

static void source_bootstrap_child(void)
{
    if (!source_intermediate) return;
    source_intermediate = 0;
    source_detached = 1;
    if (!source_forget_inherited || source_forget_inherited())
        (void)syscall(SYS_exit_group, 125);
}

pid_t setsid(void)
{
    pid_t result = (pid_t)syscall(SYS_setsid);
    if (result < 0 || !getenv("KER_NGINX_SOURCE_BOOTSTRAP_PATH")) return result;
    int *enabled = dlsym(RTLD_DEFAULT, "ngx_ff_graceful_reload");
    struct ff_reload_state **block = dlsym(RTLD_DEFAULT, "ngx_ff_reload_shm");
    /* daemon-off is part of the bounded companion profile. The only setsid
     * between this exact master and a double fork is the original source's
     * slim-primary intermediate child. Its shared block must already exist. */
    if ((uint32_t)getppid() != source_master_pid || !enabled || *enabled != 1 ||
        !block || !*block || !ff_reload_state_valid(*block, sizeof(**block))) return result;
    source_forget_inherited = (int (*)(void))dlsym(RTLD_DEFAULT,
        "ker_sb_preload_source_detach_forget");
    source_intermediate = 1;
    return result;
}

__attribute__((constructor)) static void source_bootstrap_origin(void)
{
    if (pthread_atfork(NULL, NULL, source_bootstrap_child))
        (void)syscall(SYS_exit_group, 125);
    source_master_pid = (uint32_t)getpid();
    if (start_ticks(source_master_pid, &source_master_start)) source_master_start = 0;
}

static int environment_uint(const char *name, uint64_t *value)
{
    const char *text = getenv(name);
    if (!text || *text < '0' || *text > '9') return -EINVAL;
    char *end;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || end == text || *end || !parsed) return -EINVAL;
    *value = parsed;
    return 0;
}

static int source_from_environment(uint32_t role, uint32_t generation,
    uint32_t source_epoch, const void *source_block, uint16_t operation,
    struct ker_nginx_source_bootstrap *binding)
{
    const char *path = getenv("KER_NGINX_SOURCE_BOOTSTRAP_PATH");
    if (!path) return -ENOTSUP;
    if (role == KER_NGINX_SOURCE_ROLE_SLIM && !source_detached) return -EPERM;
    if (role != KER_NGINX_SOURCE_ROLE_MASTER) {
        if (environment_consumed) return -EALREADY;
        environment_consumed = 1;
    } else if ((uint32_t)getpid() != source_master_pid) return -EPERM;
    uint64_t supervisor, supervisor_start, launch_epoch, lifetime;
    const char *nonce = getenv("KER_NGINX_SOURCE_BOOTSTRAP_NONCE");
    if (!nonce || strlen(nonce) != 32 || !source_master_pid || !source_master_start ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID", &supervisor) || supervisor > UINT32_MAX ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START", &supervisor_start) ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_EPOCH", &launch_epoch) ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS", &lifetime)) return -EINVAL;
    struct ker_nginx_source_bootstrap_record request = {
        .magic = KER_NGINX_SOURCE_BOOTSTRAP_MAGIC, .version = KER_NGINX_SOURCE_BOOTSTRAP_VERSION,
        .type = operation, .record_bytes = sizeof(request),
        .role = role, .actor_pid = (uint32_t)getpid(), .actor_tid = (uint32_t)syscall(SYS_gettid),
        .master_pid = source_master_pid, .generation = generation, .source_epoch = source_epoch,
        .master_start_ticks = source_master_start, .source_block_address = (uintptr_t)source_block,
        .launch_epoch = launch_epoch, .deadline_ns = lifetime,
    };
    if (role == KER_NGINX_SOURCE_ROLE_MASTER) {
        if (source_epoch < 1 || source_epoch > 2) return -EPROTO;
        uint64_t *handover_deadline = &source_master_handover_deadline[source_epoch];
        if (operation == KER_NGINX_SOURCE_MASTER_PARK) {
            if (*handover_deadline) return -EALREADY;
            *handover_deadline = now_ns() +
                (uint64_t)FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT * UINT64_C(1000000);
            if (*handover_deadline > lifetime)
                *handover_deadline = lifetime;
        }
        /* COMMIT consumes the PARK budget; reconnecting never renews it. */
        if (!*handover_deadline || now_ns() >= *handover_deadline)
            return -ETIMEDOUT;
        request.control_deadline_ns = *handover_deadline;
    }
    if (start_ticks_until(request.actor_pid, &request.actor_start_ticks,
            role == KER_NGINX_SOURCE_ROLE_MASTER ? request.control_deadline_ns : lifetime)) return -ESTALE;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned value = 0;
        for (unsigned j = 0; j < 2; ++j) {
            char c = nonce[2 * i + j];
            if (c >= '0' && c <= '9') value = value * 16 + (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') value = value * 16 + (unsigned)(c - 'a' + 10);
            else return -EINVAL;
        }
        request.run_nonce[i] = (uint8_t)value;
    }
    return ker_nginx_source_bootstrap_connect(path, &request, (uint32_t)supervisor,
        supervisor_start, binding);
}

int ker_nginx_source_bootstrap_from_environment(uint32_t role, uint32_t generation,
    uint32_t source_epoch, const void *source_block,
    struct ker_nginx_source_bootstrap *binding)
{
    return source_from_environment(role, generation, source_epoch, source_block,
        KER_NGINX_SOURCE_BOOTSTRAP_REQUEST, binding);
}

int ker_nginx_source_is_master(void)
{
    return getenv("KER_NGINX_SOURCE_BOOTSTRAP_PATH") &&
        (uint32_t)getpid() == source_master_pid;
}

int ker_nginx_source_master_barrier(uint16_t operation)
{
    /* Retain every attempt and receipt. Round two is not a reset: only the
     * original master's acknowledged pre-flip abort may precede that round. */
    static unsigned consumed[3], completed[3];
    unsigned bit = operation == KER_NGINX_SOURCE_MASTER_PARK ? 1u :
        operation == KER_NGINX_SOURCE_MASTER_COMMIT ? 2u :
        operation == KER_NGINX_SOURCE_MASTER_ABORT ? 4u : 0u;
    struct ff_reload_state **source = dlsym(RTLD_DEFAULT, "ngx_ff_reload_shm");
    int *enabled = dlsym(RTLD_DEFAULT, "ngx_ff_graceful_reload");
    if (!bit || !ker_nginx_source_is_master() || !source || !*source ||
        !enabled || *enabled != 1 || !ff_reload_state_valid(*source, sizeof(**source)) ||
        (*source)->active_gen != 0 || (*source)->target_gen != 1 ||
        (*source)->reload_active != 1 || (*source)->fsm_state != 2) return -EPROTO;
    uint32_t round = (*source)->epoch;
    if ((round != 1 && (round != 2 || !ker_fstack_nginx_source_fault_profile() ||
            completed[1] != (1u | 4u) || consumed[1] != (1u | 4u))) ||
        (consumed[round] & bit) ||
        (bit != 1 && (!(consumed[round] & 1) || (consumed[round] & 6))) ||
        (bit == 4 && (round != 1 || !ker_fstack_nginx_source_fault_profile()))) return -EPROTO;
    if ((bit == 1 && ((*source)->rx_owner_gen != 0 || (*source)->rx_stopped)) ||
        (bit == 2 && ((*source)->rx_owner_gen != 1 || (*source)->rx_stopped)) ||
        (bit == 4 && ((*source)->rx_owner_gen != 0 || (*source)->rx_stopped != 1))) return -ESTALE;
    consumed[round] |= bit;
    struct ker_nginx_source_bootstrap binding;
    int status = source_from_environment(KER_NGINX_SOURCE_ROLE_MASTER, 1, round,
        *source, operation, &binding);
    if (!status) {
        status = -(int)binding.record.flags;
        ker_nginx_source_bootstrap_close(&binding);
        if (!status) completed[round] |= bit;
    }
    return status;
}
