#define _GNU_SOURCE
#include "nginx-source-bootstrap.h"
#include "nginx-source-origin.h"
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <ff_reload.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* The runtime owns this worker binding for the whole source-worker lifetime.
 * The owner module receives a capability copy with channel/pidfds stripped,
 * so retain only the pointer to the original worker binding here. */
static struct ker_nginx_source_bootstrap *source_shell_worker_binding;
static uint64_t source_shell_preexit_operation;

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
    if (source_shell_worker_binding == binding) source_shell_worker_binding = NULL;
    int *fds[] = {&binding->channel, &binding->supervisor_pidfd,
        &binding->runtime_pidfd, &binding->io_pidfd, &binding->slot_fd, &binding->relay_fd,
        &binding->ready_fd, &binding->directory_fd};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); ++i) {
        if (*fds[i] >= 0) (void)syscall(SYS_close, *fds[i]);
        *fds[i] = -1;
    }
    memset(&binding->record, 0, sizeof(binding->record));
    binding->source_shell_proof_enabled = 0;
    memset(&binding->source_shell_proof, 0, sizeof(binding->source_shell_proof));
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
    union {
        struct ker_nginx_source_bootstrap_record legacy;
        struct ker_nginx_source_bootstrap_record_v4 shell;
        struct ker_nginx_source_commit_evidence_record commit_evidence;
    } received;
    size_t wire_bytes = binding->source_shell_proof_enabled ?
        sizeof(received.shell) : sizeof(received.legacy);
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(8 * sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &received, .iov_len = sizeof(received)};
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
    const struct ker_nginx_source_bootstrap_record *record =
        binding->source_shell_proof_enabled ? &received.shell.record : &received.legacy;
    if (!count && !credentials && !malformed && !message.msg_controllen)
        return -ENOTCONN;
    if (!malformed && credentials == 1 && binding->source_shell_proof_enabled &&
        count == (long)sizeof(received.commit_evidence) &&
        !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        struct ker_nginx_source_bootstrap *mutable_binding =
            (struct ker_nginx_source_bootstrap *)binding;
        struct ker_nginx_source_bootstrap_record commit_expected = binding->record;
        commit_expected.type = KER_NGINX_SOURCE_WORKER_COMMIT_EVIDENCE;
        if (received.commit_evidence.magic != KER_NGINX_SOURCE_BOOTSTRAP_MAGIC ||
            received.commit_evidence.version != KER_NGINX_SOURCE_PREEXIT_VERSION ||
            received.commit_evidence.type != KER_NGINX_SOURCE_WORKER_COMMIT_EVIDENCE ||
            received.commit_evidence.record_bytes != sizeof(received.commit_evidence) ||
            received.commit_evidence.reserved || !received.commit_evidence.native_current_cookie ||
            !mutable_binding->source_candidate_activated ||
            mutable_binding->source_commit_evidence_received ||
            received.commit_evidence.identity.record.flags != KER_NGINX_SOURCE_WORKER_CANDIDATE ||
            !ker_nginx_source_bootstrap_v4_matches(&commit_expected,
                &binding->source_shell_proof, &received.commit_evidence.identity))
            return -EPROTO;
        mutable_binding->native_commit_cookie =
            received.commit_evidence.native_current_cookie;
        mutable_binding->source_commit_evidence_received = 1;
        return live_actors(binding) ? -ESTALE : 0;
    }
    if (malformed || credentials != 1 || count != (long)wire_bytes ||
        message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
        (binding->source_shell_proof_enabled ?
            !ker_nginx_source_bootstrap_v4_matches(&expected,
                &binding->source_shell_proof, &received.shell) :
            memcmp(&expected, record, sizeof(expected)) != 0)) return -EPROTO;
    status = live_actors(binding);
    if (status) return -ESTALE;
    if (type == KER_NGINX_SOURCE_BOOTSTRAP_ACTIVATE && binding->source_shell_proof_enabled)
        ((struct ker_nginx_source_bootstrap *)binding)->source_candidate_activated = 1;
    return 1;
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

int ker_nginx_source_bootstrap_worker_commit_cookie(
    const struct ker_nginx_source_bootstrap_record *identity,
    const struct ker_nginx_source_bootstrap_proof *proof,
    uint64_t *native_commit_cookie)
{
    struct ker_nginx_source_bootstrap *binding = source_shell_worker_binding;
    if (!binding || !binding->source_shell_proof_enabled) return -EPERM;
    /* TERM may race the ordinary owner-loop poll. Consume only a queued
     * grantless COMMIT receipt here; poll_command rejects every other packet. */
    int poll_status = poll_command(binding, KER_NGINX_SOURCE_BOOTSTRAP_STOP);
    if (poll_status < 0) return poll_status;
    if (poll_status > 0) return -EPROTO;
    if (!identity || !proof || !native_commit_cookie || !binding ||
        !binding->source_candidate_activated ||
        !binding->source_commit_evidence_received || !binding->native_commit_cookie ||
        identity->flags != KER_NGINX_SOURCE_WORKER_CANDIDATE ||
        identity->actor_pid != (uint32_t)getpid() ||
        identity->actor_tid != (uint32_t)syscall(SYS_gettid) ||
        identity->generation != binding->record.generation ||
        identity->source_epoch != binding->record.source_epoch ||
        identity->launch_epoch != binding->record.launch_epoch ||
        !ker_nginx_source_bootstrap_proof_equal(proof, &binding->source_shell_proof))
        return -EPERM;
    *native_commit_cookie = binding->native_commit_cookie;
    return 0;
}

static int wait_channel(int fd, int supervisor_pidfd, short events, uint64_t deadline,
    int allow_hup_with_reply)
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
        short observed = fds[0].revents;
        /* A one-shot master RPC can have a complete reply queued even after
         * the supervisor closes the accepted socket. Validate it below. */
        if (fds[1].revents || (observed & (POLLERR | POLLNVAL)) ||
            ((observed & POLLHUP) && !(allow_hup_with_reply && (observed & POLLIN)))) {
            fprintf(stderr, "ker source bootstrap: channel failed pid=%ld fd=%d events=%x revents=%x supervisor_fd=%d revents=%x\n",
                (long)getpid(), fd, (unsigned)events, (unsigned)fds[0].revents,
                supervisor_pidfd, (unsigned)fds[1].revents);
            return -ENOTCONN;
        }
        if (observed & events) return 0;
    }
}

int ker_nginx_source_bootstrap_connect(const char *path,
    const struct ker_nginx_source_bootstrap_record *request,
    uint32_t expected_supervisor, uint64_t expected_supervisor_start,
    struct ker_nginx_source_bootstrap *binding)
{
    return ker_nginx_source_bootstrap_connect_source_shell(path, request, NULL,
        expected_supervisor, expected_supervisor_start, binding);
}


static uint64_t source_bootstrap_max_lifetime(void)
{
    const char *shell = getenv("KER_NGINX_SOURCE_SHELL_ENABLE");
    const char *successor = getenv("KER_NGINX_SOURCE_SUCCESSOR_ENABLE");
    if (shell && !strcmp(shell, "1") && successor && !strcmp(successor, "1"))
        return UINT64_C(1800000000000);
    return KER_NGINX_SOURCE_BOOTSTRAP_MAX_NS;
}

bool ker_nginx_source_upgrade_enabled(void)
{
    const char *shell = getenv("KER_NGINX_SOURCE_SHELL_ENABLE");
    const char *upgrade = getenv(KER_NGINX_SOURCE_UPGRADE_ENV);
    return shell && !strcmp(shell, "1") && upgrade && !strcmp(upgrade, "1");
}

bool ker_nginx_source_upgrade_worker(void)
{
    if (!ker_nginx_source_upgrade_enabled()) return false;
    const uintptr_t *inherited = dlsym(RTLD_DEFAULT, "ngx_inherited");
    return inherited && *inherited == 1;
}

static int bootstrap_connect_internal(const char *path,
    const struct ker_nginx_source_bootstrap_record *request,
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    uint32_t expected_supervisor, uint64_t expected_supervisor_start,
    struct ker_nginx_source_bootstrap *binding)
{
    if (!binding) return -EINVAL;
    *binding = (struct ker_nginx_source_bootstrap){.channel = -1,
        .supervisor_pidfd = -1, .runtime_pidfd = -1, .io_pidfd = -1,
        .slot_fd = -1, .relay_fd = -1, .ready_fd = -1, .directory_fd = -1};
    if (!path || !request || !expected_supervisor || !expected_supervisor_start ||
        strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return -EINVAL;
    struct ker_nginx_source_bootstrap_record_v4 shell_request;
    const struct ker_nginx_source_bootstrap_record *wire_request = request;
    size_t wire_bytes = sizeof(*request);
    if (snapshot) {
        int encode_status = ker_nginx_source_bootstrap_v4_encode(request, snapshot,
            &shell_request);
        if (encode_status) return encode_status;
        wire_request = &shell_request.record;
        wire_bytes = sizeof(shell_request);
    }
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
        request->deadline_ns - now > source_bootstrap_max_lifetime() ||
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
    status = wait_channel(binding->channel, binding->supervisor_pidfd, POLLOUT,
        handshake_deadline, 0);
    if (status) goto fail;
    long sent = syscall(SYS_sendto, binding->channel, wire_request, wire_bytes, MSG_NOSIGNAL, NULL, 0);
    if (sent != (long)wire_bytes) {
        status = sent < 0 ? -errno : -EIO; goto fail;
    }
    status = wait_channel(binding->channel, binding->supervisor_pidfd, POLLIN,
        handshake_deadline, request->role == KER_NGINX_SOURCE_ROLE_MASTER);
    if (status) goto fail;
    union {
        struct ker_nginx_source_bootstrap_record legacy;
        struct ker_nginx_source_bootstrap_record_v4 shell;
    } response;
    struct ker_nginx_source_bootstrap_record *response_record = snapshot ?
        &response.shell.record : &response.legacy;
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(8 * sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &response, .iov_len = wire_bytes};
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
    bool directory_grant = snapshot && request->role != KER_NGINX_SOURCE_ROLE_MASTER &&
        ker_nginx_source_upgrade_enabled();
    int expected_fds = request->role == KER_NGINX_SOURCE_ROLE_WORKER ? 5 : 2;
    if (directory_grant) ++expected_fds;
    if (!malformed && count == (long)wire_bytes && credentials == 1 && fd_count == expected_fds &&
        !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        struct ker_nginx_source_bootstrap_record expected = *wire_request;
        expected.type = request->role == KER_NGINX_SOURCE_ROLE_MASTER ?
            request->type + 2 : KER_NGINX_SOURCE_BOOTSTRAP_REPLY;
        expected.supervisor_pid = expected_supervisor;
        expected.supervisor_start_ticks = expected_supervisor_start;
        expected.runtime_pid = response_record->runtime_pid;
        expected.runtime_start_ticks = response_record->runtime_start_ticks;
        expected.io_pid = response_record->io_pid;
        expected.io_start_ticks = response_record->io_start_ticks;
        if (request->role == KER_NGINX_SOURCE_ROLE_MASTER && response_record->flags <= 4095)
            expected.flags = response_record->flags;
        if (request->role == KER_NGINX_SOURCE_ROLE_SLIM &&
            response_record->flags == KER_NGINX_SOURCE_SLIM_CONTROL_ONLY)
            expected.flags = response_record->flags;
        if (request->role == KER_NGINX_SOURCE_ROLE_WORKER) {
            if (response_record->flags == KER_NGINX_SOURCE_WORKER_INITIAL ||
                response_record->flags == KER_NGINX_SOURCE_WORKER_CANDIDATE)
                expected.flags = response_record->flags;
            expected.slot_device = response_record->slot_device;
            expected.slot_inode = response_record->slot_inode;
            expected.relay_cookie = response_record->relay_cookie;
            expected.ready_cookie = response_record->ready_cookie;
        }
        if ((request->role != KER_NGINX_SOURCE_ROLE_WORKER || expected.flags != 0) &&
            (snapshot ? ker_nginx_source_bootstrap_v4_matches(&expected,
                &shell_request.proof, &response.shell) :
                memcmp(&expected, response_record, sizeof(expected)) == 0) &&
            response_record->runtime_pid != response_record->io_pid && response_record->runtime_pid != expected_supervisor &&
            response_record->io_pid != expected_supervisor &&
            !live_pidfd(fds[0], response_record->runtime_pid, response_record->runtime_start_ticks, observation_deadline) &&
            !live_pidfd(fds[1], response_record->io_pid, response_record->io_start_ticks, observation_deadline)) {
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
                    (uint64_t)slot.st_dev != response_record->slot_device ||
                    (uint64_t)slot.st_ino != response_record->slot_inode || !response_record->relay_cookie ||
                    syscall(SYS_getsockopt, fds[3], SOL_SOCKET, SO_COOKIE, &cookie, &length) ||
                    length != sizeof(cookie) || cookie != response_record->relay_cookie ||
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
                if (!status && (!response_record->ready_cookie || response_record->ready_cookie == response_record->relay_cookie ||
                    syscall(SYS_getsockopt, fds[4], SOL_SOCKET, SO_COOKIE, &cookie, &length) ||
                    length != sizeof(cookie) || cookie != response_record->ready_cookie ||
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
        binding->record = *response_record;
        if (snapshot) {
            binding->source_shell_proof = shell_request.proof;
            binding->source_shell_proof_enabled = 1;
        }
        binding->runtime_pidfd = fds[0]; binding->io_pidfd = fds[1];
        if (request->role == KER_NGINX_SOURCE_ROLE_WORKER) {
            binding->slot_fd = fds[2]; binding->relay_fd = fds[3]; binding->ready_fd = fds[4];
        }
        if (directory_grant) binding->directory_fd = fds[fd_count - 1];
        fd_count = 0;
        status = request->role == KER_NGINX_SOURCE_ROLE_MASTER ?
            live_actors(binding) : ker_nginx_source_bootstrap_live(binding);
    }
    for (int i = 0; i < fd_count; ++i) (void)syscall(SYS_close, fds[i]);
    if (!status) return 0;
fail:
    ker_nginx_source_bootstrap_close(binding);
    return status;
}

int ker_nginx_source_bootstrap_connect_source_shell(const char *path,
    const struct ker_nginx_source_bootstrap_record *request,
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    uint32_t expected_supervisor, uint64_t expected_supervisor_start,
    struct ker_nginx_source_bootstrap *binding)
{
    const char *enabled = getenv("KER_NGINX_SOURCE_SHELL_ENABLE");
    if (snapshot) {
        if (!enabled || strcmp(enabled, "1")) return -EPERM;
    } else if (enabled && !strcmp(enabled, "1")) {
        return -ENOTSUP;
    }
    int status = bootstrap_connect_internal(path, request, snapshot,
        expected_supervisor, expected_supervisor_start, binding);
    if (!status && snapshot && request->role == KER_NGINX_SOURCE_ROLE_WORKER) {
        if (source_shell_worker_binding && source_shell_worker_binding != binding) {
            ker_nginx_source_bootstrap_close(binding);
            return -EALREADY;
        }
        source_shell_worker_binding = binding;
    }
    return status;
}

int ker_nginx_source_bootstrap_worker_preexit(
    const struct ker_nginx_source_bootstrap_record *identity,
    const struct ker_nginx_source_bootstrap_proof *proof,
    uint32_t worker_slot, uint32_t worker_role, uint64_t operation_id,
    uint64_t native_commit_cookie, uint64_t grant_deadline_ns,
    ker_nginx_source_preexit_pump_fn pump)
{
    struct ker_nginx_source_bootstrap *binding = source_shell_worker_binding;
    bool initial = worker_role == KER_NGINX_SOURCE_WORKER_INITIAL;
    if (!identity || !proof || !pump || !binding || binding->channel < 0 ||
        !binding->source_shell_proof_enabled ||
        (!initial && worker_role != KER_NGINX_SOURCE_WORKER_CANDIDATE) ||
        !operation_id || !grant_deadline_ns ||
        grant_deadline_ns > binding->record.deadline_ns ||
        identity->flags != worker_role ||
        identity->actor_pid != (uint32_t)getpid() ||
        identity->actor_tid != (uint32_t)syscall(SYS_gettid) ||
        memcmp(identity, &binding->record, sizeof(*identity)) ||
        identity->launch_epoch != binding->record.launch_epoch ||
        identity->source_epoch != binding->record.source_epoch ||
        identity->generation != binding->record.generation ||
        identity->actor_start_ticks != binding->record.actor_start_ticks ||
        identity->master_pid != binding->record.master_pid ||
        identity->master_start_ticks != binding->record.master_start_ticks ||
        memcmp(identity->run_nonce, binding->record.run_nonce, sizeof(identity->run_nonce)) ||
        !ker_nginx_source_bootstrap_proof_equal(proof, &binding->source_shell_proof) ||
        !proof->adapter_cycle_serial || !proof->opaque_cycle_token ||
        !binding->record.ready_cookie) return -EPERM;
    if (initial) {
        if (identity->source_epoch || identity->generation || native_commit_cookie ||
            binding->source_commit_evidence_received) return -EPERM;
    } else if (!binding->source_commit_evidence_received || !native_commit_cookie ||
        native_commit_cookie != binding->native_commit_cookie) return -EPERM;
    if (source_shell_preexit_operation) return -EALREADY;
    int live = ker_nginx_source_bootstrap_live(binding);
    if (live) return live;

    uint64_t now = now_ns();
    if (!now || now >= grant_deadline_ns) return -ETIMEDOUT;
    uint64_t deadline = now + KER_NGINX_SOURCE_PREEXIT_BUDGET_NS;
    if (deadline < now || deadline > grant_deadline_ns) deadline = grant_deadline_ns;
    if (operation_id <= source_shell_preexit_operation) return -ESTALE;

    struct ker_nginx_source_preexit_record request = {
        .magic = KER_NGINX_SOURCE_BOOTSTRAP_MAGIC,
        .version = KER_NGINX_SOURCE_PREEXIT_VERSION,
        .type = KER_NGINX_SOURCE_WORKER_PREEXIT,
        .record_bytes = sizeof(request),
        .identity = {
            .record = binding->record,
            .proof = binding->source_shell_proof,
        },
        .worker_slot = worker_slot,
        .worker_role = worker_role,
        .operation_id = operation_id,
        .operation_deadline_ns = deadline,
        .native_commit_cookie = native_commit_cookie,
    };
    request.identity.record.type = KER_NGINX_SOURCE_WORKER_PREEXIT;

    long sent;
    do {
        if (now_ns() >= deadline) return -ETIMEDOUT;
        sent = syscall(SYS_sendto, binding->channel, &request, sizeof(request),
            MSG_NOSIGNAL | MSG_DONTWAIT, NULL, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent != (long)sizeof(request)) return sent < 0 ? -errno : -EIO;
    source_shell_preexit_operation = operation_id;
    if (now_ns() >= deadline) return -ETIMEDOUT;

    bool relay_eof = false;
    bool settlement_received = false;
    for (;;) {
        now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        if (!relay_eof) {
            int pump_status = pump();
            if (pump_status == KER_NGINX_SOURCE_PREEXIT_PUMP_RELAY_EOF) {
                relay_eof = true;
            } else if (pump_status) {
                return pump_status < 0 ? pump_status : -EPROTO;
            }
        }
        now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        uint64_t remain = deadline - now;
        int timeout_ms = (int)((remain + 999999) / 1000000);
        if (timeout_ms > 1) timeout_ms = 1;
        struct pollfd fds[] = {
            {.fd = binding->channel, .events = POLLIN},
            {.fd = binding->supervisor_pidfd, .events = POLLIN},
        };
        long ready = syscall(SYS_poll, fds, 2, timeout_ms);
        /* A delayed poll result is not authority to consume an ACK or report
         * settlement after the immutable operation deadline. */
        now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -errno;
        if (fds[1].revents || (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)))
            return -ENOTCONN;
        if (!(fds[0].revents & POLLIN)) {
            if (relay_eof && settlement_received) return 0;
            continue;
        }

        struct ker_nginx_source_settled_record settled;
        char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(4 * sizeof(int))] = {0};
        struct iovec iov = {.iov_base = &settled, .iov_len = sizeof(settled)};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control)};
        long count = syscall(SYS_recvmsg, binding->channel, &message,
            MSG_TRUNC | MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return -errno;
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
        /* recvmsg may install SCM_RIGHTS even when the absolute deadline
         * expires while it is in flight. Always dispose of ancillary FDs
         * before rejecting a late packet. */
        now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        struct ker_nginx_source_preexit_record expected = request;
        if (count != (long)sizeof(settled) || malformed || credentials != 1 ||
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            settled.magic != KER_NGINX_SOURCE_BOOTSTRAP_MAGIC ||
            settled.version != KER_NGINX_SOURCE_PREEXIT_VERSION ||
            settled.type != KER_NGINX_SOURCE_WORKER_SETTLED ||
            settled.record_bytes != sizeof(settled) || settled.reserved ||
            memcmp(&settled.request, &expected, sizeof(expected)) ||
            settled.status || settled.reserved2 || settled.c31_outstanding ||
            settled.c31_last_result < 0 || settled.native_settled != 1)
            return -EPROTO;
        settlement_received = true;
        now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        if (relay_eof) return 0;
    }
}

/* Constructor state is inherited through the original fork/double-fork path;
 * it is not an inherited FD and survives the slim primary's close loop. */
static uint32_t source_master_pid;
static uint64_t source_master_start;
static uint64_t source_master_handover_deadline[
    KER_NGINX_SOURCE_COMMITTED_ROUND_LIMIT + 1];
static int environment_consumed;
static int source_intermediate;
static int source_detached;
static int (*source_forget_inherited)(void);

struct source_daemon_origin_state {
    struct ker_nginx_source_origin_record record;
    char endpoint[sizeof(((struct sockaddr_un *)0)->sun_path)];
    pid_t origin_pid;
    pid_t owner_tid;
    int origin_pidfd;
    int supervisor_pidfd;
    int origin_channel;
    int ready_pipe[2];
    int release_pipe[2];
    int active;
    int attempted;
    int consumed;
};

static struct source_daemon_origin_state source_daemon_origin = {
    .origin_pidfd = -1, .supervisor_pidfd = -1, .origin_channel = -1,
    .ready_pipe = {-1, -1}, .release_pipe = {-1, -1}
};

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

static int source_origin_close(int *fd)
{
    if (*fd < 0) return 0;
    int value = *fd;
    *fd = -1;
    return (int)syscall(SYS_close, value);
}

static void source_origin_reset(void)
{
    source_origin_close(&source_daemon_origin.origin_pidfd);
    source_origin_close(&source_daemon_origin.supervisor_pidfd);
    source_origin_close(&source_daemon_origin.origin_channel);
    source_origin_close(&source_daemon_origin.ready_pipe[0]);
    source_origin_close(&source_daemon_origin.ready_pipe[1]);
    source_origin_close(&source_daemon_origin.release_pipe[0]);
    source_origin_close(&source_daemon_origin.release_pipe[1]);
    memset(&source_daemon_origin.record, 0, sizeof(source_daemon_origin.record));
    memset(source_daemon_origin.endpoint, 0, sizeof(source_daemon_origin.endpoint));
    source_daemon_origin.origin_pid = 0;
    source_daemon_origin.owner_tid = 0;
    source_daemon_origin.active = 0;
}

static int source_origin_wait(int fd, int owner_pidfd, short events, uint64_t deadline)
{
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        struct pollfd fds[] = {{.fd = fd, .events = events},
            {.fd = owner_pidfd, .events = POLLIN}};
        uint64_t ms = (deadline - now + UINT64_C(999999)) / UINT64_C(1000000);
        int timeout = ms > INT32_MAX ? INT32_MAX : (int)ms;
        long result = syscall(SYS_poll, fds, 2, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -errno;
        if (fds[1].revents) return -ESRCH;
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) return -ENOTCONN;
        if (fds[0].revents & events) return 0;
    }
}

/* The parent-to-child A byte is the final private commit receipt. Once queued,
 * the original ngx_daemon parent may exit immediately; consume that exact byte
 * before observing its pidfd. EOF or any other byte still fails closed. */
static int source_origin_wait_release(int fd, int origin_pidfd, int supervisor_pidfd,
    uint64_t deadline)
{
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now >= deadline) return -ETIMEDOUT;
        struct pollfd fds[] = {{.fd = fd, .events = POLLIN},
            {.fd = origin_pidfd, .events = POLLIN},
            {.fd = supervisor_pidfd, .events = POLLIN}};
        uint64_t ms = (deadline - now + UINT64_C(999999)) / UINT64_C(1000000);
        int timeout = ms > INT32_MAX ? INT32_MAX : (int)ms;
        long result = syscall(SYS_poll, fds, 3, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -errno;
        if (fds[2].revents) return -ESRCH;
        if (fds[0].revents & POLLIN) {
            char release = 0;
            long count = syscall(SYS_read, fd, &release, 1);
            if (count < 0 && errno == EINTR) continue;
            if (count != 1 || release != 'A') return count < 0 ? -errno : -EPROTO;
            return 0;
        }
        if (fds[1].revents) return -ESRCH;
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) return -ENOTCONN;
    }
}

static int source_origin_namespace(uint64_t *device, uint64_t *inode)
{
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/ns/pid", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -errno;
    struct stat info;
    int status = (int)syscall(SYS_fstat, fd, &info);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    if (status) return -saved;
    if (!info.st_dev || !info.st_ino) return -EPROTO;
    *device = (uint64_t)info.st_dev;
    *inode = (uint64_t)info.st_ino;
    return 0;
}

static int source_origin_nonce(uint8_t nonce[16])
{
    const char *value = getenv("KER_NGINX_SOURCE_BOOTSTRAP_NONCE");
    if (!value || strnlen(value, 33) != 32) return -EINVAL;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned byte = 0;
        for (unsigned j = 0; j < 2; ++j) {
            char c = value[i * 2 + j];
            if (c >= '0' && c <= '9') byte = byte * 16 + (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') byte = byte * 16 + (unsigned)(c - 'a' + 10);
            else return -EINVAL;
        }
        nonce[i] = (uint8_t)byte;
    }
    return 0;
}

static int source_origin_live_record(const struct ker_nginx_source_origin_record *record,
    int origin_pidfd, int child_pidfd, uint64_t deadline)
{
    int status = live_pidfd(origin_pidfd, record->origin_pid,
        record->origin_start_ticks, deadline);
    if (!status) status = live_pidfd(child_pidfd, record->child_pid,
        record->child_start_ticks, deadline);
    uint64_t device = 0, inode = 0;
    if (!status) status = source_origin_namespace(&device, &inode);
    if (!status && (device != record->pid_namespace_device ||
            inode != record->pid_namespace_inode)) status = -EXDEV;
    return status;
}

static int
source_origin_read_cycle_snapshot(
    struct ker_source_native_ini_cycle_snapshot *snapshot)
{
    typedef int (*snapshot_read_fn)(
        struct ker_source_native_ini_cycle_snapshot *snapshot);
    snapshot_read_fn read_snapshot = (snapshot_read_fn)dlsym(RTLD_DEFAULT,
        "ker_nginx_source_native_ini_snapshot_read");
    if (!snapshot) return -EINVAL;
    if (!read_snapshot) return -ENOTSUP;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION;
    snapshot->size = sizeof(*snapshot);
    int status = read_snapshot(snapshot);
    if (status) return status;
    /* Do not inspect any output field before checking the tagged ABI. */
    return ker_nginx_source_origin_snapshot_status(0, snapshot);
}

#ifdef KER_NGINX_SOURCE_ORIGIN_TESTING
static void source_origin_test_ack_barrier(uint64_t deadline)
{
    const char *path = getenv("KER_NGINX_SOURCE_ORIGIN_TEST_ACK_BARRIER");
    const char *fd_text = getenv("KER_NGINX_SOURCE_ORIGIN_TEST_ACK_RELEASE_FD");
    char *end = NULL;
    long release_fd = fd_text ? strtol(fd_text, &end, 10) : -1;
    if (!path || !*path || !fd_text || end == fd_text || *end || release_fd < 0 ||
        release_fd > INT_MAX) return;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        char text[32];
        int length = snprintf(text, sizeof(text), "%ld\n", (long)getpid());
        if (length > 0) (void)syscall(SYS_write, fd, text, (size_t)length);
        (void)syscall(SYS_close, fd);
    }
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now >= deadline) return;
        uint64_t ms = (deadline - now + UINT64_C(999999)) / UINT64_C(1000000);
        int timeout = ms > INT32_MAX ? INT32_MAX : (int)ms;
        struct pollfd ready = {.fd = (int)release_fd, .events = POLLIN};
        long result = syscall(SYS_poll, &ready, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || !(ready.revents & POLLIN)) return;
        char release = 0;
        long count = syscall(SYS_read, (int)release_fd, &release, 1);
        if (count == 1 && release == 'U') return;
        if (count < 0 && errno == EINTR) continue;
        return;
    }
}
#endif

int ker_nginx_source_daemon_fork_prepare(void)
{
    typedef int (*predicate_fn)(void);
    predicate_fn prepared = (predicate_fn)dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_source_shell_daemon_prepared");
    predicate_fn abi_matches = (predicate_fn)dlsym(RTLD_DEFAULT,
        "ker_fstack_nginx_owner_activation_abi_matches");
    uintptr_t *process = dlsym(RTLD_DEFAULT, "ngx_process");
    struct ff_reload_state **source = dlsym(RTLD_DEFAULT, "ngx_ff_reload_shm");
    uint64_t supervisor, supervisor_start, epoch, grant_deadline, constructor_start;
    uint64_t now = now_ns(), operation_id = 0;
    uint8_t random_bytes[sizeof(operation_id)];
    uint8_t nonce[16];
    struct ker_source_native_ini_cycle_snapshot cycle_snapshot;
    int status;

    const char *endpoint = getenv("KER_NGINX_SOURCE_BOOTSTRAP_PATH");
    size_t endpoint_len = endpoint ? strnlen(endpoint, sizeof(source_daemon_origin.endpoint)) : 0;
    if (source_daemon_origin.active || source_daemon_origin.attempted ||
        source_daemon_origin.consumed ||
        source_daemon_origin.origin_pidfd >= 0 || source_daemon_origin.supervisor_pidfd >= 0 ||
        source_daemon_origin.origin_channel >= 0 || source_daemon_origin.ready_pipe[0] >= 0 ||
        source_daemon_origin.ready_pipe[1] >= 0 ||
        source_daemon_origin.release_pipe[0] >= 0 || source_daemon_origin.release_pipe[1] >= 0) {
        errno = EALREADY;
        return -1;
    }
    source_daemon_origin.attempted = 1;
    if (source_detached || environment_consumed ||
        (pid_t)syscall(SYS_gettid) != getpid() ||
        !prepared || prepared() != 1 || !abi_matches || abi_matches() != 0 ||
        !process || *process != 1 /* NGX_PROCESS_MASTER */ || !source || *source ||
        !source_master_pid || (uint32_t)getpid() != source_master_pid ||
        !source_master_start || !now || !getenv("KER_NGINX_SOURCE_SHELL_ENABLE") ||
        strcmp(getenv("KER_NGINX_SOURCE_SHELL_ENABLE"), "1") != 0 ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID", &supervisor) ||
        supervisor > UINT32_MAX ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START", &supervisor_start) ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_EPOCH", &epoch) ||
        environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS", &grant_deadline) ||
        grant_deadline <= now || grant_deadline - now > source_bootstrap_max_lifetime() ||
        !endpoint || endpoint_len == 0 ||
        endpoint_len >= sizeof(source_daemon_origin.endpoint) ||
        source_origin_nonce(nonce) ||
        start_ticks_until(source_master_pid, &constructor_start, grant_deadline) ||
        constructor_start != source_master_start) {
        errno = EPERM;
        return -1;
    }
    if (environment_uint("KER_NGINX_SOURCE_BOOTSTRAP_EPOCH", &epoch) ||
        epoch != 1 || (uint64_t)supervisor == (uint64_t)getpid()) {
        errno = EPROTO;
        return -1;
    }
    status = source_origin_read_cycle_snapshot(&cycle_snapshot);
    if (status) { errno = -status; goto fail; }
    uint64_t snapshot_time = now_ns();
    if (!snapshot_time || snapshot_time >= grant_deadline) {
        errno = ETIMEDOUT;
        goto fail;
    }
    size_t random_bytes_used = 0;
    while (random_bytes_used < sizeof(random_bytes)) {
        if (now_ns() >= grant_deadline) { errno = ETIMEDOUT; return -1; }
        long count = syscall(SYS_getrandom, random_bytes + random_bytes_used,
            sizeof(random_bytes) - random_bytes_used, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { errno = count < 0 ? errno : EIO; return -1; }
        random_bytes_used += (size_t)count;
    }
    memcpy(&operation_id, random_bytes, sizeof(operation_id));
    if (!operation_id) { errno = EIO; return -1; }
    source_daemon_origin.record = (struct ker_nginx_source_origin_record){
        .magic = KER_NGINX_SOURCE_ORIGIN_MAGIC,
        .version = KER_NGINX_SOURCE_ORIGIN_VERSION,
        .type = KER_NGINX_SOURCE_ORIGIN_REQUEST,
        .record_bytes = sizeof(struct ker_nginx_source_origin_record),
        .origin_pid = source_master_pid,
        .supervisor_pid = (uint32_t)supervisor,
        .origin_start_ticks = source_master_start,
        .supervisor_start_ticks = supervisor_start,
        .launch_epoch = epoch,
        .grant_deadline_ns = grant_deadline,
        .startup_deadline_ns = grant_deadline < now + KER_NGINX_SOURCE_ORIGIN_MAX_STARTUP_NS ?
            grant_deadline : now + KER_NGINX_SOURCE_ORIGIN_MAX_STARTUP_NS,
        .operation_id = operation_id,
    };
    status = ker_nginx_source_origin_bind_snapshot(&source_daemon_origin.record,
        &cycle_snapshot);
    if (status) { errno = -status; goto fail; }
    memcpy(source_daemon_origin.record.run_nonce, nonce, sizeof(nonce));
    memcpy(source_daemon_origin.endpoint, endpoint, endpoint_len + 1);
    status = source_origin_namespace(&source_daemon_origin.record.pid_namespace_device,
        &source_daemon_origin.record.pid_namespace_inode);
    if (status) { errno = -status; goto fail; }
    source_daemon_origin.origin_pidfd = (int)syscall(SYS_pidfd_open, source_master_pid, 0);
    if (source_daemon_origin.origin_pidfd < 0) goto fail;
    status = live_pidfd(source_daemon_origin.origin_pidfd, source_master_pid,
        source_master_start, source_daemon_origin.record.startup_deadline_ns);
    if (status) { errno = -status; goto fail; }
    if (syscall(SYS_pipe2, source_daemon_origin.ready_pipe,
            O_CLOEXEC | O_NONBLOCK) < 0) goto fail;
    if (syscall(SYS_pipe2, source_daemon_origin.release_pipe,
            O_CLOEXEC | O_NONBLOCK) < 0) goto fail;
    if (now_ns() >= source_daemon_origin.record.startup_deadline_ns) {
        errno = ETIMEDOUT;
        goto fail;
    }
    source_daemon_origin.origin_pid = getpid();
    source_daemon_origin.owner_tid = (pid_t)syscall(SYS_gettid);
    source_daemon_origin.active = 1;
    return 0;
fail:
    status = errno ? errno : EIO;
    source_origin_reset();
    errno = status;
    return -1;
}

static int source_origin_connect_and_ack(struct ker_nginx_source_origin_record *record,
    const char *path, int origin_pidfd, int child_pidfd, uint64_t deadline,
    int *channel_out, int *supervisor_pidfd_out)
{
    int supervisor_pidfd = -1, channel = -1, status = -EPROTO;
    struct ucred peer;
    socklen_t peer_size = sizeof(peer);
    if (!path || !record || !record->supervisor_pid || !record->supervisor_start_ticks)
        return -EINVAL;
    supervisor_pidfd = (int)syscall(SYS_pidfd_open, record->supervisor_pid, 0);
    if (supervisor_pidfd < 0) return -errno;
    status = live_pidfd(supervisor_pidfd, record->supervisor_pid,
        record->supervisor_start_ticks, deadline);
    if (status) goto out;
    channel = (int)syscall(SYS_socket, AF_UNIX,
        SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (channel < 0) { status = -errno; goto out; }
    int enabled = 1;
    if (syscall(SYS_setsockopt, channel, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) {
        status = -errno; goto out;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (syscall(SYS_connect, channel, &address,
            offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1)) {
        if (errno != EINPROGRESS && errno != EINTR && errno != EAGAIN) {
            status = -errno; goto out;
        }
        status = source_origin_wait(channel, supervisor_pidfd, POLLOUT, deadline);
        if (status) goto out;
        int socket_error = 0;
        socklen_t error_size = sizeof(socket_error);
        if (syscall(SYS_getsockopt, channel, SOL_SOCKET, SO_ERROR, &socket_error, &error_size) ||
            error_size != sizeof(socket_error) || socket_error) {
            status = socket_error ? -socket_error : -errno;
            goto out;
        }
    }
    if (syscall(SYS_getsockopt, channel, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) ||
        peer_size != sizeof(peer) || peer.pid != (pid_t)record->supervisor_pid ||
        peer.uid != getuid() || peer.gid != getgid()) { status = -EACCES; goto out; }
    record->child_pid = (uint32_t)getpid();
    record->child_tid = (uint32_t)syscall(SYS_gettid);
    if (start_ticks_until(record->child_pid, &record->child_start_ticks, deadline) ||
        source_origin_live_record(record, origin_pidfd, child_pidfd, deadline)) {
        status = -ESTALE; goto out;
    }
    struct iovec send_iov = {.iov_base = record, .iov_len = sizeof(*record)};
    char send_control[CMSG_SPACE(2 * sizeof(int))] = {0};
    struct msghdr send_message = {.msg_iov = &send_iov, .msg_iovlen = 1,
        .msg_control = send_control, .msg_controllen = sizeof(send_control)};
    struct cmsghdr *send_cmsg = CMSG_FIRSTHDR(&send_message);
    send_cmsg->cmsg_level = SOL_SOCKET;
    send_cmsg->cmsg_type = SCM_RIGHTS;
    send_cmsg->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int request_fds[2] = {origin_pidfd, child_pidfd};
    memcpy(CMSG_DATA(send_cmsg), request_fds, sizeof(request_fds));
    long sent;
    for (;;) {
        status = source_origin_wait(channel, supervisor_pidfd, POLLOUT, deadline);
        if (status) goto out;
        sent = syscall(SYS_sendmsg, channel, &send_message, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            status = source_origin_wait(channel, supervisor_pidfd, POLLOUT, deadline);
            if (status) goto out;
            continue;
        }
        break;
    }
    if (sent != sizeof(*record)) { status = sent < 0 ? -errno : -EIO; goto out; }
    struct ker_nginx_source_origin_record response;
    char recv_control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(4 * sizeof(int))] = {0};
    struct iovec recv_iov = {.iov_base = &response, .iov_len = sizeof(response)};
    struct msghdr recv_message = {.msg_iov = &recv_iov, .msg_iovlen = 1,
        .msg_control = recv_control, .msg_controllen = sizeof(recv_control)};
    long received;
    for (;;) {
        status = source_origin_wait(channel, supervisor_pidfd, POLLIN, deadline);
        if (status) goto out;
        received = syscall(SYS_recvmsg, channel, &recv_message,
            MSG_TRUNC | MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        break;
    }
    if (received < 0) { status = -errno; goto out; }
#ifdef KER_NGINX_SOURCE_ORIGIN_TESTING
    source_origin_test_ack_barrier(deadline);
#endif
    int rights[4], right_count = 0, credential_count = 0, malformed = 0;
    struct ucred actual_cred = {0};
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&recv_message); cmsg;
            cmsg = CMSG_NXTHDR(&recv_message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
            if (!bytes || bytes % sizeof(int)) malformed = 1;
            for (size_t i = 0; i + sizeof(int) <= bytes; i += sizeof(int)) {
                int fd; memcpy(&fd, (char *)CMSG_DATA(cmsg) + i, sizeof(fd));
                if (right_count < (int)(sizeof(rights) / sizeof(rights[0]))) rights[right_count++] = fd;
                else { (void)syscall(SYS_close, fd); malformed = 1; }
            }
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
            cmsg->cmsg_len == CMSG_LEN(sizeof(actual_cred))) {
            memcpy(&actual_cred, CMSG_DATA(cmsg), sizeof(actual_cred));
            ++credential_count;
        } else malformed = 1;
    }
    struct ker_nginx_source_origin_record expected = *record;
    expected.type = KER_NGINX_SOURCE_ORIGIN_ACK;
    if (malformed || received != sizeof(response) || credential_count != 1 || right_count != 1 ||
        (recv_message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        actual_cred.pid != peer.pid || actual_cred.uid != peer.uid || actual_cred.gid != peer.gid ||
        memcmp(&expected, &response, sizeof(expected))) {
        status = -EPROTO;
    } else {
        status = live_pidfd(rights[0], record->supervisor_pid,
            record->supervisor_start_ticks, deadline);
        if (!status) status = source_origin_live_record(record,
            origin_pidfd, child_pidfd, deadline);
    }
    for (int i = 0; i < right_count; ++i) (void)syscall(SYS_close, rights[i]);
    if (!status) {
        *channel_out = channel;
        *supervisor_pidfd_out = supervisor_pidfd;
        channel = -1;
        supervisor_pidfd = -1;
    }
out:
    if (channel >= 0) (void)syscall(SYS_close, channel);
    if (supervisor_pidfd >= 0) (void)syscall(SYS_close, supervisor_pidfd);
    return status;
}

int ker_nginx_source_daemon_fork_child(void)
{
    if (!source_daemon_origin.active || source_daemon_origin.consumed ||
        source_daemon_origin.origin_pid != getppid() ||
        source_daemon_origin.owner_tid != source_daemon_origin.origin_pid ||
        (pid_t)syscall(SYS_gettid) != getpid()) {
        errno = EPERM;
        return -1;
    }
    source_daemon_origin.consumed = 1;
    source_origin_close(&source_daemon_origin.ready_pipe[0]);
    source_origin_close(&source_daemon_origin.release_pipe[1]);
    struct ker_source_native_ini_cycle_snapshot cycle_snapshot;
    int status = source_origin_read_cycle_snapshot(&cycle_snapshot);
    if (!status) status = ker_nginx_source_origin_proof_matches(
        &source_daemon_origin.record, &cycle_snapshot);
    if (!status) {
        uint64_t snapshot_time = now_ns();
        if (!snapshot_time || snapshot_time >=
            source_daemon_origin.record.startup_deadline_ns) status = -ETIMEDOUT;
    }
    if (status) {
        source_origin_reset();
        errno = -status;
        return -1;
    }
    int child_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (child_pidfd < 0) return -1;
    uint64_t device = 0, inode = 0;
    status = source_origin_connect_and_ack(&source_daemon_origin.record,
        source_daemon_origin.endpoint, source_daemon_origin.origin_pidfd, child_pidfd,
        source_daemon_origin.record.startup_deadline_ns,
        &source_daemon_origin.origin_channel, &source_daemon_origin.supervisor_pidfd);
    if (!status && live_pidfd(child_pidfd, getpid(),
            source_daemon_origin.record.child_start_ticks,
            source_daemon_origin.record.startup_deadline_ns)) status = -ESTALE;
    if (!status) {
        char ready = 'R';
        for (;;) {
            status = live_pidfd(source_daemon_origin.origin_pidfd,
                source_daemon_origin.record.origin_pid,
                source_daemon_origin.record.origin_start_ticks,
                source_daemon_origin.record.startup_deadline_ns);
            if (!status) status = live_pidfd(source_daemon_origin.supervisor_pidfd,
                source_daemon_origin.record.supervisor_pid,
                source_daemon_origin.record.supervisor_start_ticks,
                source_daemon_origin.record.startup_deadline_ns);
            if (!status) status = live_pidfd(child_pidfd,
                source_daemon_origin.record.child_pid,
                source_daemon_origin.record.child_start_ticks,
                source_daemon_origin.record.startup_deadline_ns);
            if (status) break;
            long count = syscall(SYS_write, source_daemon_origin.ready_pipe[1], &ready, 1);
            if (count == 1) break;
            if (count < 0 && errno == EINTR) continue;
            status = count < 0 ? -errno : -EIO;
            break;
        }
    }
    if (!status) {
        status = source_origin_wait_release(source_daemon_origin.release_pipe[0],
            source_daemon_origin.origin_pidfd,
            source_daemon_origin.supervisor_pidfd,
            source_daemon_origin.record.startup_deadline_ns);
        if (!status) {
            status = live_pidfd(source_daemon_origin.supervisor_pidfd,
                source_daemon_origin.record.supervisor_pid,
                source_daemon_origin.record.supervisor_start_ticks,
                source_daemon_origin.record.startup_deadline_ns);
        }
        if (!status) status = live_pidfd(child_pidfd,
            source_daemon_origin.record.child_pid,
            source_daemon_origin.record.child_start_ticks,
            source_daemon_origin.record.startup_deadline_ns);
        if (!status) status = source_origin_namespace(&device, &inode);
        if (!status && (device != source_daemon_origin.record.pid_namespace_device ||
                inode != source_daemon_origin.record.pid_namespace_inode)) status = -EXDEV;
        if (!status) {
            source_master_pid = source_daemon_origin.record.child_pid;
            source_master_start = source_daemon_origin.record.child_start_ticks;
        }
    }
    (void)syscall(SYS_close, child_pidfd);
    source_origin_reset();
    if (status) { errno = -status; return -1; }
    return 0;
}

int ker_nginx_source_daemon_fork_parent(pid_t child)
{
    if (!source_daemon_origin.active || source_daemon_origin.consumed ||
        source_daemon_origin.origin_pid != getpid() ||
        source_daemon_origin.owner_tid != (pid_t)syscall(SYS_gettid) || child <= 0) {
        errno = EPERM;
        return -1;
    }
    source_daemon_origin.consumed = 1;
    source_origin_close(&source_daemon_origin.ready_pipe[1]);
    source_origin_close(&source_daemon_origin.release_pipe[0]);
    int child_pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    if (child_pidfd < 0) goto fail;
    uint64_t child_start = 0;
    int status = start_ticks_until((uint32_t)child, &child_start,
        source_daemon_origin.record.startup_deadline_ns);
    if (status) { errno = -status; goto fail; }
    struct pollfd fds[] = {{.fd = source_daemon_origin.ready_pipe[0], .events = POLLIN},
        {.fd = child_pidfd, .events = POLLIN}};
    char ready = 0;
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now >= source_daemon_origin.record.startup_deadline_ns) {
            errno = ETIMEDOUT; goto fail;
        }
        uint64_t ms = (source_daemon_origin.record.startup_deadline_ns - now + 999999) / 1000000;
        int timeout = ms > INT32_MAX ? INT32_MAX : (int)ms;
        long n = syscall(SYS_poll, fds, 2, timeout);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto fail;
        if (fds[1].revents) { errno = ESRCH; goto fail; }
        if (fds[0].revents & POLLIN) {
            long count = syscall(SYS_read, source_daemon_origin.ready_pipe[0], &ready, 1);
            if (count != 1 || ready != 'R') { errno = EPROTO; goto fail; }
            break;
        }
        if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            errno = ESRCH; goto fail;
        }
    }
    status = live_pidfd(source_daemon_origin.origin_pidfd,
        source_daemon_origin.record.origin_pid,
        source_daemon_origin.record.origin_start_ticks,
        source_daemon_origin.record.startup_deadline_ns);
    if (!status) status = live_pidfd(child_pidfd, (uint32_t)child, child_start,
        source_daemon_origin.record.startup_deadline_ns);
    if (status) { errno = -status; goto fail; }
    char release = 'A';
    for (;;) {
        status = live_pidfd(child_pidfd, (uint32_t)child, child_start,
            source_daemon_origin.record.startup_deadline_ns);
        if (status) { errno = -status; goto fail; }
        long count = syscall(SYS_write, source_daemon_origin.release_pipe[1], &release, 1);
        if (count == 1) break;
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            status = source_origin_wait(source_daemon_origin.release_pipe[1], child_pidfd,
                POLLOUT, source_daemon_origin.record.startup_deadline_ns);
            if (!status) continue;
            errno = -status;
        } else if (count >= 0) errno = EIO;
        goto fail;
    }
    (void)syscall(SYS_close, child_pidfd);
    child_pidfd = -1;
    source_origin_reset();
    return 0;
fail:
    {
        int saved = errno ? errno : EIO;
        if (child_pidfd >= 0) {
#ifdef SYS_pidfd_send_signal
            (void)syscall(SYS_pidfd_send_signal, child_pidfd, SIGKILL, NULL, 0);
#endif
            (void)syscall(SYS_close, child_pidfd);
        } else {
            /* Without a pidfd there is no safe numeric-PID fallback. Closing
             * the A writer makes a child that already sent R fail before its
             * original daemon path; retain the R reader until child EOF/R so
             * cleanup cannot turn its bounded failure into SIGPIPE. */
            source_origin_close(&source_daemon_origin.release_pipe[1]);
            while (source_daemon_origin.ready_pipe[0] >= 0) {
                uint64_t now = now_ns();
                if (!now || now >= source_daemon_origin.record.startup_deadline_ns) break;
                struct pollfd fds[] = {
                    {.fd = source_daemon_origin.ready_pipe[0], .events = POLLIN},
                    {.fd = source_daemon_origin.origin_pidfd, .events = POLLIN}
                };
                uint64_t ms = (source_daemon_origin.record.startup_deadline_ns - now + 999999) /
                    1000000;
                int timeout = ms > INT32_MAX ? INT32_MAX : (int)ms;
                long n = syscall(SYS_poll, fds, 2, timeout);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0 || fds[1].revents ||
                    (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))) break;
                if (fds[0].revents & POLLIN) {
                    char ready;
                    (void)syscall(SYS_read, source_daemon_origin.ready_pipe[0], &ready, 1);
                    break;
                }
            }
        }
        source_origin_reset();
        errno = saved;
        return -1;
    }
}

void ker_nginx_source_daemon_fork_abort(void)
{
    source_daemon_origin.consumed = 1;
    source_origin_reset();
}

static int source_from_environment(uint32_t role, uint32_t generation,
    uint32_t source_epoch, const void *source_block, uint16_t operation,
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    struct ker_nginx_source_bootstrap *binding)
{
    const char *path = getenv("KER_NGINX_SOURCE_BOOTSTRAP_PATH");
    if (!path) return -ENOTSUP;
    const char *shell_enabled = getenv("KER_NGINX_SOURCE_SHELL_ENABLE");
    if (shell_enabled && !strcmp(shell_enabled, "1")) {
        if (!snapshot) return -ENOTSUP;
    } else if (snapshot) return -EPERM;
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
        if (source_epoch < 1 ||
            source_epoch > KER_NGINX_SOURCE_COMMITTED_ROUND_LIMIT) return -EPROTO;
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
    return ker_nginx_source_bootstrap_connect_source_shell(path, &request, snapshot,
        (uint32_t)supervisor, supervisor_start, binding);
}

int ker_nginx_source_bootstrap_from_environment(uint32_t role, uint32_t generation,
    uint32_t source_epoch, const void *source_block,
    struct ker_nginx_source_bootstrap *binding)
{
    return source_from_environment(role, generation, source_epoch, source_block,
        KER_NGINX_SOURCE_BOOTSTRAP_REQUEST, NULL, binding);
}

int ker_nginx_source_bootstrap_from_environment_source_shell(uint32_t role,
    uint32_t generation, uint32_t source_epoch, const void *source_block,
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    struct ker_nginx_source_bootstrap *binding)
{
    if (!snapshot) return -EINVAL;
    return source_from_environment(role, generation, source_epoch, source_block,
        KER_NGINX_SOURCE_BOOTSTRAP_REQUEST, snapshot, binding);
}

int ker_nginx_source_is_master(void)
{
    return getenv("KER_NGINX_SOURCE_BOOTSTRAP_PATH") &&
        (uint32_t)getpid() == source_master_pid;
}

int ker_nginx_source_master_barrier(uint16_t operation)
{
    /* A new round consumes the preceding receipt without renewing any
     * existing deadline. An abort may authorize only the explicit retry. */
    static unsigned consumed[KER_NGINX_SOURCE_COMMITTED_ROUND_LIMIT + 1];
    static unsigned completed[KER_NGINX_SOURCE_COMMITTED_ROUND_LIMIT + 1];
    unsigned bit = operation == KER_NGINX_SOURCE_MASTER_PARK ? 1u :
        operation == KER_NGINX_SOURCE_MASTER_COMMIT ? 2u :
        operation == KER_NGINX_SOURCE_MASTER_ABORT ? 4u : 0u;
    struct ff_reload_state **source = dlsym(RTLD_DEFAULT, "ngx_ff_reload_shm");
    int *enabled = dlsym(RTLD_DEFAULT, "ngx_ff_graceful_reload");
    if (!bit || !ker_nginx_source_is_master() || !source || !*source ||
        !enabled || *enabled != 1 || !ff_reload_state_valid(*source, sizeof(**source)))
        return -EPROTO;
    uint32_t peer = 0, peer_generation = 0;
    bool upgrade = false;
    if (ker_nginx_source_upgrade_enabled() && (*source)->epoch == 1 &&
        !(*source)->reload_active && !(*source)->fsm_state) {
        ff_reload_peer_block(&peer, &peer_generation);
        upgrade = peer != 0 && peer != FF_RELOAD_EPOCH_NONE && peer_generation == 0;
    }
    if (!upgrade && ((*source)->reload_active != 1 || (*source)->fsm_state != 2))
        return -EPROTO;
    uint32_t round = (*source)->epoch;
    if (upgrade) round = KER_NGINX_SOURCE_UPGRADE_ROUND;
    if (!round || round > KER_NGINX_SOURCE_COMMITTED_ROUND_LIMIT)
        return -EPROTO;
    unsigned old_generation = 0, target_generation = 1;
    if (round > 1) {
        const char *successor = getenv("KER_NGINX_SOURCE_SUCCESSOR_ENABLE");
        const char *first = getenv("KER_NGINX_SOURCE_FIRST_HUP_ENABLE");
        int committed_successor = successor && !strcmp(successor, "1") &&
            first && !strcmp(first, "1") && !getenv("FF_FAULT") &&
            !getenv("KER_NGINX_SOURCE_ABORT_RETRY_ENABLE") &&
            completed[round - 1] == (1u | 2u) &&
            consumed[round - 1] == (1u | 2u);
        int aborted_retry = round == 2 && getenv("KER_NGINX_SOURCE_ABORT_RETRY_ENABLE") &&
            ker_fstack_nginx_source_fault_profile() &&
            completed[1] == (1u | 4u) && consumed[1] == (1u | 4u);
        if (!committed_successor && !aborted_retry &&
            (!upgrade || completed[round - 1] != (1u | 2u))) return -EPROTO;
        if (committed_successor || upgrade) {
            target_generation = round % 2;
            old_generation = 1 - target_generation;
        }
    }
    if ((*source)->active_gen != old_generation ||
        (*source)->target_gen != (upgrade ? old_generation : target_generation) ||
        (consumed[round] & bit) ||
        (bit != 1 && (!(consumed[round] & 1) || (consumed[round] & 6))) ||
        (bit == 4 && (round != 1 || !ker_fstack_nginx_source_fault_profile()))) return -EPROTO;
    if ((bit == 1 && ((*source)->rx_owner_gen != old_generation || (*source)->rx_stopped)) ||
        (bit == 2 && ((*source)->rx_owner_gen != target_generation ||
            (*source)->rx_stopped != (uint32_t)upgrade ||
            (upgrade && (*source)->reserved[4] != peer))) ||
        (bit == 4 && ((*source)->rx_owner_gen != old_generation || (*source)->rx_stopped != 1))) return -ESTALE;
    consumed[round] |= bit;
    struct ker_nginx_source_bootstrap binding;
    struct ker_source_native_ini_cycle_snapshot cycle_snapshot;
    const char *shell_enabled = getenv("KER_NGINX_SOURCE_SHELL_ENABLE");
    const struct ker_source_native_ini_cycle_snapshot *snapshot = NULL;
    if (shell_enabled && !strcmp(shell_enabled, "1")) {
        int snapshot_status = source_origin_read_cycle_snapshot(&cycle_snapshot);
        if (snapshot_status) return snapshot_status;
        snapshot = &cycle_snapshot;
    }
    int status = source_from_environment(KER_NGINX_SOURCE_ROLE_MASTER, target_generation, round,
        *source, operation, snapshot, &binding);
    if (!status) {
        status = -(int)binding.record.flags;
        ker_nginx_source_bootstrap_close(&binding);
        if (!status) completed[round] |= bit;
    }
    return status;
}
