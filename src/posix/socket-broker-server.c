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
#include <time.h>
#include <unistd.h>
#include "tcp-observer-diag-wire.h"
#include "member-census-diag-wire.h"
#include "member-census-diag.h"
#include "member-census-runtime.h"
#include "ff-owner-admission-control.h"
#include "ff-admission-task.h"

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

struct sb_group {
    bool live;
    bool owner_aware;
    bool materialized;
    bool failed;
    bool slot_issued[2];
    uint16_t port;
    int base_fd[2];
    uint32_t member_mark[2];
    uint64_t member_cookie[2];
    uint64_t incarnation;
    uint64_t claim_generation[2];
    uint64_t member_owner_token[2];
    pid_t member_owner_pid[2];
    uint64_t member_owner_start_time[2];
    struct sockaddr_in address;
    int backlog;
    uint32_t group_rights;
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
    uint64_t owner_token;
    uint64_t group_incarnation;
    uint64_t group_claim_generation;
};
struct sb_owner {
    bool live;
    bool unowned_network_history;
    bool owned_socket_history;
    bool owner_group_claimed;
    uint64_t owner_group_incarnation;
    uint64_t owner_group_claim_generation;
    uint32_t owner_group_index;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    uint64_t start_time;
    uint64_t token;
    uint32_t mark;
    int pidfd;
    int admission_listener_fd;
    int admission_peer_fd;
    bool admission_prepared;
    bool admission_attached;
    /* Sticky after the first task READY. `admission_ready` is per-window and
     * may clear during RETIRE/REARM; the initial attach deadline is one-shot. */
    bool admission_initial_ready;
    bool admission_ready;
    bool admission_failed;
    bool admission_release_busy_logged;
    struct ker_ff_admission_task *admission_task;
    int admission_listener_native_fd;
    uint64_t admission_registration_id;
    uint64_t admission_deadline_ns;
    char admission_directory[80];
    char admission_path[KER_SOCKET_BROKER_PATH_MAX + 1];
    dev_t admission_directory_dev;
    ino_t admission_directory_ino;
    dev_t admission_path_dev;
    ino_t admission_path_ino;
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
    bool payload;
    bool requests;
    int client_slot;
    int client_fd;
    struct ker_sb_header request;
    uint64_t ticket;
    uint64_t owner_token;
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
    struct sb_owner owners[KER_SB_CLIENTS];
    uint64_t next_owner_token;
    struct sb_group groups[KER_SB_OBJECTS];
    uint64_t next_group_incarnation;
    struct sb_client clients[KER_SB_CLIENTS];
    struct sb_census_job census_jobs[KER_SB_CENSUS_JOBS];
};

static int host_close(int fd)
{
    if (fd >= 0) return (int)syscall(SYS_close, fd);
    return 0;
}
static void owner_admission_endpoint_close(struct sb_owner *owner)
{
    if (!owner) return;
    if (owner->admission_task)
        (void)ker_posix_ff_admission_task_request_stop(owner->admission_task);
    (void)host_close(owner->admission_peer_fd);
    (void)host_close(owner->admission_listener_fd);
    owner->admission_peer_fd = -1;
    owner->admission_listener_fd = -1;
    struct stat identity;
    if (owner->admission_path[0] &&
        !lstat(owner->admission_path, &identity) &&
        identity.st_dev == owner->admission_path_dev &&
        identity.st_ino == owner->admission_path_ino)
        (void)syscall(SYS_unlinkat, AT_FDCWD, owner->admission_path, 0);
    if (owner->admission_directory[0] &&
        !lstat(owner->admission_directory, &identity) &&
        identity.st_dev == owner->admission_directory_dev &&
        identity.st_ino == owner->admission_directory_ino)
        (void)syscall(SYS_unlinkat, AT_FDCWD, owner->admission_directory,
            AT_REMOVEDIR);
    owner->admission_path[0] = '\0';
    owner->admission_directory[0] = '\0';
}
#ifdef KER_C16_ADMISSION_TEST_TRACE
static void owner_admission_task_trace(const char *event, int status)
{
    char line[128];
    int length = snprintf(line, sizeof(line),
        "C17_TASK_RELEASE %s status=%d\n", event, status);
    if (length > 0 && (size_t)length < sizeof(line))
        (void)syscall(SYS_write, STDOUT_FILENO, line, (size_t)length);
}
#endif
static int owner_admission_task_release(struct sb_owner *owner)
{
    if (!owner || !owner->admission_task) return -EINVAL;
    int status = ker_posix_ff_admission_task_release(owner->admission_task);
#ifdef KER_C16_ADMISSION_TEST_TRACE
    if (status == -EBUSY && !owner->admission_release_busy_logged) {
        owner_admission_task_trace("deferred", status);
        owner->admission_release_busy_logged = true;
    } else if (!status) {
        owner_admission_task_trace("released", status);
        owner->admission_release_busy_logged = false;
    }
#endif
    if (!status) owner->admission_task = NULL;
    return status;
}
static uint64_t host_monotonic_ns(void)
{
    struct timespec now = {0};
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now)) return 0;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) /
            UINT64_C(1000000000)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
        (uint64_t)now.tv_nsec;
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
static struct sb_owner *owner_by_token(struct ker_socket_broker_server *server,
    uint64_t token);
static int owner_identity_alive(struct sb_owner *owner);

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
    case KER_SB_MEMBER_CENSUS_SNAPSHOT:
    case KER_SB_MEMBER_PAYLOAD_SNAPSHOT: return KER_SOCKET_BROKER_READ;
    case KER_SB_FF_OWNER_SOCKET: return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_FF_OWNER_ADMISSION_PREPARE: return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_FF_OWNER_ADMISSION_RETIRE:
    case KER_SB_FF_OWNER_ADMISSION_REARM:
    case KER_SB_FF_OWNER_ADMISSION_STATUS: return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_FF_OWNER_GROUP_SLOT:
    case KER_SB_FF_OWNER_GROUP_PUBLISH:
        return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_FF_OWNER_GROUP_CLAIM:
    case KER_SB_FF_OWNER_GROUP_MEMBER:
        return KER_SOCKET_BROKER_CONTROL;
    case KER_SB_FF_OWNER_MATCH: case KER_SB_FF_OWNER_PAYLOAD:
    case KER_SB_FF_OWNER_REQUESTS:
        return KER_SOCKET_BROKER_READ;
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
    if (object->owner_token && object->native_fd >= 0) {
        struct sb_owner *owner = owner_by_token(server, object->owner_token);
        if (owner && owner->admission_task &&
            owner->admission_listener_native_fd == object->native_fd) {
            (void)ker_posix_ff_admission_task_listener_closed(
                owner->admission_task, object->native_fd);
            owner->admission_listener_native_fd = -1;
            owner->admission_failed = true;
        }
    }
    /* Do not retain the adopted descriptor through epoll metadata. The final
     * capability close is the final userspace fd close; original Linux applies
     * its own epoll/OFD close semantics. */
    if (object->native_fd >= 0) (void)close(object->native_fd);
    if (object->group_slot >= 0) {
        struct sb_group *group = &server->groups[object->group_slot];
        if (group && group->live && group->handles && --group->handles == 0) {
            if (group->owner_aware) {
                for (unsigned i = 0; i < 2; ++i) {
                    struct sb_owner *owner = owner_by_token(server,
                        group->member_owner_token[i]);
                    if (owner && owner->admission_task &&
                        owner->admission_listener_native_fd == group->base_fd[i]) {
                        (void)ker_posix_ff_admission_task_listener_closed(
                            owner->admission_task, group->base_fd[i]);
                        owner->admission_listener_native_fd = -1;
                        owner->admission_failed = true;
                    }
                }
            }
            if (group->base_fd[0] >= 0) (void)close(group->base_fd[0]);
            if (group->base_fd[1] >= 0) (void)close(group->base_fd[1]);
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

static bool admission_tasks_stopping(struct ker_socket_broker_server *server)
{
    bool active = false;
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_owner *owner = &server->owners[i];
        if (!owner->admission_task) continue;
        (void)ker_posix_ff_admission_task_request_stop(owner->admission_task);
        uint64_t lease = 0;
        int state = ker_posix_ff_admission_task_poll(owner->admission_task, &lease);
        if (state == KER_FF_ADMISSION_TASK_STARTING ||
            state == KER_FF_ADMISSION_TASK_READY ||
            state == KER_FF_ADMISSION_TASK_STOPPING) {
            active = true;
        } else {
            if (owner_admission_task_release(owner)) active = true;
        }
    }
    return active;
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
    object->group_incarnation = server->groups[group_slot].incarnation;
    server->groups[group_slot].handles++;
    return capability;
}

static int member_census_capability(struct ker_socket_broker_server *server,
    struct sb_object *group_object, unsigned index)
{
    if (!group_object || group_object->kind != KER_SOCKET_BROKER_REUSEPORT_GROUP ||
        group_object->group_slot < 0 || index > 1) return fail(ENOTSOCK);
    struct sb_group *group = &server->groups[group_object->group_slot];
    if (group_object->group_incarnation != group->incarnation) return fail(ESTALE);
    if (group->owner_aware && !group->materialized) return fail(EAGAIN);
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

/* Read field 22 from /proc/PID/stat. The PID itself comes from the socket
 * credential and its pidfd, never from the request payload. */
static int process_start_time(pid_t pid, uint64_t *start_time)
{
    if (pid <= 0 || !start_time) return fail(EINVAL);
    char path[64], buffer[4096];
    int length = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) return fail(EOVERFLOW);
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    ssize_t count;
    do { count = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1); }
    while (count < 0 && errno == EINTR);
    int saved = errno;
    (void)host_close(fd);
    if (count <= 0) return fail(count < 0 ? saved : EPROTO);
    buffer[count] = '\0';
    char *cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ') return fail(EPROTO);
    cursor += 2;
    /* cursor begins at field 3 (state); advance through field 22. */
    for (unsigned field = 3; field < 22; ++field) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) return fail(EPROTO);
        while (*cursor && *cursor != ' ') ++cursor;
    }
    while (*cursor == ' ') ++cursor;
    if (!*cursor) return fail(EPROTO);
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(cursor, &end, 10);
    if (errno || end == cursor || (*end && *end != ' ')) return fail(EPROTO);
    *start_time = (uint64_t)value;
    return 0;
}

static int client_identity(struct sb_client *client, uint64_t *start_time)
{
    struct pollfd pidfd = {.fd = client->pidfd, .events = POLLIN};
    int ready = (int)syscall(SYS_poll, &pidfd, 1, 0);
    if (ready < 0) return -errno;
    if (ready && (pidfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) return -ESRCH;
    if (process_start_time(client->credential.pid, start_time)) return -errno;
    return 0;
}

static struct sb_owner *owner_by_token(struct ker_socket_broker_server *server,
    uint64_t token)
{
    if (!token) return NULL;
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i)
        if (server->owners[i].live && server->owners[i].token == token)
            return &server->owners[i];
    return NULL;
}

static int owner_require_client(struct sb_owner *owner, struct sb_client *client)
{
    if (!owner || !owner->live) return -ESTALE;
    uint64_t start_time = 0;
    int status = client_identity(client, &start_time);
    if (status) return status;
    if (client->credential.pid != owner->pid || start_time != owner->start_time)
        return -EXDEV;
    return owner_identity_alive(owner);
}

static int owner_identity_alive(struct sb_owner *owner)
{
    if (!owner || !owner->live) return -ESTALE;
    struct pollfd pidfd = {.fd = owner->pidfd, .events = POLLIN};
    int ready = (int)syscall(SYS_poll, &pidfd, 1, 0);
    if (ready < 0) return -errno;
    if (ready && (pidfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) return -ESRCH;
    uint64_t current_start = 0;
    if (process_start_time(owner->pid, &current_start)) return -errno;
    return current_start == owner->start_time ? 0 : -ESTALE;
}

static struct sb_owner *owner_for_client(struct ker_socket_broker_server *server,
    struct sb_client *client, bool create, int *status_out)
{
    uint64_t start_time = 0;
    int status = client_identity(client, &start_time);
    if (status) { if (status_out) *status_out = status; return NULL; }
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_owner *owner = &server->owners[i];
        if (owner->live && owner->pid == client->credential.pid &&
            owner->start_time == start_time) {
            if (status_out) *status_out = 0;
            return owner;
        }
    }
    if (!create) { if (status_out) *status_out = 0; return NULL; }
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_owner *owner = &server->owners[i];
        if (owner->live) continue;
        int pidfd = (int)syscall(SYS_fcntl, client->pidfd, F_DUPFD_CLOEXEC, 0);
        if (pidfd < 0) { if (status_out) *status_out = -errno; return NULL; }
        *owner = (struct sb_owner){.live = true, .pid = client->credential.pid,
            .uid = client->credential.uid, .gid = client->credential.gid,
            .start_time = start_time, .pidfd = pidfd,
            .admission_listener_fd = -1, .admission_peer_fd = -1,
            .admission_listener_native_fd = -1};
        if (status_out) *status_out = 0;
        return owner;
    }
    if (status_out) *status_out = -ENOSPC;
    return NULL;
}

static int mark_actor_unowned_network(struct ker_socket_broker_server *server,
    struct sb_client *client)
{
    int status = 0;
    struct sb_owner *owner = owner_for_client(server, client, true, &status);
    if (status) return status;
    if (!owner) return -ENOSPC;
    owner->unowned_network_history = true;
    return 0;
}

static int track_actor_socket_caps(struct ker_socket_broker_server *server,
    struct sb_client *client, const int *fds, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        struct sb_object *object = lookup_cap(server, fds[i]);
        if (!object || object->kind != KER_SOCKET_BROKER_SOCKET) continue;
        bool owned = false;
        if (object->owner_token) {
            struct sb_owner *owner = owner_by_token(server, object->owner_token);
            if (owner) {
                int owner_status = owner_require_client(owner, client);
                if (!owner_status) owned = true;
                else if (owner_status != -EXDEV && owner_status != -ESRCH &&
                    owner_status != -ESTALE) return owner_status;
            }
        }
        if (!owned) {
            int status = mark_actor_unowned_network(server, client);
            if (status) return status;
        }
    }
    return 0;
}

static int owner_require_actor(struct ker_socket_broker_server *server,
    struct sb_client *client, struct sb_object *object, struct sb_owner **owner_out)
{
    if (!object || object->kind != KER_SOCKET_BROKER_FF_OWNER ||
        !object->owner_token || object->native_fd >= 0 || object->group_slot >= 0)
        return -ENOTSOCK;
    struct sb_owner *owner = owner_by_token(server, object->owner_token);
    if (!owner) return -ESTALE;
    int status = owner_require_client(owner, client);
    if (status) return status;
    if (owner_out) *owner_out = owner;
    return 0;
}

static int create_ff_owner(struct ker_socket_broker_server *server,
    struct sb_client *client, int *capability_out)
{
    int status = 0;
    struct sb_owner *owner = owner_for_client(server, client, true, &status);
    if (status) return status;
    if (!owner) return -ENOSPC;
    if (owner->unowned_network_history) return -EOPNOTSUPP;
    if (!owner->token) {
        uint32_t mark = 0;
        int allocated = allocate_member_mark(&mark);
        if (allocated) return allocated;
        if (!mark || server->next_owner_token == UINT64_MAX) return -EOVERFLOW;
        owner->token = ++server->next_owner_token;
        owner->mark = mark;
    }
    size_t slot = KER_SB_OBJECTS;
    int cap = make_capability(server, -1, KER_SOCKET_BROKER_FF_OWNER,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ, &slot);
    if (cap < 0) return -errno;
    server->objects[slot].owner_token = owner->token;
    *capability_out = cap;
    return 0;
}

static int owner_admission_prepare(struct ker_socket_broker_server *server,
    struct sb_client *client, int owner_cap,
    struct ker_sb_ff_owner_admission_prepare *response)
{
    struct sb_object *object = lookup_cap(server, owner_cap);
    struct sb_owner *owner = NULL;
    int status = owner_require_actor(server, client, object, &owner);
    if (status) return status;
    if (!(object->rights & KER_SOCKET_BROKER_CONTROL)) return -EACCES;
    if (owner->unowned_network_history) return -EOPNOTSUPP;
    if (owner->admission_prepared || owner->admission_failed) return -EALREADY;
    if (owner->owned_socket_history) return -EBUSY;
    /* Admission attaches before the first broker-owned socket is created.
     * This one-listener profile intentionally cannot retrofit an owner that
     * already has network descriptors. */
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        if (server->objects[i].live &&
            server->objects[i].kind == KER_SOCKET_BROKER_SOCKET &&
            server->objects[i].owner_token == owner->token)
            return -EBUSY;

    uint64_t registration = 0;
    long random_result = syscall(SYS_getrandom, &registration,
        sizeof(registration), 0);
    if (random_result < 0) return -errno;
    if (random_result != (long)sizeof(registration)) return -EIO;
    if (!registration) return -EIO;
    uint64_t now = host_monotonic_ns();
    if (!now || now > UINT64_MAX - UINT64_C(5000000000)) return -EOVERFLOW;
    uint64_t deadline = now + UINT64_C(5000000000);
    char directory[80], path[KER_SOCKET_BROKER_PATH_MAX + 1];
    const char *temporary_root = getenv("TMPDIR");
    if (!temporary_root || !*temporary_root) temporary_root = "/dev/shm";
    size_t root_length = strnlen(temporary_root, 64);
    struct stat root_identity;
    if (!root_length || root_length >= 64 || temporary_root[0] != '/' ||
        lstat(temporary_root, &root_identity) || !S_ISDIR(root_identity.st_mode) ||
        ((root_identity.st_mode & S_ISVTX) == 0 &&
            (root_identity.st_mode & 0022) != 0) ||
        (root_identity.st_uid != geteuid() && root_identity.st_uid != 0))
        return -EACCES;
    int length = snprintf(directory, sizeof(directory),
        "%s/ker-adm-%ld-%016llx", temporary_root, (long)getpid(),
        (unsigned long long)registration);
    if (length <= 0 || (size_t)length >= sizeof(directory)) return -ENAMETOOLONG;
    length = snprintf(path, sizeof(path), "%s/control", directory);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -ENAMETOOLONG;
    if (syscall(SYS_mkdirat, AT_FDCWD, directory, 0700)) return -errno;
    struct stat directory_identity;
    if (lstat(directory, &directory_identity) ||
        !S_ISDIR(directory_identity.st_mode) ||
        directory_identity.st_uid != geteuid() ||
        (directory_identity.st_mode & 0777) != 0700) {
        int error = errno ? errno : EACCES;
        (void)syscall(SYS_unlinkat, AT_FDCWD, directory, AT_REMOVEDIR);
        return -error;
    }
    int listener = (int)syscall(SYS_socket, AF_UNIX,
        SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        int error = errno;
        (void)syscall(SYS_unlinkat, AT_FDCWD, directory, AT_REMOVEDIR);
        return -error;
    }
    int pass_credentials = 1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, (size_t)length + 1);
    int result = 0;
    if (syscall(SYS_setsockopt, listener, SOL_SOCKET, SO_PASSCRED,
            &pass_credentials, sizeof(pass_credentials)) ||
        syscall(SYS_bind, listener, &address,
            (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                strlen(path) + 1)) ||
        syscall(SYS_chmod, path, 0600) || syscall(SYS_listen, listener, 1))
        result = -errno;
    struct stat path_identity;
    if (!result && (lstat(path, &path_identity) ||
        !S_ISSOCK(path_identity.st_mode) || path_identity.st_uid != geteuid()))
        result = -(errno ? errno : EACCES);
    if (result) {
        int error = -result;
        (void)host_close(listener);
        (void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
        (void)syscall(SYS_unlinkat, AT_FDCWD, directory, AT_REMOVEDIR);
        return -error;
    }
    owner->admission_listener_fd = listener;
    owner->admission_peer_fd = -1;
    owner->admission_prepared = true;
    owner->admission_deadline_ns = deadline;
    owner->admission_registration_id = registration;
    owner->admission_directory_dev = directory_identity.st_dev;
    owner->admission_directory_ino = directory_identity.st_ino;
    owner->admission_path_dev = path_identity.st_dev;
    owner->admission_path_ino = path_identity.st_ino;
    memcpy(owner->admission_directory, directory, strlen(directory) + 1);
    memcpy(owner->admission_path, path, strlen(path) + 1);
    memcpy(response->endpoint_path, path, strlen(path) + 1);
    response->registration_id = registration;
    response->reserved = 0;
    return 0;
}

static int owner_admission_peer_valid(struct sb_owner *owner, int fd)
{
    struct ucred peer = {0};
    socklen_t length = sizeof(peer);
    if (host_getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length))
        return -errno;
    if (length != sizeof(peer)) return -EPROTO;
    if (peer.pid != owner->pid || peer.uid != owner->uid || peer.gid != owner->gid)
        return -EACCES;
    uint64_t start_time = 0;
    int status = process_start_time(peer.pid, &start_time);
    if (status) return status;
    if (start_time != owner->start_time) return -ESTALE;
    struct pollfd owner_pidfd = {.fd = owner->pidfd, .events = POLLIN};
    int ready = (int)syscall(SYS_poll, &owner_pidfd, 1, 0);
    if (ready < 0) return -errno;
    if (ready && (owner_pidfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
        return -ESRCH;
    int peer_pidfd = -1;
    length = sizeof(peer_pidfd);
    if (host_getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &peer_pidfd, &length)) {
        int error = errno ? errno : EPROTO;
        if (peer_pidfd >= 0) (void)host_close(peer_pidfd);
        return -error;
    }
    if (length != sizeof(peer_pidfd)) {
        (void)host_close(peer_pidfd);
        return -EPROTO;
    }
    struct pollfd peer_identity = {.fd = peer_pidfd, .events = POLLIN};
    ready = (int)syscall(SYS_poll, &peer_identity, 1, 0);
    status = ready < 0 ? -errno : ready &&
        (peer_identity.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) ? -ESRCH : 0;
    (void)host_close(peer_pidfd);
    return status;
}

static int owner_admission_receive_hello(struct sb_owner *owner)
{
    unsigned char bytes[sizeof(struct ker_ff_owner_admission_hello) + 1] = {0};
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 8)] = {0};
    struct iovec iov = {.iov_base = bytes, .iov_len = sizeof(bytes)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t amount = syscall(SYS_recvmsg, owner->admission_peer_fd, &message,
        MSG_DONTWAIT | MSG_CMSG_CLOEXEC | MSG_TRUNC);
    if (amount < 0) return errno == EAGAIN || errno == EWOULDBLOCK ||
        errno == EINTR ? 0 : -errno;
    struct ucred credentials = {0};
    unsigned credential_count = 0;
    bool malformed = !amount || !!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *control_message = CMSG_FIRSTHDR(&message);
         control_message; control_message = CMSG_NXTHDR(&message, control_message)) {
        if (control_message->cmsg_level != SOL_SOCKET) {
            malformed = true;
            continue;
        }
        if (control_message->cmsg_type == SCM_CREDENTIALS) {
            if (control_message->cmsg_len != CMSG_LEN(sizeof(credentials)) ||
                ++credential_count != 1) {
                malformed = true;
                continue;
            }
            memcpy(&credentials, CMSG_DATA(control_message), sizeof(credentials));
            continue;
        }
        if (control_message->cmsg_type == SCM_RIGHTS &&
            control_message->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes_length = control_message->cmsg_len - CMSG_LEN(0);
            if (bytes_length % sizeof(int)) malformed = true;
            for (size_t offset = 0; offset + sizeof(int) <= bytes_length;
                 offset += sizeof(int)) {
                int received_fd = -1;
                memcpy(&received_fd, (unsigned char *)CMSG_DATA(control_message) + offset,
                    sizeof(received_fd));
                if (host_close(received_fd)) {
                    malformed = true;
                } else {
#ifdef KER_C16_ADMISSION_TEST_TRACE
                    char trace[96];
                    int trace_length = snprintf(trace, sizeof(trace),
                        "C16_HELLO_RIGHTS_CLOSED fd=%d\n", received_fd);
                    if (trace_length > 0 && (size_t)trace_length < sizeof(trace))
                        (void)syscall(SYS_write, STDOUT_FILENO, trace,
                            (size_t)trace_length);
#endif
                }
            }
            malformed = true;
            continue;
        }
        malformed = true;
    }
    if (malformed || credential_count != 1 ||
        credentials.pid != owner->pid || credentials.uid != owner->uid ||
        credentials.gid != owner->gid || amount != sizeof(struct ker_ff_owner_admission_hello))
        return -EPROTO;
    struct ker_ff_owner_admission_hello hello = {0};
    memcpy(&hello, bytes, sizeof(hello));
    if (hello.magic != KER_FF_OWNER_ADMISSION_HELLO_MAGIC ||
        hello.version != KER_FF_OWNER_ADMISSION_HELLO_VERSION ||
        hello.length != sizeof(hello) ||
        hello.registration_id != owner->admission_registration_id || hello.reserved)
        return -EACCES;
    int status = owner_admission_peer_valid(owner, owner->admission_peer_fd);
    if (status) return status;
    struct ker_ff_admission_task_config config = {
        .owner_mark = owner->mark,
        .registration_id = owner->admission_registration_id,
        .actor_pid = owner->pid,
        .actor_uid = owner->uid,
        .actor_gid = owner->gid,
        .actor_start_time = owner->start_time,
        .actor_pidfd = owner->pidfd,
        .peer_fd = owner->admission_peer_fd};
    status = ker_posix_ff_admission_task_start(&config, &owner->admission_task);
    if (status) return status;
    (void)host_close(owner->admission_peer_fd);
    owner->admission_peer_fd = -1;
    owner->admission_attached = true;
    return 1;
}

static void pump_owner_admission_endpoints(struct ker_socket_broker_server *server)
{
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_owner *owner = &server->owners[i];
        if (!owner->live || !owner->admission_prepared) continue;
        if (owner->admission_task) {
            uint64_t current_lease = 0;
            int current_state = ker_posix_ff_admission_task_poll(
                owner->admission_task, &current_lease);
            if (current_state == KER_FF_ADMISSION_TASK_TERMINAL ||
                (current_state < 0 && current_state != -EINPROGRESS)) {
                int release_status = owner_admission_task_release(owner);
                owner->admission_ready = false;
                owner->admission_failed = true;
                if (!release_status) owner->admission_listener_native_fd = -1;
                continue;
            }
            if (current_state == KER_FF_ADMISSION_TASK_STOPPING) continue;
            if (current_state == KER_FF_ADMISSION_TASK_QUARANTINED) {
                owner->admission_ready = false;
                owner->admission_failed = true;
            } else if (current_state == KER_FF_ADMISSION_TASK_READY && current_lease) {
                owner->admission_initial_ready = true;
                owner->admission_ready = true;
                continue;
            } else if (owner->admission_initial_ready &&
                (current_state == KER_FF_ADMISSION_TASK_RETIRING ||
                 current_state == KER_FF_ADMISSION_TASK_RETIRED ||
                 current_state == KER_FF_ADMISSION_TASK_REARMING)) {
                /* This is an established owner in a deliberate window gap.
                 * Do not reapply the initial HELLO/READY deadline. */
                owner->admission_ready = false;
                continue;
            }
            if (owner->admission_ready) continue;
        } else if (owner->admission_ready) {
            continue;
        }
        if (owner->admission_failed) {
            if (owner->admission_task) {
                uint64_t ignored_lease = 0;
                int state = ker_posix_ff_admission_task_poll(
                    owner->admission_task, &ignored_lease);
                if (state != KER_FF_ADMISSION_TASK_STARTING &&
                    state != KER_FF_ADMISSION_TASK_READY &&
                    state != KER_FF_ADMISSION_TASK_STOPPING) {
                    (void)owner_admission_task_release(owner);
                }
            }
            continue;
        }
        uint64_t now = host_monotonic_ns();
        if (!now || now >= owner->admission_deadline_ns) {
            owner_admission_endpoint_close(owner);
            owner->admission_failed = true;
            owner->admission_attached = false;
            continue;
        }
        if (owner->admission_listener_fd >= 0 && owner->admission_peer_fd < 0) {
            int fd = (int)syscall(SYS_accept4, owner->admission_listener_fd,
                NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd >= 0) {
                int pass_credentials = 1;
                if (owner_admission_peer_valid(owner, fd) ||
                    syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_PASSCRED,
                        &pass_credentials, sizeof(pass_credentials)))
                    (void)host_close(fd);
                else
                    owner->admission_peer_fd = fd;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                owner_admission_endpoint_close(owner);
                owner->admission_failed = true;
            }
        }
        if (owner->admission_peer_fd >= 0 && !owner->admission_attached) {
            int status = owner_admission_receive_hello(owner);
            if (status < 0) {
                owner_admission_endpoint_close(owner);
                owner->admission_failed = true;
                owner->admission_attached = false;
            }
        }
        if (owner->admission_attached && owner->admission_task) {
            uint64_t lease = 0;
            int task_status = ker_posix_ff_admission_task_poll(
                owner->admission_task, &lease);
            if (task_status == KER_FF_ADMISSION_TASK_READY && lease) {
                owner->admission_ready = true;
            } else if (task_status < 0) {
                owner_admission_endpoint_close(owner);
                owner->admission_failed = true;
                if (!owner_admission_task_release(owner))
                    owner->admission_listener_native_fd = -1;
            }
        }
    }
}

/* READY is written by the independent admission worker immediately after its
 * queue starts. A client can issue its first socket RPC before this broker
 * pump has copied the worker state into the cached flag, so refresh the task
 * state at the RPC boundary as well. */
static int owner_admission_ready_status(struct sb_owner *owner)
{
    if (!owner || !owner->admission_prepared) return 1;
    if (owner->admission_failed) return -ETIMEDOUT;
    if (!owner->admission_task) return 0;
    uint64_t lease = 0;
    int state = ker_posix_ff_admission_task_poll(owner->admission_task, &lease);
    if (state == KER_FF_ADMISSION_TASK_READY && lease) {
        owner->admission_initial_ready = true;
        owner->admission_ready = true;
        return 1;
    }
    if (state == KER_FF_ADMISSION_TASK_RETIRING ||
        state == KER_FF_ADMISSION_TASK_RETIRED ||
        state == KER_FF_ADMISSION_TASK_REARMING) {
        owner->admission_ready = false;
        return -EAGAIN;
    }
    if (state == KER_FF_ADMISSION_TASK_QUARANTINED) {
        owner->admission_failed = true;
        owner->admission_ready = false;
        return -EIO;
    }
    if (state == KER_FF_ADMISSION_TASK_TERMINAL ||
        (state < 0 && state != -EINPROGRESS)) {
        owner->admission_failed = true;
        return -ETIMEDOUT;
    }
    return 0;
}

static int owner_admission_window_action(struct ker_socket_broker_server *server,
    struct sb_client *client, int owner_cap, uint16_t operation,
    struct ker_sb_ff_owner_admission_window *response)
{
    struct sb_object *object = lookup_cap(server, owner_cap);
    struct sb_owner *owner = NULL;
    int status = owner_require_actor(server, client, object, &owner);
    if (status) return status;
    if (!(object->rights & KER_SOCKET_BROKER_CONTROL)) return -EACCES;
    if (!owner->admission_prepared || !owner->admission_attached ||
        !owner->admission_task || owner->admission_failed)
        return -ENOTCONN;
    if (operation == KER_SB_FF_OWNER_ADMISSION_RETIRE)
        status = ker_posix_ff_admission_task_window_action(
		    owner->admission_task, KER_FF_ADMISSION_WINDOW_RETIRE, -1);
    else if (operation == KER_SB_FF_OWNER_ADMISSION_REARM) {
        if (owner->admission_listener_native_fd < 0) return -ENOTCONN;
        status = ker_posix_ff_admission_task_window_action(
		    owner->admission_task, KER_FF_ADMISSION_WINDOW_REARM,
		    owner->admission_listener_native_fd);
    } else if (operation != KER_SB_FF_OWNER_ADMISSION_STATUS) {
        return -EOPNOTSUPP;
    }
    if (status) return status;
    uint32_t state = 0;
    uint64_t lease = 0, epoch = 0;
    int task_status = 0;
    status = ker_posix_ff_admission_task_poll_window(owner->admission_task,
        &state, &lease, &epoch, &task_status);
    if (status) return status;
    *response = (struct ker_sb_ff_owner_admission_window){
        .state = state, .reserved = 0, .queue_lease = lease, .epoch = epoch,
        .status = task_status, .reserved2 = 0};
    return 0;
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

static int owner_group_plan_create(struct ker_socket_broker_server *server,
    const struct ker_sb_ff_owner_group_plan *args, int *capability_out)
{
    if (!server || !args || !capability_out) return -EINVAL;
    struct sockaddr_in address = {0};
    memcpy(&address, args->address, sizeof(address));
    if (address.sin_family != AF_INET || !address.sin_port || args->backlog < 0 ||
        !(args->group_rights & KER_SOCKET_BROKER_CONTROL) ||
        (args->group_rights & ~KER_SOCKET_BROKER_ALL)) return -EINVAL;
    int authority = native_net_admin_present();
    if (authority < 0) return authority;
    uint16_t port = ntohs(address.sin_port);
    if (group_port_reserved(server, port)) return -EADDRINUSE;
    bool existing_binding = false;
    if (broker_has_binding(server, port, &existing_binding)) return -errno;
    if (existing_binding) return -EADDRINUSE;
    size_t slot = KER_SB_OBJECTS;
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        if (!server->groups[i].live) { slot = i; break; }
    if (slot == KER_SB_OBJECTS) return -EMFILE;
    if (server->next_group_incarnation == UINT64_MAX) return -EOVERFLOW;
    uint64_t incarnation = ++server->next_group_incarnation;
    server->groups[slot] = (struct sb_group){.live = true, .owner_aware = true,
        .port = port, .base_fd = {-1, -1}, .incarnation = incarnation,
        .claim_generation = {1, 1}, .address = address, .backlog = args->backlog,
        .group_rights = args->group_rights};
    int capability = group_handle(server, (int)slot, -1,
        KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN, KER_SOCKET_BROKER_CONTROL, 0);
    if (capability < 0) {
        int error = errno;
        server->groups[slot] = (struct sb_group){.base_fd = {-1, -1}};
        return -error;
    }
    *capability_out = capability;
    return 0;
}

static int owner_group_delegate_slot(struct ker_socket_broker_server *server,
    struct sb_object *plan, unsigned index, int *capability_out)
{
    if (!plan || plan->kind != KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN ||
        plan->group_slot < 0 || index > 1) return -ENOTSOCK;
    struct sb_group *group = &server->groups[plan->group_slot];
    if (!group->live || !group->owner_aware ||
        plan->group_incarnation != group->incarnation) return -ESTALE;
    if (group->failed) return -ECANCELED;
    if (group->materialized || group->slot_issued[index]) return -EALREADY;
    int capability = group_handle(server, plan->group_slot, -1,
        KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT, KER_SOCKET_BROKER_CONTROL, index);
    if (capability < 0) return -errno;
    /* group_handle creates the new object in the first available slot; locate
     * it by the returned capability before recording its immutable generation. */
    struct sb_object *delegated = lookup_cap(server, capability);
    if (!delegated) {
        (void)host_close(capability);
        return -EIO;
    }
    delegated->group_claim_generation = group->claim_generation[index];
    delegated->owner_token = group->member_owner_token[index];
    group->slot_issued[index] = true;
    *capability_out = capability;
    return 0;
}

static int owner_group_claim_slot(struct ker_socket_broker_server *server,
    struct sb_client *client, int owner_cap, int slot_cap)
{
    struct sb_object *owner_object = lookup_cap(server, owner_cap);
    struct sb_object *claim = lookup_cap(server, slot_cap);
    struct sb_owner *owner = NULL;
    int status = owner_require_actor(server, client, owner_object, &owner);
    if (status) return status;
    if (!(owner_object->rights & KER_SOCKET_BROKER_CONTROL) ||
        !claim || claim->kind != KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT ||
        !(claim->rights & KER_SOCKET_BROKER_CONTROL) || claim->group_slot < 0 ||
        claim->group_index > 1) return -EACCES;
    struct sb_group *group = &server->groups[claim->group_slot];
    unsigned index = claim->group_index;
    if (!group->live || !group->owner_aware ||
        claim->group_incarnation != group->incarnation ||
        claim->group_claim_generation != group->claim_generation[index]) return -ESTALE;
    if (group->member_owner_token[index]) return -EALREADY;
    if (group->failed || group->materialized) return -ECANCELED;
    if (owner->unowned_network_history || owner->owned_socket_history) return -EOPNOTSUPP;
    if (!owner->mark || !owner->token) return -ESTALE;
    if (owner->owner_group_claimed) return -EALREADY;
    unsigned other = index ^ 1u;
    if (group->member_owner_token[other] &&
        (group->member_owner_token[other] == owner->token ||
         (group->member_owner_pid[other] == owner->pid &&
          group->member_owner_start_time[other] == owner->start_time)))
        return -EEXIST;
    group->member_owner_token[index] = owner->token;
    group->member_owner_pid[index] = owner->pid;
    group->member_owner_start_time[index] = owner->start_time;
    group->member_mark[index] = owner->mark;
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i) {
        struct sb_object *candidate = &server->objects[i];
        if (candidate->live &&
            candidate->kind == KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT &&
            candidate->group_slot == claim->group_slot &&
            candidate->group_incarnation == group->incarnation &&
            candidate->group_index == index &&
            candidate->group_claim_generation == group->claim_generation[index])
            candidate->owner_token = owner->token;
    }
    owner->owner_group_claimed = true;
    owner->owner_group_incarnation = group->incarnation;
    owner->owner_group_claim_generation = group->claim_generation[index];
    owner->owner_group_index = index;
    return 0;
}

static int owner_group_materialize(struct ker_socket_broker_server *server,
    struct sb_object *plan, int *group_capability)
{
    if (!plan || plan->kind != KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN ||
        plan->group_slot < 0 || !(plan->rights & KER_SOCKET_BROKER_CONTROL))
        return -ENOTSOCK;
    struct sb_group *group = &server->groups[plan->group_slot];
    if (!group->live || !group->owner_aware ||
        group->incarnation != plan->group_incarnation) return -ESTALE;
    if (group->failed) return -ECANCELED;
    if (group->materialized) return -EALREADY;
    if (!group->member_owner_token[0] || !group->member_owner_token[1]) return -EAGAIN;
    struct sb_owner *owners[2] = {
        owner_by_token(server, group->member_owner_token[0]),
        owner_by_token(server, group->member_owner_token[1])};
    for (unsigned i = 0; i < 2; ++i) {
        if (!owners[i] || owners[i]->pid != group->member_owner_pid[i] ||
            owners[i]->start_time != group->member_owner_start_time[i] ||
            owners[i]->mark != group->member_mark[i]) {
            group->failed = true;
            return -ESTALE;
        }
        int live = owner_identity_alive(owners[i]);
        if (live) {
            group->failed = true;
            return live;
        }
    }
    if (owners[0]->token == owners[1]->token || owners[0]->pid == owners[1]->pid)
        return -EEXIST;
    if ((owners[0]->admission_prepared && owners[1]->admission_prepared) ||
        owners[0]->admission_prepared) return -EOPNOTSUPP;
    if (owners[1]->admission_prepared) {
        int ready = owner_admission_ready_status(owners[1]);
        if (ready <= 0) return ready < 0 ? ready : -EAGAIN;
    }
    int authority = native_net_admin_present();
    if (authority < 0) return authority;
    /* Claim is the boundary between reservation and socket effects. Any
     * network history acquired afterwards invalidates the whole reservation. */
    for (unsigned i = 0; i < 2; ++i) {
        if (owners[i]->unowned_network_history || owners[i]->owned_socket_history)
            return -EOPNOTSUPP;
    }
    owners[0]->owned_socket_history = true;
    owners[1]->owned_socket_history = true;

    int listener[2] = {-1, -1};
    bool admission_registered = false;
    int status = 0;
    int one = 1;
    listener[0] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener[0] < 0) { status = -errno; goto fail; }
    if (setsockopt(listener[0], SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) ||
        set_member_mark(listener[0], group->member_mark[0]) ||
        bind(listener[0], (const struct sockaddr *)&group->address,
            sizeof(group->address)) ||
        listen(listener[0], group->backlog) || reuseport_filter(listener[0], 0)) {
        status = -errno; goto fail;
    }
    if (socket_cookie(listener[0], &group->member_cookie[0])) {
        status = -errno; goto fail;
    }
    listener[1] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener[1] < 0) { status = -errno; goto fail; }
    if (setsockopt(listener[1], SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) ||
        set_member_mark(listener[1], group->member_mark[1]) ||
        bind(listener[1], (const struct sockaddr *)&group->address,
            sizeof(group->address))) {
        status = -errno; goto fail;
    }
    if (owners[1]->admission_prepared) {
        status = ker_posix_ff_admission_task_set_listener(
            owners[1]->admission_task, listener[1]);
        if (status) goto fail;
        owners[1]->admission_listener_native_fd = listener[1];
        admission_registered = true;
    }
    if (listen(listener[1], group->backlog)) { status = -errno; goto fail; }
    if (socket_cookie(listener[1], &group->member_cookie[1])) {
        status = -errno; goto fail;
    }
    group->base_fd[0] = listener[0];
    group->base_fd[1] = listener[1];
    int capability = group_handle(server, plan->group_slot, -1,
        KER_SOCKET_BROKER_REUSEPORT_GROUP, group->group_rights, 0);
    if (capability < 0) {
        status = -errno;
        group->base_fd[0] = group->base_fd[1] = -1;
        goto fail;
    }
    group->materialized = true;
    *group_capability = capability;
    return 0;
fail:
    if (admission_registered) {
        (void)ker_posix_ff_admission_task_listener_closed(
            owners[1]->admission_task, listener[1]);
        owners[1]->admission_listener_native_fd = -1;
        owners[1]->admission_failed = true;
    }
    if (listener[1] >= 0) (void)close(listener[1]);
    if (listener[0] >= 0) (void)close(listener[0]);
    group->member_cookie[0] = group->member_cookie[1] = 0;
    group->failed = true;
    return status ? status : -EIO;
}

static int owner_group_member_create(struct ker_socket_broker_server *server,
    struct sb_client *client, int owner_cap, int claim_cap, int *member_cap)
{
    struct sb_object *owner_object = lookup_cap(server, owner_cap);
    struct sb_object *claim = lookup_cap(server, claim_cap);
    struct sb_owner *owner = NULL;
    int status = owner_require_actor(server, client, owner_object, &owner);
    if (status) return status;
    if (!(owner_object->rights & KER_SOCKET_BROKER_CONTROL) || !claim ||
        claim->kind != KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT ||
        !(claim->rights & KER_SOCKET_BROKER_CONTROL) || claim->group_slot < 0 ||
        claim->group_index > 1) return -EACCES;
    struct sb_group *group = &server->groups[claim->group_slot];
    unsigned index = claim->group_index;
    if (!group->live || !group->owner_aware || !group->materialized || group->failed ||
        claim->group_incarnation != group->incarnation ||
        claim->group_claim_generation != group->claim_generation[index] ||
        claim->owner_token != owner->token ||
        group->member_owner_token[index] != owner->token) return -ESTALE;
    status = owner_identity_alive(owner);
    if (status) return status;
    if (owner->unowned_network_history) return -EOPNOTSUPP;
    uint64_t cookie = 0;
    if (socket_cookie(group->base_fd[index], &cookie)) return -errno;
    if (cookie != group->member_cookie[index]) return -ESTALE;
    int mark = 0;
    socklen_t mark_length = sizeof(mark);
    if (getsockopt(group->base_fd[index], SOL_SOCKET, SO_MARK,
            &mark, &mark_length)) return -errno;
    if (mark_length != sizeof(mark) || (uint32_t)mark != owner->mark)
        return -ESTALE;
    int native_fd = fcntl(group->base_fd[index], F_DUPFD_CLOEXEC, 0);
    if (native_fd < 0) return -errno;
    int capability = group_handle(server, claim->group_slot, native_fd,
        KER_SOCKET_BROKER_SOCKET, KER_SOCKET_BROKER_ALL, index);
    if (capability < 0) {
        int error = errno;
        (void)close(native_fd);
        return -error;
    }
    struct sb_object *member = lookup_cap(server, capability);
    if (!member) {
        (void)host_close(capability);
        return -EIO;
    }
    member->owner_token = owner->token;
    member->group_claim_generation = group->claim_generation[index];
    *member_cap = capability;
    return 0;
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
    struct sb_client *client, const struct ker_sb_header *request,
    const unsigned char *input, size_t input_length,
    int *fds, size_t fd_count, unsigned char *output, size_t *output_length,
    int *passed_fd, int64_t *result)
{
    *output_length = 0; *passed_fd = -1; *result = -EINVAL;
    size_t expected_rights = request->operation == KER_SB_SOCKET ||
        request->operation == KER_SB_EPOLL_CREATE1 ||
        request->operation == KER_SB_REUSEPORT_GROUP_CREATE ||
        request->operation == KER_SB_FF_OWNER_CREATE ||
        request->operation == KER_SB_FF_OWNER_GROUP_PLAN ? 0 :
        request->operation == KER_SB_EPOLL_CTL ||
        request->operation == KER_SB_FF_OWNER_MATCH ||
        request->operation == KER_SB_FF_OWNER_GROUP_CLAIM ||
        request->operation == KER_SB_FF_OWNER_GROUP_MEMBER ? 2 : 1;
    if (fd_count != expected_rights) return -EPROTO;
    if (expected_rights && request->operation != KER_SB_EPOLL_CTL &&
        request->operation != KER_SB_FF_OWNER_SOCKET &&
        request->operation != KER_SB_FF_OWNER_MATCH &&
        request->operation != KER_SB_FF_OWNER_PAYLOAD &&
        request->operation != KER_SB_FF_OWNER_ADMISSION_RETIRE &&
        request->operation != KER_SB_FF_OWNER_ADMISSION_REARM &&
        request->operation != KER_SB_FF_OWNER_ADMISSION_STATUS &&
        request->operation != KER_SB_FF_OWNER_ADMISSION_PREPARE &&
        request->operation != KER_SB_FF_OWNER_GROUP_CLAIM &&
        request->operation != KER_SB_FF_OWNER_GROUP_MEMBER) {
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
        else if (request->operation == KER_SB_FF_OWNER_GROUP_SLOT ||
            request->operation == KER_SB_FF_OWNER_GROUP_PUBLISH)
            expected_kind = KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN;
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
    case KER_SB_FF_OWNER_CREATE: {
        if (input_length || fd_count) return -EPROTO;
        int capability = -1;
        status = create_ff_owner(server, client, &capability);
        if (status) return status;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_FF_OWNER_GROUP_PLAN: {
        if (input_length != sizeof(struct ker_sb_ff_owner_group_plan) || fd_count)
            return -EPROTO;
        struct ker_sb_ff_owner_group_plan args;
        memcpy(&args, input, sizeof(args));
        int capability = -1;
        status = owner_group_plan_create(server, &args, &capability);
        if (status) return status;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_FF_OWNER_GROUP_SLOT: {
        if (input_length != sizeof(struct ker_sb_ff_owner_group_slot) || fd_count != 1)
            return -EPROTO;
        struct ker_sb_ff_owner_group_slot args;
        memcpy(&args, input, sizeof(args));
        if (args.reserved || args.index > 1) return -EINVAL;
        struct sb_object *plan = lookup_cap(server, fds[0]);
        int capability = -1;
        status = owner_group_delegate_slot(server, plan, args.index, &capability);
        if (status) return status;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_FF_OWNER_GROUP_CLAIM:
        if (input_length || fd_count != 2) return -EPROTO;
        status = owner_group_claim_slot(server, client, fds[0], fds[1]);
        if (status) return status;
        *result = 0; return 0;
    case KER_SB_FF_OWNER_GROUP_PUBLISH: {
        if (input_length || fd_count != 1) return -EPROTO;
        struct sb_object *plan = lookup_cap(server, fds[0]);
        int capability = -1;
        status = owner_group_materialize(server, plan, &capability);
        if (status) return status;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_FF_OWNER_GROUP_MEMBER: {
        if (input_length || fd_count != 2) return -EPROTO;
        int capability = -1;
        status = owner_group_member_create(server, client, fds[0], fds[1],
            &capability);
        if (status) return status;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_FF_OWNER_ADMISSION_PREPARE: {
        if (input_length || fd_count != 1) return -EPROTO;
        struct ker_sb_ff_owner_admission_prepare response = {0};
        status = owner_admission_prepare(server, client, fds[0], &response);
        if (status) return status;
        memcpy(output, &response, sizeof(response));
        *output_length = sizeof(response); *result = 0; return 0;
    }
    case KER_SB_FF_OWNER_ADMISSION_RETIRE:
    case KER_SB_FF_OWNER_ADMISSION_REARM:
    case KER_SB_FF_OWNER_ADMISSION_STATUS: {
        if (input_length || fd_count != 1) return -EPROTO;
        struct ker_sb_ff_owner_admission_window response = {0};
        status = owner_admission_window_action(server, client, fds[0],
            request->operation, &response);
        if (status) return status;
        memcpy(output, &response, sizeof(response));
        *output_length = sizeof(response); *result = 0; return 0;
    }
    case KER_SB_FF_OWNER_SOCKET: {
        if (input_length != sizeof(struct ker_sb_socket_args) || fd_count != 1)
            return -EPROTO;
        struct sb_object *owner_object = lookup_cap(server, fds[0]);
        struct sb_owner *owner = NULL;
        status = owner_require_actor(server, client, owner_object, &owner);
        if (status) return status;
        if (!owner_object || (owner_object->rights & KER_SOCKET_BROKER_CONTROL) == 0)
            return -EACCES;
        if (owner->owner_group_claimed) {
            bool group_found = false;
            for (size_t i = 0; i < KER_SB_OBJECTS; ++i) {
                struct sb_group *group = &server->groups[i];
                if (group->live && group->owner_aware &&
                    group->incarnation == owner->owner_group_incarnation) {
                    group_found = true;
                    break;
                }
            }
            if (group_found) return -EBUSY;
            if (!group_found) return -ESTALE;
        }
        if (owner->admission_prepared) {
            int ready = owner_admission_ready_status(owner);
            if (ready <= 0) return ready < 0 ? ready : -EAGAIN;
        }
        /* Sticky history prevents close-then-attach from escaping this
         * one-listener admission profile. Set before any socket side effect. */
        owner->owned_socket_history = true;
        struct ker_sb_socket_args args;
        memcpy(&args, input, sizeof(args));
        int base_type = args.type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
        if ((args.domain != AF_INET && args.domain != AF_INET6) ||
            base_type != SOCK_STREAM || (args.protocol && args.protocol != IPPROTO_TCP) ||
            (args.type & ~(SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)))
            return -EOPNOTSUPP;
        int native_fd = socket(args.domain,
            args.type | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
        if (native_fd < 0) return -errno;
        if (set_member_mark(native_fd, owner->mark)) {
            int error = errno; (void)close(native_fd); return -error;
        }
        size_t slot = KER_SB_OBJECTS;
        int capability = make_capability(server, native_fd, KER_SOCKET_BROKER_SOCKET,
            KER_SOCKET_BROKER_ALL, &slot);
        if (capability < 0) {
            int error = errno; (void)close(native_fd); return -error;
        }
        server->objects[slot].owner_token = owner->token;
        *passed_fd = capability; *result = 1; return 0;
    }
    case KER_SB_FF_OWNER_MATCH: {
        if (input_length || fd_count != 2) return -EPROTO;
        struct sb_object *owner_object = lookup_cap(server, fds[0]);
        struct sb_object *socket_object = lookup_cap(server, fds[1]);
        struct sb_owner *owner = NULL;
        status = owner_require_actor(server, client, owner_object, &owner);
        if (status) return status;
        if (!socket_object || socket_object->kind != KER_SOCKET_BROKER_SOCKET ||
            socket_object->native_fd < 0) return -ENOTSOCK;
        if (!(owner_object->rights & KER_SOCKET_BROKER_READ) ||
            !(socket_object->rights & KER_SOCKET_BROKER_READ)) return -EACCES;
        if (socket_object->owner_token != owner->token) { *result = 0; return 0; }
        int mark = 0; socklen_t mark_length = sizeof(mark);
        if (getsockopt(socket_object->native_fd, SOL_SOCKET, SO_MARK,
                &mark, &mark_length)) return -errno;
        if (mark_length != sizeof(mark)) return -EPROTO;
        if ((uint32_t)mark != owner->mark) return -EPROTO;
        *result = 1; return 0;
    }
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
        if (group->owner_aware) return -EOPNOTSUPP;
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
        if (object->group_incarnation != group->incarnation) return -ESTALE;
        if (group->owner_aware) {
            if (!group->materialized || group->failed) return -EAGAIN;
            struct sb_owner *owner = owner_by_token(server,
                group->member_owner_token[args.index]);
            status = owner_identity_alive(owner);
            if (status) return status;
            if (args.index == 1 && owner->admission_prepared) {
                int ready = owner_admission_ready_status(owner);
                if (ready <= 0) return ready < 0 ? ready : -EAGAIN;
                if (owner->admission_listener_native_fd != group->base_fd[1])
                    return -ESTALE;
            }
        }
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
            object->kind != KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN &&
            object->kind != KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT &&
            object->kind != KER_SOCKET_BROKER_MEMBER_CENSUS &&
            object->kind != KER_SOCKET_BROKER_TCP_OBSERVER &&
            object->kind != KER_SOCKET_BROKER_FF_OWNER) {
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
        if (object->owner_token) {
            struct sb_owner *owner = owner_by_token(server, object->owner_token);
            if (owner && owner->admission_prepared) return -EOPNOTSUPP;
        }
        if (object->kind == KER_SOCKET_BROKER_REUSEPORT_GROUP) return -EOPNOTSUPP;
        if (object->kind == KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN ||
            object->kind == KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT) return -EOPNOTSUPP;
        if (object->kind == KER_SOCKET_BROKER_MEMBER_CENSUS) return -EOPNOTSUPP;

        if (object->kind == KER_SOCKET_BROKER_TCP_OBSERVER) return -EOPNOTSUPP;

        if (object->kind == KER_SOCKET_BROKER_MEMBER_CENSUS) return -EOPNOTSUPP;
        if (object->kind == KER_SOCKET_BROKER_FF_OWNER) return -EOPNOTSUPP;

        int native_fd = fcntl(object->native_fd, F_DUPFD_CLOEXEC, 0);
        if (native_fd < 0) return -errno;
        if (object->group_slot >= 0) {
            int capability = group_handle(server, object->group_slot, native_fd,
                KER_SOCKET_BROKER_SOCKET, object->rights, object->group_index);
            if (capability < 0) { int error = errno; (void)close(native_fd); return -error; }
            struct sb_object *duplicate = lookup_cap(server, capability);
            if (!duplicate) { (void)host_close(capability); return -EIO; }
            duplicate->owner_token = object->owner_token;
            duplicate->group_claim_generation = object->group_claim_generation;
            *passed_fd = capability;
            status = 0;
        } else {
            size_t duplicate_slot = KER_SB_OBJECTS;
            int capability = make_capability(server, native_fd, object->kind,
                object->rights, &duplicate_slot);
            if (capability < 0) {
                int error = errno; (void)close(native_fd); return -error;
            }
            server->objects[duplicate_slot].owner_token = object->owner_token;
            *passed_fd = capability;
            status = 0;
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
        status = mark_actor_unowned_network(server, client);
        if (status) return status;
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
        if (object->owner_token) {
            struct sb_owner *owner = owner_by_token(server, object->owner_token);
            if (!owner) return -ESTALE;
            int ready = owner_admission_ready_status(owner);
            if (ready <= 0) return ready < 0 ? ready : -EAGAIN;
        }
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
        bool admission_listener = false;
        struct sb_owner *listen_owner = object->owner_token ?
            owner_by_token(server, object->owner_token) : NULL;
        if (listen_owner && listen_owner->admission_prepared) {
            status = ker_posix_ff_admission_task_set_listener(
                listen_owner->admission_task, object->native_fd);
            if (status) return status;
            admission_listener = true;
        }
        int call_result = listen(object->native_fd, args.value);
        if (call_result < 0 && admission_listener) {
            (void)ker_posix_ff_admission_task_listener_closed(
                listen_owner->admission_task, object->native_fd);
            listen_owner->admission_listener_native_fd = -1;
            listen_owner->admission_failed = true;
        } else if (call_result == 0 && admission_listener) {
            listen_owner->admission_listener_native_fd = object->native_fd;
        }
        *result = call_result < 0 ? -errno : call_result; return 0;
    }
    case KER_SB_ACCEPT4: {
        if (input_length != sizeof(struct ker_sb_integer)) return -EPROTO;
        struct ker_sb_integer args; memcpy(&args, input, sizeof(args));
        if (args.value & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) return -EINVAL;
        struct ker_sb_address address = {0};
        socklen_t length = sizeof(address.bytes);
        struct sb_object *listener = lookup_cap(server, fds[0]);
        if (!listener) return -EBADF;
        if (listener->owner_token) {
            struct sb_owner *owner = owner_by_token(server, listener->owner_token);
            status = owner_require_client(owner, client);
            if (status) return status;
        }
        int native_fd = accept4(listener->native_fd,
            (struct sockaddr *)address.bytes, &length, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (native_fd < 0) return -errno;
        if (length > sizeof(address.bytes)) { (void)close(native_fd); return -EOVERFLOW; }
        address.length = length;
        memcpy(output, &address, sizeof(address));
        *output_length = sizeof(address);
        uint64_t inherited_owner_token = listener->owner_token;
        if (inherited_owner_token) {
            struct sb_owner *owner = owner_by_token(server, inherited_owner_token);
            int mark = 0; socklen_t mark_length = sizeof(mark);
            if (!owner || getsockopt(native_fd, SOL_SOCKET, SO_MARK, &mark,
                    &mark_length) || mark_length != sizeof(mark) ||
                (uint32_t)mark != owner->mark) {
                int error = errno ? errno : EPROTO;
                (void)close(native_fd); return -error;
            }
        }
        size_t accepted_slot = KER_SB_OBJECTS;
        int accepted_cap = make_capability(server, native_fd, KER_SOCKET_BROKER_SOCKET,
            KER_SOCKET_BROKER_ALL, &accepted_slot);
        if (accepted_cap < 0) { int error = errno; (void)close(native_fd); return -error; }
        server->objects[accepted_slot].owner_token = inherited_owner_token;
        *passed_fd = accepted_cap;
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
        /* The admission owner validates TCP_FASTOPEN while registering its
         * listener. Do not let a later socket-option RPC re-enable TFO after
         * that one-time check; keep generic, unowned broker sockets unchanged. */
        if (args.level == IPPROTO_TCP && args.option == TCP_FASTOPEN &&
            object->owner_token) {
            struct sb_owner *owner = owner_by_token(server, object->owner_token);
            if (owner && owner->admission_prepared) return -EOPNOTSUPP;
        }
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
        operation == KER_SB_REUSEPORT_GROUP_CREATE ||
        operation == KER_SB_FF_OWNER_CREATE ||
        operation == KER_SB_FF_OWNER_GROUP_PLAN) return 0;
    return operation == KER_SB_EPOLL_CTL || operation == KER_SB_FF_OWNER_MATCH ||
        operation == KER_SB_FF_OWNER_GROUP_CLAIM ||
        operation == KER_SB_FF_OWNER_GROUP_MEMBER ? 2 : 1;
}

static int start_member_census_job(struct ker_socket_broker_server *server,
    struct sb_client *client, const struct ker_sb_header *request, int census_cap,
    bool payload)
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
    int submitted = payload ? ker_member_payload_query_submit(identity.mark, &ticket) :
        ker_member_census_query_submit(&identity, &ticket);
    if (submitted) return submitted;
    *job = (struct sb_census_job){.live = true, .payload = payload,
        .client_slot = (int)(client - server->clients), .client_fd = client->fd,
        .request = *request, .ticket = ticket};
    client->census_job = (int)slot;
    return 0;
}

static int start_ff_owner_payload_job(struct ker_socket_broker_server *server,
    struct sb_client *client, const struct ker_sb_header *request, int owner_cap)
{
    struct sb_object *object = lookup_cap(server, owner_cap);
    struct sb_owner *owner = NULL;
    int status = owner_require_actor(server, client, object, &owner);
    if (status) return status;
    if (!(object->rights & KER_SOCKET_BROKER_READ)) return -EACCES;
    if (owner->unowned_network_history) return -EOPNOTSUPP;
    if (client->census_job >= 0) return -EBUSY;
    size_t slot = KER_SB_CENSUS_JOBS;
    for (size_t i = 0; i < KER_SB_CENSUS_JOBS; ++i)
        if (!server->census_jobs[i].live) { slot = i; break; }
    if (slot == KER_SB_CENSUS_JOBS) return -EAGAIN;
    uint64_t ticket = 0;
    status = ker_member_payload_query_submit(owner->mark, &ticket);
    if (status) return status;
    server->census_jobs[slot] = (struct sb_census_job){.live = true,
        .payload = true, .client_slot = (int)(client - server->clients),
        .client_fd = client->fd, .request = *request, .ticket = ticket,
        .owner_token = owner->token};
    client->census_job = (int)slot;
    return 0;
}

static int start_ff_owner_requests_job(struct ker_socket_broker_server *server,
    struct sb_client *client, const struct ker_sb_header *request, int owner_cap)
{
    struct sb_object *object = lookup_cap(server, owner_cap);
    struct sb_owner *owner = NULL;
    int status = owner_require_actor(server, client, object, &owner);
    if (status) return status;
    if (!(object->rights & KER_SOCKET_BROKER_READ)) return -EACCES;
    if (owner->unowned_network_history) return -EOPNOTSUPP;
    if (client->census_job >= 0) return -EBUSY;
    size_t slot = KER_SB_CENSUS_JOBS;
    for (size_t i = 0; i < KER_SB_CENSUS_JOBS; ++i)
        if (!server->census_jobs[i].live) { slot = i; break; }
    if (slot == KER_SB_CENSUS_JOBS) return -EAGAIN;
    uint64_t ticket = 0;
    status = ker_member_requests_query_submit(owner->mark, &ticket);
    if (status) return status;
    server->census_jobs[slot] = (struct sb_census_job){.live = true,
        .requests = true, .client_slot = (int)(client - server->clients),
        .client_fd = client->fd, .request = *request, .ticket = ticket,
        .owner_token = owner->token};
    client->census_job = (int)slot;
    return 0;
}

static void finish_member_census_jobs(struct ker_socket_broker_server *server)
{
    for (size_t i = 0; i < KER_SB_CENSUS_JOBS; ++i) {
        struct sb_census_job *job = &server->census_jobs[i];
        if (!job->live) continue;
        struct ker_socket_member_census_snapshot snapshot = {0};
        struct ker_socket_member_payload_snapshot payload_snapshot = {0};
        uint64_t request_count = 0;
        int query_status = 0;
        int ready = job->requests ?
            ker_member_requests_query_poll(job->ticket, &query_status, &request_count) :
            job->payload ?
                ker_member_payload_query_poll(job->ticket, &query_status, &payload_snapshot) :
                ker_member_census_query_poll(job->ticket, &query_status, &snapshot);
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
                const void *output = query_status ? NULL : job->requests ?
                    (const void *)&request_count : job->payload ?
                        (const void *)&payload_snapshot : (const void *)&snapshot;
                size_t output_length = query_status ? 0 : job->requests ?
                    sizeof(request_count) : job->payload ?
                        sizeof(payload_snapshot) : sizeof(snapshot);
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
    int tracking_status = track_actor_socket_caps(server, client, fds, fd_count);
    if (tracking_status) {
        for (size_t i = 0; i < fd_count; ++i) (void)host_close(fds[i]);
        send_reply(client, &request, tracking_status, NULL, 0, -1);
        return;
    }
    unsigned char output[KER_SOCKET_BROKER_IO_MAX] = {0};
    size_t output_length = 0;
    int passed_fd = -1;
    int64_t result = 0;
    int dispatch;
    bool deferred = false;
    if (request.operation == KER_SB_MEMBER_CENSUS_SNAPSHOT ||
        request.operation == KER_SB_MEMBER_PAYLOAD_SNAPSHOT ||
        request.operation == KER_SB_FF_OWNER_PAYLOAD ||
        request.operation == KER_SB_FF_OWNER_REQUESTS) {
        struct sb_object *object = fd_count == 1 ? lookup_cap(server, fds[0]) : NULL;
        uint32_t right = required_right(request.operation);
        if (input_length) dispatch = -EPROTO;
        else if (!object) dispatch = -EBADF;
        else if ((request.operation == KER_SB_FF_OWNER_PAYLOAD ||
                request.operation == KER_SB_FF_OWNER_REQUESTS) &&
            object->kind != KER_SOCKET_BROKER_FF_OWNER) dispatch = -ENOTSOCK;
        else if (request.operation != KER_SB_FF_OWNER_PAYLOAD &&
            request.operation != KER_SB_FF_OWNER_REQUESTS &&
            object->kind != KER_SOCKET_BROKER_MEMBER_CENSUS) dispatch = -ENOTSOCK;
        else if ((object->rights & right) != right) dispatch = -EACCES;
        else if (request.operation == KER_SB_FF_OWNER_PAYLOAD)
            dispatch = start_ff_owner_payload_job(server, client, &request, fds[0]);
        else if (request.operation == KER_SB_FF_OWNER_REQUESTS)
            dispatch = start_ff_owner_requests_job(server, client, &request, fds[0]);
        else dispatch = start_member_census_job(server, client, &request, fds[0],
            request.operation == KER_SB_MEMBER_PAYLOAD_SNAPSHOT);
        if (!dispatch) deferred = true;
    } else {
        dispatch = dispatch_request(server, client, &request, input, input_length, fds, fd_count,
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
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        struct sb_owner *owner = &server->owners[i];
        if (!owner->live) continue;
        struct pollfd pfd = {.fd = owner->pidfd, .events = POLLIN};
        int ready = (int)syscall(SYS_poll, &pfd, 1, 0);
        if (ready <= 0 || !(pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
            continue;
        bool referenced = false;
        for (size_t j = 0; owner->token && j < KER_SB_OBJECTS; ++j)
            if (server->objects[j].live &&
                server->objects[j].owner_token == owner->token) referenced = true;
        for (size_t j = 0; owner->token && j < KER_SB_CENSUS_JOBS; ++j)
            if (server->census_jobs[j].live && server->census_jobs[j].owner_token == owner->token)
                referenced = true;
        for (size_t j = 0; owner->token && j < KER_SB_OBJECTS; ++j) {
            struct sb_group *group = &server->groups[j];
            if (group->live && group->owner_aware &&
                (group->member_owner_token[0] == owner->token ||
                 group->member_owner_token[1] == owner->token)) referenced = true;
        }
        if (!referenced) {
            owner_admission_endpoint_close(owner);
            if (owner->admission_task) {
                uint64_t ignored_lease = 0;
                int state = ker_posix_ff_admission_task_poll(
                    owner->admission_task, &ignored_lease);
                if (state == KER_FF_ADMISSION_TASK_STARTING ||
                    state == KER_FF_ADMISSION_TASK_READY ||
                    state == KER_FF_ADMISSION_TASK_STOPPING) {
                    referenced = true;
                } else {
                    if (owner_admission_task_release(owner)) referenced = true;
                }
            }
        }
        if (!referenced) {
            (void)host_close(owner->pidfd);
            *owner = (struct sb_owner){.pidfd = -1,
                .admission_listener_fd = -1, .admission_peer_fd = -1,
                .admission_listener_native_fd = -1};
        }
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
    pump_owner_admission_endpoints(server);
    finish_member_census_jobs(server);
    bool should_stop = server->failure || (server->stop_when_empty &&
        !object_count(server) && !client_count(server));
    if (should_stop && admission_tasks_stopping(server)) {
        struct timespec task_pause = {.tv_nsec = 1000000};
        (void)syscall(SYS_nanosleep, &task_pause, NULL);
        return 0;
    }
    if (should_stop) {
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
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        server->clients[i] = (struct sb_client){.fd = -1, .pidfd = -1, .census_job = -1};
        server->owners[i].pidfd = -1;
        server->owners[i].admission_listener_fd = -1;
        server->owners[i].admission_peer_fd = -1;
        server->owners[i].admission_listener_native_fd = -1;
    }
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
    for (size_t i = 0; i < KER_SB_CLIENTS; ++i) {
        owner_admission_endpoint_close(&server->owners[i]);
        if (server->owners[i].admission_task) {
            int status = ker_posix_ff_admission_task_release(
                server->owners[i].admission_task);
            if (status) abort();
            server->owners[i].admission_task = NULL;
        }
        (void)host_close(server->owners[i].pidfd);
    }
    (void)host_close(server->listener);
    if (server->path_bound) {
        struct stat identity;
        if (!lstat(server->path, &identity) && identity.st_dev == server->path_dev &&
            identity.st_ino == server->path_ino) (void)syscall(SYS_unlinkat, AT_FDCWD, server->path, 0);
    }
    release_runtime_lease(server);
    free(server);
}
