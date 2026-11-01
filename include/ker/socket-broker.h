#ifndef KER_SOCKET_BROKER_H
#define KER_SOCKET_BROKER_H

/* Explicit capability API for moving original-Linux sockets between processes.
 * This is separate from libc and from ker-posix: client programs link only
 * ker-socket-client and receive opaque host pipe write-end capabilities. */
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KER_SOCKET_BROKER_PATH_MAX 107
#define KER_SOCKET_BROKER_IO_MAX 4096
#define KER_SOCKET_BROKER_EVENTS_MAX 64

enum ker_socket_broker_kind {
    KER_SOCKET_BROKER_SOCKET = 1,
    KER_SOCKET_BROKER_EPOLL = 2,
    KER_SOCKET_BROKER_REUSEPORT_GROUP = 3,
    KER_SOCKET_BROKER_TCP_OBSERVER = 4,
    KER_SOCKET_BROKER_MEMBER_CENSUS = 5,
    KER_SOCKET_BROKER_FF_OWNER = 6,
    KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN = 7,
    KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT = 8
};

enum ker_socket_broker_rights {
    KER_SOCKET_BROKER_READ = 1u << 0,
    KER_SOCKET_BROKER_WRITE = 1u << 1,
    KER_SOCKET_BROKER_CONTROL = 1u << 2,
    KER_SOCKET_BROKER_NAME = 1u << 3,
    KER_SOCKET_BROKER_OPTION = 1u << 4,
    KER_SOCKET_BROKER_WAIT = 1u << 5,
    KER_SOCKET_BROKER_ALL = (1u << 6) - 1
};

#define KER_SOCKET_BROKER_TCP_STATES 14

/* state_counts uses the original Linux TCP state numbers as array indices;
 * index zero is reserved and remains zero in a successful snapshot. */
enum ker_socket_tcp_state {
    KER_SOCKET_TCP_STATE_ESTABLISHED = 1,
    KER_SOCKET_TCP_STATE_SYN_SENT = 2,
    KER_SOCKET_TCP_STATE_SYN_RECV = 3,
    KER_SOCKET_TCP_STATE_FIN_WAIT1 = 4,
    KER_SOCKET_TCP_STATE_FIN_WAIT2 = 5,
    KER_SOCKET_TCP_STATE_TIME_WAIT = 6,
    KER_SOCKET_TCP_STATE_CLOSE = 7,
    KER_SOCKET_TCP_STATE_CLOSE_WAIT = 8,
    KER_SOCKET_TCP_STATE_LAST_ACK = 9,
    KER_SOCKET_TCP_STATE_LISTEN = 10,
    KER_SOCKET_TCP_STATE_CLOSING = 11,
    KER_SOCKET_TCP_STATE_NEW_SYN_RECV = 12,
    KER_SOCKET_TCP_STATE_BOUND_INACTIVE = 13
};

struct ker_socket_tcp_observer_snapshot {
    uint64_t cookie;
    uint32_t receive_queue;
    uint32_t send_queue;
    uint8_t state;
    uint8_t present;
};

/* Raw original-Linux TCP state counts for one fixed reuseport member mark.
 * This is a read-only observation over a sample interval, not an atomic
 * snapshot. It deliberately contains no queue or application-level counters. */
struct ker_socket_member_census_snapshot {
    uint64_t total;
    uint64_t state_counts[KER_SOCKET_BROKER_TCP_STATES];
    uint64_t listener_cookie;
};

/* Original-Linux queued TCP payload sampled across one authenticated member
 * mark. This is sequential socket observation, not a quiescence guarantee. */
struct ker_socket_member_payload_snapshot {
    uint64_t payload_bytes;
    uint64_t sampled_sockets;
};

struct ker_socket_client {
    char path[KER_SOCKET_BROKER_PATH_MAX + 1];
    int session_fd;
    pid_t owner_pid;
    uint64_t sequence;
};

/* A client context owns one authenticated request channel. Calls through one
 * context must be serialized by its caller; distinct contexts may be used by
 * independent threads/processes. If used after fork(), the first operation
 * discards the inherited channel and reconnects as the new process.
 * Capability descriptors are ordinary host pipe write-end FDs: dup, close,
 * SCM_RIGHTS, and exec inheritance use normal Linux semantics. */
int ker_socket_client_open(struct ker_socket_client *client, const char *path);
void ker_socket_client_close(struct ker_socket_client *client);

/* All created network sockets are nonblocking in the broker. cap_fd values
 * are opaque host pipe write-end capabilities, not POSIX network descriptors.
 * Only dup/close, SCM_RIGHTS transfer and descriptor inheritance are
 * supported on a capability fd. Do not pass one to poll/select/epoll for
 * readiness: its poll state reports only capability lifetime. shutdown
 * returns ENOTSOCK. Accidental writes are drained and ignored; do not use the
 * pipe as data transport. A host dup(cap_fd) is another reference to the same
 * broker descriptor. ker_socket_client_dup() asks original Linux for a
 * distinct descriptor sharing the open file description and its separate
 * epoll-registration key. Calls return
 * 0/nonnegative result or -1 with errno set. EAGAIN is returned from
 * original Linux without blocking the broker loop. A transport failure after
 * sending a request can leave operation completion unknown; the client never
 * replays a request automatically, so callers must resolve/reconcile that
 * state before retrying a mutating operation. */
int ker_socket_client_socket(struct ker_socket_client *client, int domain,
    int type, int protocol);
int ker_socket_client_bind(struct ker_socket_client *client, int cap_fd,
    const struct sockaddr *address, socklen_t length);
int ker_socket_client_connect(struct ker_socket_client *client, int cap_fd,
    const struct sockaddr *address, socklen_t length);
int ker_socket_client_listen(struct ker_socket_client *client, int cap_fd, int backlog);
int ker_socket_client_accept4(struct ker_socket_client *client, int cap_fd,
    struct sockaddr *address, socklen_t *length, int flags);
ssize_t ker_socket_client_read(struct ker_socket_client *client, int cap_fd,
    void *buffer, size_t length);
ssize_t ker_socket_client_write(struct ker_socket_client *client, int cap_fd,
    const void *buffer, size_t length);
int ker_socket_client_shutdown(struct ker_socket_client *client, int cap_fd, int how);
int ker_socket_client_getsockname(struct ker_socket_client *client, int cap_fd,
    struct sockaddr *address, socklen_t *length);
int ker_socket_client_getpeername(struct ker_socket_client *client, int cap_fd,
    struct sockaddr *address, socklen_t *length);
/* Socket options are restricted to flat, explicitly supported values:
 * SOL_SOCKET REUSEADDR, REUSEPORT, KEEPALIVE, RCVBUF, SNDBUF, RCVLOWAT,
 * SNDLOWAT, LINGER, RCVTIMEO and SNDTIMEO for set/get; TYPE, ERROR, DOMAIN,
 * PROTOCOL, ACCEPTCONN and SO_COOKIE for get only (SO_COOKIE requires an exact
 * uint64_t value); SO_LINGER accepts only disabled linger
 * or enabled linger with zero duration; TCP NODELAY, CORK, DEFER_ACCEPT,
 * KEEPIDLE, KEEPINTVL, KEEPCNT and FASTOPEN; and IPv6 V6ONLY. Unknown and
 * pointer- or descriptor-bearing options return EOPNOTSUPP before reaching
 * original Linux. Allowed flat options retain original Linux validation. */
int ker_socket_client_setsockopt(struct ker_socket_client *client, int cap_fd,
    int level, int option, const void *value, socklen_t length);
int ker_socket_client_getsockopt(struct ker_socket_client *client, int cap_fd,
    int level, int option, void *value, socklen_t *length);

/* A TCP observer is a read-only metadata capability for one connected IPv4
 * TCP socket. It retains neither the socket descriptor nor its open-file
 * description. Snapshot fields come from original Linux INET_DIAG. */
int ker_socket_client_tcp_observer_create(struct ker_socket_client *client,
    int socket_cap);
int ker_socket_client_tcp_observer_snapshot(struct ker_socket_client *client,
    int observer_cap, struct ker_socket_tcp_observer_snapshot *snapshot);

int ker_socket_client_epoll_create1(struct ker_socket_client *client, int flags);
int ker_socket_client_epoll_ctl(struct ker_socket_client *client, int epoll_cap,
    int operation, int socket_cap, const struct epoll_event *event);
/* Wait is deliberately nonblocking: timeout is always zero, and original
 * Linux supplies all readiness and event data. */
int ker_socket_client_epoll_wait(struct ker_socket_client *client, int epoll_cap,
    struct epoll_event *events, int maxevents);

/* Descriptor inspection and duplication preserve original-Linux descriptor
 * and open-file-description semantics. DESCRIBE also reports a typed
 * REUSEPORT_GROUP capability with zero status flags. DUP returns a new
 * capability backed by a distinct original descriptor for socket and epoll
 * objects; group-capability DUP returns EOPNOTSUPP. The returned host
 * capability has FD_CLOEXEC cleared, like POSIX dup(); the broker's private
 * native duplicate remains close-on-exec. */
int ker_socket_client_describe(struct ker_socket_client *client, int cap_fd,
    enum ker_socket_broker_kind *kind, int *status_flags);
int ker_socket_client_dup(struct ker_socket_client *client, int cap_fd);
int ker_socket_client_getfl(struct ker_socket_client *client, int cap_fd);
int ker_socket_client_setfl(struct ker_socket_client *client, int cap_fd, int flags);
/* ioctl is intentionally limited to FIONBIO (enable only) and FIONREAD;
 * other requests return EOPNOTSUPP without forwarding caller pointers. */
int ker_socket_client_ioctl(struct ker_socket_client *client, int cap_fd,
    unsigned long request, void *argument);
int ker_socket_client_fionbio(struct ker_socket_client *client, int cap_fd, int enabled);
int ker_socket_client_fionread(struct ker_socket_client *client, int cap_fd, int *available);
/* SEND accepts MSG_DONTWAIT, MSG_MORE, MSG_NOSIGNAL; the broker always adds
 * MSG_NOSIGNAL. RECV accepts MSG_PEEK and MSG_DONTWAIT. */
ssize_t ker_socket_client_send(struct ker_socket_client *client, int cap_fd,
    const void *buffer, size_t length, int flags);
ssize_t ker_socket_client_recv(struct ker_socket_client *client, int cap_fd,
    void *buffer, size_t length, int flags);

/* A broker-created two-member IPv4 TCP SO_REUSEPORT group. The broker owns
 * both original-Linux listener descriptors; a GROUP capability controls the
 * selected member, while MEMBER capabilities refer to individual listeners.
 * Group/member caps are opaque pipe capabilities. Host dup/SCM_RIGHTS creates
 * another reference; SDK dup is intentionally unsupported for GROUP caps.
 * Accepted sockets are ordinary independent socket capabilities. */
int ker_socket_client_reuseport_group_create(struct ker_socket_client *client,
    const struct sockaddr_in *address, int backlog);
int ker_socket_client_reuseport_group_member(struct ker_socket_client *client,
    int group_cap, unsigned index);
int ker_socket_client_reuseport_group_select(struct ker_socket_client *client,
    int group_cap, unsigned index);

/* Deferred owner-aware fixed two-member IPv4 reuseport group. The plan
 * reserves a tuple but creates no listener until both distinct FF owner
 * actors claim their one delegated index. Each slot can be issued once and
 * each claim succeeds once. A successful claim is a reusable, index-scoped
 * receipt for that actor's member only; it does not grant group selection or
 * delegation authority. Publish is also one-shot. */
int ker_socket_client_owner_group_plan(struct ker_socket_client *client,
    const struct sockaddr_in *address, int backlog, uint32_t group_rights);
int ker_socket_client_owner_group_slot(struct ker_socket_client *client,
    int plan_cap, unsigned index);
int ker_socket_client_ff_owner_group_claim(struct ker_socket_client *client,
    int owner_cap, int slot_cap);
int ker_socket_client_owner_group_publish(struct ker_socket_client *client,
    int plan_cap);
int ker_socket_client_owner_group_member(struct ker_socket_client *client,
    int owner_cap, int claimed_slot_cap);

/* A census capability copies immutable group-member metadata, but retains no
 * group or TCP descriptor. Creation and reads require CONTROL and READ rights
 * respectively. The broker requires preexisting NET_ADMIN authority for its
 * private fixed INET_DIAG query; it never elevates credentials. */
int ker_socket_client_member_census_create(struct ker_socket_client *client,
    int group_cap, unsigned index);
int ker_socket_client_member_census_snapshot(struct ker_socket_client *client,
    int census_cap, struct ker_socket_member_census_snapshot *snapshot);
int ker_socket_client_member_payload_snapshot(struct ker_socket_client *client,
    int census_cap, struct ker_socket_member_payload_snapshot *snapshot);

/* Narrow F-Stack runtime owner context. The broker binds this opaque
 * capability to the authenticated process; callers cannot select a mark or
 * process identity. These calls are intended for the FF runtime adapter. */
int ker_socket_client_ff_owner_create(struct ker_socket_client *client);
int ker_socket_client_ff_owner_socket(struct ker_socket_client *client,
    int owner_cap, int domain, int type, int protocol);
int ker_socket_client_ff_owner_match(struct ker_socket_client *client,
    int owner_cap, int socket_cap);
int ker_socket_client_ff_owner_payload_snapshot(struct ker_socket_client *client,
    int owner_cap, struct ker_socket_member_payload_snapshot *snapshot);
int ker_socket_client_ff_owner_requests(struct ker_socket_client *client,
    int owner_cap, uint64_t *request_count);

#ifdef __cplusplus
}
#endif
#endif
