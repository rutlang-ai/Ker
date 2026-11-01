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
    KER_SOCKET_BROKER_REUSEPORT_GROUP = 3
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
 * PROTOCOL and ACCEPTCONN for get only; SO_LINGER accepts only disabled linger
 * or enabled linger with zero duration; TCP NODELAY, CORK, DEFER_ACCEPT,
 * KEEPIDLE, KEEPINTVL, KEEPCNT and FASTOPEN; and IPv6 V6ONLY. Unknown and
 * pointer- or descriptor-bearing options return EOPNOTSUPP before reaching
 * original Linux. Allowed flat options retain original Linux validation. */
int ker_socket_client_setsockopt(struct ker_socket_client *client, int cap_fd,
    int level, int option, const void *value, socklen_t length);
int ker_socket_client_getsockopt(struct ker_socket_client *client, int cap_fd,
    int level, int option, void *value, socklen_t *length);

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

#ifdef __cplusplus
}
#endif
#endif
