#ifndef KER_SOCKET_BROKER_SERVER_H
#define KER_SOCKET_BROKER_SERVER_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ker_socket_broker_server;
enum ker_socket_broker_kind { KER_SOCKET_BROKER_SOCKET = 1, KER_SOCKET_BROKER_EPOLL = 2 };
enum ker_socket_broker_rights {
    KER_SOCKET_BROKER_READ = 1u << 0,
    KER_SOCKET_BROKER_WRITE = 1u << 1,
    KER_SOCKET_BROKER_CONTROL = 1u << 2,
    KER_SOCKET_BROKER_NAME = 1u << 3,
    KER_SOCKET_BROKER_OPTION = 1u << 4,
    KER_SOCKET_BROKER_WAIT = 1u << 5,
    KER_SOCKET_BROKER_ALL = (1u << 6) - 1
};

/* Creates a same-UID host AF_UNIX SOCK_SEQPACKET listener. No native Linux
 * socket is created by this call. The caller should place the path in a
 * directory inaccessible to untrusted users. */
struct ker_socket_broker_server *ker_socket_broker_server_create(const char *path);
/* Adopt a descriptor returned by this process's ker-posix socket/epoll APIs.
 * On success ownership of native_fd transfers to the server; the caller must
 * stop using it. The server closes it when the last issued capability
 * disappears. Adopt only before server_run() and serialize adoption calls;
 * callers must quiesce concurrent use during transfer.
 * Host descriptors, descriptor-table kinds other than the
 * requested socket/epoll kind, and non-INET/non-stream/non-datagram sockets
 * are rejected. rights is a server-enforced mask.
 * The returned descriptor is an opaque host pipe write-end reference. */
int ker_socket_broker_server_adopt(struct ker_socket_broker_server *server,
    int native_fd, enum ker_socket_broker_kind kind, uint32_t rights);
/* Runs ker_posix_run on the current broker thread. With stop_when_empty, adopt
 * at least one object before starting the loop. The callback stops and
 * finalizes original Linux when stop_when_empty is true and all capabilities
 * and request sessions have closed. */
int ker_socket_broker_server_run(struct ker_socket_broker_server *server,
    int stop_when_empty);
void ker_socket_broker_server_destroy(struct ker_socket_broker_server *server);

#ifdef __cplusplus
}
#endif
#endif
