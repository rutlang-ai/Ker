#ifndef KER_SOCKET_BROKER_SERVER_H
#define KER_SOCKET_BROKER_SERVER_H
#include <ker/socket-broker.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ker_socket_broker_server;

/* Creates a same-UID host AF_UNIX SOCK_SEQPACKET listener. No native Linux
 * socket is created by this call. One ker-posix runtime permits one live
 * broker server; a concurrent create fails with errno=EBUSY. The caller
 * should place the path in a directory inaccessible to untrusted users. */
struct ker_socket_broker_server *ker_socket_broker_server_create(const char *path);
/* Adopt a descriptor returned by this process's ker-posix socket/epoll APIs.
 * On success ownership of native_fd transfers to the server; the caller must
 * stop using it. The server closes it when the last issued capability
 * disappears. Adopt only before server_run() and serialize adoption calls;
 * callers must quiesce concurrent use during transfer.
 * Host descriptors, descriptor-table kinds other than the
 * requested socket/epoll kind, and non-INET/non-stream/non-datagram sockets
 * are rejected. Sockets with enabled nonzero SO_LINGER are rejected because
 * their final close could block the broker loop. The trusted caller must not
 * mutate the shared open-file description through an outside alias while it
 * is adopted. rights is a server-enforced mask.
 * The returned descriptor is an opaque host pipe write-end reference. */
int ker_socket_broker_server_adopt(struct ker_socket_broker_server *server,
    int native_fd, enum ker_socket_broker_kind kind, uint32_t rights);
/* Pre-run factory for a broker-owned, fixed two-listener IPv4 TCP reuseport
 * group. The returned capability has exactly rights; the RPC constructor
 * issues CONTROL. address must contain a nonzero IPv4 port. */
int ker_socket_broker_server_reuseport_group_create(struct ker_socket_broker_server *server,
    const struct sockaddr_in *address, int backlog, uint32_t rights);
/* Runs ker_posix_run on the current broker thread. With stop_when_empty, adopt
 * at least one object before starting the loop. The callback stops and
 * finalizes original Linux when stop_when_empty is true and all capabilities
 * and request sessions have closed. */
int ker_socket_broker_server_run(struct ker_socket_broker_server *server,
    int stop_when_empty);
/* Opt-in private-supervisor readiness profile. Attach one pre-created
 * AF_UNIX SOCK_SEQPACKET control endpoint before run; control_fd is borrowed
 * and duplicated, and the peer must be this process's supervisor. The adapter
 * pins that parent identity and emits one
 * authenticated-by-kernel READY record from the first broker pump only after
 * bootstrap_complete_empty succeeds. For this profile the initial capability
 * set must be empty. server_run(server, 0) then remains available for RPC
 * until an authenticated one-shot STOP arrives. STOP_ACK confirms acceptance
 * only; normal run return and checked destroy are still required for cleanup.
 * These functions do not enable Nginx graceful reload or grant packet I/O. */
int ker_socket_broker_server_readiness_attach(
    struct ker_socket_broker_server *server, int control_fd,
    const uint8_t run_nonce[16], uint64_t worker_epoch,
    const uint8_t expected_worker_profile_sha256[32],
    uint64_t expected_supervisor_start_ticks);
int ker_socket_broker_server_bootstrap_complete_empty(
    struct ker_socket_broker_server *server);
#ifdef KER_SOCKET_BROKER_READINESS_TESTING
int ker_socket_broker_server_readiness_test_parent_error(
    const struct ker_socket_broker_server *server);
#endif
#ifdef KER_SOCKET_BROKER_RX_OWNER_RELAY_TESTING
typedef int (*ker_socket_broker_test_run_hook)(void *context);
int ker_socket_broker_server_run_with_test_hooks(
    struct ker_socket_broker_server *server, int stop_when_empty,
    ker_socket_broker_test_run_hook prepare,
    ker_socket_broker_test_run_hook pump, void *context);
#endif
void ker_socket_broker_server_destroy(struct ker_socket_broker_server *server);
/* Error-reporting teardown variant. If a fail-closed ingress quarantine
 * cannot be confirmed, returns -1/errno and retains the server and its pinned
 * descriptors so the caller may retry teardown; no healthy release is
 * implied. */
int ker_socket_broker_server_destroy_checked(
    struct ker_socket_broker_server *server);

#ifdef __cplusplus
}
#endif
#endif
