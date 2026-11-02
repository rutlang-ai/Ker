#ifndef KER_RUNTIME_SERVICE_CLIENT_H
#define KER_RUNTIME_SERVICE_CLIENT_H

#include <stdint.h>
#include "runtime-service-wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KER_RUNTIME_SERVICE_PATH_MAX 107

/* Private client for the supervisor-owned runtime service. Calls on one
 * context must be serialized by its owner. The descriptor is deliberately
 * never closed after fork: its integer may already have been reused by the
 * caller's close-all phase. Reconnect creates a new channel and revalidates
 * the same lease with CHECK. */
struct ker_runtime_service_client {
    char path[KER_RUNTIME_SERVICE_PATH_MAX + 1];
    int fd;
    int initialized;
    int lease_valid;
    int cleanup_only;
    int failed;
    int fd_identity_valid;
    uint64_t fd_device;
    uint64_t fd_inode;
    uint64_t fd_cookie;
    uint64_t owner_start_time;
    uint64_t sequence;
    uint64_t service_epoch;
    int32_t owner_pid;
    int32_t supervisor_pid;
    uint32_t supervisor_uid;
    uint32_t supervisor_gid;
    uint64_t supervisor_start_time;
    uint8_t supervisor_exe_sha256[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t run_nonce[KER_RUNTIME_SERVICE_NONCE_BYTES];
    uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES];
    uint8_t role_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t expected_worker_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t worker_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t lease_id[KER_RUNTIME_SERVICE_LEASE_BYTES];
};

/* Initialize a fresh context before its first claim. */
void ker_runtime_service_client_init(struct ker_runtime_service_client *client);
int ker_runtime_service_claim(struct ker_runtime_service_client *client,
    const char *path, const uint8_t run_nonce[KER_RUNTIME_SERVICE_NONCE_BYTES],
    uint64_t service_epoch,
    const uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES],
    const uint8_t role_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES],
    const uint8_t expected_worker_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES],
    int32_t supervisor_pid, uint64_t supervisor_start_time,
    const uint8_t supervisor_exe_sha256[KER_RUNTIME_SERVICE_PROFILE_BYTES]);
int ker_runtime_service_check(struct ker_runtime_service_client *client);
int ker_runtime_service_release(struct ker_runtime_service_client *client);
int ker_runtime_service_reconnect(struct ker_runtime_service_client *client);
/* Close only if the descriptor still names the socket created by this
 * context. Safe after descriptor-table teardown and numeric FD reuse. Closing
 * the channel does not release the supervisor-owned lease; reconnect/check or
 * release it explicitly from the same process. */
void ker_runtime_service_client_close(struct ker_runtime_service_client *client);

#ifdef __cplusplus
}
#endif

#endif
