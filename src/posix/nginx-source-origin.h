#ifndef KER_NGINX_SOURCE_ORIGIN_H
#define KER_NGINX_SOURCE_ORIGIN_H

#include <stdint.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include "source-native-ini.h"

/* Origin correlation only. This protocol grants no generation, descriptor
 * slot, packet ownership, readiness, or source reload operation. */
#define KER_NGINX_SOURCE_ORIGIN_MAGIC UINT32_C(0x4b534f41)
#define KER_NGINX_SOURCE_ORIGIN_VERSION UINT16_C(2)
#define KER_NGINX_SOURCE_ORIGIN_PROOF_VERSION UINT32_C(1)
#define KER_NGINX_SOURCE_ORIGIN_REQUEST UINT16_C(1)
#define KER_NGINX_SOURCE_ORIGIN_ACK UINT16_C(2)
#define KER_NGINX_SOURCE_ORIGIN_MAX_STARTUP_NS UINT64_C(5000000000)

struct ker_nginx_source_origin_record {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t record_bytes;
    uint32_t flags;
    uint32_t origin_pid;
    uint32_t child_pid;
    uint32_t child_tid;
    uint32_t supervisor_pid;
    uint64_t origin_start_ticks;
    uint64_t child_start_ticks;
    uint64_t supervisor_start_ticks;
    uint64_t launch_epoch;
    uint64_t grant_deadline_ns;
    uint64_t startup_deadline_ns;
    uint64_t operation_id;
    uint8_t run_nonce[16];
    uint64_t pid_namespace_device;
    uint64_t pid_namespace_inode;
    uint32_t proof_version;
    uint32_t proof_flags;
    uint64_t adapter_cycle_serial;
    uint64_t opaque_cycle_token;
    uint8_t config_sha256[32];
    uint8_t ini_sha256[32];
};

_Static_assert(offsetof(struct ker_nginx_source_origin_record, proof_version) == 120,
    "source origin v2 must preserve the exact v1 prefix");
_Static_assert(offsetof(struct ker_nginx_source_origin_record, proof_flags) == 124 &&
    offsetof(struct ker_nginx_source_origin_record, adapter_cycle_serial) == 128 &&
    offsetof(struct ker_nginx_source_origin_record, opaque_cycle_token) == 136 &&
    offsetof(struct ker_nginx_source_origin_record, config_sha256) == 144 &&
    offsetof(struct ker_nginx_source_origin_record, ini_sha256) == 176,
    "source origin v2 proof field offsets");
_Static_assert(sizeof(struct ker_nginx_source_origin_record) == 208,
    "source origin wire layout");
_Static_assert(sizeof(uintptr_t) <= sizeof(uint64_t),
    "opaque source cycle token must fit the 64-bit wire field");

static inline int
ker_nginx_source_origin_snapshot_status(int provider_status,
    const struct ker_source_native_ini_cycle_snapshot *snapshot)
{
    if (provider_status) return provider_status;
    if (!ker_source_native_ini_snapshot_abi_valid(snapshot)) return -EPROTO;
    if (!snapshot->adapter_cycle_serial || !snapshot->cycle_identity) return -ESTALE;
    unsigned config_bits = 0, ini_bits = 0;
    for (size_t i = 0; i < sizeof(snapshot->config_sha256); i++) {
        config_bits |= snapshot->config_sha256[i];
        ini_bits |= snapshot->ini_sha256[i];
    }
    return config_bits && ini_bits ? 0 : -EPROTO;
}

static inline int
ker_nginx_source_origin_bind_snapshot(struct ker_nginx_source_origin_record *record,
    const struct ker_source_native_ini_cycle_snapshot *snapshot)
{
    if (!record) return -EINVAL;
    int status = ker_nginx_source_origin_snapshot_status(0, snapshot);
    if (status) return status;
    if (record->magic != KER_NGINX_SOURCE_ORIGIN_MAGIC ||
        record->version != KER_NGINX_SOURCE_ORIGIN_VERSION ||
        record->type != KER_NGINX_SOURCE_ORIGIN_REQUEST ||
        record->record_bytes != sizeof(*record)) return -EPROTO;
    record->proof_version = KER_NGINX_SOURCE_ORIGIN_PROOF_VERSION;
    record->proof_flags = 0;
    record->adapter_cycle_serial = snapshot->adapter_cycle_serial;
    record->opaque_cycle_token = (uint64_t)snapshot->cycle_identity;
    memcpy(record->config_sha256, snapshot->config_sha256,
        sizeof(record->config_sha256));
    memcpy(record->ini_sha256, snapshot->ini_sha256,
        sizeof(record->ini_sha256));
    return 0;
}

static inline int
ker_nginx_source_origin_proof_matches(
    const struct ker_nginx_source_origin_record *record,
    const struct ker_source_native_ini_cycle_snapshot *snapshot)
{
    int status = ker_nginx_source_origin_snapshot_status(0, snapshot);
    if (status) return status;
    if (!record) return -EINVAL;
    if (record->magic != KER_NGINX_SOURCE_ORIGIN_MAGIC ||
        record->version != KER_NGINX_SOURCE_ORIGIN_VERSION ||
        record->type != KER_NGINX_SOURCE_ORIGIN_REQUEST ||
        record->record_bytes != sizeof(*record) ||
        record->proof_version != KER_NGINX_SOURCE_ORIGIN_PROOF_VERSION ||
        record->proof_flags != 0) return -EPROTO;
    if (record->adapter_cycle_serial != snapshot->adapter_cycle_serial ||
        record->opaque_cycle_token != (uint64_t)snapshot->cycle_identity ||
        memcmp(record->config_sha256, snapshot->config_sha256,
            sizeof(record->config_sha256)) ||
        memcmp(record->ini_sha256, snapshot->ini_sha256,
            sizeof(record->ini_sha256))) return -ESTALE;
    return 0;
}

/* Called only around the pinned original ngx_daemon fork by the bounded shim.
 * Prepare captures the one absolute startup budget before real fork. Parent
 * returns zero only after the child validated its exact supervisor ACK.
 * Child failure is fatal before original daemon code may continue. */
int ker_nginx_source_daemon_fork_prepare(void);
int ker_nginx_source_daemon_fork_parent(pid_t child);
int ker_nginx_source_daemon_fork_child(void);
void ker_nginx_source_daemon_fork_abort(void);

#endif
