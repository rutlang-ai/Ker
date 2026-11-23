#ifndef KER_NGINX_SOURCE_BOOTSTRAP_H
#define KER_NGINX_SOURCE_BOOTSTRAP_H

#include <stdint.h>

/* Private source bootstrap. A slim control-only grant has no application or
 * packet ownership. Workers must finish exact slot, classifier and native I/O
 * bindings before committing ff_init or publishing generation readiness. */
#define KER_NGINX_SOURCE_BOOTSTRAP_MAGIC UINT32_C(0x4b534247)
#define KER_NGINX_SOURCE_BOOTSTRAP_VERSION 3
#define KER_NGINX_SOURCE_BOOTSTRAP_SHELL_VERSION 4
#define KER_NGINX_SOURCE_BOOTSTRAP_REQUEST 1
#define KER_NGINX_SOURCE_BOOTSTRAP_REPLY 2
#define KER_NGINX_SOURCE_BOOTSTRAP_STOP 3
#define KER_NGINX_SOURCE_BOOTSTRAP_ACTIVATE 4
#define KER_NGINX_SOURCE_MASTER_PARK 5
#define KER_NGINX_SOURCE_MASTER_COMMIT 6
#define KER_NGINX_SOURCE_MASTER_ABORT 9
#define KER_NGINX_SOURCE_WORKER_PREEXIT 10
#define KER_NGINX_SOURCE_WORKER_SETTLED 11
#define KER_NGINX_SOURCE_WORKER_COMMIT_EVIDENCE 12
#define KER_NGINX_SOURCE_PREEXIT_VERSION 1
/* Final shutdown includes native kernel teardown and DPDK/EAL worker exit. */
#define KER_NGINX_SOURCE_PREEXIT_BUDGET_NS UINT64_C(1000000000)
#define KER_NGINX_SOURCE_SLIM_CONTROL_ONLY 1
#define KER_NGINX_SOURCE_WORKER_INITIAL 2
#define KER_NGINX_SOURCE_WORKER_CANDIDATE 4
#define KER_NGINX_SOURCE_ROLE_SLIM 0
#define KER_NGINX_SOURCE_ROLE_WORKER 1
#define KER_NGINX_SOURCE_ROLE_MASTER 2
#define KER_NGINX_SOURCE_COMMITTED_ROUND_LIMIT UINT32_C(100)
#define KER_NGINX_SOURCE_BOOTSTRAP_MAX_NS UINT64_C(420000000000)
#define KER_NGINX_SOURCE_UPGRADE_ENV "KER_NGINX_SOURCE_UPGRADE_ENABLE"
#define KER_NGINX_SOURCE_UPGRADE_ROUND UINT32_C(2)

#include "source-native-ini.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>

struct ker_nginx_source_bootstrap_record {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t record_bytes;
    uint32_t role;
    uint32_t actor_pid;
    uint32_t actor_tid;
    uint32_t master_pid;
    uint32_t generation;
    uint32_t source_epoch;
    uint32_t reserved;
    uint64_t actor_start_ticks;
    uint64_t master_start_ticks;
    uint64_t source_block_address;
    uint64_t launch_epoch;
    uint64_t deadline_ns;
    uint8_t run_nonce[16];
    uint32_t supervisor_pid;
    uint32_t runtime_pid;
    uint32_t io_pid;
    uint32_t flags;
    uint64_t supervisor_start_ticks;
    uint64_t runtime_start_ticks;
    uint64_t io_start_ticks;
    uint64_t slot_device;
    uint64_t slot_inode;
    uint64_t relay_cookie;
    uint64_t ready_cookie;
    /* Master RPC only: original absolute operation budget, never renewed. */
    uint64_t control_deadline_ns;
};

_Static_assert(sizeof(struct ker_nginx_source_bootstrap_record) == 176,
    "source bootstrap wire layout");

struct ker_nginx_source_bootstrap_proof {
    uint32_t version;
    uint32_t flags;
    uint64_t adapter_cycle_serial;
    uint64_t opaque_cycle_token;
    uint8_t config_sha256[32];
    uint8_t ini_sha256[32];
};

struct ker_nginx_source_bootstrap_record_v4 {
    struct ker_nginx_source_bootstrap_record record;
    struct ker_nginx_source_bootstrap_proof proof;
};

/* Bounded final-owner exit handshake. The immutable bootstrap record and v4
 * source-cycle proof are repeated so the SDK can bind this operation to the
 * exact worker grant without treating an exit request as authority. */
struct ker_nginx_source_preexit_record {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t record_bytes;
    uint32_t reserved;
    struct ker_nginx_source_bootstrap_record_v4 identity;
    uint32_t worker_slot;
    uint32_t worker_role;
    uint64_t operation_id;
    uint64_t operation_deadline_ns;
    uint64_t native_commit_cookie;
};

struct ker_nginx_source_settled_record {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t record_bytes;
    uint32_t reserved;
    struct ker_nginx_source_preexit_record request;
    uint32_t status;
    uint32_t reserved2;
    uint64_t c31_outstanding;
    uint64_t c31_last_packet_id;
    int32_t c31_last_result;
    uint32_t native_settled;
};

/* Status-only receipt after source master COMMIT is fully applied. It grants
 * no new slot or packet authority; the worker already owns this exact grant. */
struct ker_nginx_source_commit_evidence_record {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t record_bytes;
    uint32_t reserved;
    struct ker_nginx_source_bootstrap_record_v4 identity;
    uint64_t native_current_cookie;
};

_Static_assert(sizeof(struct ker_nginx_source_preexit_record) == 312,
    "source worker pre-exit wire layout");
_Static_assert(sizeof(struct ker_nginx_source_settled_record) == 360,
    "source worker settlement wire layout");
_Static_assert(sizeof(struct ker_nginx_source_commit_evidence_record) == 288,
    "source worker COMMIT evidence wire layout");

typedef int (*ker_nginx_source_preexit_pump_fn)(void);
enum ker_nginx_source_preexit_pump_status {
    KER_NGINX_SOURCE_PREEXIT_PUMP_RELAY_EOF = 0x4b530001,
};

int ker_nginx_source_bootstrap_worker_preexit(
    const struct ker_nginx_source_bootstrap_record *identity,
    const struct ker_nginx_source_bootstrap_proof *proof,
    uint32_t worker_slot, uint32_t worker_role, uint64_t operation_id,
    uint64_t native_commit_cookie, uint64_t grant_deadline_ns,
    ker_nginx_source_preexit_pump_fn pump);

int ker_nginx_source_bootstrap_worker_commit_cookie(
    const struct ker_nginx_source_bootstrap_record *identity,
    const struct ker_nginx_source_bootstrap_proof *proof,
    uint64_t *native_commit_cookie);

_Static_assert(sizeof(struct ker_nginx_source_bootstrap_proof) == 88,
    "source-shell proof layout");
_Static_assert(offsetof(struct ker_nginx_source_bootstrap_record_v4, proof) == 176,
    "source-shell proof appended after legacy record");
_Static_assert(sizeof(struct ker_nginx_source_bootstrap_record_v4) == 264,
    "source-shell v4 wire layout");

static inline int
ker_nginx_source_bootstrap_proof_from_snapshot(
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    struct ker_nginx_source_bootstrap_proof *proof)
{
    if (!snapshot || !proof) return -EINVAL;
    if (!ker_source_native_ini_snapshot_abi_valid(snapshot)) return -EPROTO;
    if (!snapshot->adapter_cycle_serial || !snapshot->cycle_identity) return -ESTALE;
    unsigned config_bits = 0, ini_bits = 0;
    for (size_t i = 0; i < sizeof(snapshot->config_sha256); i++) {
        config_bits |= snapshot->config_sha256[i];
        ini_bits |= snapshot->ini_sha256[i];
    }
    if (!config_bits || !ini_bits) return -EPROTO;
    struct ker_nginx_source_bootstrap_proof value = {
        .version = 1,
        .flags = 0,
        .adapter_cycle_serial = snapshot->adapter_cycle_serial,
        .opaque_cycle_token = (uint64_t)snapshot->cycle_identity,
    };
    memcpy(value.config_sha256, snapshot->config_sha256,
        sizeof(value.config_sha256));
    memcpy(value.ini_sha256, snapshot->ini_sha256, sizeof(value.ini_sha256));
    *proof = value;
    return 0;
}

static inline int
ker_nginx_source_bootstrap_proof_equal(
    const struct ker_nginx_source_bootstrap_proof *left,
    const struct ker_nginx_source_bootstrap_proof *right)
{
    return left && right && left->version == 1 && right->version == 1 &&
        left->flags == 0 && right->flags == 0 &&
        !memcmp(left, right, sizeof(*left));
}

static inline int
ker_nginx_source_bootstrap_v4_matches(
    const struct ker_nginx_source_bootstrap_record *expected,
    const struct ker_nginx_source_bootstrap_proof *expected_proof,
    const struct ker_nginx_source_bootstrap_record_v4 *actual)
{
    return expected && expected_proof && actual &&
        actual->record.version == KER_NGINX_SOURCE_BOOTSTRAP_SHELL_VERSION &&
        actual->record.record_bytes == sizeof(*actual) &&
        !memcmp(expected, &actual->record, sizeof(*expected)) &&
        ker_nginx_source_bootstrap_proof_equal(expected_proof, &actual->proof);
}

static inline int
ker_nginx_source_bootstrap_v4_encode(
    const struct ker_nginx_source_bootstrap_record *legacy_request,
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    struct ker_nginx_source_bootstrap_record_v4 *wire)
{
    if (!legacy_request || !snapshot || !wire) return -EINVAL;
    if (legacy_request->version != KER_NGINX_SOURCE_BOOTSTRAP_VERSION ||
        legacy_request->record_bytes != sizeof(*legacy_request)) return -EPROTO;
    struct ker_nginx_source_bootstrap_proof proof;
    int status = ker_nginx_source_bootstrap_proof_from_snapshot(snapshot, &proof);
    if (status) return status;
    struct ker_nginx_source_bootstrap_record_v4 value = {
        .record = *legacy_request,
        .proof = proof,
    };
    value.record.version = KER_NGINX_SOURCE_BOOTSTRAP_SHELL_VERSION;
    value.record.record_bytes = sizeof(value);
    *wire = value;
    return 0;
}

struct ker_nginx_source_bootstrap {
    struct ker_nginx_source_bootstrap_record record;
    int channel;
    int supervisor_pidfd;
    int runtime_pidfd;
    int io_pidfd;
    int slot_fd;
    int relay_fd;
    int ready_fd;
    int directory_fd;
    uint32_t source_shell_proof_enabled;
    struct ker_nginx_source_bootstrap_proof source_shell_proof;
    uint32_t source_candidate_activated;
    uint32_t source_commit_evidence_received;
    uint64_t native_commit_cookie;
};

/* The pinned caller supplies the actual source-created block and role, after
 * checking its original Nginx ABI/process globals. Opens a fresh host Unix
 * channel, so the source slim primary's inherited-FD close loop is preserved.
 * Only transport identity is established here; no successful protocol/FSM stub. */
int ker_nginx_source_bootstrap_connect(const char *path,
    const struct ker_nginx_source_bootstrap_record *request,
    uint32_t expected_supervisor, uint64_t expected_supervisor_start,
    struct ker_nginx_source_bootstrap *binding);
int ker_nginx_source_bootstrap_connect_source_shell(const char *path,
    const struct ker_nginx_source_bootstrap_record *request,
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    uint32_t expected_supervisor, uint64_t expected_supervisor_start,
    struct ker_nginx_source_bootstrap *binding);
int ker_nginx_source_bootstrap_live(const struct ker_nginx_source_bootstrap *binding);
/* 0 while idle, 1 for the exact supervisor's correlated STOP, negative on fault. */
int ker_nginx_source_bootstrap_poll_stop(const struct ker_nginx_source_bootstrap *binding);
int ker_nginx_source_bootstrap_poll_activate(const struct ker_nginx_source_bootstrap *binding);
void ker_nginx_source_bootstrap_close(struct ker_nginx_source_bootstrap *binding);
bool ker_nginx_source_upgrade_enabled(void);
bool ker_nginx_source_upgrade_worker(void);
int ker_nginx_source_is_master(void);
int ker_nginx_source_master_barrier(uint16_t operation);
int ker_fstack_nginx_source_fault_profile(void);

int ker_nginx_source_bootstrap_from_environment(uint32_t role, uint32_t generation,
    uint32_t source_epoch, const void *source_block,
    struct ker_nginx_source_bootstrap *binding);
int ker_nginx_source_bootstrap_from_environment_source_shell(uint32_t role,
    uint32_t generation, uint32_t source_epoch, const void *source_block,
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    struct ker_nginx_source_bootstrap *binding);

#endif
