#ifndef KER_NGINX_SOURCE_BOOTSTRAP_H
#define KER_NGINX_SOURCE_BOOTSTRAP_H

#include <stdint.h>

/* Private source bootstrap. A slim control-only grant has no application or
 * packet ownership. Workers must finish exact slot, classifier and native I/O
 * bindings before committing ff_init or publishing generation readiness. */
#define KER_NGINX_SOURCE_BOOTSTRAP_MAGIC UINT32_C(0x4b534247)
#define KER_NGINX_SOURCE_BOOTSTRAP_VERSION 3
#define KER_NGINX_SOURCE_BOOTSTRAP_REQUEST 1
#define KER_NGINX_SOURCE_BOOTSTRAP_REPLY 2
#define KER_NGINX_SOURCE_BOOTSTRAP_STOP 3
#define KER_NGINX_SOURCE_BOOTSTRAP_ACTIVATE 4
#define KER_NGINX_SOURCE_MASTER_PARK 5
#define KER_NGINX_SOURCE_MASTER_COMMIT 6
#define KER_NGINX_SOURCE_SLIM_CONTROL_ONLY 1
#define KER_NGINX_SOURCE_WORKER_INITIAL 2
#define KER_NGINX_SOURCE_WORKER_CANDIDATE 4
#define KER_NGINX_SOURCE_ROLE_SLIM 0
#define KER_NGINX_SOURCE_ROLE_WORKER 1
#define KER_NGINX_SOURCE_ROLE_MASTER 2
#define KER_NGINX_SOURCE_BOOTSTRAP_MAX_NS UINT64_C(300000000000)

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

struct ker_nginx_source_bootstrap {
    struct ker_nginx_source_bootstrap_record record;
    int channel;
    int supervisor_pidfd;
    int runtime_pidfd;
    int io_pidfd;
    int slot_fd;
    int relay_fd;
    int ready_fd;
};

/* The pinned caller supplies the actual source-created block and role, after
 * checking its original Nginx ABI/process globals. Opens a fresh host Unix
 * channel, so the source slim primary's inherited-FD close loop is preserved.
 * Only transport identity is established here; no successful protocol/FSM stub. */
int ker_nginx_source_bootstrap_connect(const char *path,
    const struct ker_nginx_source_bootstrap_record *request,
    uint32_t expected_supervisor, uint64_t expected_supervisor_start,
    struct ker_nginx_source_bootstrap *binding);
int ker_nginx_source_bootstrap_live(const struct ker_nginx_source_bootstrap *binding);
/* 0 while idle, 1 for the exact supervisor's correlated STOP, negative on fault. */
int ker_nginx_source_bootstrap_poll_stop(const struct ker_nginx_source_bootstrap *binding);
int ker_nginx_source_bootstrap_poll_activate(const struct ker_nginx_source_bootstrap *binding);
void ker_nginx_source_bootstrap_close(struct ker_nginx_source_bootstrap *binding);
int ker_nginx_source_is_master(void);
int ker_nginx_source_master_barrier(uint16_t operation);

int ker_nginx_source_bootstrap_from_environment(uint32_t role, uint32_t generation,
    uint32_t source_epoch, const void *source_block,
    struct ker_nginx_source_bootstrap *binding);

#endif
