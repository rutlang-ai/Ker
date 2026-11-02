#ifndef KER_POSIX_RX_DECISION_WIRE_H
#define KER_POSIX_RX_DECISION_WIRE_H

/* Private ker-run <-> native I/O worker <-> trusted LKL application wire ABI.
 * This is local-host SOCK_SEQPACKET framing, not an installed SDK interface.
 * Every integer is little-endian; the peers are same-host processes from
 * the same build. Fixed-width, packed fields and exact lengths are validated
 * before use. */
#include <stddef.h>
#include <stdint.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The private RX decision wire ABI requires a little-endian host"
#endif

#define KER_RX_DECISION_MAGIC UINT32_C(0x4b525844) /* "KRXD" */
#define KER_RX_DECISION_VERSION UINT16_C(1)
#define KER_RX_DECISION_MAX_MESSAGE UINT32_C(9216)
#define KER_RX_DECISION_MAX_FRAME UINT32_C(9022)
#define KER_RX_DECISION_MAX_PENDING UINT32_C(1)
#define KER_RX_DECISION_DEADLINE_NS UINT64_C(100000000)
#define KER_RX_DECISION_NONCE_BYTES 16
#define KER_RX_DECISION_BOOTSTRAP_CONTROL_ID UINT64_C(1)
#define KER_RX_DECISION_HELLO_CONTROL_ID UINT64_C(2)
#define KER_RX_DECISION_STOP_CONTROL_ID UINT64_C(3)

enum ker_rx_decision_type {
    KER_RX_DECISION_BOOTSTRAP = 1,
    KER_RX_DECISION_HELLO = 2,
    KER_RX_DECISION_READY = 3,
    KER_RX_DECISION_DATA = 4,
    KER_RX_DECISION_RESULT = 5,
    KER_RX_DECISION_STOP = 6,
    KER_RX_DECISION_SETTLED = 7,
};

enum ker_rx_decision_action {
    KER_RX_DECISION_LOCAL = 1,
    KER_RX_DECISION_DROP = 2,
};

enum ker_rx_decision_bootstrap_role {
    KER_RX_DECISION_TARGET_WORKER = 1,
    KER_RX_DECISION_TARGET_CONSUMER = 2,
};

/* 64-byte common header. packet_id is zero except DATA/RESULT; control_id is
 * zero except control messages. BOOTSTRAP uses id 1, HELLO and READY both use
 * id 2, and STOP and SETTLED both use id 3. deadline_ns is nonzero only on
 * DATA and is an absolute CLOCK_MONOTONIC timestamp. */
struct __attribute__((packed)) ker_rx_decision_header {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t header_bytes;
    uint32_t message_bytes;
    uint8_t run_nonce[KER_RX_DECISION_NONCE_BYTES];
    uint64_t worker_epoch;
    uint64_t packet_id;
    uint64_t control_id;
    uint64_t deadline_ns;
};

/* BOOTSTRAP body. target_role and target identity describe the expected
 * REMOTE PEER, not the receiving process: the consumer receives WORKER and
 * the worker receives CONSUMER. Exactly two SCM_RIGHTS descriptors accompany
 * it: expected-peer pidfd, supervisor pidfd. The sender is independently
 * authenticated against SO_PEERCRED and per-message SCM_CREDENTIALS. */
struct __attribute__((packed)) ker_rx_decision_bootstrap {
    uint32_t target_role;
    uint32_t target_pid;
    uint32_t target_uid;
    uint32_t target_gid;
    uint64_t target_start_ticks;
    uint32_t supervisor_pid;
    uint32_t supervisor_uid;
    uint32_t supervisor_gid;
    uint32_t reserved;
    uint64_t supervisor_start_ticks;
};

/* DATA metadata. The datagram then contains exactly first_segment_bytes of
 * read-only snapshot data. The producer retains the original mbuf until one
 * valid RESULT or its fail-closed expiry; this snapshot is never reinjected. */
struct __attribute__((packed)) ker_rx_decision_data {
    uint32_t packet_bytes;
    uint32_t first_segment_bytes;
    uint16_t data_offset;
    uint16_t segment_count;
    uint16_t queue_id;
    uint16_t queue_count;
    uint16_t vlan_tci;
    uint16_t flags;
    uint64_t rx_offload_flags;
    uint32_t data_room_bytes;
};

struct __attribute__((packed)) ker_rx_decision_result {
    uint32_t action;
    uint32_t reserved[3];
};

struct __attribute__((packed)) ker_rx_decision_settled {
    uint64_t last_packet_id;
    uint32_t outstanding_count;
    uint32_t reserved;
};

_Static_assert(sizeof(struct ker_rx_decision_header) == 64, "RX decision header ABI");
_Static_assert(offsetof(struct ker_rx_decision_header, run_nonce) == 16, "RX nonce offset");
_Static_assert(offsetof(struct ker_rx_decision_header, deadline_ns) == 56, "RX deadline offset");
_Static_assert(sizeof(struct ker_rx_decision_bootstrap) == 48, "RX bootstrap ABI");
_Static_assert(sizeof(struct ker_rx_decision_data) == 32, "RX data metadata ABI");
_Static_assert(sizeof(struct ker_rx_decision_result) == 16, "RX result ABI");
_Static_assert(sizeof(struct ker_rx_decision_settled) == 16, "RX settled ABI");

#endif
