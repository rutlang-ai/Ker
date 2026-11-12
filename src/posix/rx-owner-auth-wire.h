#ifndef KER_RX_OWNER_AUTH_WIRE_H
#define KER_RX_OWNER_AUTH_WIRE_H

#include <stdint.h>

#define KER_RX_OWNER_AUTH_MAGIC UINT32_C(0x4b524f41)
#define KER_RX_OWNER_AUTH_VERSION UINT16_C(1)
#define KER_RX_OWNER_AUTH_OWNER UINT16_C(1)
#define KER_RX_OWNER_AUTH_ACK UINT16_C(2)
#define KER_RX_OWNER_AUTH_PEER UINT16_C(3)
#define KER_RX_OWNER_AUTH_PEER_ACK UINT16_C(4)
#define KER_RX_OWNER_AUTH_NONCE_BYTES 16
#define KER_RX_OWNER_PEER_MAX_AUTHORITY_NS UINT64_C(300000000000)

struct ker_rx_owner_auth_record {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t record_bytes;
    uint32_t supervisor_pid;
    uint32_t owner_pid;
    uint32_t owner_tid;
    uint32_t owner_role;
    uint32_t flags;
    uint64_t worker_epoch;
    uint64_t supervisor_start_ticks;
    uint64_t owner_start_ticks;
    uint64_t slot_device;
    uint64_t slot_inode;
    uint64_t cookie;
    uint8_t run_nonce[KER_RX_OWNER_AUTH_NONCE_BYTES];
};

/* One finite, non-renewable old-owner binding, authorized by the already
 * pinned supervisor for this exact current candidate and its slot. Carries
 * exactly old-owner pidfd + application side of the old relay channel.
 * The old worker must also ACK the supervisor's APP_AUTH on that channel
 * before PEER_ACK is emitted and forwarding is permitted. */
struct ker_rx_owner_peer_auth_record {
    struct ker_rx_owner_auth_record owner;
    uint32_t primary_pid;
    uint32_t primary_tid;
    uint64_t primary_start_ticks;
    uint64_t primary_slot_device;
    uint64_t primary_slot_inode;
    uint64_t primary_cookie;
    uint64_t authority_deadline_ns;
};

_Static_assert(sizeof(struct ker_rx_owner_auth_record) == 96, "owner AUTH ABI");
_Static_assert(sizeof(struct ker_rx_owner_peer_auth_record) == 144, "peer AUTH ABI");

#endif
