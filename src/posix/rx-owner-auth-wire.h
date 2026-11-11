#ifndef KER_RX_OWNER_AUTH_WIRE_H
#define KER_RX_OWNER_AUTH_WIRE_H

#include <stdint.h>

#define KER_RX_OWNER_AUTH_MAGIC UINT32_C(0x4b524f41)
#define KER_RX_OWNER_AUTH_VERSION UINT16_C(1)
#define KER_RX_OWNER_AUTH_OWNER UINT16_C(1)
#define KER_RX_OWNER_AUTH_ACK UINT16_C(2)
#define KER_RX_OWNER_AUTH_NONCE_BYTES 16

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

#endif
