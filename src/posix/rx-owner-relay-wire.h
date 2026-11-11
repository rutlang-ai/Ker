#ifndef KER_RX_OWNER_RELAY_WIRE_H
#define KER_RX_OWNER_RELAY_WIRE_H

#include <stdint.h>

#define KER_RX_OWNER_RELAY_MAGIC UINT32_C(0x4b525852)
#define KER_RX_OWNER_RELAY_VERSION UINT16_C(1)
#define KER_RX_OWNER_RELAY_MAX_FRAME UINT32_C(9022)
#define KER_RX_OWNER_RELAY_NONCE_BYTES 16
#define KER_RX_OWNER_RELAY_REQUEST UINT16_C(1)
#define KER_RX_OWNER_RELAY_REPLY UINT16_C(2)
#define KER_RX_OWNER_RELAY_APP_AUTH UINT16_C(3)
#define KER_RX_OWNER_RELAY_AUTH_ACK UINT16_C(5)

struct ker_rx_owner_relay_header {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint64_t packet_id;
    uint64_t deadline_ns;
    uint8_t run_nonce[KER_RX_OWNER_RELAY_NONCE_BYTES];
    uint64_t worker_epoch;
    uint64_t app_start_ticks;
    uint64_t owner_start_ticks;
    uint64_t supervisor_start_ticks;
    uint32_t app_pid;
    uint32_t owner_pid;
    uint32_t owner_tid;
    uint32_t supervisor_pid;
    uint32_t frame_bytes;
    uint16_t queue_id;
    uint16_t queue_count;
    uint16_t action;
    uint16_t reserved;
    uint32_t frame_hash32;
    int32_t dispatcher_result;
    uint16_t vlan_tci;
    uint8_t vlan_stripped;
    uint8_t frame_unchanged;
};

#endif
