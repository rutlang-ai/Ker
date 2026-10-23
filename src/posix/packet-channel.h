#ifndef KER_POSIX_PACKET_CHANNEL_H
#define KER_POSIX_PACKET_CHANNEL_H
#include <stdint.h>
#define KER_NATIVE_DEFAULT_MTU 1500
#define KER_NATIVE_MIN_MTU 1280
#define KER_NATIVE_MAX_MTU 9000
#define KER_NATIVE_MAX_GSO 65554
/* Private local SOCK_SEQPACKET device-control ABI, independent of frames. */
#define KER_MTU_MAGIC 0x4b4d5455U
#define KER_MTU_GET 1U
#define KER_MTU_SET 2U
struct ker_mtu_message {
    uint32_t magic, operation;
    int32_t mtu, previous, status;
};
/* Original native virtio-net v1 framing, including negotiated TX metadata. */
struct ker_packet_header {
    uint8_t flags, gso_type;
    uint16_t header_length, gso_size, checksum_start, checksum_offset, buffers;
};
_Static_assert(sizeof(struct ker_packet_header) == 12, "virtio-net v1 header size");
#endif
