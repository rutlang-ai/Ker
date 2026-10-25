#ifndef KER_POSIX_PACKET_CHANNEL_H
#define KER_POSIX_PACKET_CHANNEL_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
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
/* The simple Ethernet TX path does not implement these offload fields.
 * `buffers` is RX-only mergeable-buffer accounting, not TX metadata. */
static inline int ker_packet_tx_header_simple_supported(const struct ker_packet_header *header)
{
    return header && !header->flags && !header->gso_type && !header->header_length &&
        !header->gso_size && !header->checksum_start && !header->checksum_offset;
}
/* Validate the original packet-channel prefix exactly as the TX consumer
 * interprets it, without treating the RX-only `buffers` field as TX metadata. */
static inline int ker_packet_tx_frame_header_supported(const void *frame, size_t length)
{
    if (!frame || length < sizeof(struct ker_packet_header)) return 0;
    struct ker_packet_header header;
    memcpy(&header, frame, sizeof(header));
    return ker_packet_tx_header_simple_supported(&header);
}
#endif
