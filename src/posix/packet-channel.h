#ifndef KER_POSIX_PACKET_CHANNEL_H
#define KER_POSIX_PACKET_CHANNEL_H
#include <stdint.h>
/* Native virtio-net v1 framing. Offloads remain disabled; this header only
 * separates the imported Linux device ABI from complete Ethernet frames. */
struct ker_packet_header {
    uint8_t flags, gso_type;
    uint16_t header_length, gso_size, checksum_start, checksum_offset, buffers;
};
_Static_assert(sizeof(struct ker_packet_header) == 12, "virtio-net v1 header size");
#endif
