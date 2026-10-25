#include "packet-channel.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "line %u: %s\n", __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

int main(void)
{
    struct ker_packet_header header = {0};
    CHECK(ker_packet_tx_header_simple_supported(&header));
    header.buffers = 16394;
    CHECK(ker_packet_tx_header_simple_supported(&header));

    const size_t unsupported_offsets[] = {
        offsetof(struct ker_packet_header, flags),
        offsetof(struct ker_packet_header, gso_type),
        offsetof(struct ker_packet_header, header_length),
        offsetof(struct ker_packet_header, gso_size),
        offsetof(struct ker_packet_header, checksum_start),
        offsetof(struct ker_packet_header, checksum_offset),
    };
    for (unsigned i = 0; i < sizeof(unsupported_offsets) / sizeof(unsupported_offsets[0]); i++) {
        header = (struct ker_packet_header){0};
        ((unsigned char *)&header)[unsupported_offsets[i]] = 1;
        CHECK(!ker_packet_tx_header_simple_supported(&header));
    }
    CHECK(!ker_packet_tx_header_simple_supported(NULL));
    puts("PASS: simple TX validation ignores RX buffer count and rejects unsupported TX metadata");
    return 0;
}
