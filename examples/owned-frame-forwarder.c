#define _DEFAULT_SOURCE
/* An owned-frame conversion caller; original PMD loopback, no network stack. */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "owned-frame-port.h"
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "owned-frame caller: %s\n", #x); return 1; } } while (0)
int main(int argc, char **argv)
{
    int used = rte_eal_init(argc, argv); REQUIRE(used >= 0);
    argc -= used; argv += used;
    REQUIRE(argc == 3);
    unsigned char bytes[65536], output[65536];
    FILE *input = fopen(argv[1], "rb"); REQUIRE(input);
    size_t length = fread(bytes, 1, sizeof(bytes), input);
    REQUIRE(!ferror(input) && length >= 14 && length <= UINT16_MAX && feof(input));
    REQUIRE(fclose(input) == 0);
    struct example_frame_port port; REQUIRE(example_frame_port_open(&port) == 0);
    struct rte_eth_stats before; REQUIRE(rte_eth_stats_get(port.port, &before) == 0);
    REQUIRE(before.opackets == 0 && before.ipackets == 0);
    struct rte_mbuf *packet = example_frame_from_bytes(port.pool, bytes, (unsigned)length);
    REQUIRE(packet);
    REQUIRE(example_owned_send(port.sender, packet, (int)length) == 0); /* Consumes packet. */
    struct rte_mbuf *received = NULL;
    REQUIRE(rte_eth_rx_burst(port.port, 0, &received, 1) == 1 && received->pkt_len == length);
    const void *data = rte_pktmbuf_read(received, 0, (uint32_t)length, output); REQUIRE(data);
    REQUIRE(memcmp(data, bytes, length) == 0);
    FILE *file = fopen(argv[2], "wb"); REQUIRE(file);
    REQUIRE(fwrite(data, 1, length, file) == length && fclose(file) == 0);
    unsigned segments = received->nb_segs;
    rte_pktmbuf_free(received);
    struct rte_eth_stats after; REQUIRE(rte_eth_stats_get(port.port, &after) == 0);
    REQUIRE(after.opackets == 1 && after.ipackets == 1);
    struct example_owned_send_stats stats; example_owned_send_snapshot(&stats);
    REQUIRE(stats.accepted == 1 && stats.inputs_freed == 1 && !stats.copy_failures && !stats.dropped_segments);
    REQUIRE(example_frame_port_close(&port) == 0);
    REQUIRE(rte_eal_cleanup() == 0);
    printf("OWNED_FRAME_FORWARDED bytes=%zu segments=%u tx=1 rx=1 pool=511\n", length, segments);
    return 0;
}
