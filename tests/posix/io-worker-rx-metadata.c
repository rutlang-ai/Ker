#define _GNU_SOURCE
#include <sys/types.h>
#include <rte_ether.h>
#include "io-worker-rx-metadata.h"

#include <stdio.h>

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "metadata check failed at %s:%d: %s\n", \
            __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void)
{
    unsigned char frame[RTE_ETHER_HDR_LEN] = {0};
    struct rte_mbuf packet = {0};
    packet.buf_addr = frame;
    packet.data_len = sizeof(frame);
    packet.pkt_len = sizeof(frame);
    packet.nb_segs = 1;
    struct rte_ring *pending = (struct rte_ring *)(uintptr_t)1;
    struct ker_worker_exception bridge = {
        .pending = pending,
        .ether_type = RTE_ETHER_TYPE_ARP
    };
    frame[12] = 0x08;
    frame[13] = 0x06;
    packet.ol_flags = RTE_MBUF_F_RX_RSS_HASH |
        RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD;

    REQUIRE(ker_io_worker_metadata_supported(&packet));
    REQUIRE(ker_worker_exception_route(&bridge, &packet) == KER_EXCEPTION_HOST);
    REQUIRE(ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_HOST, true));

    bridge.port_mode = true;
    REQUIRE(ker_worker_exception_route(&bridge, &packet) == KER_EXCEPTION_SHARED);
    REQUIRE(ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_SHARED, true));

    bridge.port_mode = false;
    bridge.ether_type = RTE_ETHER_TYPE_ARP;
    frame[12] = 0x08;
    frame[13] = 0x00;
    REQUIRE(ker_worker_exception_route(&bridge, &packet) == KER_EXCEPTION_NATIVE);
    REQUIRE(!ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_NATIVE, true));

    packet.ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD;
    REQUIRE(ker_io_worker_metadata_supported(&packet));
    REQUIRE(ker_worker_exception_route(&bridge, &packet) == KER_EXCEPTION_NATIVE);
    REQUIRE(ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_NATIVE, true));

    packet.ol_flags |= RTE_MBUF_F_RX_VLAN_STRIPPED;
    REQUIRE(!ker_io_worker_metadata_supported(&packet));
    REQUIRE(!ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_NATIVE, true));

    packet.ol_flags = RTE_MBUF_F_RX_RSS_HASH |
        RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD;
    packet.vlan_tci = 1;
    REQUIRE(!ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_NATIVE, true));
    REQUIRE(ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_HOST, true));

    /* Decision-off retains the existing native path's broad metadata policy. */
    REQUIRE(ker_io_worker_route_metadata_supported(&packet,
        KER_EXCEPTION_NATIVE, false));
    return 0;
}
