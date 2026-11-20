#include "worker-offload.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static unsigned char bytes[10000], snapshot[10000];
static struct rte_mbuf packet;
static struct ker_packet_header header;
static struct ker_worker_offload state;
static void reset(void)
{
    memset(bytes, 0, sizeof(bytes));
    bytes[12] = 8;
    struct rte_ipv4_hdr *ip = (void *)(bytes + 14);
    ip->version_ihl = 0x45;
    ip->next_proto_id = IPPROTO_TCP;
    ip->total_length = rte_cpu_to_be_16(sizeof(bytes) - 14);
    ip->src_addr = rte_cpu_to_be_32(0xc6120002);
    ip->dst_addr = rte_cpu_to_be_32(0xc6120001);
    struct rte_tcp_hdr *tcp = (void *)(bytes + 34);
    tcp->data_off = 5U << 4;
    packet = (struct rte_mbuf){.buf_addr = bytes, .buf_len = sizeof(bytes),
        .data_len = sizeof(bytes), .pkt_len = sizeof(bytes), .nb_segs = 1};
    state = (struct ker_worker_offload){.mode = 2, .tap = true, .features = 0x801,
        .flags = RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM};
    header = (struct ker_packet_header){.flags = 1, .gso_type = 1, .gso_size = 1460,
        .header_length = 54, .checksum_start = 34, .checksum_offset = 16};
}
static void reject(void)
{
    struct ker_worker_offload_result result;
    memcpy(snapshot, bytes, sizeof(bytes));
    CHECK(ker_worker_offload_apply(&state, &header, &packet, 1500, &result) < 0);
    CHECK(!memcmp(snapshot, bytes, sizeof(bytes)) && packet.ol_flags == 0 && packet.pkt_len == sizeof(bytes));
}
int main(void)
{
    reset(); header.flags = 3; reject();
    reset(); header.flags = 0; reject();
    reset(); header.checksum_start = 65535; reject();
    reset(); header.checksum_offset = 65535; reject();
    reset(); header.checksum_offset = 15; reject();
    reset(); header.gso_type = 4; reject();
    reset(); header.gso_size = 0; reject();
    reset(); header.gso_size = 1461; reject();
    reset(); header.header_length = 53; reject();
    reset(); header.header_length = 10001; reject();
    reset(); state.mode = 1; reject();
    reset(); state.mode = 0; reject();
    reset(); header.gso_type = header.gso_size = header.header_length = 0; reject(); /* oversized non-GSO */
    reset();
    struct ker_worker_offload_result result;
    CHECK(!ker_worker_offload_apply(&state, &header, &packet, 1500, &result));
    CHECK(result.tso4 == 1 && result.tso6 == 0 && result.tcp == 1 && result.ip == 1);
    CHECK(packet.tso_segsz == 1446 && packet.l2_len == 14 && packet.l3_len == 20 && packet.l4_len == 20);
    CHECK(packet.ol_flags & RTE_MBUF_F_TX_TCP_SEG);
    reset();
    packet.data_len = packet.pkt_len = 54;
    struct rte_ipv4_hdr *ip = (void *)(bytes + 14);
    ip->next_proto_id = IPPROTO_ICMP;
    ip->total_length = rte_cpu_to_be_16(40);
    memset(bytes + 34, 0x31, 20);
    bytes[34] = 8; bytes[35] = bytes[36] = bytes[37] = 0;
    header.gso_type = header.gso_size = header.header_length = 0;
    header.checksum_offset = 2;
    CHECK(!ker_worker_offload_apply(&state, &header, &packet, 1500, &result));
    CHECK(result.fallback == 1 && packet.ol_flags == 0);
    unsigned sum = 0;
    for (unsigned index = 34; index < 54; index += 2) sum += ((unsigned)bytes[index] << 8) | bytes[index + 1];
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    CHECK(sum == 65535);
    /* Unknown network protocols still use the generic virtio byte-range
     * checksum contract, rather than being passed through incomplete. */
    bytes[12] = 0x88; bytes[13] = 0xb5;
    bytes[36] = bytes[37] = 0;
    packet.ol_flags = 0;
    CHECK(!ker_worker_offload_apply(&state, &header, &packet, 1500, &result));
    CHECK(result.fallback == 1 && packet.ol_flags == 0);
    sum = 0;
    for (unsigned index = 34; index < 54; index += 2) sum += ((unsigned)bytes[index] << 8) | bytes[index + 1];
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    CHECK(sum == 65535);
    puts("PASS: malformed virtio metadata rejects before buffer/ownership changes; original DPDK header parsing and TAP segment bound qualified (no hardware execution claim)");
    return 0;
}
