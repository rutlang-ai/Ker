/* Exercise real TAP PMD ownership, with injected copy/write rejection. */
#define _GNU_SOURCE
#include "worker-mbuf.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static unsigned used;
static void usage(struct rte_mempool *pool, void *arg)
{
    (void)arg;
    used += rte_mempool_in_use_count(pool);
}
static unsigned in_use(void) { used = 0; rte_mempool_walk(usage, NULL); return used; }
static unsigned char bytes[6000], before[6000], after[6000];
static unsigned snapshot(struct rte_mbuf *packet, struct rte_mbuf *descriptors)
{
    unsigned i = 0;
    for (struct rte_mbuf *p = packet; p; p = p->next) descriptors[i++] = *p;
    const void *data = rte_pktmbuf_read(packet, 0, packet->pkt_len, before);
    CHECK(data); if (data != before) memcpy(before, data, packet->pkt_len);
    return i;
}
int main(int argc, char **argv)
{
    void (*fault)(const char *, int) = (void (*)(const char *, int))dlsym(RTLD_DEFAULT, "ker_test_tap_fault");
    bool (*fired)(void) = (bool (*)(void))dlsym(RTLD_DEFAULT, "ker_test_tap_fault_fired");
    CHECK(fault && fired && rte_eal_init(argc, argv) >= 0);
    /* Match production: resolve through the selected driver's own, already
     * loaded module (EAL loads PMDs RTLD_LOCAL). */
    uint16_t selected_port;
    CHECK(!rte_eth_dev_get_port_by_name("net_tap0", &selected_port));
    struct rte_eth_dev_info selected_info = {0};
    CHECK(!rte_eth_dev_info_get(selected_port, &selected_info));
    Dl_info selected_module;
    CHECK(dladdr(rte_dev_driver(selected_info.device), &selected_module));
    void *tap_module = dlopen(selected_module.dli_fname, RTLD_NOW | RTLD_NOLOAD);
    int (*abi)(uint16_t) = tap_module ? (int (*)(uint16_t))dlsym(tap_module,
        "ker_dpdk_tap_tx_retry_abi") : NULL;
    if (!abi) { puts("SKIP: qualified TAP ownership PMD not installed"); return 77; }
    uint16_t port;
    CHECK(!rte_eth_dev_get_port_by_name("net_tap0", &port));
    CHECK(abi(port) == 1 && abi(RTE_MAX_ETHPORTS) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) { execlp("ip", "ip", "link", "set", "retrytap", "up", (char *)NULL); _exit(127); }
    int status; CHECK(waitpid(child, &status, 0) == child && status == 0);
    struct rte_eth_conf conf = {0};
    conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
        RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_TSO | RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    CHECK(!rte_eth_dev_configure(port, 1, 1, &conf));
    struct rte_mempool *pool = rte_pktmbuf_pool_create("retry_packets", 1023, 0, 0, 1024, rte_socket_id());
    CHECK(pool);
    CHECK(!rte_eth_tx_queue_setup(port, 0, 128, rte_socket_id(), NULL));
    CHECK(!rte_eth_rx_queue_setup(port, 0, 128, rte_socket_id(), NULL, pool));
    CHECK(!rte_eth_dev_start(port));
    unsigned baseline = in_use();
    for (unsigned shape = 0; shape < 5; shape++) {
        for (unsigned inject = 0; inject < (shape == 2 ? 5U : 3U); inject++) {
            unsigned length = shape == 2 ? 6000 : (shape == 1 ? 1400 : 800);
            memset(bytes, 0, sizeof(bytes));
            memset(bytes, 0xff, 6); bytes[6] = 2; bytes[12] = 8;
            struct rte_ipv4_hdr *ip = (void *)(bytes + 14);
            ip->version_ihl = 0x45; ip->time_to_live = 64;
            ip->total_length = rte_cpu_to_be_16(length - 14);
            ip->src_addr = rte_cpu_to_be_32(0xc6120002); ip->dst_addr = rte_cpu_to_be_32(0xc6120001);
            ip->next_proto_id = shape == 0 ? IPPROTO_UDP : IPPROTO_TCP;
            if (!shape) {
                struct rte_udp_hdr *udp = (void *)(bytes + 34);
                udp->dgram_len = rte_cpu_to_be_16(length - 34); udp->dst_port = rte_cpu_to_be_16(42000);
                udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, 0);
            } else {
                struct rte_tcp_hdr *tcp = (void *)(bytes + 34);
                tcp->data_off = 5U << 4; tcp->dst_port = rte_cpu_to_be_16(42000);
                tcp->cksum = rte_ipv4_phdr_cksum(ip, shape >= 2 ? RTE_MBUF_F_TX_TCP_SEG : 0);
            }
            for (unsigned j = 54; j < length; j++) bytes[j] = (j * 17) ^ (j >> 8);
            struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, bytes, length);
            CHECK(packet);
            packet->l2_len = 14; packet->l3_len = 20; packet->l4_len = !shape ? 8 : 20;
            packet->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM |
                (!shape ? RTE_MBUF_F_TX_UDP_CKSUM : RTE_MBUF_F_TX_TCP_CKSUM);
            if (shape == 4) packet->ol_flags &= ~RTE_MBUF_F_TX_L4_MASK;
            if (shape >= 2) { packet->ol_flags |= RTE_MBUF_F_TX_TCP_SEG; packet->tso_segsz = 1400; }
            struct rte_mbuf descriptors[10];
            unsigned segments = snapshot(packet, descriptors);
            struct rte_mbuf *held[1024];
            unsigned held_count = 0;
            bool pressure = (shape == 2 ? inject >= 3 : inject == 2);
            if (pressure) {
                struct rte_mempool *target = shape == 2 ? rte_mempool_lookup("mp_net_tap0") : pool;
                CHECK(target);
                unsigned keep = shape == 1 ? 1 : (shape == 2 && inject == 4 ? 3 : 0);
                while (rte_mempool_avail_count(target) > keep) {
                    CHECK(held_count < 1024);
                    held[held_count] = rte_pktmbuf_alloc(target);
                    CHECK(held[held_count]); held_count++;
                }
            }
            unsigned allocated = in_use();
            fault(pressure ? "disabled" : (inject == 0 ? "copy" : "write"), inject == 2 ? 2 : 0);
            CHECK(rte_eth_tx_burst(port, 0, &packet, 1) == 0);
            CHECK(in_use() == allocated);
            CHECK(pressure || fired());
            struct rte_mbuf *segment = packet;
            for (unsigned j = 0; j < segments; j++) {
                CHECK(segment && !memcmp(segment, &descriptors[j], sizeof(*segment)));
                segment = segment->next;
            }
            CHECK(!segment);
            const void *data = rte_pktmbuf_read(packet, 0, length, after);
            CHECK(data && !memcmp(data, before, length));
            for (unsigned j = 0; j < held_count; j++) rte_pktmbuf_free(held[j]);
            fault("disabled", 0);
            CHECK(rte_eth_tx_burst(port, 0, &packet, 1) == 1);
            CHECK(in_use() == baseline);
            printf("PASS: shape=%u fault=%u caller descriptor/chain/bytes unchanged, retry accepted, zero leaked mbufs\n", shape, inject);
        }
    }
    CHECK(!rte_eth_dev_stop(port)); CHECK(!rte_eth_dev_close(port));
    CHECK(!in_use()); rte_mempool_free(pool); CHECK(!rte_eal_cleanup());
    return 0;
}
