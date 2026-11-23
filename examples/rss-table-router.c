/* Caller-owned software RSS-table routing demonstration. Synthetic UDP L3
 * bytes are metadata fixtures: no protocol state or Linux port allocation. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rss-table-policy.h"
#include <ker/packet-dispatcher.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "RSS example: %s\n", #c); exit(1); } } while (0)
static void ker_test_eal_init(void)
{
    cpu_set_t allowed;
    CHECK(!sched_getaffinity(0, sizeof(allowed), &allowed));
    int cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); ++cpu) {}
    CHECK(cpu < CPU_SETSIZE);
    char mapping[64], prefix[64];
    snprintf(mapping, sizeof(mapping), "--lcores=0@%d", cpu);
    snprintf(prefix, sizeof(prefix), "--file-prefix=rss-example-%ld", (long)getpid());
    char *args[] = {"rss-example", mapping, prefix, "--no-huge", "--no-pci", "--no-shconf", "--iova-mode=va", "--no-telemetry", "-m", "64"};
    CHECK(rte_eal_init(sizeof(args) / sizeof(args[0]), args) >= 0);
}
static uint32_t independent_hash(const uint8_t *tuple, unsigned size)
{
    static const uint8_t key[] = {0xd1,0x81,0xc6,0x2c,0xf7,0xf4,0xdb,0x5b,
        0x19,0x83,0xa2,0xfc,0x94,0x3e,0x1a,0xdb,0xd9,0x38,0x9e,0x6b,
        0xd1,0x03,0x9c,0x2c,0xa7,0x44,0x99,0xad,0x59,0x3d,0x56,0xd9,
        0xf3,0x25,0x3c,0x06,0x2a,0xdc,0x1f,0xfc};
    uint32_t result = 0;
    for (unsigned bit = 0; bit < size * 8; ++bit) {
        if (!(tuple[bit / 8] & (0x80u >> (bit % 8)))) continue;
        uint32_t window = 0;
        for (unsigned k = 0; k < 32; ++k) {
            unsigned index = bit + k;
            window = (window << 1) | ((key[index / 8] >> (7 - index % 8)) & 1u);
        }
        result ^= window;
    }
    return result;
}
static void real_consumer(void)
{
    ker_test_eal_init();
    struct rte_mempool *pool = rte_pktmbuf_pool_create("rss-model-pool", 511, 0, 0, 2048, SOCKET_ID_ANY);
    CHECK(pool);
    struct rte_ring *input = rte_ring_create("rss-model-input", 128, SOCKET_ID_ANY, 0);
    struct rte_ring *local = rte_ring_create("rss-model-local", 128, SOCKET_ID_ANY, 0);
    struct rte_ring *other = rte_ring_create("rss-model-other", 128, SOCKET_ID_ANY, 0);
    CHECK(input && local && other);
    struct rte_ring *rx[] = {input}, *tx[] = {input};
    int port = rte_eth_from_rings("rss-model-pmd", rx, 1, tx, 1, SOCKET_ID_ANY);
    CHECK(port >= 0);
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    CHECK(!rte_eth_dev_configure((uint16_t)port, 1, 1, &conf));
    CHECK(!rte_eth_rx_queue_setup((uint16_t)port, 0, 128, SOCKET_ID_ANY, NULL, pool));
    CHECK(!rte_eth_tx_queue_setup((uint16_t)port, 0, 128, SOCKET_ID_ANY, NULL));
    CHECK(!rte_eth_dev_start((uint16_t)port));
    struct ff_rss_check_cfg rules;
    memset(&rules, 0, sizeof(rules));
    rules.enable = 1; rules.nb_rss_tbl = 2;
    rules.rss_tbl_cfgs[0].family = AF_INET;
    CHECK(inet_pton(AF_INET, "192.0.2.1", &rules.rss_tbl_cfgs[0].saddr) == 1);
    CHECK(inet_pton(AF_INET, "198.51.100.2", &rules.rss_tbl_cfgs[0].daddr) == 1);
    rules.rss_tbl_cfgs[0].sport = htons(9000);
    rules.rss_tbl_cfgs[1].family = AF_INET6;
    CHECK(inet_pton(AF_INET6, "2001:db8::1", rules.rss_tbl_cfgs[1].saddr6) == 1);
    CHECK(inet_pton(AF_INET6, "2001:db8::2", rules.rss_tbl_cfgs[1].daddr6) == 1);
    rules.rss_tbl_cfgs[1].sport = htons(9000);
    CHECK(!example_rss_configure(&rules, 4, 1, 128, 10000, 20000));
    CHECK(!ker_packet_dispatcher_register(example_rss_dispatch));
    unsigned own = 0, foreign = 0;
    for (unsigned i = 0; i < 128; ++i) {
        unsigned family = i / 64;
        unsigned size = family ? 48 : 28;
        struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
        CHECK(packet);
        uint8_t *data = (uint8_t *)rte_pktmbuf_append(packet, size);
        CHECK(data); memset(data, 0, size);
        if (family) {
            data[0] = 0x60; data[6] = 17;
            memcpy(data + 8, rules.rss_tbl_cfgs[1].saddr6, 16);
            memcpy(data + 24, rules.rss_tbl_cfgs[1].daddr6, 16);
        } else {
            data[0] = 0x45; data[9] = 17;
            memcpy(data + 12, &rules.rss_tbl_cfgs[0].saddr, 4);
            memcpy(data + 16, &rules.rss_tbl_cfgs[0].daddr, 4);
        }
        memcpy(data + (family ? 40 : 20), &rules.rss_tbl_cfgs[family].sport, 2);
        uint16_t destination = htons((uint16_t)(10000 + i % 64));
        memcpy(data + (family ? 42 : 22), &destination, 2);
        uint8_t exact[48]; memcpy(exact, data, size);
        int expected = (independent_hash(data + (family ? 8 : 12), family ? 36 : 12) & 127u) % 4 == 1;
        CHECK(rte_eth_tx_burst((uint16_t)port, 0, &packet, 1) == 1);
        struct rte_mbuf *received = NULL;
        CHECK(rte_eth_rx_burst((uint16_t)port, 0, &received, 1) == 1 && received == packet);
        CHECK(!example_rss_route(received, local, other));
        struct rte_mbuf *output = NULL;
        CHECK(!rte_ring_dequeue(expected ? local : other, (void **)&output));
        CHECK(output == packet && !memcmp(rte_pktmbuf_mtod(output, void *), exact, size));
        CHECK(!rte_ring_count(local) && !rte_ring_count(other));
        if (expected) ++own; else ++foreign;
        rte_pktmbuf_free(output);
    }
    CHECK(own && foreign);
    struct rte_eth_stats statistics;
    CHECK(!rte_eth_stats_get((uint16_t)port, &statistics));
    CHECK(statistics.ipackets == 128 && statistics.opackets == 128);
    CHECK(!ker_packet_dispatcher_unregister());
    example_rss_reset();
    struct rte_mbuf *detached = rte_pktmbuf_alloc(pool); CHECK(detached);
    CHECK(example_rss_route(detached, local, other) == -ENOTCONN);
    rte_pktmbuf_free(detached);
    CHECK(rte_mempool_avail_count(pool) == 511);
    struct rte_mbuf *all[511];
    for (unsigned i = 0; i < 511; ++i) {
        all[i] = rte_pktmbuf_alloc(pool); CHECK(all[i]);
        for (unsigned j = 0; j < i; ++j) CHECK(all[i] != all[j]);
    }
    CHECK(!rte_pktmbuf_alloc(pool));
    for (unsigned i = 0; i < 511; ++i) rte_pktmbuf_free(all[i]);
    CHECK(!rte_eth_dev_stop((uint16_t)port)); CHECK(!rte_eth_dev_close((uint16_t)port));
    rte_ring_free(input); rte_ring_free(local); rte_ring_free(other); rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    printf("software RSS table consumer:128 IPv4/IPv6 original-PMD packets, local=%u other=%u, pool511/511\n", own, foreign);
}
int main(void) { real_consumer(); return 0; }
