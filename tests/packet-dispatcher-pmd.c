/* Caller-owned routing/response/drop policy over the original net_ring PMD. */
#include <ker/packet-dispatcher.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "check.h"
static unsigned plain_calls, context_calls, replacement_calls;
static unsigned sequence;
static int decision, stripped;
static uint16_t tci;
static void *expected_data;
static void inspect(void *data, uint16_t *length, uint16_t queue, uint16_t queues)
{
    CHECK(data == expected_data && *length == 64 && queue == 1 && queues == 2);
    unsigned char *bytes = data;
    for (unsigned i = 0; i < 64; ++i) CHECK(bytes[i] == (unsigned char)(sequence+i));
    bytes[20] ^= 0x5a;
    --*length;
}
static int plain(void *data, uint16_t *length, uint16_t queue, uint16_t queues)
{
    ++plain_calls; inspect(data, length, queue, queues); return decision;
}
static int context(void *data, uint16_t *length, uint16_t queue, uint16_t queues,
    struct ker_dispatcher_context ctx)
{
    CHECK(ctx.vlan.stripped == stripped && ctx.vlan.vlan_tci == (stripped ? htons(tci) : 0));
    ++context_calls; inspect(data, length, queue, queues); return decision;
}
static int replacement(void *data, uint16_t *length, uint16_t queue, uint16_t queues,
    struct ker_dispatcher_context ctx)
{
    ++replacement_calls; return context(data, length, queue, queues, ctx);
}
int main(int argc, char **argv)
{
    CHECK(rte_eal_init(argc, argv) >= 0);
    struct rte_mempool *pool = rte_pktmbuf_pool_create("dispatch_pool", 127, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(pool);
    struct rte_ring *rx[2], *tx[2];
    for (unsigned q = 0; q < 2; ++q) {
        char name[32]; snprintf(name, sizeof(name), "dispatch_rx_%u", q);
        rx[q] = rte_ring_create(name, 64, SOCKET_ID_ANY, 0); CHECK(rx[q]);
        snprintf(name, sizeof(name), "dispatch_tx_%u", q);
        tx[q] = rte_ring_create(name, 64, SOCKET_ID_ANY, 0); CHECK(tx[q]);
    }
    struct rte_ring *peer = rte_ring_create("dispatch_caller_peer", 64, SOCKET_ID_ANY, 0); CHECK(peer);
    int created = rte_eth_from_rings("dispatch", rx, 2, tx, 2, SOCKET_ID_ANY); CHECK(created >= 0);
    uint16_t port = (uint16_t)created;
    struct rte_eth_conf conf = {0}; CHECK(!rte_eth_dev_configure(port, 2, 2, &conf));
    for (unsigned q = 0; q < 2; ++q) {
        CHECK(!rte_eth_rx_queue_setup(port, q, 128, SOCKET_ID_ANY, NULL, pool));
        CHECK(!rte_eth_tx_queue_setup(port, q, 128, SOCKET_ID_ANY, NULL));
    }
    CHECK(!rte_eth_dev_start(port));
    unsigned transmitted = 0, dropped = 0, forwarded = 0;
    for (sequence = 0; sequence < 12; ++sequence) {
        decision = 0; stripped = 0; tci = 0xb123;
        switch (sequence) {
        case 0: break; /* default queue */
        case 1: CHECK(!ker_packet_dispatcher_register(plain)); break;
        case 2: CHECK(!ker_packet_dispatcher_register_context(context)); stripped = 1; break;
        case 3: CHECK(!ker_packet_dispatcher_unregister()); decision = 1; break;
        case 4: stripped = 1; break;
        case 5: CHECK(!ker_packet_dispatcher_register_context(replacement)); break;
        case 6: decision = -1; break;
        case 7: decision = -2; stripped = 1; break;
        case 8: decision = -3; break;
        case 9: decision = 2; break;
        case 10:
            CHECK(!ker_packet_dispatcher_unregister_context() && !ker_packet_dispatcher_unregister_context());
            CHECK(!ker_packet_dispatcher_unregister() && !ker_packet_dispatcher_unregister()); break;
        case 11:
            CHECK(!ker_packet_dispatcher_register(plain) && !ker_packet_dispatcher_register(NULL));
            CHECK(!ker_packet_dispatcher_register_context(context) && !ker_packet_dispatcher_register_context(NULL)); break;
        }
        int enabled = sequence >= 1 && sequence <= 9;
        struct rte_mbuf *packet = rte_pktmbuf_alloc(pool); CHECK(packet);
        unsigned char *data = (void *)rte_pktmbuf_append(packet, 64); CHECK(data);
        for (unsigned i = 0; i < 64; ++i) data[i] = (unsigned char)(sequence+i);
        packet->ol_flags = stripped ? RTE_MBUF_F_RX_VLAN_STRIPPED : 0;
        packet->vlan_tci = tci;
        uint64_t flags = packet->ol_flags;
        expected_data = data;
        CHECK(!rte_ring_enqueue(rx[1], packet));
        struct rte_mbuf *input = NULL; CHECK(rte_eth_rx_burst(port, 1, &input, 1) == 1 && input == packet);
        uint16_t length = 999;
        int result = ker_packet_dispatch(input, &length, 1, 2);
        CHECK(result == (enabled ? decision : 1) && length == (enabled ? 63 : 64));
        CHECK(input->data_len == 64 && input->pkt_len == 64 && input->ol_flags == flags && input->vlan_tci == tci);
        for (unsigned i = 0; i < 64; ++i)
            CHECK(data[i] == (unsigned char)(((sequence+i)&255) ^ (enabled && i == 20 ? 0x5a : 0)));
        /* Explicit application policy; no FreeBSD peer implementation here. */
        if (result == -1 || result >= 2) { ++dropped; rte_pktmbuf_free(input); }
        else if (result == -3) {
            CHECK(!rte_ring_enqueue(peer, input)); void *object;
            CHECK(!rte_ring_dequeue(peer, &object) && object == input);
            ++forwarded; rte_pktmbuf_free(object);
        } else {
            unsigned queue = result == -2 ? 1U : (unsigned)result;
            CHECK(length <= input->data_len); input->data_len = length; input->pkt_len = length;
            CHECK(rte_eth_tx_burst(port, queue, &input, 1) == 1);
            void *object; CHECK(!rte_ring_dequeue(tx[queue], &object) && object == packet);
            CHECK(((struct rte_mbuf *)object)->pkt_len == length && !memcmp(rte_pktmbuf_mtod((struct rte_mbuf *)object, void *), data, length));
            ++transmitted; rte_pktmbuf_free(object);
        }
        CHECK(rte_mempool_avail_count(pool) == 127 && rte_ring_empty(peer));
        for (unsigned q = 0; q < 2; ++q) CHECK(rte_ring_empty(rx[q]) && rte_ring_empty(tx[q]));
    }
    CHECK(plain_calls == 2 && context_calls == 7 && replacement_calls == 5);
    CHECK(transmitted == 9 && dropped == 2 && forwarded == 1);
    struct rte_eth_stats stats; CHECK(!rte_eth_stats_get(port, &stats));
    CHECK(stats.ipackets == 12 && stats.opackets == 9);
    CHECK(!ker_packet_dispatcher_unregister() && !ker_packet_dispatcher_unregister_context());
    CHECK(!rte_eth_dev_stop(port) && !rte_eth_dev_close(port));
    for (unsigned q = 0; q < 2; ++q) { rte_ring_free(rx[q]); rte_ring_free(tx[q]); }
    rte_ring_free(peer); CHECK(rte_mempool_avail_count(pool) == 127); rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    puts("PASS: original PMD RX12/TX9, caller drop2/peer1, plain2/context7/replacement5, VLAN/length/default/precedence/unregister, pool127/127");
    return 0;
}
