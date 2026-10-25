#include "check.h"
#include "eal.h"
#include "runtime/ethdev-rx.h"
#include "runtime/memory.h"
#include "runtime/skb.h"
#include <errno.h>
#include <limits.h>
#include "compat/ethernet-abi.h"
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_COUNT 31
#define DESTINATION_ROOM 2050 /* Exercise cache-line rounding as well. */
#define MAX_FRAME 4096
static struct ker_packet_pool source, destination;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_protocol_handler handler;
static unsigned int expected_length, expected_headroom, callbacks;
static uint8_t expected_marker;

static uint8_t wire_byte(unsigned int offset, uint8_t marker)
{
    if (offset == 0) return 2;
    if (offset == 6) return 4;
    if (offset == 12) return 8;
    if (offset == 13) return 0;
    return (uint8_t)(offset * 13U + marker);
}

static int receive_packet(struct sk_buff *skb, struct ker_protocol_handler *ph,
    struct net_device *original, void *arg)
{
    (void)arg;
    CHECK(ph == &handler && original == device.native && skb->dev == device.native);
    CHECK(ker_skb_validate(skb, &context) == 0);
    CHECK(skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(skb->len == expected_length - ETH_HLEN);
    CHECK(skb_headroom(skb) == expected_headroom + ETH_HLEN);
    const uint8_t *bytes = skb_mac_header(skb);
    for (unsigned int i = 0; i < expected_length; ++i)
        CHECK(bytes[i] == wire_byte(i, expected_marker));
    /* The final byte must fit before the imported Linux shared-info area. */
    unsigned int usable = RTE_ALIGN_FLOOR(DESTINATION_ROOM, SMP_CACHE_BYTES) -
        ker_skb_shared_info_size();
    CHECK(skb_tailroom(skb) >= 0 && (unsigned int)skb_tailroom(skb) ==
        usable - expected_headroom - expected_length);
    callbacks++;
    CHECK(ker_skb_free(skb) == 0);
    return NET_RX_SUCCESS;
}

static struct rte_mbuf *make_packet(unsigned int length, uint8_t marker)
{
    CHECK(length >= ETH_HLEN && length <= MAX_FRAME);
    struct rte_mbuf *head = NULL;
    unsigned int offset = 0;
    while (offset < length) {
        struct rte_mbuf *segment = rte_pktmbuf_alloc(source.mbufs);
        CHECK(segment);
        /* Split Ethernet and IP fields into genuine small source segments. */
        unsigned int count = offset ? 173 : 10;
        if (count > length - offset) count = length - offset;
        uint8_t *bytes = (uint8_t *)rte_pktmbuf_append(segment, count);
        CHECK(bytes);
        for (unsigned int i = 0; i < count; ++i)
            bytes[i] = wire_byte(offset + i, marker);
        if (head) CHECK(rte_pktmbuf_chain(head, segment) == 0);
        else head = segment;
        offset += count;
    }
    CHECK(head->nb_segs > 1 && head->pkt_len == length);
    return head;
}

static void check_pools(unsigned int source_used, unsigned int destination_used)
{
    CHECK(rte_mempool_avail_count(source.mbufs) == POOL_COUNT - source_used);
    CHECK(rte_mempool_avail_count(destination.mbufs) == POOL_COUNT - destination_used);
    CHECK(context.live == 0);
}

static void test_capacity(uint16_t port, struct rte_ring *ring, unsigned int headroom)
{
    struct ker_ethdev_rx input = {0};
    CHECK(ker_ethdev_rx_init(&input, &device, &runtime, port, 0, headroom) == 0);
    unsigned int capacity = RTE_ALIGN_FLOOR(DESTINATION_ROOM, SMP_CACHE_BYTES) -
        ker_skb_shared_info_size() - headroom;
    CHECK(capacity > ETH_HLEN && capacity + 1 <= MAX_FRAME);
    expected_headroom = headroom;

    /* Both sides of the exact linear-copy boundary, with no pool pressure. */
    for (unsigned int i = 0; i < 2; ++i) {
        expected_length = capacity - 1 + i;
        expected_marker = (uint8_t)(headroom + i);
        unsigned int before = callbacks;
        CHECK(rte_ring_enqueue(ring, make_packet(expected_length, expected_marker)) == 0);
        CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && callbacks == before + 1 &&
            !input.pending && !input.last_error && !input.last_dropped);
        check_pools(0, 0);
    }
    unsigned int before = callbacks;
    CHECK(rte_ring_enqueue(ring, make_packet(capacity + 1, 0xee)) == 0);
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && callbacks == before &&
        !input.pending && input.last_error == -ENOSPC && input.last_dropped == 1);
    check_pools(0, 0);

    /* A permanently oversized head must be dropped even if no destination
     * backing is available; only the fitting successor may become pending. */
    struct rte_mbuf *oversized = make_packet(capacity + 1, 0xef);
    expected_length = capacity;
    expected_marker = 0x5a;
    struct rte_mbuf *fitting = make_packet(expected_length, expected_marker);
    unsigned int fitting_segments = fitting->nb_segs;
    CHECK(rte_ring_enqueue(ring, oversized) == 0 && rte_ring_enqueue(ring, fitting) == 0);
    struct rte_mbuf *held[POOL_COUNT];
    for (unsigned int i = 0; i < POOL_COUNT; ++i) {
        held[i] = rte_pktmbuf_alloc(destination.mbufs);
        CHECK(held[i]);
    }
    CHECK(!rte_pktmbuf_alloc(destination.mbufs));
    CHECK(ker_ethdev_rx_poll(&input, 2) == 1 && input.last_completed == 1 &&
        input.last_dropped == 1 && input.last_error == -ENOMEM &&
        input.pending == fitting && callbacks == before && rte_ring_empty(ring));
    check_pools(fitting_segments, POOL_COUNT);
    CHECK(ker_ethdev_rx_poll(&input, 1) == -ENOMEM && input.pending == fitting &&
        !input.last_completed && !input.last_dropped && callbacks == before);
    check_pools(fitting_segments, POOL_COUNT);
    /* Direct allocation uses the same stable pool geometry, without changing
     * output or descriptor counts on a permanent admission failure. */
    struct sk_buff *sentinel = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_alloc(&context, capacity + 1, headroom, &sentinel) == -ENOSPC &&
        sentinel == (struct sk_buff *)(uintptr_t)1 && context.live == 0);
    CHECK(ker_skb_alloc(&context, 0, UINT_MAX, &sentinel) == -ENOSPC &&
        sentinel == (struct sk_buff *)(uintptr_t)1);
    CHECK(ker_ethdev_rx_cleanup(&input) == -EBUSY);
    rte_pktmbuf_free(held[0]);
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && callbacks == before + 1 &&
        !input.pending && !input.last_error && !input.last_dropped);
    for (unsigned int i = 1; i < POOL_COUNT; ++i) rte_pktmbuf_free(held[i]);
    check_pools(0, 0);
    CHECK(ker_ethdev_rx_cleanup(&input) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&source, "rx_capacity_source", POOL_COUNT, 0, 512,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_packet_pool_init(&destination, "rx_capacity_dest", POOL_COUNT, 0,
        DESTINATION_ROOM, SOCKET_ID_ANY) == 0);
    struct rte_ring *ring = rte_ring_create("rx_capacity_ring", 4, rte_socket_id(),
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    struct rte_ring *tx = rte_ring_create("rx_capacity_tx", 4, rte_socket_id(),
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    CHECK(ring && tx);
    struct rte_ring *rxq[] = {ring}, *txq[] = {tx};
    int port = rte_eth_from_rings("rx_capacity_port", rxq, 1, txq, 1, rte_socket_id());
    CHECK(port >= 0);
    struct rte_eth_conf conf = {0};
    CHECK(rte_eth_dev_configure((uint16_t)port, 1, 1, &conf) == 0);
    CHECK(rte_eth_rx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL,
        source.mbufs) == 0);
    CHECK(rte_eth_tx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL) == 0);
    CHECK(rte_eth_dev_start((uint16_t)port) == 0);
    CHECK(ker_skb_context_init(&context, &destination, "rx_capacity_ctx") == 0);
    static const uint8_t mac[6] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_eth_device_init(&device, &context, "cap0", 1, mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_protocol_register(&runtime, &handler, &device,
        rte_cpu_to_be_16(ETH_P_IP), receive_packet, NULL) == 0);
    const unsigned int headrooms[] = {0, 32, 128};
    for (unsigned int i = 0; i < sizeof(headrooms) / sizeof(headrooms[0]); ++i)
        test_capacity((uint16_t)port, ring, headrooms[i]);
    CHECK(callbacks == 9);
    struct rte_eth_stats stats = {0};
    CHECK(rte_eth_stats_get((uint16_t)port, &stats) == 0 && stats.ipackets == 15);
    CHECK(rte_ring_empty(ring) && rte_ring_empty(tx));
    CHECK(ker_protocol_unregister(&handler) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_eth_dev_stop((uint16_t)port) == 0);
    CHECK(rte_eth_dev_close((uint16_t)port) == 0);
    rte_ring_free(ring);
    rte_ring_free(tx);
    CHECK(ker_packet_pool_cleanup(&source) == 0);
    CHECK(ker_packet_pool_cleanup(&destination) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
