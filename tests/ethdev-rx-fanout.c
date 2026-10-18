#include "check.h"
#include "eal.h"
#include "runtime/ethdev-rx.h"
#include "runtime/memory.h"
#include "runtime/skb.h"
#include "runtime/worker.h"
#include <errno.h>
#include <linux/if_ether.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_COUNT 31
#define FRAME_LEN 86
static struct ker_packet_pool source, destination;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_protocol_handler global_handler, device_handler;
static struct ker_ethdev_rx input;
static struct ker_worker worker;
static uint8_t expected[FRAME_LEN];
static struct sk_buff *retained, *copy, *dispatch_skb;
static struct rte_mbuf *held[POOL_COUNT];
static unsigned int held_count, calls, packets;
static int global_status, device_status;
static bool retain_and_clone;

static void verify(struct sk_buff *skb)
{
    CHECK(ker_skb_validate(skb, &context) == 0);
    CHECK(skb->dev == device.native && skb->skb_iif == device.native->ifindex);
    CHECK(skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(skb->len == FRAME_LEN - ETH_HLEN && skb->mac_len == ETH_HLEN);
    CHECK(skb->network_header == skb_headroom(skb));
    CHECK(skb->transport_header == skb->network_header);
    CHECK(memcmp(skb_mac_header(skb), expected, ETH_HLEN) == 0);
    CHECK(memcmp(skb->data, expected + ETH_HLEN, skb->len) == 0);
}

static int receive_packet(struct sk_buff *skb, struct ker_protocol_handler *ph,
    struct net_device *original, void *arg)
{
    (void)arg;
    CHECK(original == device.native);
    verify(skb);
    /* The original Linux ptype delivery visits the global list before the
     * device list and grants each callback its own descriptor reference. */
    CHECK(ker_protocol_unregister(ph) == -EBUSY);
    CHECK(ker_ethdev_rx_cleanup(&input) == -EBUSY);
    if (ph == &global_handler) {
        CHECK(calls++ == 0 && refcount_read(&skb->users) == 2);
        dispatch_skb = skb;
        if (retain_and_clone) {
            CHECK(!retained && !copy);
            retained = skb;
        } else CHECK(ker_skb_free(skb) == 0);
        return global_status;
    }
    CHECK(ph == &device_handler && calls++ == 1 && skb == dispatch_skb);
    CHECK(refcount_read(&skb->users) == (retain_and_clone ? 2 : 1));
    if (retain_and_clone) {
        CHECK(ker_skb_make_writable(skb, 0, 0) == -EBUSY);
        CHECK(ker_skb_clone(skb, &copy) == 0 && copy != skb && copy->head == skb->head);
        /* Exhaust backing only after RX has allocated its independent copy.
         * A failed COW must preserve the clone, parent and shared headers. */
        while (held_count < POOL_COUNT &&
            (held[held_count] = rte_pktmbuf_alloc(destination.mbufs))) ++held_count;
        CHECK(held_count == POOL_COUNT - 1);
        unsigned char *head = copy->head;
        CHECK(ker_skb_make_writable(copy, 0, 0) == -ENOMEM && copy->head == head &&
            retained->head == head && context.live == 2);
        verify(retained);
        verify(copy);
    }
    CHECK(ker_skb_free(skb) == 0);
    return device_status;
}

static void inject(struct rte_ring *ring, uint8_t marker)
{
    for (unsigned int i = 0; i < FRAME_LEN; ++i)
        expected[i] = (uint8_t)(marker + i * 17);
    expected[0] = 2;
    expected[6] = 4;
    expected[12] = 8;
    expected[13] = 0;
    /* Both destination/source MACs cross segment boundaries. Payload is
     * opaque: no IP or transport processing is implemented by this test. */
    const unsigned int lengths[] = {3, 7, FRAME_LEN - 10};
    struct rte_mbuf *head = NULL;
    unsigned int offset = 0;
    for (unsigned int i = 0; i < 3; ++i) {
        struct rte_mbuf *segment = rte_pktmbuf_alloc(source.mbufs);
        CHECK(segment);
        uint8_t *bytes = rte_pktmbuf_append(segment, lengths[i]);
        CHECK(bytes);
        memcpy(bytes, expected + offset, lengths[i]);
        if (head) CHECK(rte_pktmbuf_chain(head, segment) == 0);
        else head = segment;
        offset += lengths[i];
    }
    CHECK(rte_ring_enqueue(ring, head) == 0);
    calls = 0;
    dispatch_skb = NULL;
}

static void poll_one(int expected_error, unsigned int expected_drops,
    unsigned int expected_calls)
{
    struct ker_worker_result result = {0};
    CHECK(ker_worker_poll(&worker, packets++, &result) == 0 && result.rx == 1);
    CHECK(calls == expected_calls && !input.pending && input.last_completed == 1 &&
        input.last_dropped == expected_drops && input.last_error == expected_error);
    CHECK(rte_mempool_avail_count(source.mbufs) == POOL_COUNT);
    if (!retain_and_clone)
        CHECK(context.live == 0 &&
            rte_mempool_avail_count(destination.mbufs) == POOL_COUNT);
}

static void test_retained_copy(struct rte_ring *ring, bool release_parent_first,
    bool writable)
{
    retain_and_clone = true;
    inject(ring, (uint8_t)(0x30 + release_parent_first + 2 * writable));
    poll_one(0, 0, 2);
    CHECK(refcount_read(&retained->users) == 1 && refcount_read(&copy->users) == 1 &&
        retained->head == copy->head && skb_cloned(retained) && skb_cloned(copy));
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    CHECK(ker_skb_context_cleanup(&context) == -EBUSY);
    if (writable) {
        rte_pktmbuf_free(held[--held_count]);
        CHECK(ker_skb_make_writable(copy, 0, 0) == 0 && copy->head != retained->head);
        verify(copy);
        verify(retained);
        copy->data[0] ^= 0xff;
        skb_mac_header(copy)[0] ^= 0xff;
        verify(retained); /* The clone's write affects neither parent header. */
        CHECK(copy->data[0] == (uint8_t)(expected[ETH_HLEN] ^ 0xff) &&
            skb_mac_header(copy)[0] == (uint8_t)(expected[0] ^ 0xff));
    }
    if (release_parent_first) {
        CHECK(ker_skb_free(retained) == 0 && context.live == 1);
        if (writable) {
            CHECK(copy->data[0] == (uint8_t)(expected[ETH_HLEN] ^ 0xff));
            CHECK(skb_mac_header(copy)[0] == (uint8_t)(expected[0] ^ 0xff));
        } else verify(copy);
        CHECK(rte_mempool_avail_count(destination.mbufs) == (writable ? 1U : 0U));
        CHECK(ker_skb_free(copy) == 0);
    } else {
        CHECK(ker_skb_free(copy) == 0 && context.live == 1);
        verify(retained);
        CHECK(rte_mempool_avail_count(destination.mbufs) == (writable ? 1U : 0U));
        CHECK(ker_skb_free(retained) == 0);
    }
    retained = copy = NULL;
    while (held_count) rte_pktmbuf_free(held[--held_count]);
    CHECK(context.live == 0 && rte_mempool_avail_count(destination.mbufs) == POOL_COUNT);
    retain_and_clone = false;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&source, "fanout_source", POOL_COUNT, 0, 2048,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_packet_pool_init(&destination, "fanout_destination", POOL_COUNT, 0, 2048,
        SOCKET_ID_ANY) == 0);
    struct rte_ring *ring = rte_ring_create("fanout_rx", 4, rte_socket_id(), RING_F_EXACT_SZ);
    struct rte_ring *tx = rte_ring_create("fanout_tx", 4, rte_socket_id(), RING_F_EXACT_SZ);
    CHECK(ring && tx);
    struct rte_ring *rxq[] = {ring}, *txq[] = {tx};
    int port = rte_eth_from_rings("fanout_port", rxq, 1, txq, 1, rte_socket_id());
    CHECK(port >= 0);
    struct rte_eth_conf conf = {0};
    CHECK(rte_eth_dev_configure((uint16_t)port, 1, 1, &conf) == 0);
    CHECK(rte_eth_rx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL,
        source.mbufs) == 0);
    CHECK(rte_eth_tx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL) == 0);
    CHECK(rte_eth_dev_start((uint16_t)port) == 0);
    CHECK(ker_skb_context_init(&context, &destination, "fanout_context") == 0);
    static const uint8_t mac[6] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_eth_device_init(&device, &context, "fan0", 1, mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_protocol_register(&runtime, &global_handler, NULL,
        rte_cpu_to_be_16(ETH_P_IP), receive_packet, NULL) == 0);
    CHECK(ker_protocol_register(&runtime, &device_handler, &device,
        rte_cpu_to_be_16(ETH_P_IP), receive_packet, NULL) == 0);
    CHECK(ker_ethdev_rx_init(&input, &device, &runtime, (uint16_t)port, 0, 32) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.rx = ker_ethdev_rx_poll, .arg = &input};
    CHECK(ker_worker_init(&worker, &destination, &config, &ops) == 0);

    /* Intermediate DROP is not the final Linux delivery status. An invalid
     * callback status is instead recorded explicitly by Ker's adapter. */
    global_status = NET_RX_DROP;
    device_status = NET_RX_SUCCESS;
    inject(ring, 0x10);
    poll_one(0, 0, 2);
    global_status = NET_RX_SUCCESS;
    device_status = NET_RX_DROP;
    inject(ring, 0x11);
    poll_one(0, 1, 2);
    global_status = -EIO;
    device_status = NET_RX_SUCCESS;
    inject(ring, 0x12);
    poll_one(-EPROTO, 1, 2);
    global_status = NET_RX_SUCCESS;
    test_retained_copy(ring, true, false);
    test_retained_copy(ring, false, false);
    test_retained_copy(ring, true, true);
    test_retained_copy(ring, false, true);

    CHECK(ker_protocol_unregister(&global_handler) == 0);
    CHECK(ker_protocol_unregister(&device_handler) == 0);
    inject(ring, 0x70);
    poll_one(0, 1, 0);
    CHECK(context.live == 0 && rte_mempool_avail_count(destination.mbufs) == POOL_COUNT);
    struct rte_eth_stats stats = {0};
    CHECK(rte_eth_stats_get((uint16_t)port, &stats) == 0 && stats.ipackets == 8);
    CHECK(rte_ring_empty(ring) && rte_ring_empty(tx));
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_ethdev_rx_cleanup(&input) == 0);
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
