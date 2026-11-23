#include "check.h"
#include "eal.h"
#include "runtime/ethdev-rx.h"
#include "runtime/memory.h"
#include "runtime/skb.h"
#include <errno.h>
#include <linux/if_ether.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_COUNT 63
#define FRAME_LEN 74
#define FRAME_COUNT 5
#define EXT_LEN 256
#define POISON 0xa5

/* Quarantine released storage until assertions finish: poisoning in the real
 * DPDK final-reference callback makes accidental source aliasing deterministic. */
struct external_storage {
    struct rte_mbuf_ext_shared_info info;
    void *bytes;
    unsigned int releases;
};
static struct external_storage storage[FRAME_COUNT][2];
static uint8_t frames[FRAME_COUNT][FRAME_LEN];
static struct sk_buff *retained[3];
static unsigned int delivered, releases, expected_releases;
static struct ker_packet_pool source, destination;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_protocol_handler handler;

static void release_external(void *address, void *opaque)
{
    struct external_storage *slot = opaque;
    CHECK(address == slot->bytes && slot->releases == 0);
    memset(address, POISON, EXT_LEN);
    slot->releases++;
    releases++;
}

static void verify_skb(struct sk_buff *skb, unsigned int id)
{
    CHECK(ker_skb_validate(skb, &context) == 0);
    CHECK(skb->dev == device.native && skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(skb->len == FRAME_LEN - ETH_HLEN);
    CHECK(memcmp(skb->data, frames[id] + ETH_HLEN, skb->len) == 0);
    CHECK(memcmp(skb_mac_header(skb), frames[id], ETH_HLEN) == 0);
}

static int retain_packet(struct sk_buff *skb, struct ker_protocol_handler *ph,
    struct net_device *original, void *arg)
{
    (void)arg;
    CHECK(ph == &handler && original == device.native && delivered < 3);
    /* Both external segments have already reached their final reference. */
    CHECK(releases == expected_releases);
    verify_skb(skb, delivered);
    retained[delivered++] = skb; /* Handler owns the skb beyond RX dispatch. */
    return NET_RX_SUCCESS;
}

static struct rte_mbuf *make_segment(unsigned int id, unsigned int index,
    unsigned int offset, uint16_t length, bool external)
{
    struct rte_mbuf *segment = rte_pktmbuf_alloc(source.mbufs);
    CHECK(segment);
    if (external) {
        struct external_storage *slot = &storage[id][index];
        slot->bytes = rte_malloc(NULL, EXT_LEN, RTE_CACHE_LINE_SIZE);
        CHECK(slot->bytes);
        slot->info.free_cb = release_external;
        slot->info.fcb_opaque = slot;
        rte_mbuf_ext_refcnt_set(&slot->info, 1);
        rte_pktmbuf_attach_extbuf(segment, slot->bytes, RTE_BAD_IOVA,
            EXT_LEN, &slot->info);
        segment->data_off = 0;
    }
    uint8_t *bytes = rte_pktmbuf_append(segment, length);
    CHECK(bytes);
    memcpy(bytes, frames[id] + offset, length);
    return segment;
}

static struct rte_mbuf *make_packet(unsigned int id)
{
    CHECK(id < FRAME_COUNT);
    for (unsigned int i = 0; i < FRAME_LEN; ++i)
        frames[id][i] = (uint8_t)(id * 17 + i);
    frames[id][0] = 2;
    frames[id][6] = 4;
    frames[id][12] = 8;
    frames[id][13] = 0;
    /* Mixed external/direct/external chain splits both Ethernet and IP data.
     * Only Ethernet classification is claimed; this is an opaque IP payload. */
    struct rte_mbuf *head = make_segment(id, 0, 0, 10, true);
    struct rte_mbuf *middle = make_segment(id, 0, 10, 13, false);
    struct rte_mbuf *tail = make_segment(id, 1, 23, FRAME_LEN - 23, true);
    CHECK(rte_pktmbuf_chain(head, middle) == 0);
    CHECK(rte_pktmbuf_chain(head, tail) == 0);
    CHECK(head->nb_segs == 3);
    return head;
}

static void check_storage(unsigned int id, bool released)
{
    for (unsigned int i = 0; i < 2; ++i) {
        struct external_storage *slot = &storage[id][i];
        CHECK(slot->releases == (unsigned int)released);
        CHECK(rte_mbuf_ext_refcnt_read(&slot->info) == (released ? 0 : 1));
        if (released) {
            const uint8_t *bytes = slot->bytes;
            for (unsigned int j = 0; j < EXT_LEN; ++j) CHECK(bytes[j] == POISON);
        }
    }
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&source, "ext_life_source", POOL_COUNT, 0, 4096,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_packet_pool_init(&destination, "ext_life_dest", POOL_COUNT, 0, 4096,
        SOCKET_ID_ANY) == 0);
    struct rte_ring *ring = rte_ring_create("ext_life_rx", 4, rte_socket_id(),
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    struct rte_ring *tx = rte_ring_create("ext_life_tx", 4, rte_socket_id(),
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    CHECK(ring && tx);
    struct rte_ring *rxq[] = {ring}, *txq[] = {tx};
    int port = rte_eth_from_rings("ext_life_port", rxq, 1, txq, 1, rte_socket_id());
    CHECK(port >= 0);
    struct rte_eth_conf conf = {0};
    CHECK(rte_eth_dev_configure((uint16_t)port, 1, 1, &conf) == 0);
    CHECK(rte_eth_rx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL,
        source.mbufs) == 0);
    CHECK(rte_eth_tx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL) == 0);
    CHECK(rte_eth_dev_start((uint16_t)port) == 0);
    CHECK(ker_skb_context_init(&context, &destination, "ext_life_context") == 0);
    static const uint8_t mac[6] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_eth_device_init(&device, &context, "ext0", 1, mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_protocol_register(&runtime, &handler, &device,
        rte_cpu_to_be_16(ETH_P_IP), retain_packet, NULL) == 0);
    struct ker_ethdev_rx input = {0};
    CHECK(ker_ethdev_rx_init_profile(&input, &device, &runtime, (uint16_t)port,
        0, 32, KER_ETHDEV_RX_COPY_IMMUTABLE_EXTERNAL) == 0);

    /* No sibling/parent reference masks premature release or accidental alias. */
    CHECK(rte_ring_enqueue(ring, make_packet(0)) == 0);
    expected_releases = 2;
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && delivered == 1 && !input.last_dropped);
    check_storage(0, true);
    CHECK(rte_mempool_avail_count(source.mbufs) == POOL_COUNT);
    verify_skb(retained[0], 0);

    struct rte_mbuf *first = make_packet(1), *second = make_packet(2);
    CHECK(rte_ring_enqueue(ring, first) == 0 && rte_ring_enqueue(ring, second) == 0);
    struct rte_mbuf *held[POOL_COUNT];
    unsigned int held_count = 0;
    while (held_count < POOL_COUNT &&
        (held[held_count] = rte_pktmbuf_alloc(destination.mbufs))) ++held_count;
    CHECK(held_count == POOL_COUNT - 1);
    /* Repeated ENOMEM must neither consume the successor nor release backing. */
    for (unsigned int i = 0; i < 2; ++i) {
        CHECK(ker_ethdev_rx_poll(&input, 2) == -ENOMEM && input.pending == first &&
            input.last_error == -ENOMEM && !input.last_completed && delivered == 1);
        CHECK(rte_ring_count(ring) == 1 && releases == 2);
        check_storage(1, false);
        check_storage(2, false);
    }
    CHECK(ker_ethdev_rx_cleanup(&input) == -EBUSY);
    rte_pktmbuf_free(held[--held_count]);
    expected_releases = 4;
    CHECK(ker_ethdev_rx_poll(&input, 2) == 1 && delivered == 2 &&
        input.pending == second && input.last_error == -ENOMEM && !input.last_dropped);
    check_storage(1, true);
    check_storage(2, false);
    CHECK(rte_ring_empty(ring));
    rte_pktmbuf_free(held[--held_count]);
    expected_releases = 6;
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && delivered == 3 && !input.pending &&
        !input.last_error && !input.last_dropped);
    check_storage(2, true);
    for (unsigned int i = 0; i < 3; ++i) verify_skb(retained[i], i);
    CHECK(rte_mempool_avail_count(source.mbufs) == POOL_COUNT);

    /* Cancellation transfers the last reference; only the caller's release
     * poisons the source. The next dropped packet releases exactly once. */
    struct rte_mbuf *cancel = make_packet(3), *drop = make_packet(4);
    drop->ol_flags |= RTE_MBUF_F_RX_VLAN_STRIPPED;
    CHECK(rte_ring_enqueue(ring, cancel) == 0 && rte_ring_enqueue(ring, drop) == 0);
    CHECK(ker_ethdev_rx_poll(&input, 2) == -ENOMEM && input.pending == cancel &&
        rte_ring_count(ring) == 1 && releases == 6);
    struct rte_mbuf *returned = NULL;
    CHECK(ker_ethdev_rx_cancel(&input, &returned) == 1 && returned == cancel &&
        !input.pending && releases == 6);
    check_storage(3, false);
    rte_pktmbuf_free(returned);
    check_storage(3, true);
    CHECK(releases == 8);
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && input.last_dropped == 1 &&
        input.last_error == -ENOTSUP && delivered == 3 && releases == 10);
    check_storage(4, true);
    returned = held[0]; /* Empty cancel must preserve a live output sentinel. */
    CHECK(ker_ethdev_rx_cancel(&input, &returned) == 0 && returned == held[0]);
    CHECK(rte_mempool_avail_count(source.mbufs) == POOL_COUNT);

    for (unsigned int i = 0; i < FRAME_COUNT; ++i)
        for (unsigned int j = 0; j < 2; ++j) rte_free(storage[i][j].bytes);
    /* Copied skbs also survive physical release of every source allocation. */
    for (unsigned int i = 0; i < 3; ++i) {
        verify_skb(retained[i], i);
        CHECK(ker_skb_free(retained[i]) == 0);
    }
    while (held_count) rte_pktmbuf_free(held[--held_count]);
    CHECK(rte_mempool_avail_count(destination.mbufs) == POOL_COUNT);
    struct rte_eth_stats stats = {0};
    CHECK(rte_eth_stats_get((uint16_t)port, &stats) == 0 && stats.ipackets == FRAME_COUNT);
    CHECK(rte_ring_empty(ring) && rte_ring_empty(tx));
    CHECK(ker_ethdev_rx_cleanup(&input) == 0);
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
