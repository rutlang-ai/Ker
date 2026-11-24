#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/skb-queue.h"
#include "runtime/transport-receive.h"
#include "runtime/udp-create.h"
#include "runtime/tcp-create.h"
#include "runtime/worker.h"
#include <errno.h>
#include <string.h>

#define TEST_HEADROOM 192U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static struct rte_mbuf *pending;
static unsigned char expected_payload[32];
static unsigned int expected_length, received;
static enum ker_transport_protocol expected_protocol;
static const unsigned char source_mac[6] = {2, 1, 2, 3, 4, 5};
static const unsigned char destination_mac[6] = {2, 6, 7, 8, 9, 10};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x026433c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;

static int receive_packet(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    CHECK(message->protocol == expected_protocol);
    if (expected_protocol == KER_TRANSPORT_UDP) {
        CHECK(message->packet.udp.source_port == source_port);
        CHECK(message->packet.udp.destination_port == destination_port);
        CHECK(message->packet.udp.payload_length == expected_length);
        CHECK(!memcmp(message->packet.udp.payload, expected_payload, expected_length));
    } else {
        CHECK(message->packet.tcp.source_port == source_port);
        CHECK(message->packet.tcp.destination_port == destination_port);
        CHECK(message->packet.tcp.payload_length == expected_length);
        CHECK(!memcmp(message->packet.tcp.payload, expected_payload, expected_length));
    }
    ++received;
    return NET_RX_SUCCESS;
}

static int rx_poll(void *arg, unsigned int budget)
{
    (void)arg;
    CHECK(budget == 1);
    if (!pending)
        return 0;
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, pending, 128, &skb) == 0);
    ker_packet_free(pending);
    pending = NULL;
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}

static struct sk_buff *make(unsigned int length, unsigned int headroom)
{
    struct sk_buff *skb = NULL;
    uint8_t *data = NULL;
    CHECK(ker_skb_alloc(&context, length, headroom, &skb) == 0);
    CHECK(ker_skb_put(skb, length, &data) == 0);
    for (unsigned int i = 0; i < length; ++i)
        data[i] = (uint8_t)(0x31U + i * 17U);
    return skb;
}

static void verify_chain(const struct rte_mbuf *chain, const uint8_t *bytes,
    unsigned int length, unsigned int limit, unsigned int headroom)
{
    CHECK(chain && chain->pkt_len == length && chain->nb_segs > 0);
    const struct rte_mbuf *segment = chain;
    unsigned int offset = 0, count = 0;
    while (segment) {
        CHECK(RTE_MBUF_DIRECT(segment) && !RTE_MBUF_HAS_EXTBUF(segment));
        CHECK(rte_mbuf_refcnt_read(segment) == 1 && segment->ol_flags == 0 &&
            segment->packet_type == RTE_PTYPE_UNKNOWN && !segment->tx_offload &&
            !segment->vlan_tci && !segment->vlan_tci_outer);
        CHECK((uint32_t)segment->data_off + segment->data_len <= segment->buf_len);
        CHECK(segment->data_len <= RTE_MIN(limit,
            (unsigned int)(segment->buf_len - segment->data_off)));
        if (!count)
            CHECK(segment->data_off == headroom);
        else
            CHECK(segment->data_off == RTE_PKTMBUF_HEADROOM &&
                segment->pkt_len == segment->data_len && segment->nb_segs == 1);
        CHECK(offset + segment->data_len <= length);
        CHECK(!memcmp(rte_pktmbuf_mtod(segment, const void *), bytes + offset,
            segment->data_len));
        offset += segment->data_len;
        ++count;
        segment = segment->next;
    }
    CHECK(offset == length && count == chain->nb_segs);
    if (length)
        CHECK(count > 1 || length <= limit);
    else
        CHECK(count == 1);
}

static void simple_copy_cases(void)
{
    struct sk_buff *skb = make(25, TEST_HEADROOM);
    uint8_t original[25]; memcpy(original, skb->data, sizeof(original));
    struct rte_mbuf *out = (void *)(uintptr_t)1;
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 0, &out) == -EINVAL);
    CHECK(out == (void *)(uintptr_t)1 && context.live == 1);
    CHECK(ker_skb_to_mbuf_chain_copy(skb, (unsigned int)UINT16_MAX + 1U, &out) == -EOVERFLOW);
    CHECK(out == (void *)(uintptr_t)1 && context.live == 1);
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 8, &out) == 0);
    CHECK(refcount_read(&skb->users) == 1 && !memcmp(skb->data, original, sizeof(original)));
    verify_chain(out, original, sizeof(original), 8, TEST_HEADROOM);
    memset(skb->data, 0xee, skb->len);
    CHECK(!memcmp(rte_pktmbuf_mtod(out, const void *), original, 8));
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
    verify_chain(out, original, sizeof(original), 8, TEST_HEADROOM);
    ker_packet_free(out);

    skb = make(25, TEST_HEADROOM);
    memcpy(original, skb->data, sizeof(original));
    CHECK(ker_skb_to_mbuf_chain_copy(skb, UINT16_MAX, &out) == 0);
    CHECK(out->nb_segs == 1 && out->data_len == sizeof(original));
    verify_chain(out, original, sizeof(original), UINT16_MAX, TEST_HEADROOM);
    ker_packet_free(out); /* The skb source remains intact when the copy dies first. */
    CHECK(!memcmp(skb->data, original, sizeof(original)));
    CHECK(ker_skb_free(skb) == 0);

    skb = make(24, TEST_HEADROOM);
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 8, &out) == 0);
    CHECK(out->nb_segs == 3 && out->pkt_len == 24);
    verify_chain(out, skb->data, skb->len, 8, TEST_HEADROOM);
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(out);

    skb = make(5, TEST_HEADROOM);
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 1, &out) == 0);
    CHECK(out->nb_segs == 5);
    verify_chain(out, skb->data, skb->len, 1, TEST_HEADROOM);
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(out);

    skb = make(19, 73);
    CHECK(ker_skb_get(skb) == 0 && refcount_read(&skb->users) == 2);
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 7, &out) == 0);
    verify_chain(out, skb->data, skb->len, 7, 73);
    CHECK(ker_skb_free(skb) == 0 && context.live == 1);
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
    CHECK(out->pkt_len == 19);
    ker_packet_free(out);

    skb = make(0, 96);
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 16, &out) == 0);
    CHECK(out->nb_segs == 1 && !out->next && !out->pkt_len && out->data_off == 96);
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(out);
}

static void allocation_sweep(
    int (*export_chain)(struct sk_buff *, unsigned int, struct rte_mbuf **),
    unsigned int limit)
{
    const unsigned int headroom = 64;
    const bool partial = export_chain != ker_skb_to_mbuf_chain_copy;
    uint8_t original[15], expected[15];
    struct sk_buff *skb = make(sizeof(original), headroom);
    if (partial) {
        /* Two words sum to 0xffff, with the checksum field starting at byte 3. */
        memset(skb->data, 0, skb->len);
        skb->data[1] = 0x12;
        skb->data[2] = 0x34;
        skb->data[3] = 0xed;
        skb->data[4] = 0xcb;
        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum_start = headroom + 1;
        skb->csum_offset = 2;
    }
    memcpy(original, skb->data, sizeof(original));
    memcpy(expected, original, sizeof(expected));
    if (partial) {
        const uint8_t folded = export_chain == ker_skb_to_mbuf_chain_software_checksum_exact ?
            0 : UINT8_MAX;
        expected[3] = expected[4] = folded;
    }

    const unsigned int required = (sizeof(original) + limit - 1) / limit;
    const unsigned int charge = skb->truesize;
    struct rte_mbuf *held[63];
    unsigned int held_count = 0;
    while (held_count < RTE_DIM(held) && (held[held_count] = ker_packet_alloc(&pool)))
        ++held_count;
    CHECK(held_count >= required && !rte_mempool_avail_count(pool.mbufs));

    struct rte_mbuf *sentinel = (void *)(uintptr_t)1;
    struct rte_mbuf *out = sentinel;
    for (unsigned int available = 0; available < required; ++available) {
        for (unsigned int attempt = 0; attempt < 2; ++attempt) {
            CHECK(export_chain(skb, limit, &out) == -ENOMEM && out == sentinel);
            CHECK(rte_mempool_avail_count(pool.mbufs) == available);
            CHECK(context.live == 1 && refcount_read(&skb->users) == 1);
            CHECK(skb_headroom(skb) == headroom && skb->len == sizeof(original) &&
                skb->truesize == charge && !memcmp(skb->data, original, sizeof(original)));
            CHECK(skb->ip_summed == (partial ? CHECKSUM_PARTIAL : CHECKSUM_NONE));
            if (partial)
                CHECK(skb->csum_start == headroom + 1 && skb->csum_offset == 2);
        }
        ker_packet_free(held[--held_count]);
    }

    CHECK(rte_mempool_avail_count(pool.mbufs) == required);
    CHECK(export_chain(skb, limit, &out) == 0 && out->nb_segs == required);
    CHECK(!rte_mempool_avail_count(pool.mbufs) && context.live == 1);
    CHECK(!memcmp(skb->data, original, sizeof(original)));
    CHECK(ker_skb_free(skb) == 0 && !context.live);
    verify_chain(out, expected, sizeof(expected), limit, headroom);
    ker_packet_free(out);
    while (held_count)
        ker_packet_free(held[--held_count]);
    CHECK(rte_mempool_avail_count(pool.mbufs) == RTE_DIM(held));
}

static void allocation_rollback(void)
{
    static int (*const modes[])(struct sk_buff *, unsigned int, struct rte_mbuf **) = {
        ker_skb_to_mbuf_chain_copy,
        ker_skb_to_mbuf_chain_software_checksum,
        ker_skb_to_mbuf_chain_software_checksum_exact,
    };
    const unsigned int limits[] = {1, 2, 7, 15};
    for (unsigned int i = 0; i < RTE_DIM(modes); ++i)
        for (unsigned int j = 0; j < RTE_DIM(limits); ++j)
            allocation_sweep(modes[i], limits[j]);
}

static void unsupported_boundaries(void)
{
    struct sk_buff *skb = make(16, 64);
    struct rte_mbuf *out = (void *)(uintptr_t)1;
    skb->ip_summed = CHECKSUM_PARTIAL;
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 8, &out) == -ENOTSUP && out == (void *)(uintptr_t)1);
    skb->ip_summed = CHECKSUM_NONE;
    skb_shinfo(skb)->gso_size = 1;
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 8, &out) == -ENOTSUP && out == (void *)(uintptr_t)1);
    skb_shinfo(skb)->gso_size = 0;
    skb->data_len = 1;
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 8, &out) == -ENOTSUP && out == (void *)(uintptr_t)1);
    skb->data_len = 0;
    skb->len++;
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 8, &out) == -EINVAL && out == (void *)(uintptr_t)1);
    skb->len--;
    CHECK(ker_skb_free(skb) == 0);

    struct ker_skb_queue queue = {0};
    CHECK(ker_skb_queue_init(&queue, &context, 1, SIZE_MAX) == 0);
    skb = make(16, 64);
    struct sk_buff *alias = skb, *popped = NULL;
    CHECK(ker_skb_queue_push(&queue, &skb) == 0 && !skb);
    CHECK(ker_skb_to_mbuf_chain_copy(alias, 8, &out) == -EBUSY && out == (void *)(uintptr_t)1);
    CHECK(ker_skb_queue_pop(&queue, &popped) == 1 && popped == alias);
    CHECK(ker_skb_free(popped) == 0);
    CHECK(ker_skb_queue_cleanup(&queue) == 0);
}

static void packet_roundtrip(enum ker_transport_protocol protocol)
{
    static const uint8_t udp_data[] = {1, 2, 3, 4, 5};
    static const uint8_t tcp_data[] = {9, 8, 7, 6, 5, 4};
    const uint8_t *payload = protocol == KER_TRANSPORT_UDP ? udp_data : tcp_data;
    unsigned int length = protocol == KER_TRANSPORT_UDP ? sizeof(udp_data) : sizeof(tcp_data);
    memcpy(expected_payload, payload, length);
    expected_length = length;
    expected_protocol = protocol;
    struct sk_buff *skb = NULL;
    int error;
    if (protocol == KER_TRANSPORT_UDP)
        error = ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
            destination_ip, source_port, destination_port, 64, payload, length, &skb);
    else
        error = ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip,
            destination_ip, source_port, destination_port, (__be32)0x04030201,
            (__be32)0x08070605, (__be16)0x0040, 0x18, 64, payload, length, &skb);
    CHECK(error == 0 && skb);
    unsigned int original_headroom = skb_headroom(skb);
    struct rte_mbuf *chain = NULL;
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 13, &chain) == 0);
    verify_chain(chain, skb->data, skb->len, 13, original_headroom);
    CHECK(refcount_read(&skb->users) == 1 && context.live == 1);
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
    pending = chain;
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.rx == 1 && !pending && received == (protocol == KER_TRANSPORT_UDP ? 1U : 2U));
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 63);
}

static void *foreign_export(void *arg)
{
    struct sk_buff *skb = arg;
    struct rte_mbuf *out = (void *)(uintptr_t)1;
    CHECK(ker_skb_to_mbuf_chain_copy(skb, 8, &out) == -EXDEV);
    CHECK(out == (void *)(uintptr_t)1);
    return NULL;
}

static void wrong_worker(void)
{
    struct sk_buff *skb = make(8, 64);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign_export, skb) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(ker_skb_free(skb) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "chain_export", 63, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "chain_export_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "chain-export0", 3,
        source_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device,
        receive_packet, &receiver) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.rx = rx_poll};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);

    simple_copy_cases();
    allocation_rollback();
    unsupported_boundaries();
    wrong_worker();
    packet_roundtrip(KER_TRANSPORT_UDP);
    packet_roundtrip(KER_TRANSPORT_TCP);

    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
