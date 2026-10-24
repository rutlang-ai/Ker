#define _GNU_SOURCE
#include "worker-mbuf.h"
#include "worker-wait.h"
#include "worker-tx.h"
#include "worker-rx-drain.h"
#include "worker-scatter.h"
#include <errno.h>
#include <rte_eal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

struct tx_mock { uint16_t limit; unsigned int next; };
static uint16_t mock_tx_burst(void *context, struct rte_mbuf **packets, uint16_t count)
{
    struct tx_mock *mock = context;
    uint16_t accepted = count < mock->limit ? count : mock->limit;
    for (uint16_t i = 0; i < accepted; ++i) {
        CHECK(*rte_pktmbuf_mtod(packets[i], unsigned char *) == mock->next++);
        rte_pktmbuf_free(packets[i]); /* PMD may release before returning. */
    }
    return accepted;
}
static void test_tx_batch(void)
{
    struct rte_mempool *pool = rte_pktmbuf_pool_create("tx_batch_test", 63, 0, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(pool);
    struct ker_worker_tx queue = {0};
    unsigned char input[4096] = {0};
    const size_t lengths[] = {14, sizeof(input), 16};
    for (unsigned int i = 0; i < 3; ++i) {
        input[0] = (unsigned char)i;
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, input, lengths[i]);
        CHECK(packet && ker_worker_tx_append(&queue, packet, 1000 + i * 100));
    }
    CHECK(queue.count == 3 && queue.first_ns == 1000);
    CHECK(ker_worker_tx_wait_us(&queue, 100, 1000) == 100);
    CHECK(ker_worker_tx_wait_us(&queue, 100, 1001) == 100);
    CHECK(ker_worker_tx_wait_us(&queue, 100, 100999) == 1);
    CHECK(ker_worker_tx_wait_us(&queue, 100, 101000) == 0);
    CHECK(ker_worker_tx_wait_us(&queue, 0, 1000) == 0);
    struct tx_mock mock = {0};
    struct ker_worker_tx_result result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(!result.packets && !result.bytes && queue.count == 3 && queue.retrying);
    CHECK(ker_worker_tx_wait_us(&queue, 100, 1000) == 0);
    mock.limit = 1;
    result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(result.packets == 1 && result.bytes == 14 && !result.multiseg && queue.count == 2);
    result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(result.packets == 1 && result.bytes == 4096 && result.multiseg == 1 && queue.count == 1);
    result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(result.packets == 1 && result.bytes == 16 && queue.count == 0 && !queue.retrying);
    CHECK(rte_mempool_avail_count(pool) == 63);
    /* A retained ordinary TAP suffix can be retried even when other packets
     * in the original burst carried offload metadata. The marker is captured
     * before the PMD call, which may mutate/free packet buffers. */
    for (unsigned int i = 0; i < 2; ++i) {
        input[0] = (unsigned char)i;
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, input, 64);
        CHECK(packet);
        if (i == 0) packet->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM;
        CHECK(ker_worker_tx_append(&queue, packet, 3000));
    }
    mock = (struct tx_mock){.limit = 1, .next = 0};
    result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(result.packets == 1 && !result.rejected_offload && queue.count == 1);
    ker_worker_tx_discard(&queue);
    for (unsigned int i = 0; i < 2; ++i) {
        input[0] = (unsigned char)i;
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, input, 64);
        CHECK(packet);
        if (i == 1) packet->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM;
        CHECK(ker_worker_tx_append(&queue, packet, 3500));
    }
    mock = (struct tx_mock){.limit = 1, .next = 0};
    result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(result.packets == 1 && result.rejected_offload && queue.count == 1);
    ker_worker_tx_discard(&queue);
    for (unsigned int i = 0; i < 2; ++i) {
        input[0] = (unsigned char)i;
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, input, 64);
        CHECK(packet && ker_worker_tx_append(&queue, packet, 4000));
    }
    mock = (struct tx_mock){.limit = 1, .next = 0};
    result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(result.packets == 1 && !result.rejected_offload && queue.count == 1);
    ker_worker_tx_discard(&queue);
    CHECK(rte_mempool_avail_count(pool) == 63);
    for (unsigned int i = 0; i < KER_WORKER_TX_CAPACITY; ++i) {
        input[0] = (unsigned char)i;
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, input, 14);
        CHECK(packet && ker_worker_tx_append(&queue, packet, 2000));
    }
    CHECK(!ker_worker_tx_wait_us(&queue, 100, 2000));
    struct rte_mbuf *extra = rte_pktmbuf_alloc(pool); CHECK(extra);
    CHECK(!ker_worker_tx_append(&queue, extra, 2000)); rte_pktmbuf_free(extra);
    mock = (struct tx_mock){.limit = 11};
    result = ker_worker_tx_flush(&queue, mock_tx_burst, &mock);
    CHECK(result.packets == 11 && result.bytes == 154 && queue.count == 21);
    ker_worker_tx_discard(&queue); /* Shutdown/error frees only the retained suffix. */
    CHECK(!queue.count && rte_mempool_avail_count(pool) == 63);
    rte_mempool_free(pool);
}

struct rx_mock {
    const uint16_t *bursts;
    size_t burst_count;
    size_t calls;
    uint64_t freed;
};
static uint16_t mock_rx_burst(void *context, struct rte_mbuf **packets,
    uint16_t capacity)
{
    struct rx_mock *mock = context;
    if (mock->calls == mock->burst_count) return 0;
    uint16_t count = mock->bursts[mock->calls++];
    if (count > capacity) count = capacity;
    for (uint16_t i = 0; i < count; ++i)
        packets[i] = (struct rte_mbuf *)(uintptr_t)(mock->freed + i + 1);
    return count;
}

static void mock_rx_free(void *context, struct rte_mbuf *packet)
{
    CHECK(packet != NULL);
    struct rx_mock *mock = context;
    mock->freed++;
}

static void test_rx_startup_drain(void)
{
    uint64_t discarded;
    const uint16_t empty[] = {0};
    struct rx_mock mock = {.bursts = empty, .burst_count = 1};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 4,
        &discarded) == 0);
    CHECK(discarded == 0 && mock.freed == 0 && mock.calls == 1);

    const uint16_t queued[] = {2, 1, 0};
    mock = (struct rx_mock){.bursts = queued, .burst_count = 3};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 4,
        &discarded) == 0);
    CHECK(discarded == 3 && mock.freed == 3 && mock.calls == 3);

    const uint16_t exact_budget[] = {2, 2, 0};
    mock = (struct rx_mock){.bursts = exact_budget, .burst_count = 3};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 4,
        &discarded) == 0);
    CHECK(discarded == 4 && mock.freed == 4 && mock.calls == 3);

    const uint16_t continuous[] = {2, 2, 2};
    mock = (struct rx_mock){.bursts = continuous, .burst_count = 3};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 4,
        &discarded) == -EAGAIN);
    CHECK(discarded == 5 && mock.freed == 5 && mock.calls == 3);

    /* A full configured virtio ring exceeds the old adjusted 256-descriptor
     * budget. Drain all 4096 packets, then keep the one-packet overflow probe. */
    uint16_t full_ring[130];
    for (size_t i = 0; i < 128; ++i) full_ring[i] = 32;
    full_ring[128] = 0;
    mock = (struct rx_mock){.bursts = full_ring, .burst_count = 130};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 4096,
        &discarded) == 0);
    CHECK(discarded == 4096 && mock.freed == 4096 && mock.calls == 129);
    full_ring[128] = 1;
    mock = (struct rx_mock){.bursts = full_ring, .burst_count = 130};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 4096,
        &discarded) == -EAGAIN);
    CHECK(discarded == 4097 && mock.freed == 4097 && mock.calls == 129);

    /* Bond drains may cover all member rings and exceed UINT16_MAX. */
    uint16_t large_ring[2189] = {0};
    for (size_t i = 0; i < 2187; i++) large_ring[i] = 32;
    large_ring[2187] = 16;
    mock = (struct rx_mock){.bursts = large_ring, .burst_count = 2189};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 70000,
        &discarded) == 0);
    CHECK(discarded == 70000 && mock.freed == 70000 && mock.calls == 2189);
    large_ring[2188] = 1;
    mock = (struct rx_mock){.bursts = large_ring, .burst_count = 2189};
    CHECK(ker_worker_rx_drain(mock_rx_burst, mock_rx_free, &mock, 70000,
        &discarded) == -EAGAIN);
    CHECK(discarded == 70001 && mock.freed == 70001 && mock.calls == 2189);
}
static void test_scatter_rx_limits(void)
{
    const uint32_t payload = RTE_MBUF_DEFAULT_BUF_SIZE - RTE_PKTMBUF_HEADROOM;
    struct rte_eth_dev_info info = {0};
    info.max_mtu = 9000;
    info.max_rx_pktlen = 9022;
    CHECK(ker_worker_rx_eth_overhead(&info) == 22);
    info.max_rx_pktlen = 9018;
    CHECK(ker_worker_rx_eth_overhead(&info) == RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN);
    info.max_rx_pktlen = 9010;
    CHECK(ker_worker_rx_eth_overhead(&info) == RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN);
    info.max_rx_pktlen = 9024;
    CHECK(ker_worker_rx_eth_overhead(&info) == 24);
    info.max_rx_pktlen = 3;
    CHECK(ker_worker_rx_eth_overhead(&info) == RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN);
    info.max_mtu = UINT16_MAX;
    info.max_rx_pktlen = UINT32_MAX;
    CHECK(ker_worker_rx_eth_overhead(&info) == RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN);

    uint32_t overhead = RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN;
    CHECK(ker_worker_rx_required_segments(payload - overhead, overhead) == 1);
    CHECK(ker_worker_rx_required_segments(2026, overhead) == 1);
    uint64_t required = ker_worker_rx_required_segments(payload - overhead + 1, overhead);
    CHECK(ker_worker_rx_required_segments(2027, overhead) == 2);
    CHECK(required == 2);
    CHECK(ker_worker_rx_required_segments(2034, overhead) == 2);
    CHECK(ker_worker_scatter_required_segments(2034) == 2);
    CHECK(ker_worker_rx_limits_support(required, 2));
    CHECK(ker_worker_rx_limits_support(required, 0));
    CHECK(ker_worker_rx_limits_support(required, UINT16_MAX));
    CHECK(!ker_worker_rx_limits_support(required, 1));
    uint64_t jumbo = ker_worker_rx_required_segments(9000, overhead);
    CHECK(jumbo == 5);
    CHECK(!ker_worker_rx_limits_support(jumbo, 4));
}

static void test_worker_wait_plan(void)
{
    short events;
    int wait_us;
    ker_worker_wait_plan(100000, false, false, &events, &wait_us);
    CHECK(events == POLLIN && wait_us == 100000);
    ker_worker_wait_plan(100000, true, false, &events, &wait_us);
    CHECK(events == 0 && wait_us == 1000);
    ker_worker_wait_plan(100000, false, true, &events, &wait_us);
    CHECK(events == POLLOUT && wait_us == 1000);
    ker_worker_wait_plan(100000, true, true, &events, &wait_us);
    CHECK(events == POLLOUT && wait_us == 1000);
    ker_worker_wait_plan(0, true, false, &events, &wait_us);
    CHECK(events == 0 && wait_us == 0);
}

static void test_descriptor_pool_budget(void)
{
    uint32_t count = 0;
    uint32_t aggregate_rx = 256, aggregate_tx = 256;
    CHECK(ker_worker_mbuf_pool_count(256, 256, &count) == 0 && count == 4095);
    CHECK(ker_worker_mbuf_pool_count(4096, 4096, &count) == 0 && count == 8512);
    CHECK(ker_worker_mbuf_pool_count(32768, 32768, &count) == 0 && count == 65856);
    CHECK(ker_worker_mbuf_pool_count(1, 1, NULL) == -EINVAL);
    CHECK(ker_worker_mbuf_pool_count(UINT32_MAX, 1, &count) == -EOVERFLOW);
    CHECK(ker_worker_mbuf_pool_count(UINT32_MAX - 319, 0, &count) == -EOVERFLOW);
    for (unsigned member = 0; member < 16; member++)
        CHECK(ker_worker_mbuf_budget_add(&aggregate_rx, &aggregate_tx, 256, 256) == 0);
    CHECK(aggregate_rx == 4352 && aggregate_tx == 4352);
    CHECK(ker_worker_mbuf_pool_count(aggregate_rx, aggregate_tx, &count) == 0 && count == 9024);
    aggregate_rx = aggregate_tx = 256;
    for (unsigned member = 0; member < 4; member++)
        CHECK(ker_worker_mbuf_budget_add_queues(&aggregate_rx, &aggregate_tx, 3, 512, 256) == 0);
    CHECK(aggregate_rx == 6400 && aggregate_tx == 3328);
    CHECK(ker_worker_mbuf_budget_add_queues(&aggregate_rx, &aggregate_tx, 0, 1, 1) == -EINVAL);
    CHECK(ker_worker_mbuf_budget_add_queues(&aggregate_rx, &aggregate_tx, 2, UINT32_MAX, 0) == -EOVERFLOW);
    aggregate_rx = aggregate_tx = 256;
    CHECK(ker_worker_mbuf_budget_add(&aggregate_rx, &aggregate_tx, UINT32_MAX, 0) == -EOVERFLOW);
    CHECK(ker_worker_mbuf_budget_add(NULL, &aggregate_tx, 1, 1) == -EINVAL);
}

static void test_handoff_pool_budget(void)
{
    uint32_t count = 0, segments = 0;
    const uint32_t buffer_size = RTE_MBUF_DEFAULT_BUF_SIZE;
    const uint32_t overhead = RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN;
    CHECK(ker_worker_mbuf_frame_segments(9000, overhead, buffer_size, &segments) == 0);
    CHECK(segments == 5);
    CHECK(ker_worker_mbuf_frame_segments(9000, overhead,
        RTE_PKTMBUF_HEADROOM, &segments) == -EINVAL);
    CHECK(ker_worker_mbuf_frame_segments(UINT32_MAX, UINT32_MAX,
        RTE_PKTMBUF_HEADROOM + 1, &segments) == -EOVERFLOW);
    /* Reviewer example: ring usable capacity 255 plus a 32-packet burst. */
    CHECK(ker_worker_mbuf_handoff_pool_count(8512, 16, 287, 5, &count) == 0);
    CHECK(count == 8512 + 22960);
    /* Production conservatively reserves the full 256-slot ring plus burst. */
    CHECK(ker_worker_mbuf_handoff_pool_count(8512, 16, 288, 5, &count) == 0);
    CHECK(count == 8512 + 23040);
    CHECK(ker_worker_mbuf_handoff_pool_count(0, UINT32_MAX, 2, 1, &count) == -EOVERFLOW);
    CHECK(ker_worker_mbuf_handoff_pool_count(0, 1, UINT32_MAX, 2, &count) == -EOVERFLOW);
    CHECK(ker_worker_mbuf_handoff_pool_count(UINT32_MAX, 1, 1, 1, &count) == -EOVERFLOW);
    CHECK(ker_worker_mbuf_handoff_pool_count(0, 0, 1, 0, &count) == -EINVAL);
}

static void test_scatter_segment_limits(void)
{
    const uint32_t payload = RTE_MBUF_DEFAULT_BUF_SIZE - RTE_PKTMBUF_HEADROOM;
    CHECK(ker_worker_scatter_required_segments(payload - RTE_ETHER_HDR_LEN - RTE_VLAN_HLEN) == 1);
    CHECK(ker_worker_scatter_required_segments(payload - RTE_ETHER_HDR_LEN - RTE_VLAN_HLEN + 1) == 2);
    CHECK(ker_worker_scatter_required_segments(2034) == 2);
    uint16_t required = ker_worker_scatter_required_segments(9000);
    CHECK(required == 5);
    CHECK(required == (9018 / payload + (9018 % payload != 0)));
    CHECK(ker_worker_scatter_limits_support(required, required, required));
    CHECK(ker_worker_scatter_limits_support(required, 0, required));
    CHECK(ker_worker_scatter_limits_support(required, required, 0));
    CHECK(ker_worker_scatter_limits_support(required, 0, 0));
    CHECK(!ker_worker_scatter_limits_support(required, required - 1, 0));
    CHECK(!ker_worker_scatter_limits_support(required, 0, required - 1));
    CHECK(!ker_worker_scatter_limits_support(required, required - 1, required));
    CHECK(!ker_worker_scatter_limits_support(required, required, required - 1));
}

int main(void)
{
    test_worker_wait_plan();
    test_descriptor_pool_budget();
    test_handoff_pool_budget();
    test_rx_startup_drain();
    test_scatter_rx_limits();
    test_scatter_segment_limits();
    cpu_set_t cpus;
    CHECK(!sched_getaffinity(0, sizeof(cpus), &cpus));
    int cpu = 0;
    while (cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &cpus)) cpu++;
    CHECK(cpu < CPU_SETSIZE);
    char cores[64];
    snprintf(cores, sizeof(cores), "--lcores=0@%d", cpu);
    char *args[] = {"worker-mbuf", cores, "--no-huge", "--no-pci", "--no-shconf", "--no-telemetry", "--iova-mode=va", "-m", "64"};
    CHECK(rte_eal_init(sizeof(args) / sizeof(args[0]), args) >= 0);
    test_tx_batch();
    struct rte_mempool *pool = rte_pktmbuf_pool_create("chain_test", 31, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(pool);
    unsigned char input[9014], output[9014];
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (unsigned char)(i * 13 + 7);
    const size_t lengths[] = {14, 2047, 2048, 2049, 4096, 9014};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        size_t length = lengths[i];
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, input, length);
        CHECK(packet && packet->pkt_len == length);
        CHECK(packet->nb_segs == (length + 2047) / 2048);
        const void *bytes = rte_pktmbuf_read(packet, 0, length, output);
        CHECK(bytes && !memcmp(bytes, input, length));
        CHECK(rte_mempool_avail_count(pool) == 31u - packet->nb_segs);
        rte_pktmbuf_free(packet);
        CHECK(rte_mempool_avail_count(pool) == 31);
    }
    struct rte_mbuf *held[28];
    for (size_t i = 0; i < 28; i++) CHECK((held[i] = rte_pktmbuf_alloc(pool)));
    CHECK(rte_mempool_avail_count(pool) == 3);
    errno = 0;
    CHECK(!ker_worker_mbuf_from_bytes(pool, input, sizeof(input)) && errno == ENOBUFS);
    CHECK(rte_mempool_avail_count(pool) == 3);
    for (size_t i = 0; i < 28; i++) rte_pktmbuf_free(held[i]);
    CHECK(rte_mempool_avail_count(pool) == 31);
    CHECK(!ker_worker_mbuf_from_bytes(pool, NULL, 14) && errno == EINVAL);
    CHECK(!ker_worker_mbuf_from_bytes(pool, input, 0) && errno == EINVAL);
    rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    puts("PASS: real DPDK mbuf chains, segment boundaries and allocation-failure reclamation");
    return 0;
}
