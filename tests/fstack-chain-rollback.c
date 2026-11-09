#include "check.h"
#include "eal.h"
#include "runtime/memory.h"
#include "runtime/skb.h"
#include <errno.h>
#include <string.h>

#define POOL_COUNT 63U
#define MAX_LENGTH 37U

/* Scenario adaptation of F-Stack's multiseg/copydata-failure cases. Exhaust
 * real pool objects at every allocation boundary; no allocator or BSD stubs. */
typedef int (*export_fn)(struct sk_buff *, unsigned int, struct rte_mbuf **);

static uint16_t wire_checksum(const uint8_t *bytes, unsigned int length)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < length; i += 2) {
        sum += (uint32_t)bytes[i] << 8;
        if (i + 1 < length) sum += bytes[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static void verify_chain(struct rte_mbuf *chain, const uint8_t *expected,
    unsigned int length, unsigned int limit, unsigned int headroom)
{
    unsigned int offset = 0, segments = 0;
    CHECK(chain && chain->pkt_len == length &&
        chain->nb_segs == (length + limit - 1) / limit);
    for (struct rte_mbuf *seg = chain; seg; seg = seg->next) {
        CHECK(RTE_MBUF_DIRECT(seg) && !RTE_MBUF_HAS_EXTBUF(seg) &&
            rte_mbuf_refcnt_read(seg) == 1 && !seg->ol_flags && !seg->tx_offload);
        CHECK(seg->data_off == (segments ? RTE_PKTMBUF_HEADROOM : headroom));
        CHECK(seg->data_len == RTE_MIN(limit, length - offset));
        CHECK(!memcmp(rte_pktmbuf_mtod(seg, const void *), expected + offset,
            seg->data_len));
        offset += seg->data_len;
        ++segments;
    }
    CHECK(offset == length && segments == chain->nb_segs);
}

static void allocation_sweep(struct ker_packet_pool *pool,
    struct ker_skb_context *context, export_fn export, bool partial, bool exact,
    unsigned int length, unsigned int limit, unsigned int headroom, bool zero,
    unsigned int layout)
{
    struct sk_buff *skb = NULL;
    uint8_t *data = NULL, original[MAX_LENGTH], expected[MAX_LENGTH];
    CHECK(ker_skb_alloc(context, length, headroom, &skb) == 0);
    CHECK(ker_skb_put(skb, length, &data) == 0);
    for (unsigned int i = 0; i < length; ++i) data[i] = (uint8_t)(i * 17U + 3U);
    /* Cover a field at the beginning, across tiny segments, and at the end.
     * The checksum range starts on both even and odd byte offsets. */
    unsigned int start = layout == 1 ? 0 : 1;
    unsigned int field = layout == 1 ? 0 : layout == 2 ? length - 2 : 3;
    if (partial) {
        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum_start = (uint16_t)(headroom + start);
        skb->csum_offset = (uint16_t)(field - start);
        if (zero) {
            bool found = false;
            for (unsigned int seed = 0; seed <= UINT16_MAX; ++seed) {
                data[field] = (uint8_t)(seed >> 8);
                data[field + 1] = (uint8_t)seed;
                if (wire_checksum(data + start, length - start) == 0) {
                    found = true;
                    break;
                }
            }
            CHECK(found);
        }
    }
    memcpy(original, data, length);
    memcpy(expected, data, length);
    if (partial) {
        uint16_t checksum = wire_checksum(data + start, length - start);
        if (!exact && !checksum) checksum = UINT16_MAX;
        expected[field] = (uint8_t)(checksum >> 8);
        expected[field + 1] = (uint8_t)checksum;
    }
    const unsigned int required = (length + limit - 1) / limit;
    struct rte_mbuf *held[POOL_COUNT];
    unsigned int held_count = 0;
    while (held_count < POOL_COUNT &&
        (held[held_count] = ker_packet_alloc(pool)) != NULL) ++held_count;
    CHECK(rte_mempool_avail_count(pool->mbufs) == 0 && held_count >= required);
    const unsigned int exhausted_count = held_count;
    uint16_t saved_start = skb->csum_start, saved_offset = skb->csum_offset;
    unsigned int saved_truesize = skb->truesize;

    for (unsigned int available = 0; available < required; ++available) {
        if (available) ker_packet_free(held[--held_count]);
        /* Repetition detects leaks that only become visible on a retry. */
        for (unsigned int retry = 0; retry < 2; ++retry) {
            struct rte_mbuf *out = (void *)(uintptr_t)1;
            CHECK(export(skb, limit, &out) == -ENOMEM);
            CHECK(out == (void *)(uintptr_t)1 && context->live == 1);
            CHECK(rte_mempool_avail_count(pool->mbufs) == available);
            CHECK(skb->data == data && skb->len == length &&
                skb_headroom(skb) == headroom && skb->truesize == saved_truesize &&
                refcount_read(&skb->users) == 1 &&
                skb->ip_summed == (partial ? CHECKSUM_PARTIAL : CHECKSUM_NONE) &&
                skb->csum_start == saved_start && skb->csum_offset == saved_offset);
            CHECK(!memcmp(data, original, length));
        }
    }
    ker_packet_free(held[--held_count]);
    CHECK(rte_mempool_avail_count(pool->mbufs) == required);
    struct rte_mbuf *out = NULL;
    CHECK(export(skb, limit, &out) == 0);
    CHECK(rte_mempool_avail_count(pool->mbufs) == 0 && context->live == 1 &&
        !memcmp(data, original, length));
    verify_chain(out, expected, length, limit, headroom);
    CHECK(ker_skb_free(skb) == 0 && context->live == 0);
    verify_chain(out, expected, length, limit, headroom);
    ker_packet_free(out);
    CHECK(rte_mempool_avail_count(pool->mbufs) == POOL_COUNT - held_count);
    CHECK(held_count + required == exhausted_count);
    while (held_count) ker_packet_free(held[--held_count]);
    CHECK(rte_mempool_avail_count(pool->mbufs) == POOL_COUNT);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    bool partial = strcmp(argv[1], "copy") != 0;
    bool exact = strcmp(argv[1], "exact") == 0;
    CHECK(!partial || exact || strcmp(argv[1], "checksum") == 0);
    export_fn export = !partial ? ker_skb_to_mbuf_chain_copy : exact ?
        ker_skb_to_mbuf_chain_software_checksum_exact :
        ker_skb_to_mbuf_chain_software_checksum;
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_packet_pool pool = {0};
    struct ker_skb_context context = {0};
    CHECK(ker_packet_pool_init(&pool, "rollback_pool", POOL_COUNT, 0, 4096,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "rollback_skb") == 0);
    const unsigned int lengths[] = {16, MAX_LENGTH};
    const unsigned int limits[] = {1, 2, 7, MAX_LENGTH};
    const unsigned int headrooms[] = {64, 192};
    for (unsigned int i = 0; i < RTE_DIM(lengths); ++i)
        for (unsigned int j = 0; j < RTE_DIM(limits); ++j)
            for (unsigned int h = 0; h < RTE_DIM(headrooms); ++h)
                for (unsigned int layout = 0; layout < (partial ? 3U : 1U); ++layout)
                    for (unsigned int zero = 0; zero <= (unsigned int)partial; ++zero)
                        allocation_sweep(&pool, &context, export, partial, exact,
                            lengths[i], limits[j], headrooms[h], zero != 0, layout);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_live_allocations() == 0 && ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
