#include "check.h"
#include "eal.h"
#include "runtime/memory.h"
#include "runtime/tx-export.h"
#include <errno.h>
#include <string.h>

#define POOL_COUNT 63U
#define PACKETS 3U
#define MAX_LENGTH 25U
#define HEADROOM 192U

/* F-Stack segmented-send/failure scenarios adapted to Ker's bounded TX FIFO.
 * These are opaque bytes, not a transport implementation or NIC test. */
struct packet_record {
    struct sk_buff *original;
    uint8_t before[MAX_LENGTH], expected[MAX_LENGTH];
    unsigned int length, charge;
};
struct sink_state {
    struct packet_record records[PACKETS];
    struct rte_mbuf *accepted;
    unsigned int calls, next, limit;
    int error;
};

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

static void check_original(const struct packet_record *record, bool partial)
{
    const struct sk_buff *skb = record->original;
    CHECK(skb->len == record->length && skb->truesize == record->charge &&
        skb_headroom(skb) == HEADROOM && refcount_read(&skb->users) == 1);
    CHECK(skb->ip_summed == (partial ? CHECKSUM_PARTIAL : CHECKSUM_NONE));
    if (partial) CHECK(skb->csum_start == HEADROOM + 1 && skb->csum_offset == 2);
    CHECK(!memcmp(skb->data, record->before, record->length));
}

static void check_copy(struct rte_mbuf *chain,
    const struct packet_record *record, unsigned int limit)
{
    unsigned int offset = 0, count = 0;
    CHECK(chain->pkt_len == record->length &&
        chain->nb_segs == (record->length + limit - 1) / limit);
    for (struct rte_mbuf *segment = chain; segment; segment = segment->next) {
        CHECK(RTE_MBUF_DIRECT(segment) && !RTE_MBUF_HAS_EXTBUF(segment) &&
            rte_mbuf_refcnt_read(segment) == 1 && !segment->ol_flags &&
            !segment->tx_offload);
        CHECK(segment->data_off == (count ? RTE_PKTMBUF_HEADROOM : HEADROOM));
        CHECK(segment->data_len == RTE_MIN(limit, record->length - offset));
        CHECK(!memcmp(rte_pktmbuf_mtod(segment, const void *),
            record->expected + offset, segment->data_len));
        offset += segment->data_len;
        ++count;
    }
    CHECK(offset == record->length && count == chain->nb_segs);
}

static int sink(struct rte_mbuf *chain, void *arg)
{
    struct sink_state *state = arg;
    CHECK(state->next < PACKETS && !state->accepted);
    check_copy(chain, &state->records[state->next], state->limit);
    ++state->calls;
    if (state->error) return state->error;
    state->accepted = chain;
    ++state->next;
    return 0;
}

static void make_packet(struct ker_skb_context *context,
    struct packet_record *record, unsigned int length, unsigned int tag,
    bool partial, bool exact)
{
    uint8_t *data = NULL;
    CHECK(ker_skb_alloc(context, length, HEADROOM, &record->original) == 0);
    CHECK(ker_skb_put(record->original, length, &data) == 0);
    record->length = length;
    record->charge = record->original->truesize;
    for (unsigned int i = 0; i < length; ++i) data[i] = (uint8_t)(tag + i * 17U);
    if (partial) {
        record->original->ip_summed = CHECKSUM_PARTIAL;
        record->original->csum_start = HEADROOM + 1;
        record->original->csum_offset = 2;
        /* Distinguish exact folding from the legacy zero-mangling mode. */
        bool found = false;
        for (unsigned int seed = 0; seed <= UINT16_MAX; ++seed) {
            data[3] = (uint8_t)(seed >> 8);
            data[4] = (uint8_t)seed;
            if (!wire_checksum(data + 1, length - 1)) { found = true; break; }
        }
        CHECK(found);
    }
    memcpy(record->before, data, length);
    memcpy(record->expected, data, length);
    if (partial) {
        uint16_t checksum = wire_checksum(data + 1, length - 1);
        if (!exact && !checksum) checksum = UINT16_MAX;
        record->expected[3] = (uint8_t)(checksum >> 8);
        record->expected[4] = (uint8_t)checksum;
    }
}

static void exercise(struct ker_packet_pool *pool, struct ker_skb_context *context,
    bool partial, bool exact, unsigned int limit)
{
    struct ker_tx_export tx = {0};
    struct sink_state state = {.limit = limit};
    int (*init)(struct ker_tx_export *, struct ker_skb_context *, unsigned int,
        size_t, unsigned int, ker_tx_export_sink_fn, void *) =
        !partial ? ker_tx_export_init_chain : exact ?
        ker_tx_export_init_chain_software_checksum_exact :
        ker_tx_export_init_chain_software_checksum;
    CHECK(init(&tx, context, PACKETS, SIZE_MAX, limit, sink, &state) == 0);
    const unsigned int lengths[] = {17, 25, 9};
    size_t total_charge = 0;
    for (unsigned int i = 0; i < PACKETS; ++i) {
        make_packet(context, &state.records[i], lengths[i], 3 + i * 47,
            partial, exact);
        struct sk_buff *skb = state.records[i].original;
        total_charge += skb->truesize;
        CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    }
    CHECK(tx.packets == PACKETS && tx.bytes == total_charge && context->live == PACKETS);
    struct rte_mbuf *held[POOL_COUNT];
    unsigned int held_count = 0;
    while (held_count < POOL_COUNT &&
        (held[held_count] = ker_packet_alloc(pool)) != NULL) ++held_count;
    CHECK(held_count == POOL_COUNT - PACKETS && !rte_mempool_avail_count(pool->mbufs));
    unsigned int required = (lengths[0] + limit - 1) / limit;
    for (unsigned int available = 0; available < required; ++available) {
        if (available) ker_packet_free(held[--held_count]);
        for (unsigned int retry = 0; retry < 2; ++retry) {
            CHECK(ker_tx_export_poll(&tx, PACKETS) == -ENOMEM);
            CHECK(tx.pending == state.records[0].original &&
                tx.pending_charge == state.records[0].charge &&
                tx.packets == PACKETS && tx.bytes == total_charge &&
                tx.last_error == -ENOMEM && !tx.last_completed && !tx.polling);
            CHECK(!state.calls && !state.next && !state.accepted && context->live == PACKETS);
            CHECK(rte_mempool_avail_count(pool->mbufs) == available);
            for (unsigned int i = 0; i < PACKETS; ++i) check_original(&state.records[i], partial);
            CHECK(ker_tx_export_cleanup(&tx) == -EBUSY);
        }
    }
    ker_packet_free(held[--held_count]);
    const int errors[] = {-EAGAIN, -ENOBUFS, 1};
    for (unsigned int i = 0; i < RTE_DIM(errors); ++i) {
        state.error = errors[i];
        int expected_error = errors[i] > 0 ? -EPROTO : errors[i];
        CHECK(ker_tx_export_poll(&tx, PACKETS) == expected_error);
        CHECK(tx.last_error == expected_error && !tx.last_completed &&
            tx.pending == state.records[0].original && tx.bytes == total_charge &&
            tx.packets == PACKETS && context->live == PACKETS);
        CHECK(state.calls == i + 1 && !state.next && !state.accepted);
        CHECK(rte_mempool_avail_count(pool->mbufs) == required);
        for (unsigned int j = 0; j < PACKETS; ++j) check_original(&state.records[j], partial);
    }
    state.error = 0;
    /* The accepted copy holds every free mbuf. Freeing its source makes only
     * one available, so the next FIFO entry must fail after a successful prefix. */
    CHECK(ker_tx_export_poll(&tx, PACKETS) == 1);
    CHECK(state.calls == RTE_DIM(errors) + 1 && state.next == 1 && state.accepted);
    CHECK(tx.last_completed == 1 && tx.last_error == -ENOMEM &&
        tx.pending == state.records[1].original && tx.pending_charge == state.records[1].charge &&
        tx.packets == PACKETS - 1 && tx.bytes == total_charge - state.records[0].charge);
    CHECK(context->live == PACKETS - 1 && rte_mempool_avail_count(pool->mbufs) == 1);
    /* Cancel the pending head before its queued successor. */
    for (unsigned int i = 1; i < PACKETS; ++i) {
        struct sk_buff *returned = NULL;
        CHECK(ker_tx_export_cancel(&tx, &returned) == 1 && returned == state.records[i].original);
        check_original(&state.records[i], partial);
        CHECK(tx.packets == PACKETS - i - 1 && !tx.pending);
    }
    CHECK(!tx.pending && !tx.pending_charge && !tx.packets && !tx.bytes &&
        context->live == PACKETS - 1);
    struct sk_buff *unchanged = (void *)(uintptr_t)1;
    CHECK(ker_tx_export_cancel(&tx, &unchanged) == 0 && unchanged == (void *)(uintptr_t)1);
    check_copy(state.accepted, &state.records[0], limit);
    ker_packet_free(state.accepted);
    state.accepted = NULL;
    while (held_count) ker_packet_free(held[--held_count]);
    /* Restore resources and re-enqueue the exact canceled originals. */
    for (unsigned int i = 1; i < PACKETS; ++i) {
        struct sk_buff *skb = state.records[i].original;
        CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    }
    for (unsigned int i = 1; i < PACKETS; ++i) {
        CHECK(ker_tx_export_poll(&tx, 1) == 1);
        CHECK(tx.last_completed == 1 && !tx.last_error && !tx.pending &&
            tx.packets == PACKETS - i - 1 && context->live == PACKETS - i - 1);
        CHECK(state.next == i + 1 && state.accepted);
        check_copy(state.accepted, &state.records[i], limit);
        ker_packet_free(state.accepted);
        state.accepted = NULL;
    }
    CHECK(!tx.bytes && !tx.pending_charge && state.calls == RTE_DIM(errors) + PACKETS);
    CHECK(ker_tx_export_cleanup(&tx) == 0 && !context->queue_live);
    CHECK(rte_mempool_avail_count(pool->mbufs) == POOL_COUNT);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    bool partial = strcmp(argv[1], "copy") != 0;
    bool exact = strcmp(argv[1], "exact") == 0;
    CHECK(!partial || exact || strcmp(argv[1], "checksum") == 0);
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_packet_pool pool = {0};
    struct ker_skb_context context = {0};
    CHECK(ker_packet_pool_init(&pool, "tx_rollback", POOL_COUNT, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tx_rollback_skb") == 0);
    const unsigned int limits[] = {1, 2, 7};
    for (unsigned int i = 0; i < RTE_DIM(limits); ++i)
        exercise(&pool, &context, partial, exact, limits[i]);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(!ker_memory_live_allocations() && ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
