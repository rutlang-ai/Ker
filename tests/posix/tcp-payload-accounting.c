#ifdef NDEBUG
#undef NDEBUG
#endif
#include <asm/ker_tcp_payload_accounting.h>
#include <asm/ker_tcp_payload.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(struct ker_tcp_payload_request) == 32,
    "private ioctl ABI must remain fixed-width");

static void expect(__u32 seq, __u32 end_seq, __u32 snd_una, __u32 payload,
    bool syn, bool fin, __u64 expected)
{
    __u64 result = UINT64_MAX;
    assert(ker_tcp_payload_pending(seq, end_seq, snd_una, payload,
        syn, fin, &result) == 0);
    assert(result == expected);
}

int main(void)
{
    /* Full payload, partial cumulative ACK, and pcount-independent prefix. */
    expect(100, 200, 100, 100, false, false, 100);
    expect(100, 200, 137, 100, false, false, 63);
    expect(100, 200, 200, 100, false, false, 0);

    /* A data-bearing SYN reserves one sequence number but its payload counts. */
    expect(100, 201, 101, 100, true, false, 100);
    expect(100, 201, 151, 100, true, false, 50);

    /* FIN consumes sequence space but has no payload bytes. */
    expect(100, 101, 100, 0, false, true, 0);
    expect(100, 201, 100, 100, false, true, 100);
    expect(100, 201, 200, 100, false, true, 0);

    /* Wraparound retains ordinary TCP half-range ordering. */
    expect(UINT32_MAX - 9, 90, UINT32_MAX - 4, 100, false, false, 95);
    expect(UINT32_MAX - 9, 90, 40, 100, false, false, 50);

    __u64 ignored = 0;
    assert(ker_tcp_payload_pending(1, 3, 1, 1, false, false, &ignored) < 0);
    assert(ker_tcp_payload_pending(1, 0x80000001U, 1,
        0x80000000U, false, false, &ignored) < 0);
    assert(ker_tcp_payload_pending(1, 2, 0x80000001U,
        1, false, false, &ignored) < 0);
    assert(ker_tcp_payload_pending(1, 2, 1, 1,
        false, false, NULL) < 0);
    __u64 total = UINT64_MAX - 5;
    assert(ker_tcp_payload_accumulate(&total, 5) == 0);
    assert(total == UINT64_MAX);
    assert(ker_tcp_payload_accumulate(&total, 1) < 0);
    assert(total == UINT64_MAX);
    assert(ker_tcp_payload_accumulate(NULL, 1) < 0);
    __u32 total_nodes = 0, socket_nodes = 0;
    for (__u32 i = 0; i < KER_TCP_PAYLOAD_MAX_SKB_NODES_PER_SOCKET; ++i)
        assert(ker_tcp_payload_queue_node(&total_nodes, &socket_nodes) == 0);
    assert(total_nodes == KER_TCP_PAYLOAD_MAX_SKB_NODES_PER_SOCKET);
    assert(ker_tcp_payload_queue_node(&total_nodes, &socket_nodes) < 0);
    total_nodes = KER_TCP_PAYLOAD_MAX_SKB_NODES_TOTAL - 1;
    socket_nodes = 0;
    assert(ker_tcp_payload_queue_node(&total_nodes, &socket_nodes) == 0);
    assert(total_nodes == KER_TCP_PAYLOAD_MAX_SKB_NODES_TOTAL);
    assert(ker_tcp_payload_queue_node(&total_nodes, &socket_nodes) < 0);
    return 0;
}
