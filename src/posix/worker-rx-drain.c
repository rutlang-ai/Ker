#include "worker-rx-drain.h"

#include <errno.h>

#define RX_DRAIN_BURST 32

int ker_worker_rx_drain(ker_worker_rx_burst_fn burst,
    ker_worker_rx_free_fn free_packet, void *context, uint16_t packet_budget,
    uint64_t *discarded)
{
    struct rte_mbuf *packets[RX_DRAIN_BURST];
    uint32_t consumed = 0;

    if (!burst || !free_packet || !discarded) return -EINVAL;
    *discarded = 0;
    for (;;) {
        uint16_t capacity = RX_DRAIN_BURST;
        if (consumed >= packet_budget) capacity = 1;
        else if (packet_budget - consumed < capacity)
            capacity = (uint16_t)(packet_budget - consumed);

        uint16_t count = burst(context, packets, capacity);
        if (count > capacity) {
            for (uint16_t i = 0; i < capacity; ++i)
                free_packet(context, packets[i]);
            return -EIO;
        }
        if (!count) return 0;
        for (uint16_t i = 0; i < count; ++i) free_packet(context, packets[i]);
        consumed += count;
        *discarded = consumed;
        if (consumed > packet_budget) return -EAGAIN;
    }
}
