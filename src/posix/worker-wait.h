#ifndef KER_WORKER_WAIT_H
#define KER_WORKER_WAIT_H

#include <stdbool.h>
#include <poll.h>

/* Select readiness interests and timeout for one worker wait. Retained packet
 * state needs bounded retries; only an otherwise idle worker waits its full
 * configured interval for new channel TX or control input. */
static inline void ker_worker_wait_plan(int idle_sleep_us, bool tx_pending,
    bool rx_pending, short *packet_events, int *wait_us)
{
    *packet_events = POLLIN;
    *wait_us = idle_sleep_us;
    if (tx_pending || rx_pending) {
        if (*wait_us > 1000) *wait_us = 1000;
        if (rx_pending) *packet_events = POLLOUT;
        else if (tx_pending) *packet_events = 0;
    }
}

#endif
