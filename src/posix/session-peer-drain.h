/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef KER_SESSION_PEER_DRAIN_H
#define KER_SESSION_PEER_DRAIN_H

#include <errno.h>
#include <time.h>

/* Retry only the transient generation-gate race. The caller supplies one
 * deadline for the whole drain batch so a full ring cannot multiply the wait. */
static inline int ker_session_peer_dequeue_until(int (*dequeue)(void *),
    void *context, const struct timespec *deadline)
{
    if (!dequeue || !deadline) return -EINVAL;
    for (;;) {
        int result = dequeue(context);
        if (result != -EBUSY) return result;

        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return -errno;
        if (now.tv_sec > deadline->tv_sec ||
            (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec))
            return -ETIMEDOUT;

        struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
        time_t seconds = deadline->tv_sec - now.tv_sec;
        long nanoseconds = deadline->tv_nsec - now.tv_nsec;
        if (nanoseconds < 0) { seconds--; nanoseconds += 1000000000L; }
        if (seconds == 0 && nanoseconds < delay.tv_nsec) delay.tv_nsec = nanoseconds;
        int sleep_result;
        do { sleep_result = nanosleep(&delay, &delay); }
        while (sleep_result && errno == EINTR);
        if (sleep_result) return -errno;
    }
}

#endif
