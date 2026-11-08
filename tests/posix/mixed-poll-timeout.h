#ifndef KER_MIXED_POLL_TIMEOUT_H
#define KER_MIXED_POLL_TIMEOUT_H
#include <sys/time.h>
static inline void mixed_poll_update_timeout(struct timeval *timeout,
                                             long long budget,
                                             long long used,
                                             int poll_result)
{
    long long remaining = poll_result == 0 || used >= budget ? 0 : budget - used;
    timeout->tv_sec = remaining / 1000000;
    timeout->tv_usec = remaining % 1000000;
}
#endif
