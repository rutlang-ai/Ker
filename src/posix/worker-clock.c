/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "worker-clock.h"
#include <errno.h>
#include <time.h>

int ker_worker_now_ns(int64_t *nanoseconds)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    if (value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return -1;
    }
    if ((uint64_t)value.tv_sec > (uint64_t)(INT64_MAX - value.tv_nsec) / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        return -1;
    }
    *nanoseconds = (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
    return 0;
}
