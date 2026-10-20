/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "realtime-clock.h"
#include <errno.h>
#include <time.h>
#include <lkl.h>

int ker_native_sync_realtime(void)
{
    /* The host callback used for protocol timers remains monotonic. Only
     * private Linux realtime receives the host's wall-clock epoch. */
    struct timespec host;
    if (clock_gettime(CLOCK_REALTIME, &host)) return -errno;
    struct __lkl__kernel_timespec native = {.tv_sec = host.tv_sec, .tv_nsec = host.tv_nsec};
    return (int)lkl_sys_clock_settime(LKL_CLOCK_REALTIME, &native);
}
