// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "host-clock.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <lkl_host.h>

/* LKL's time callback cannot return an error. Do not let a failed host clock
 * feed uninitialized timestamps into original Linux timers and scheduling.
 * The pinned callback ignores clock_gettime's result; adapt it here. */
static unsigned long long monotonic_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("ker: host monotonic clock");
        abort();
    }
    return (unsigned long long)value.tv_sec * 1000000000ULL + value.tv_nsec;
}
/* The upstream POSIX panic uses assert(0), which can return under NDEBUG.
 * Kernel panic is unconditionally fatal, including Release builds. */
static void host_panic(void)
{
    abort();
}
void ker_native_host_clock_init(struct lkl_host_operations *ops)
{
    ops->time = monotonic_ns;
    ops->panic = host_panic;
}
