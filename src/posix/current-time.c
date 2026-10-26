/* SPDX-License-Identifier: GPL-2.0-only */
#include <ker/posix.h>
#include "fd-table.h"
#include "syscall-result.h"
#include <lkl.h>

int ker_posix_get_current_time(int64_t *seconds, long *nanoseconds)
{
    if (!ker_native_ready()) { errno = ENETDOWN; return -1; }
    struct __lkl__kernel_timespec value;
    long result = lkl_sys_clock_gettime(LKL_CLOCK_REALTIME, &value);
    if (result) return (int)ker_native_result(result);
    /* Publish optional outputs only after the original kernel accepted the
     * read. Never substitute host time or expose partial error-path writes. */
    if (seconds) *seconds = value.tv_sec;
    if (nanoseconds) *nanoseconds = value.tv_nsec;
    return 0;
}
