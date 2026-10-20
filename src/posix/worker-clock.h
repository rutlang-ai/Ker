/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_WORKER_CLOCK_H
#define KER_WORKER_CLOCK_H
#include <stdint.h>
/* Return 0 and nanoseconds, or -1 with errno and an unchanged output. */
int ker_worker_now_ns(int64_t *nanoseconds);
#endif
