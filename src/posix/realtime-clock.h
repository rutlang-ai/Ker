/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_NATIVE_REALTIME_CLOCK_H
#define KER_NATIVE_REALTIME_CLOCK_H
/* Synchronize only the booted private Linux kernel. Returns negative errno. */
int ker_native_sync_realtime(void);
#endif
