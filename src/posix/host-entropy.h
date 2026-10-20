/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_NATIVE_HOST_ENTROPY_H
#define KER_NATIVE_HOST_ENTROPY_H
/* Called after original Linux boots, before exposing application sockets.
 * Returns zero or a negative host/Linux errno. Only the private kernel is seeded. */
int ker_native_seed_entropy(void);
#endif
