/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_SESSION_RING_NAMES_H
#define KER_SESSION_RING_NAMES_H
#include "io-session.h"
#include <stdio.h>

/* Same-host resident namespace; not the F-Stack ring-name ABI. */
static inline int ker_session_ring_name(char *name, size_t size,
    unsigned slot, unsigned generation, unsigned process, unsigned channel)
{
    static const char *const channels[] = {"ctl", "rx", "tx", "reply"};
    if (!name || slot >= KER_SESSION_SLOTS || generation >= KER_SESSION_GENERATIONS ||
        process >= KER_SESSION_PROCESSES || channel >= KER_SESSION_CHANNELS)
        return -EINVAL;
    int result = snprintf(name, size, "ker_s%u_g%u_p%u_%s", slot, generation, process, channels[channel]);
    return result < 0 || (size_t)result >= size ? -ENAMETOOLONG : 0;
}
#endif
