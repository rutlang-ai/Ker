#ifndef KER_POSIX_DIAGNOSTICS_H
#define KER_POSIX_DIAGNOSTICS_H
#include <stdint.h>
struct ker_native_counters {
    uint64_t active_opens, passive_opens, retransmitted_segments;
    uint64_t zero_window_probes, out_of_order_queued;
};
int ker_native_counters(struct ker_native_counters *out);
#endif
