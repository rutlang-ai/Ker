#ifndef KER_POSIX_DIAGNOSTICS_H
#define KER_POSIX_DIAGNOSTICS_H
#include <stdint.h>
struct ker_native_counters {
    uint64_t active_opens, passive_opens, retransmitted_segments;
    uint64_t zero_window_probes, out_of_order_queued;
    uint64_t udp_in_datagrams, udp_out_datagrams, udp_in_errors, udp_no_ports;
    uint64_t ip_frag_ok, ip_frag_creates, ip_reasm_ok, ip_reasm_fails;
};
int ker_native_counters(struct ker_native_counters *out);
#endif
