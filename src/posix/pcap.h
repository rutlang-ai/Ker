#ifndef KER_PACKET_CAPTURE_H
#define KER_PACKET_CAPTURE_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
struct rte_mbuf;
/* One worker owns each capture. Packets are borrowed, never consumed. */
struct ker_pcap {
    FILE *file;
    char *directory;
    char *prefix;
    uint64_t bytes, maximum;
    uint32_t snaplen;
    unsigned int slot;
    bool nanoseconds, failed;
};
int ker_pcap_open(struct ker_pcap *capture, const char *directory,
    const char *prefix, uint32_t snaplen, uint64_t maximum, bool nanoseconds);
int ker_pcap_write(struct ker_pcap *capture, const struct rte_mbuf *packet,
    const struct timespec *timestamp);
int ker_pcap_close(struct ker_pcap *capture);
#endif
