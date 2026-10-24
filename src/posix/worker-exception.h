/* Owned Ethernet frames between a worker and an exclusive host Linux TAP. */
#ifndef KER_WORKER_EXCEPTION_H
#define KER_WORKER_EXCEPTION_H
#include <stdbool.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "worker-exception-filter.h"
enum ker_exception_route { KER_EXCEPTION_NATIVE, KER_EXCEPTION_HOST, KER_EXCEPTION_SHARED, KER_EXCEPTION_DROP };
struct ker_pcap;
struct rte_ether_addr;
struct ker_worker_exception {
    int fd;
    struct rte_mempool *pool;
    struct rte_ring *pending;
    unsigned owner;
    uint16_t ether_type;
    bool port_mode, reject;
    struct ker_exception_filter filter;
    uint64_t shared_selected, shared_arp, shared_icmp_error, shared_failed, fragment_dropped;
    uint32_t rate_limit, console_limit, general_limit;
    uint64_t console_packets, general_packets;
    uint64_t console_charged, general_charged, console_dropped, general_dropped;
    int64_t window_start;
    uint64_t window_packets, selected, enqueued, to_host, to_host_dropped;
    uint64_t host_received, from_host, wire_dropped, malformed, shutdown_dropped, rate_dropped;
};
/* Creates a new nonpersistent TAP. Existing interfaces are never attached or
 * modified. The borrowed pool outlives close; the MAC is the wire PMD MAC.
 * No vnet header/offloads; caller owns only complete Ethernet frames. */
int ker_worker_exception_open(struct ker_worker_exception *bridge, const char *iface,
    struct rte_mempool *pool, const struct rte_ether_addr *mac, unsigned mtu, uint16_t ether_type, unsigned capacity, uint32_t rate_limit, uint32_t console_limit, uint32_t general_limit);
/* Resolve the currently owned TAP via its live fd, including after rename.
 * Device control stays on the opening EAL lcore. Setter verifies readback;
 * callers must roll back both devices if a setter fails after mutation. */
int ker_worker_exception_mtu(struct ker_worker_exception *bridge, unsigned *mtu, bool set);
/* Snapshot both exception directions on its owning lcore. Returns 1 when
 * either adapter queue has pending work, 0 when currently quiescent. */
int ker_worker_exception_mtu_busy(struct ker_worker_exception *bridge);
enum ker_exception_route ker_worker_exception_route(const struct ker_worker_exception *, const struct rte_mbuf *);
/* Outer EtherType predicate; route() also handles port/control policies. */
bool ker_worker_exception_matches(const struct ker_worker_exception *bridge, const struct rte_mbuf *packet);
/* Same lcore as open/poll/close. Successful enqueue or -ENOBUFS consumes and
 * NULLs *packet, including freeing an admission-limit or full-queue drop. Other errors retain it. */
int ker_worker_exception_enqueue(struct ker_worker_exception *bridge, struct rte_mbuf **packet);
/* Delivers one bounded burst each way. Only the accepted wire TX prefix is
 * transferred to the PMD; all unaccepted owned mbufs are freed exactly once.
 * rate_limit is a per-second batch gate (a batch may overshoot), not pacing. */
int ker_worker_exception_poll(struct ker_worker_exception *bridge, uint16_t wire_port,
    unsigned mtu, int64_t now_ns, struct ker_pcap *capture, bool *progress);
int ker_worker_exception_close(struct ker_worker_exception *bridge);
#endif
