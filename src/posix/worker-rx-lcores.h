#ifndef KER_WORKER_RX_LCORES_H
#define KER_WORKER_RX_LCORES_H
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#define KER_RX_QUEUES 16
#define KER_RX_BURST 32
#define KER_RX_HANDOFF_CAPACITY 256
struct ker_worker_rx_lcores;
struct ker_pcap;
struct ker_rx_poll_queue {
    struct rte_ring *handoff;
    unsigned owner, observed;
    int cpu;
    uint64_t polled, polls, stalled, shutdown;
    struct rte_mbuf *pending[KER_RX_BURST];
    uint16_t count, index;
};
struct ker_rx_poller {
    struct ker_worker_rx_lcores *rx;
    unsigned lcore;
    bool launched;
};
struct ker_worker_rx_lcores {
    uint16_t port, queues;
    unsigned main, count;
    bool remote;
    int notify_fd;
    atomic_bool stopping;
    atomic_int error;
    struct ker_rx_poll_queue queue[KER_RX_QUEUES];
    struct ker_rx_poller poller[KER_RX_QUEUES];
};
/* Each selected enabled EAL lcore owns at least one disjoint ethdev RX queue.
 * NULL preserves main-only polling. Exception delivery requires main inclusion.
 * Call plan before configuring the device, start after device/queue setup. */
int ker_worker_rx_lcores_plan(struct ker_worker_rx_lcores *, uint16_t port,
    uint16_t queues, const char *selection, bool require_main);
int ker_worker_rx_lcores_start(struct ker_worker_rx_lcores *);
/* Main-lcore consumer; hands off complete mbufs without changing their bytes
 * or metadata. A full SP/SC ring retains its producer's FIFO suffix. */
uint16_t ker_worker_rx_lcores_burst(struct ker_worker_rx_lcores *, uint16_t queue,
    struct rte_mbuf **packets, uint16_t capacity);
void ker_worker_rx_lcores_ack(struct ker_worker_rx_lcores *);
/* Join all producers before touching PMD queues/pool. Frees retained/queued
 * suffixes once and preserves final statistics. Safe after partial startup. */
int ker_worker_rx_lcores_stop(struct ker_worker_rx_lcores *, uint64_t *discarded, struct ker_pcap *capture);
#endif
