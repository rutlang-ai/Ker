/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_SESSION_GENERATION_RINGS_H
#define KER_SESSION_GENERATION_RINGS_H

#include <stdint.h>
#include <stdatomic.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#define KER_GENERATION_RING_CAPACITY 64U
#define KER_GENERATION_RING_GENERATIONS 2U
#define KER_GENERATION_CLEANUP_CONFIG_VERSION 1U

/* Primary-private cleanup selection for the current one-port generation-ring
 * geometry. Queue bits describe which existing rings cleanup may reclaim;
 * they do not configure the physical PMD/control port. */
struct ker_generation_cleanup_config {
    uint32_t version;
    uint32_t size;
    uint16_t ports;
    uint16_t queues;
    uint64_t rx_queue_mask;
    uint64_t tx_queue_mask;
};

struct ker_generation_identity {
    uint64_t session;
    uint64_t epoch;
    uint32_t slot;
    uint32_t generation;
    uint32_t process;
    uint32_t pid;
};

struct ker_generation_rings;

/* Quiescent primary snapshot of the shared generation-ring telemetry.
 * Full counters are enqueue failures caused by a full DPDK ring. Peaks are
 * event-time observed occupancy maxima, aggregated as maxima across rings.
 * tx_drop counts accepted queued TX logical packets/chains that a validated
 * resident detach/death ring transaction removes and frees before consumer
 * release. It excludes segments, off-ring/inflight journals, failed or rolled
 * back cleanup, consumer releases, and caller-owned full-enqueue rejections. */
struct ker_generation_ring_stats {
    uint64_t rx_full;
    uint64_t tx_full;
    uint64_t tx_drop;
    uint64_t packet_drop;
    uint64_t packet_full;
    uint32_t rx_peak;
    uint32_t tx_peak;
    uint32_t rx_capacity;
    uint32_t tx_capacity;
    uint32_t rx_rings;
    uint32_t tx_rings;
};

/* The primary creates permanent port/queue/generation RX and TX rings.
 * Secondary attaches only to already-created rings. Neither operation changes
 * Linux protocol state; these rings transfer original DPDK mbuf objects. */
int ker_generation_rings_create(uint64_t session, uint16_t ports,
    uint16_t queues, struct rte_mempool *pool, struct ker_generation_rings **out);
int ker_generation_rings_attach(uint64_t session, uint16_t ports,
    uint16_t queues, struct rte_mempool *pool, struct ker_generation_rings **out);
int ker_generation_rings_detach(struct ker_generation_rings *rings);
int ker_generation_admit(struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity, int registered_pidfd);
int ker_generation_unregister(struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity);
/* Resident-only orderly detach. Close the selected generation's operation
 * gate, validate journal/ring ownership, and reclaim its configured RX ring
 * plus TX only when requested by the resident's pinned detach decision. */
int ker_generation_orderly_detach(struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,
    const struct ker_generation_cleanup_config *cleanup, int drain_tx,
    unsigned *rx_reclaimed, unsigned *tx_reclaimed);
int ker_generation_orderly_detach_ready(struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,
    const struct ker_generation_cleanup_config *cleanup);

int ker_generation_rx_enqueue(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer, uint16_t port,
    uint16_t queue, uint32_t target_generation, struct rte_mbuf *packet);
int ker_generation_rx_dequeue(struct ker_generation_rings *rings,
    const struct ker_generation_identity *consumer, uint16_t port,
    uint16_t queue, struct rte_mbuf **packet);
int ker_generation_tx_enqueue(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer, uint16_t port,
    uint16_t queue, struct rte_mbuf *packet);
int ker_generation_tx_dequeue_peer(struct ker_generation_rings *rings,
    const struct ker_generation_identity *consumer, uint16_t port,
    uint16_t queue, struct rte_mbuf **packet);
/* Resident-owned prepared packet lease. The packet pool is distinct from the
 * session message/PMD lease pool, but commit publishes into the existing TX
 * generation ring and shares its journal/recovery path. Indices are scoped to
 * the validated packet pool table; callers must never transmit raw pointers. */
int ker_generation_packet_prepare(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer,
    const struct ker_generation_identity *consumer, uint16_t port, uint16_t queue,
    uint32_t *object_index, uint64_t *lease_id);
uint64_t ker_generation_packet_pool_tag(const struct ker_generation_rings *rings);
struct rte_mbuf *ker_generation_packet_resolve(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer, uint32_t object_index,
    uint64_t lease_id);
int ker_generation_packet_write_complete(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer, uint32_t object_index,
    uint64_t lease_id);
int ker_generation_packet_commit(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer, uint16_t port, uint16_t queue,
    uint32_t object_index, uint64_t lease_id);
int ker_generation_packet_cancel(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer, uint32_t object_index,
    uint64_t lease_id);
/* Reserved for a future external-send ledger. These remain fail-closed until
 * the PMD and wire completion boundaries are journaled by the real adapter. */
int ker_generation_packet_pmd_accepted(struct ker_generation_rings *rings,
    const struct ker_generation_identity *consumer, struct rte_mbuf *packet);
int ker_generation_packet_wire_pending(struct ker_generation_rings *rings,
    const struct ker_generation_identity *consumer, struct rte_mbuf *packet);
uint64_t ker_generation_rx_full_count(struct ker_generation_rings *rings,
    uint16_t port, uint16_t queue, uint32_t target_generation);
int ker_generation_rings_stats(struct ker_generation_rings *rings,
    struct ker_generation_ring_stats *stats);
int ker_generation_packet_release(struct ker_generation_rings *rings,
    const struct ker_generation_identity *owner, struct rte_mbuf *packet);

#ifdef KER_SESSION_TEST_HOOKS
uint32_t ker_generation_packet_pool_in_use(struct ker_generation_rings *rings);
int ker_generation_test_packet_object_index(struct ker_generation_rings *rings,
    const struct rte_mbuf *packet,uint32_t *object_index);
int ker_generation_test_tx_snapshot(struct ker_generation_rings *rings,uint16_t port,
    uint16_t queue,uint32_t generation,uint32_t *count,uint32_t *packet_pool_in_use);
int ker_generation_test_fill_tx_capacity(struct ker_generation_rings *rings,
    const struct ker_generation_identity *producer,uint16_t port,uint16_t queue,uint32_t *filled);
int ker_generation_test_packet_table_duplicate(struct ker_generation_rings *rings,
    uint32_t index,uint32_t duplicate_index,uintptr_t *original);
int ker_generation_test_packet_table_restore(struct ker_generation_rings *rings,
    uint32_t index,uintptr_t original);
int ker_generation_test_packet_force_untracked_send(struct ker_generation_rings *rings,
    uint32_t index,uint64_t lease_id);
int ker_generation_test_packet_restore_prepared(struct ker_generation_rings *rings,
    uint32_t index,uint64_t lease_id);
int ker_generation_test_reopen_after_failclosed_reap(struct ker_generation_rings *rings);
int ker_generation_test_reopen_after_failed_detach(struct ker_generation_rings *rings,
    uint32_t generation);
int ker_generation_test_packet_drop_count(struct ker_generation_rings *rings,uint16_t port,
    uint16_t queue,uint32_t generation,uint64_t *count);
int ker_generation_test_packet_full_count(struct ker_generation_rings *rings,uint16_t port,
    uint16_t queue,uint32_t generation,uint64_t *count);
/* Test-only: observe the same generation-directory lookup used by attach. */
int ker_generation_rings_test_directory_present(void);
/* Test-only: repeat the production secondary attach and require identical objects. */
int ker_generation_rings_test_replay(struct ker_generation_rings *rings);
/* Test-only: pause one successful real dequeue before its active lease exits. */
void ker_generation_test_hold_next_dequeue(void);
/* Test-only: make the next resident detach fail validation after collection. */
void ker_generation_test_corrupt_next_detach(void);
void ker_generation_test_corrupt_next_reap(void);
void ker_generation_test_hold_after_ring_remove(_Atomic unsigned *ready, _Atomic unsigned *release);
void ker_generation_test_hold_after_dequeue_cas(_Atomic unsigned *ready);
void ker_generation_test_hold_after_enqueue_prepare(_Atomic unsigned *ready);
void ker_generation_test_hold_packet_commit(_Atomic unsigned *ready,_Atomic unsigned *release);
void ker_generation_test_hold_after_packet_enqueue(_Atomic unsigned *ready,_Atomic unsigned *release);
/* Test-only late journal corruption and raw metric observation for reaper rollback. */
int ker_generation_test_corrupt_late_queued_rx(struct ker_generation_rings *rings,
    const struct ker_generation_identity *owner, uint32_t after_ring_slot);
void ker_generation_test_restore_reap_corruption(void);
int ker_generation_test_tx_drop_count(struct ker_generation_rings *rings,
    uint16_t port, uint16_t queue, uint32_t generation, uint64_t *count);
int ker_generation_test_active_counts(struct ker_generation_rings *rings,uint32_t counts[4]);
#endif

/* Reclaim only after the exact registered PIDFD is readable. */
int ker_generation_reap_dead(struct ker_generation_rings *rings,
    const struct ker_generation_identity *owner);
int ker_generation_rings_destroy(struct ker_generation_rings *rings);

#endif
