/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_IO_SESSION_H
#define KER_IO_SESSION_H
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <errno.h>
#define KER_SESSION_MAGIC UINT64_C(0x4b45525345535331)
#define KER_SESSION_VERSION 10U
#define KER_SESSION_SLOTS 4U
#define KER_SESSION_GENERATIONS 2U
#define KER_SESSION_PROCESSES 4U
#define KER_SESSION_CHANNELS 4U
#define KER_SESSION_CAPACITY 64U
#define KER_SESSION_POOL "ker_session_messages"
#define KER_SESSION_OBJECTS 511U
#define KER_SESSION_PROBE_PAYLOAD 64U
#define KER_SESSION_ZONE "ker_session_directory"
enum ker_session_command {
    KER_SESSION_MASTER = 1, KER_SESSION_RESERVE = 2, KER_SESSION_RELEASE = 3,
    KER_SESSION_STATUS = 4, KER_SESSION_ATTACHED = 5, KER_SESSION_PROBE = 6,
    KER_SESSION_PMD_ACQUIRE = 7, KER_SESSION_PMD_STATUS = 8, KER_SESSION_EPOCH_LIVE = 9,
    KER_SESSION_DRAIN_MODE = 10, KER_SESSION_HEARTBEAT = 11, KER_SESSION_PEER_STATUS = 12,
    KER_SESSION_COORDINATE_QUERY = 13, KER_SESSION_PEER_RESERVE = 14,
    KER_SESSION_RING_DETACH = 15, KER_SESSION_RING_DETACH_ARM = 16,
    KER_SESSION_PMD_HANDOFF_PREPARE = 17, KER_SESSION_PMD_HANDOFF_QUIESCED = 18,
    KER_SESSION_FRAME_PREPARE = 19, KER_SESSION_FRAME_COMMIT = 20, KER_SESSION_FRAME_CANCEL = 21
};
enum ker_session_state { KER_SESSION_PREPARING, KER_SESSION_READY, KER_SESSION_STOPPING };
/* Internal same-host ABI, not a public F-Stack wire or ring-name ABI. */
/* The resident publishes one advisory peer tuple to a worker. A versioned
 * snapshot prevents readers from combining fields across true->true peer
 * replacement; only the resident serializes writers. */
static inline void ker_session_peer_write_begin(_Atomic uint64_t *version)
{
    atomic_fetch_add_explicit(version, 1, memory_order_seq_cst);
}
static inline void ker_session_peer_write_end(_Atomic uint64_t *version)
{
    atomic_fetch_add_explicit(version, 1, memory_order_seq_cst);
}
static inline int ker_session_peer_read_observed(_Atomic uint64_t *version,
    _Atomic uint64_t *epoch, _Atomic uint64_t *generation, _Atomic uint64_t *draining,
    uint64_t *epoch_out, uint64_t *generation_out, uint64_t *draining_out,
    void (*odd_retry)(void *), void *context)
{
    for (unsigned attempt = 0; attempt < 100000; attempt++) {
        uint64_t before = atomic_load_explicit(version, memory_order_seq_cst);
        if (before & 1) {
            if (odd_retry) odd_retry(context);
            continue;
        }
        uint64_t e = atomic_load_explicit(epoch, memory_order_seq_cst);
        uint64_t g = atomic_load_explicit(generation, memory_order_seq_cst);
        uint64_t d = atomic_load_explicit(draining, memory_order_seq_cst);
        uint64_t after = atomic_load_explicit(version, memory_order_seq_cst);
        if (before == after && !(after & 1)) {
            *epoch_out = e; *generation_out = g; *draining_out = d;
            return 0;
        }
        if (odd_retry) odd_retry(context);
    }
    return -EAGAIN;
}
static inline int ker_session_peer_read(_Atomic uint64_t *version,
    _Atomic uint64_t *epoch, _Atomic uint64_t *generation, _Atomic uint64_t *draining,
    uint64_t *epoch_out, uint64_t *generation_out, uint64_t *draining_out)
{
    return ker_session_peer_read_observed(version, epoch, generation, draining,
        epoch_out, generation_out, draining_out, NULL, NULL);
}
struct ker_session_message {
    uint64_t magic, version, command, sequence, session, epoch;
    uint64_t generation, process, token, slot, capability;
    int64_t status;
    uint64_t tx_lease_id, rx_lease_id;
    uint64_t packet_pool_tag;
    uint32_t packet_object_index;
    uint16_t packet_port, packet_queue;
};
_Static_assert(sizeof(struct ker_session_message) == 128, "session wire ABI");
_Static_assert(offsetof(struct ker_session_message,status)==88 &&
    offsetof(struct ker_session_message,tx_lease_id)==96 &&
    offsetof(struct ker_session_message,rx_lease_id)==104 &&
    offsetof(struct ker_session_message,packet_pool_tag)==112 &&
    offsetof(struct ker_session_message,packet_object_index)==120 &&
    offsetof(struct ker_session_message,packet_port)==124 &&
    offsetof(struct ker_session_message,packet_queue)==126, "session wire field order");
/* Shared control transport: request producer owns the mbuf until enqueue,
 * resident owns it until reply enqueue, then the same secondary owns it.
 * The object remains allocated under its coordinate lease throughout. */
struct ker_session_probe {
    struct ker_session_message identity;
    uint64_t responder;
    uint8_t payload[KER_SESSION_PROBE_PAYLOAD];
};
_Static_assert(sizeof(struct ker_session_probe) == 200, "shared control envelope ABI");
static inline int ker_session_probe_check(const struct ker_session_probe *probe,
    const struct ker_session_message *expected, uint64_t previous_sequence)
{
    const struct ker_session_message *m = &probe->identity;
    return m->magic != KER_SESSION_MAGIC || m->version != KER_SESSION_VERSION ||
        m->command != KER_SESSION_PROBE || m->sequence <= previous_sequence ||
        m->session != expected->session || m->epoch != expected->epoch ||
        m->slot != expected->slot || m->generation != expected->generation ||
        m->process != expected->process || m->token || m->capability || m->status != -EINPROGRESS ||
        m->tx_lease_id != expected->tx_lease_id || m->rx_lease_id != expected->rx_lease_id ||
        m->packet_pool_tag || m->packet_object_index || m->packet_port || m->packet_queue || probe->responder ?
        -ESTALE : 0;
}
struct ker_session_directory {
    uint64_t magic, version, size, session;
    uint32_t primary_pid, slots, generations, processes, channels, capacity;
    _Atomic unsigned state;
    uint32_t ring_pmd;
    /* Coordinate key, never a PID/liveness substitute. Held until exact borrower death. */
    _Atomic uint64_t pmd_owner;
    /* Immutable session-stable exception endpoint identity. Authorization
     * uses pmd_owner as the single atomic grant key for both resources. */
    _Atomic uint32_t exception_ifindex;
    _Atomic uintptr_t pmd_lease;
    _Atomic uintptr_t pmd_rx_lease;
    _Atomic uint64_t pmd_tx_lease_id;
    _Atomic uint64_t pmd_rx_lease_id;
    /* 0 idle, 1 selected in shared ring, 2 TAP write in progress,
     * 3 TAP read in progress, 4 outbound frame in lease, 5 PMD TX pending,
     * 6 external wire send in progress, 7 TAP copy complete/native RX pending,
     * 8 native packet-channel send in progress (ambiguous on process death). */
    _Atomic uint32_t pmd_exception_phase;
    _Atomic uint64_t pmd_exception_discarded;
    _Atomic uint64_t epoch[KER_SESSION_SLOTS];
    /* Advisory per-caller peer snapshot: coordinates remain populated on fallback. */
    _Atomic uint64_t peer_version[KER_SESSION_SLOTS][KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
    _Atomic uint64_t peer_epoch[KER_SESSION_SLOTS][KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
    _Atomic uint64_t peer_generation[KER_SESSION_SLOTS][KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
    _Atomic uint64_t peer_draining[KER_SESSION_SLOTS][KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
    /* Resident assigns the original mbuf before acknowledging RESERVE; only
     * exact borrower death permits clearing this lease and returning it. */
    _Atomic uintptr_t lease[KER_SESSION_SLOTS][KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
};
#endif
