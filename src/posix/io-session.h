/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_IO_SESSION_H
#define KER_IO_SESSION_H
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#define KER_SESSION_MAGIC UINT64_C(0x4b45525345535331)
#define KER_SESSION_VERSION 4U
#define KER_SESSION_SLOTS 4U
#define KER_SESSION_GENERATIONS 2U
#define KER_SESSION_PROCESSES 4U
#define KER_SESSION_CHANNELS 4U
#define KER_SESSION_CAPACITY 64U
#define KER_SESSION_POOL "ker_session_messages"
#define KER_SESSION_OBJECTS 511U
#define KER_SESSION_PROBE_PAYLOAD 64U
#define KER_SESSION_ZONE "ker_session_directory"
enum ker_session_command { KER_SESSION_MASTER = 1, KER_SESSION_RESERVE,
    KER_SESSION_RELEASE, KER_SESSION_STATUS, KER_SESSION_ATTACHED, KER_SESSION_PROBE, KER_SESSION_PMD_ACQUIRE, KER_SESSION_PMD_STATUS };
enum ker_session_state { KER_SESSION_PREPARING, KER_SESSION_READY, KER_SESSION_STOPPING };
/* Internal same-host ABI, not a public F-Stack wire or ring-name ABI. */
struct ker_session_message {
    uint64_t magic, version, command, sequence, session, epoch;
    uint64_t generation, process, token, slot;
    int64_t status;
};
_Static_assert(sizeof(struct ker_session_message) == 88, "session wire ABI");
/* Shared control transport: request producer owns the mbuf until enqueue,
 * resident owns it until reply enqueue, then the same secondary owns it.
 * The object remains allocated under its coordinate lease throughout. */
struct ker_session_probe {
    struct ker_session_message identity;
    uint64_t responder;
    uint8_t payload[KER_SESSION_PROBE_PAYLOAD];
};
_Static_assert(sizeof(struct ker_session_probe) == 160, "shared control envelope ABI");
static inline int ker_session_probe_check(const struct ker_session_probe *probe,
    const struct ker_session_message *expected, uint64_t previous_sequence)
{
    const struct ker_session_message *m = &probe->identity;
    return m->magic != KER_SESSION_MAGIC || m->version != KER_SESSION_VERSION ||
        m->command != KER_SESSION_PROBE || m->sequence <= previous_sequence ||
        m->session != expected->session || m->epoch != expected->epoch ||
        m->slot != expected->slot || m->generation != expected->generation ||
        m->process != expected->process || m->token || m->status != -EINPROGRESS || probe->responder ?
        -ESTALE : 0;
}
struct ker_session_directory {
    uint64_t magic, version, size, session;
    uint32_t primary_pid, slots, generations, processes, channels, capacity;
    _Atomic unsigned state;
    uint32_t ring_pmd;
    /* Coordinate key, never a PID/liveness substitute. Held until exact borrower death. */
    _Atomic uint64_t pmd_owner;
    _Atomic uintptr_t pmd_lease;
    _Atomic uint64_t epoch[KER_SESSION_SLOTS];
    /* Resident assigns the original mbuf before acknowledging RESERVE; only
     * exact borrower death permits clearing this lease and returning it. */
    _Atomic uintptr_t lease[KER_SESSION_SLOTS][KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
};
#endif
