/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_IO_SESSION_H
#define KER_IO_SESSION_H
#include <stdint.h>
#include <stdatomic.h>
#define KER_SESSION_MAGIC UINT64_C(0x4b45525345535331)
#define KER_SESSION_VERSION 1U
#define KER_SESSION_SLOTS 4U
#define KER_SESSION_GENERATIONS 2U
#define KER_SESSION_PROCESSES 4U
#define KER_SESSION_CHANNELS 3U
#define KER_SESSION_CAPACITY 64U
#define KER_SESSION_ZONE "ker_session_directory"
enum ker_session_command { KER_SESSION_MASTER = 1, KER_SESSION_RESERVE,
    KER_SESSION_RELEASE, KER_SESSION_STATUS, KER_SESSION_ATTACHED };
enum ker_session_state { KER_SESSION_PREPARING, KER_SESSION_READY, KER_SESSION_STOPPING };
/* Internal same-host ABI, not a public F-Stack wire or ring-name ABI. */
struct ker_session_message {
    uint64_t magic, version, command, sequence, session, epoch;
    uint64_t generation, process, token, slot;
    int64_t status;
};
_Static_assert(sizeof(struct ker_session_message) == 88, "session wire ABI");
struct ker_session_directory {
    uint64_t magic, version, size, session;
    uint32_t primary_pid, slots, generations, processes, channels, capacity;
    _Atomic unsigned state;
    _Atomic uint64_t epoch[KER_SESSION_SLOTS];
};
#endif
