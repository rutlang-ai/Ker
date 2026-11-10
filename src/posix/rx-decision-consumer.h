#ifndef KER_POSIX_RX_DECISION_CONSUMER_H
#define KER_POSIX_RX_DECISION_CONSUMER_H

#include "rx-decision-wire.h"
#include <stddef.h>
#include <stdint.h>

/* Private, uninstalled integration for a trusted central LKL application.
 * The callback runs synchronously on the thread that calls ker_posix_run().
 * Snapshot memory is read-only and valid only for the duration of the call. */
struct ker_rx_decision_packet {
    uint64_t packet_id;
    uint64_t deadline_ns;
    uint32_t packet_bytes;
    uint32_t first_segment_bytes;
    uint32_t data_room_bytes;
    uint16_t data_offset;
    uint16_t segment_count;
    uint16_t queue_id;
    uint16_t queue_count;
    uint16_t vlan_tci;
    uint16_t flags;
    uint64_t rx_offload_flags;
    const void *first_segment;
};

typedef int (*ker_rx_decision_handler)(
    const struct ker_rx_decision_packet *packet, void *context);

/* A handler may return DEFER after copying any packet data it needs. Exactly
 * one packet lease remains pending until the owner thread completes it. Before
 * stopping the application loop, callers must complete any pending lease and
 * switch the handler to its own bounded synchronous drain policy; a handler
 * that continues to defer cannot be serviced after the app loop stops. */
#define KER_RX_DECISION_DEFER 3

/* Successful registration consumes fd. Registration is single-use and must
 * happen before ker_posix_run(), on the same thread that will run it. A
 * registered consumer requires a non-NULL loop callback that returns
 * boundedly; the handler is pumped before and after each callback. */
int ker_posix_rx_decision_register(int fd,
    ker_rx_decision_handler handler, void *context);
/* Complete the one pending lease on the registered owner thread. Returns 0
 * or -1/errno. IDs are single-use; the original worker deadline and fresh
 * worker/supervisor pidfd identity checks still apply. */
int ker_posix_rx_decision_complete(uint64_t packet_id, int action);
/* Returns 1 after the authenticated worker READY handshake, 0 before it. */
int ker_posix_rx_decision_is_ready(void);

/* Private run-loop lifecycle; called only by ker_posix_run(). */
int ker_rx_decision_consumer_start(void);
int ker_rx_decision_consumer_pump(void);
int ker_rx_decision_consumer_prepare_runtime_shutdown(void);
int ker_rx_decision_consumer_registered(void);
int ker_rx_decision_consumer_error(void);
#ifdef KER_C31_RX_DECISION_TESTING
#ifndef KER_C31_TEST_API
#define KER_C31_TEST_API __attribute__((visibility("default")))
#endif
/* Make one shutdown call return EBUSY before sending STOP. */
KER_C31_TEST_API void ker_posix_rx_decision_test_shutdown_ebusy_once(void);
#endif

#endif
