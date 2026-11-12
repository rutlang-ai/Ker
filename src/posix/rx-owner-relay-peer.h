#ifndef KER_RX_OWNER_RELAY_PEER_H
#define KER_RX_OWNER_RELAY_PEER_H

#include "rx-owner-relay-wire.h"
#include <sys/types.h>

/* Private caller-owned, serialized old-owner binding. The supervisor must
 * authenticate this identity/slot and delegate the channel and pidfd first.
 * This transport verifies per-message process identity; it does not discover
 * peers or authorize a generation/slot from a PID supplied by the application.
 * Keep both descriptors and the binding alive through each operation. The
 * caller must also maintain/revalidate the live reload window and slot
 * authority before settling C31; transport success is not new slot authority. */
struct ker_rx_owner_relay_peer {
    int fd;
    int pidfd;
    uid_t uid;
    gid_t gid;
    struct ker_rx_owner_relay_header identity;
    uint64_t last_packet_id;
};

/* Relay exactly one already validated PEER reply's immutable frame to the
 * bound old owner. Reuse the original packet id/deadline; never extend a C31
 * lease or reinject the snapshot. Each id gets at most one send attempt.
 * A second PEER/error/response result becomes DROP, never another hop. Return
 * 0 and a C31 LOCAL/DROP action only for an authenticated unchanged reply;
 * negative errno leaves action untouched. The caller retains its original
 * packet and must settle a failed relay as DROP/expiry through C31. */
int ker_rx_owner_relay_peer_forward(struct ker_rx_owner_relay_peer *peer,
    const struct ker_rx_owner_relay_header *source, const void *frame,
    size_t bytes, int *action);

#endif
