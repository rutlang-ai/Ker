#ifndef EXAMPLE_A10_DISPATCH_POLICY_H
#define EXAMPLE_A10_DISPATCH_POLICY_H
#include "flow-map-policy.h"
#include <ker/packet-dispatcher.h>
/* Caller policy for bounded Ethernet/IPv4/TCP tuple fixtures. This extracts
 * metadata only; no socket, handshake, syncache or TCP state is implemented. */
int example_a10_classifier(void *data,uint16_t *length,uint16_t queue,
    uint16_t queues,struct ker_dispatcher_context context);
/* The application input callback takes ownership of each dequeued mbuf.
 * A bound, un-stopped, parked role may drain the caller-owned software ring.
 * The hardware-owner role leaves it untouched. Directory-less serialized
 * fixture profile only: caller owns ring identity, exclusivity and lifetime. */
typedef void (*example_a10_input_fn)(struct rte_mbuf *,void *);
int example_a10_parked_input(struct rte_ring *,unsigned budget,
    example_a10_input_fn,void *);
#endif
