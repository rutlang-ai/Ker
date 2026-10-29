#ifndef EXAMPLE_FLOW_MAP_POLICY_H
#define EXAMPLE_FLOW_MAP_POLICY_H
#include <stdint.h>
#include "ff_flow_map.h"
/* Original ff_api.h declarations without importing the FreeBSD API surface. */
typedef struct ff_flow_key ff_flow_key_t;
void ff_flow_map_open(void);
void ff_flow_map_close(void);
int ff_flow_map_lookup(const struct ff_flow_key *key);
/* Caller-owned single-thread policy; all users must be quiescent for control
 * changes. A borrowed real ker::reload state is required for tracking. */
void example_flow_enable(int enabled);
struct rte_mbuf;
struct rte_ring;
/* Bounded UDP L3 demonstration profile (v4 without options; v6 without
 * extensions). No TCP/PCB integration. Successful enqueue transfers ownership;
 * every error leaves the packet with the caller. */
int example_flow_route(struct rte_mbuf *packet, struct rte_ring *local,
    struct rte_ring *peer);
#endif
