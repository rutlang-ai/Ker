/* Application policy, never linked into a Ker library. The table records
 * caller-selected metadata; original Linux retains all transport state. */
#define _GNU_SOURCE
#include "flow-map-policy.h"
#include <ker/reload.h>
#include <errno.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "ff_config.h"
#include "ff_reload.h"
struct ff_config example_flow_configuration;
static int example_flow_attached(void)
{
    struct ker_reload_runtime view;
    return ker_reload_runtime_view(&view) == 0 && view.attached;
}
/* Translate only dependency gates to the actual borrowed Ker runtime. */
#define ff_global_cfg example_flow_configuration
#define ff_reload_state_attached example_flow_attached
#include "ff_flow_map.c"
#undef ff_global_cfg
#undef ff_reload_state_attached

void example_flow_enable(int enabled)
{
    ff_flow_map_close();
    example_flow_configuration.dpdk.graceful_reload = !!enabled;
}
int example_flow_route(struct rte_mbuf *packet, struct rte_ring *local,
    struct rte_ring *peer)
{
    uint8_t buffer[48];
    if (!packet || !local || !peer) return -EINVAL;
    if (packet->pkt_len < 1) return -EINVAL;
    const uint8_t *data = rte_pktmbuf_read(packet, 0, 1, buffer);
    if (!data) return -EINVAL;
    unsigned size = (data[0] >> 4) == 4 ? 28 : 48;
    data = rte_pktmbuf_read(packet, 0, size, buffer);
    if (!data) return -EINVAL;
    struct ff_flow_key key;
    memset(&key, 0, sizeof(key));
    if (data[0] == 0x45 && data[9] == 17 && !(data[6] & 0x3f) && !data[7]) {
        key.af = FF_FLOW_MAP_V4;
        memcpy(key.src, data + 12, 4);
        memcpy(key.dst, data + 16, 4);
        memcpy(&key.sport, data + 20, 2);
        memcpy(&key.dport, data + 22, 2);
    } else if ((data[0] >> 4) == 6 && data[6] == 17) {
        key.af = FF_FLOW_MAP_V6;
        memcpy(key.src, data + 8, 16);
        memcpy(key.dst, data + 24, 16);
        memcpy(&key.sport, data + 40, 2);
        memcpy(&key.dport, data + 42, 2);
    } else return -EPROTONOSUPPORT;
    struct rte_ring *destination = !ff_flow_map_active() || ff_flow_map_lookup(&key) ? local : peer;
    return rte_ring_enqueue(destination, packet) == 0 ? 0 : -ENOBUFS;
}
