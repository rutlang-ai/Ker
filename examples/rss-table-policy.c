#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <rte_ring.h>
#include <ker/packet-dispatcher.h>
#include "rss-table-policy.h"
/* Declare before the original ff_memory.h inline accessor. */
struct ff_config example_rss_configuration;
#include "rss-table-internal.h"
#include "ff_log.h"
struct lcore_conf example_rss_lcores[RTE_MAX_LCORE];
struct context_handle {
    struct ff_dpdk_if_context *context;
    struct context_handle *next;
};
static struct context_handle *handles;
void *example_rss_context_new(struct ff_dpdk_if_context *context)
{
    if (!context) return NULL;
    struct context_handle *handle = malloc(sizeof(*handle));
    if (!handle) return NULL;
    *handle = (struct context_handle){context, handles};
    handles = handle;
    return handle;
}
static struct ff_dpdk_if_context *context_host(void *opaque)
{
    struct context_handle *handle = opaque;
    return handle ? handle->context : NULL;
}
static void context_free(void *opaque)
{
    struct context_handle **link = &handles;
    while (*link && *link != opaque) link = &(*link)->next;
    if (*link) {
        struct context_handle *handle = *link;
        *link = handle->next;
        free(handle);
    }
}
void example_rss_context_cleanup(void)
{
    while (handles) context_free(handles);
}
/* Preserve diagnostic output; never turn a failed operation into success. */
static int model_log(uint32_t level, uint32_t type, const char *format, ...)
{
    (void)level; (void)type;
    va_list args;
    va_start(args, format);
    int result = vfprintf(stderr, format, args);
    va_end(args);
    return result;
}
#define ff_log model_log
#define ff_veth_softc_to_hostc context_host
#define ff_veth_free_softc context_free
#include "rss-key.inc"
static int rsskey_len = sizeof(default_rsskey_40bytes);
static uint8_t *rsskey = default_rsskey_40bytes;
static uint16_t rss_reta_size[RTE_MAX_ETHPORTS];
#include "rss-tables.inc"
#include "rss-functions.inc"

static struct ff_rss_check_cfg owned_rules;
static int configured;
void example_rss_reset(void)
{
    example_rss_context_cleanup();
    memset(&example_rss_configuration, 0, sizeof(example_rss_configuration));
    memset(example_rss_lcores, 0, sizeof(example_rss_lcores));
    memset(rss_reta_size, 0, sizeof(rss_reta_size));
    memset(ff_rss_tbl, 0, sizeof(ff_rss_tbl));
    memset(ff_rss_tbl6, 0, sizeof(ff_rss_tbl6));
    configured = 0;
}
int example_rss_configure(const struct ff_rss_check_cfg *rules, uint16_t queues,
    uint16_t own_queue, uint16_t reta_size, uint16_t first, uint16_t last)
{
    example_rss_reset();
    if (!rules || !rules->enable || !queues || own_queue >= queues ||
        !reta_size || (reta_size & (reta_size - 1)) || first > last ||
        rules->nb_rss_tbl < 1 || rules->nb_rss_tbl > FF_RSS_TBL_MAX_ENTRIES)
        return -EINVAL;
    for (int i = 0; i < rules->nb_rss_tbl; ++i)
        if (rules->rss_tbl_cfgs[i].port_id != 0 ||
            (rules->rss_tbl_cfgs[i].family != 0 && rules->rss_tbl_cfgs[i].family != AF_INET &&
             rules->rss_tbl_cfgs[i].family != AF_INET6)) return -EINVAL;
    owned_rules = *rules;
    owned_rules.rss_tbl_str = NULL; /* Only parsed fixed-size rules are consumed. */
    example_rss_configuration.dpdk.rss_check_cfgs = &owned_rules;
    example_rss_lcores[0].nb_queue_list[0] = queues;
    example_rss_lcores[0].tx_queue_id[0] = own_queue;
    rss_reta_size[0] = reta_size;
    if (ff_rss_tbl_init() || ff_rss_tbl6_init() ||
        ff_rss_tbl_set_portrange(first, last) || ff_rss_tbl6_set_portrange(first, last)) {
        example_rss_reset(); return -EINVAL;
    }
    configured = 1;
    return 0;
}
int example_rss_dispatch(void *bytes, uint16_t *length, uint16_t queue, uint16_t queues)
{
    (void)queue;
    if (!configured || !bytes || !length || !*length ||
        queues != example_rss_lcores[0].nb_queue_list[0]) return -1;
    const uint8_t *data = bytes;
    unsigned size = (data[0] >> 4) == 4 ? 28 : 48;
    if (*length < size) return -1;
    uint16_t first = 0, last = 0, *ports = NULL, sport, dport;
    int result;
    if (data[0] == 0x45 && data[9] == 17 && !(data[6] & 0x3f) && !data[7]) {
        uint32_t src, dst;
        memcpy(&src, data + 12, 4); memcpy(&dst, data + 16, 4);
        memcpy(&sport, data + 20, 2); memcpy(&dport, data + 22, 2);
        result = ff_rss_tbl_get_portrange(src, dst, sport, &first, &last, &ports);
    } else if ((data[0] >> 4) == 6 && data[6] == 17) {
        memcpy(&sport, data + 40, 2); memcpy(&dport, data + 42, 2);
        result = ff_rss_tbl6_get_portrange(data + 8, data + 24, sport, &first, &last, &ports);
    } else return -EPROTONOSUPPORT;
    if (result && result != -ENOENT) return result;
    int destination = (example_rss_lcores[0].tx_queue_id[0] + 1) % queues;
    if (!result && ports)
        for (uint32_t i = first; i <= last; ++i)
            if (ports[i] == ntohs(dport)) { destination = example_rss_lcores[0].tx_queue_id[0]; break; }
    return destination;
}

int example_rss_route(struct rte_mbuf *packet, struct rte_ring *local, struct rte_ring *other)
{
    if (!configured) return -ENOTCONN;
    if (!packet || !local || !other) return -EINVAL;
    if (packet->nb_segs != 1 || packet->pkt_len > UINT16_MAX) return -ENOTSUP;
    uint16_t length = packet->data_len;
    uint16_t own = example_rss_lcores[0].tx_queue_id[0];
    uint16_t queues = example_rss_lcores[0].nb_queue_list[0];
    int destination = ker_packet_dispatch(packet, &length, own, queues);
    if (destination < 0 || destination >= queues || length != packet->data_len) return -EINVAL;
    return rte_ring_enqueue(destination == own ? local : other, packet) ? -ENOBUFS : 0;
}
