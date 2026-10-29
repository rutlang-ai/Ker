#define _GNU_SOURCE
#include <ker/peer-dispatcher.h>
#include <ker/reload.h>
#include <errno.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
int ker_packet_dispatch_peer(struct rte_mbuf **packet, uint16_t *length,
    uint16_t queue, uint16_t queues, struct rte_ring *peer,
    int *decision, struct ker_peer_dispatch_stats *stats)
{
    if (!packet || !*packet || !length || !queues || queue>=queues || !peer ||
        !decision || !stats)
        return -EINVAL;
    *decision=ker_packet_dispatch(*packet,length,queue,queues);
    if (*decision!=KER_DISPATCH_PEER) return KER_PEER_PASSTHROUGH;
    struct ker_reload_runtime view;
    int result=ker_reload_runtime_view(&view);
    if (result) return result;
    struct rte_mbuf *owned=*packet;
    if (view.attached && view.reload_active) {
        if (!rte_ring_enqueue(peer,owned)) {
            ++stats->forwarded;
            *packet=NULL;
            return KER_PEER_FORWARDED;
        }
        ++stats->full;
    } else ++stats->closed;
    stats->dropped_segments+=owned->nb_segs;
    rte_pktmbuf_free(owned);
    *packet=NULL;
    return KER_PEER_DROPPED;
}
