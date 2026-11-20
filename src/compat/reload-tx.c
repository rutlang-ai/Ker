#define _GNU_SOURCE
#include <ker/reload-tx.h>
#include <ker/reload.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
struct ker_reload_tx {
    struct rte_mempool *pool;
    struct rte_ring *drain;
    uint16_t port,queue;
    int active;
    struct rte_mbuf *batch[KER_RELOAD_TX_BURST];
    struct ker_reload_tx_stats stats;
};
static int valid(struct ker_reload_tx *tx)
{
    if (!tx) return -EINVAL;
    if (tx->active) return -EBUSY;
    struct ker_reload_runtime view;
    int result=ker_reload_runtime_view(&view);
    return result ? result : view.attached ? 0 : -ENOTCONN;
}
int ker_reload_tx_create(struct rte_mempool *pool, struct rte_ring *drain,
    uint16_t port, uint16_t queue, struct ker_reload_tx **out)
{
    if (!pool || !drain || !out || *out || !rte_eth_dev_is_valid_port(port)) return -EINVAL;
    struct ker_reload_tx *tx=calloc(1,sizeof(*tx)); if (!tx) return -ENOMEM;
    tx->pool=pool;tx->drain=drain;tx->port=port;tx->queue=queue;
    int result=valid(tx); if(result){free(tx);return result;}
    *out=tx;return 0;
}
int ker_reload_tx_destroy(struct ker_reload_tx **tx)
{
    if (!tx || !*tx) return -EINVAL;
    if ((*tx)->active || (*tx)->stats.staged) return -EBUSY;
    free(*tx);*tx=NULL;return 0;
}
static void discard(struct ker_reload_tx *tx)
{
    for(unsigned i=0;i<tx->stats.staged;i++) {
        tx->stats.guard_dropped_segments+=tx->batch[i]->nb_segs;
        rte_pktmbuf_free(tx->batch[i]);
    }
    tx->stats.staged=0;
}
static void burst(struct ker_reload_tx *tx,struct rte_mbuf **packets,unsigned count)
{
    if(!count)return;
    tx->active=1;
    unsigned sent=rte_eth_tx_burst(tx->port,tx->queue,packets,(uint16_t)count);
    tx->active=0;
    ++tx->stats.hardware_calls;tx->stats.hardware_packets+=sent;
    for(unsigned i=sent;i<count;i++) {
        tx->stats.hardware_dropped_segments+=packets[i]->nb_segs;
        rte_pktmbuf_free(packets[i]);
    }
}
struct flush_context {struct ker_reload_tx *tx;int called;};
static int flush_allowed(void *opaque)
{
    struct flush_context *context=opaque;context->called=1;
    struct ker_reload_tx *tx=context->tx;
    burst(tx,tx->batch,tx->stats.staged);tx->stats.staged=0;return 0;
}
int ker_reload_tx_flush(struct ker_reload_tx *tx)
{
    int result=valid(tx);if(result)return result;
    if(!tx->stats.staged)return 0;
    struct flush_context context={tx,0};
    result=ker_reload_poll(flush_allowed,&context);tx->stats.last_poll_error=result;
    if(!context.called)discard(tx); /* denial or a failed admission cannot reach hardware */
    return result;
}
static void divert(struct ker_reload_tx *tx,struct rte_mbuf *packet)
{
    if(!rte_ring_enqueue(tx->drain,packet))++tx->stats.diverted;
    else {
        ++tx->stats.full;tx->stats.divert_dropped_segments+=packet->nb_segs;
        rte_pktmbuf_free(packet);
    }
}
static int stage(struct ker_reload_tx *tx,struct rte_mbuf *packet)
{
    tx->batch[tx->stats.staged++]=packet;
    return tx->stats.staged==KER_RELOAD_TX_BURST ? ker_reload_tx_flush(tx) : 0;
}
int ker_reload_tx_owned(struct ker_reload_tx *tx,struct rte_mbuf **packet)
{
    int result=valid(tx);if(result)return result;
    if(!packet || !*packet)return -EINVAL;
    struct rte_mbuf *owned=*packet;*packet=NULL;++tx->stats.accepted;
    if(!ker_reload_rx_allowed()){divert(tx,owned);return 0;}
    return stage(tx,owned);
}
int ker_reload_tx_copy(struct ker_reload_tx *tx,const void *data,uint16_t length)
{
    int result=valid(tx);if(result)return result;
    if(!data || !length)return -EINVAL;
    struct rte_mbuf *packet=rte_pktmbuf_alloc(tx->pool);if(!packet)return -ENOMEM;
    void *copy=rte_pktmbuf_append(packet,length);
    if(!copy){rte_pktmbuf_free(packet);return -ENOSPC;}
    memcpy(copy,data,length);
    result=ker_reload_tx_owned(tx,&packet);
    if(packet)rte_pktmbuf_free(packet);
    return result;
}
int ker_reload_tx_reply(struct ker_reload_tx *tx,struct rte_mbuf **packet,uint16_t length)
{
    int result=valid(tx);if(result)return result;
    if(!packet || !*packet || !length)return -EINVAL;
    if((*packet)->nb_segs!=1)return -ENOTSUP;
    if(length>rte_pktmbuf_data_len(*packet))return -EINVAL;
    struct rte_mbuf *owned=*packet;*packet=NULL;
    owned->pkt_len=owned->data_len=length;++tx->stats.accepted;
    return stage(tx,owned);
}
int ker_reload_tx_pass(struct ker_reload_tx *tx)
{
    int result=valid(tx);if(result)return result;
    if(ker_reload_rx_allowed())return ker_reload_tx_flush(tx);
    for(unsigned i=0;i<tx->stats.staged;i++)divert(tx,tx->batch[i]);
    tx->stats.staged=0;return 0;
}
struct drain_context {struct ker_reload_tx *tx;struct rte_ring *ring;};
static int drain_allowed(void *opaque)
{
    struct drain_context *context=opaque;
    struct rte_mbuf *packets[KER_RELOAD_TX_BURST];
    unsigned count=rte_ring_dequeue_burst(context->ring,(void **)packets,KER_RELOAD_TX_BURST,NULL);
    burst(context->tx,packets,count);return (int)count;
}
int ker_reload_tx_drain(struct ker_reload_tx *tx,struct rte_ring *ring)
{
    int result=valid(tx);if(result)return result;
    if(!ring)return -EINVAL;
    if(tx->stats.staged)return -EBUSY;
    struct drain_context context={tx,ring};
    result=ker_reload_poll(drain_allowed,&context);
    tx->stats.last_poll_error=result<0?result:0;return result;
}
int ker_reload_tx_cancel(struct ker_reload_tx *tx,struct rte_mbuf **packet)
{
    if(!tx || !packet || *packet)return -EINVAL;
    if(tx->active)return -EBUSY;
    if(!tx->stats.staged)return 0;
    *packet=tx->batch[0];--tx->stats.staged;
    memmove(tx->batch,tx->batch+1,tx->stats.staged*sizeof(tx->batch[0]));return 1;
}
int ker_reload_tx_snapshot(const struct ker_reload_tx *tx,struct ker_reload_tx_stats *stats)
{
    if(!tx || !stats)return -EINVAL;
    *stats=tx->stats;return 0;
}
