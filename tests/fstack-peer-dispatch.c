/* Adapted from test_ut_nr_27_dispatch_peer_boundary at the pinned F-Stack
 * snapshot. Real public Ker ownership API, original EAL/ring/mbuf/PMD; no
 * ff_dpdk_if global layout or FreeBSD protocol behavior is substituted. */
#define _GNU_SOURCE
#include "eal.h"
#include <ker/peer-dispatcher.h>
#include <ker/reload.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <errno.h>
#include <string.h>
static int selected=KER_DISPATCH_PEER;
static unsigned calls;
static int choose(void *data, uint16_t *length, uint16_t queue, uint16_t queues,
    struct ker_dispatcher_context context)
{
    CHECK(data && *length==32 && queue==0 && queues==2);
    CHECK(!context.vlan.stripped && !context.vlan.vlan_tci);
    calls++;
    return selected; /* receives borrowed bytes, never the owned mbuf */
}
static struct rte_mbuf *make(struct rte_mempool *pool, unsigned char value)
{
    struct rte_mbuf *m=rte_pktmbuf_alloc(pool); CHECK(m);
    void *p=rte_pktmbuf_append(m,32); CHECK(p); memset(p,value,32);
    return m;
}
static int dispatch(struct rte_mbuf **m,struct rte_ring *peer,struct ker_peer_dispatch_stats *stats)
{
    uint16_t length=0; int decision=99;
    int result=ker_packet_dispatch_peer(m,&length,0,2,peer,&decision,stats);
    CHECK(decision==selected && length==32);
    return result;
}
int main(void)
{
    ker_test_eal_init();
    struct rte_mempool *pool=rte_pktmbuf_pool_create("peer_pool",127,0,0,512,SOCKET_ID_ANY); CHECK(pool);
    struct rte_ring *peer=rte_ring_create("peer_g1",64,SOCKET_ID_ANY,0);
    struct rte_ring *tx=rte_ring_create("peer_tx",64,SOCKET_ID_ANY,0); CHECK(peer && tx);
    struct rte_ring *rx[]={peer},*out[]={tx};
    int created=rte_eth_from_rings("peer_dispatch",rx,1,out,1,SOCKET_ID_ANY); CHECK(created>=0);
    uint16_t port=(uint16_t)created; struct rte_eth_conf conf={0};
    CHECK(!rte_eth_dev_configure(port,1,1,&conf));
    CHECK(!rte_eth_rx_queue_setup(port,0,64,SOCKET_ID_ANY,NULL,pool));
    CHECK(!rte_eth_tx_queue_setup(port,0,64,SOCKET_ID_ANY,NULL)); CHECK(!rte_eth_dev_start(port));
    size_t size=ker_reload_state_size(); void *state=calloc(1,size); CHECK(state);
    CHECK(!ker_reload_state_init(state,size,0)); CHECK(!ker_reload_bind_state(state,size,1,0));
    CHECK(!ker_reload_worker_select(0,0));
    uint32_t epoch,target; CHECK(!ker_reload_round_begin(&epoch,&target) && target==1);
    CHECK(!ker_packet_dispatcher_register_context(choose));
    struct ker_peer_dispatch_stats stats={0};
    struct rte_mbuf *m=make(pool,0x91),*original=m,*received=NULL;
    unsigned before=rte_mempool_avail_count(pool);
    CHECK(dispatch(&m,peer,&stats)==KER_PEER_FORWARDED && !m);
    CHECK(rte_ring_count(peer)==1 && rte_mempool_avail_count(pool)==before);
    CHECK(rte_eth_rx_burst(port,0,&received,1)==1 && received==original && received->pkt_len==32);
    for(unsigned i=0;i<32;i++) CHECK(rte_pktmbuf_mtod(received,unsigned char *)[i]==0x91);
    CHECK(rte_mbuf_refcnt_read(received)==1); rte_pktmbuf_free(received);
    /* Full peer ring: count the failed enqueue, free exactly once, keep FIFO. */
    unsigned capacity=rte_ring_get_capacity(peer); CHECK(capacity==63);
    for(unsigned i=0;i<capacity;i++) CHECK(!rte_ring_enqueue(peer,make(pool,(unsigned char)i)));
    before=rte_mempool_avail_count(pool); m=make(pool,0xee);
    CHECK(dispatch(&m,peer,&stats)==KER_PEER_DROPPED && !m);
    CHECK(rte_mempool_avail_count(pool)==before && rte_ring_count(peer)==capacity && stats.full==1);
    /* Closed round: no enqueue attempt, no full-counter increment, no leak. */
    CHECK(!ker_reload_round_finish(0)); before=rte_mempool_avail_count(pool); m=make(pool,0xef);
    CHECK(dispatch(&m,peer,&stats)==KER_PEER_DROPPED && !m);
    CHECK(rte_mempool_avail_count(pool)==before && rte_ring_count(peer)==capacity && stats.full==1 && stats.closed==1);
    for(unsigned i=0;i<capacity;i++) {
        CHECK(rte_eth_rx_burst(port,0,&received,1)==1 && rte_mbuf_refcnt_read(received)==1);
        for(unsigned b=0;b<32;b++) CHECK(rte_pktmbuf_mtod(received,unsigned char *)[b]==i);
        rte_pktmbuf_free(received);
    }
    CHECK(rte_ring_empty(peer) && rte_mempool_avail_count(pool)==127);
    /* Non-PEER policy and invalid arguments retain caller ownership. */
    const int results[]={0,1,-1,-2};
    for(unsigned i=0;i<4;i++) {
        selected=results[i]; m=make(pool,0x55); original=m;
        CHECK(dispatch(&m,peer,&stats)==KER_PEER_PASSTHROUGH && m==original && rte_mbuf_refcnt_read(m)==1);
        rte_pktmbuf_free(m);
    }
    selected=KER_DISPATCH_PEER; m=make(pool,0x56); original=m;
    uint16_t length=123; int decision=123; unsigned previous_calls=calls;
    CHECK(ker_packet_dispatch_peer(&m,&length,2,2,peer,&decision,&stats)==-EINVAL && m==original && calls==previous_calls);
    CHECK(length==123 && decision==123); rte_pktmbuf_free(m);
    m=make(pool,0x57); original=m;
    CHECK(ker_packet_dispatch_peer(&m,&length,0,2,NULL,&decision,&stats)==-EINVAL && m==original && calls==previous_calls);
    rte_pktmbuf_free(m);
    ker_reload_unbind_state(); free(state);
    m=make(pool,0x58); CHECK(dispatch(&m,peer,&stats)==KER_PEER_DROPPED && !m && stats.closed==2);
    /* A dropped chain releases every segment, with segment-based drop count. */
    m=make(pool,0x59); struct rte_mbuf *tail=make(pool,0x5a);
    CHECK(!rte_pktmbuf_chain(m,tail) && m->nb_segs==2);
    CHECK(dispatch(&m,peer,&stats)==KER_PEER_DROPPED && !m && stats.closed==3);
    CHECK(stats.forwarded==1 && stats.full==1 && stats.dropped_segments==5 && rte_mempool_avail_count(pool)==127);
    CHECK(!ker_packet_dispatcher_unregister_context());
    /* Allocation uniqueness catches a duplicated free-list entry after drops. */
    struct rte_mbuf *all[127];
    for(unsigned i=0;i<127;i++) { all[i]=rte_pktmbuf_alloc(pool); CHECK(all[i]); for(unsigned j=0;j<i;j++) CHECK(all[i]!=all[j]); }
    CHECK(!rte_pktmbuf_alloc(pool)); for(unsigned i=0;i<127;i++) rte_pktmbuf_free(all[i]);
    struct rte_eth_stats counters; CHECK(!rte_eth_stats_get(port,&counters) && counters.ipackets==64);
    CHECK(!rte_eth_dev_stop(port)); CHECK(!rte_eth_dev_close(port));
    rte_ring_free(peer); rte_ring_free(tx); rte_mempool_free(pool); CHECK(!rte_eal_cleanup());
    puts("PASS: source PEER transfer/full/closed assertions; real net_ring64 FIFO, exact counters, callback ownership and unique pool127/127 cleanup");
    return 0;
}
