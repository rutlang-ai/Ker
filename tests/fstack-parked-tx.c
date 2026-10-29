/* Source-shaped IT-NR-A09 TX tests from the pinned F-Stack integration suite.
 * All control/mbuf/burst operations use actual public Ker and DPDK APIs. */
#define _GNU_SOURCE
#include "eal.h"
#include <ker/reload-tx.h>
#include <ker/reload.h>
#include <ker/packet-dispatcher.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <errno.h>
#include <string.h>
static struct rte_mempool *pool;
static struct rte_ring *drain,*wire,*rx;
static struct ker_reload_tx *old,*owner,*call_context;
static uint16_t port;
static uint64_t calls,submitted,reentry_checks;
static struct rte_mbuf *packet(unsigned char value)
{
    struct rte_mbuf *m=rte_pktmbuf_alloc(pool);CHECK(m);
    void *p=rte_pktmbuf_append(m,64);CHECK(p);memset(p,value,64);return m;
}
static uint16_t count_burst(uint16_t device,uint16_t queue,struct rte_mbuf **packets,uint16_t count,void *arg)
{
    CHECK(device==port && queue==0 && packets && count && arg==pool);
    ++calls;submitted+=count;
    struct ker_reload_tx *tx=call_context;CHECK(tx);
    struct rte_mbuf *nested=packet(0xfa),*same=nested,*cancelled=NULL;
    CHECK(ker_reload_tx_owned(tx,&nested)==-EBUSY && nested==same);
    struct ker_reload_tx *local=tx;
    CHECK(ker_reload_tx_destroy(&local)==-EBUSY && local==tx);
    CHECK(ker_reload_tx_cancel(tx,&cancelled)==-EBUSY && !cancelled);
    rte_pktmbuf_free(nested);++reentry_checks;
    return count;
}
static struct ker_reload_tx_stats stats(struct ker_reload_tx *tx)
{struct ker_reload_tx_stats s;CHECK(!ker_reload_tx_snapshot(tx,&s));return s;}
static void select_generation(int generation)
{CHECK(!ker_reload_worker_select(generation,(unsigned)generation));}
static void park(void)
{CHECK(!ker_reload_rx_mark(1,0));select_generation(0);CHECK(!ker_reload_rx_allowed());}
static unsigned drain_all(void)
{
    select_generation(1);call_context=owner;unsigned n=0;int result;
    while((result=ker_reload_tx_drain(owner,drain))>0)n+=(unsigned)result;
    CHECK(!result);select_generation(0);call_context=old;return n;
}
static void received(unsigned count,unsigned char value,int sequence)
{
    CHECK(rte_ring_count(wire)==count);
    for(unsigned i=0;i<count;i++) {
        struct rte_mbuf *m=NULL;CHECK(!rte_ring_dequeue(wire,(void **)&m) && m && m->pkt_len==64);
        CHECK(rte_mbuf_refcnt_read(m)==1);
        for(unsigned b=0;b<64;b++)CHECK(rte_pktmbuf_mtod(m,unsigned char *)[b]==(unsigned char)(value+(sequence?i:0)));
        rte_pktmbuf_free(m);
    }
}
static void divert_case(void)
{
    park();unsigned char bytes[64];memset(bytes,0x31,sizeof(bytes));
    for(unsigned i=0;i<8;i++)CHECK(!ker_reload_tx_copy(old,bytes,sizeof(bytes)));
    for(unsigned i=0;i<4;i++){struct rte_mbuf *m=packet(0x31);CHECK(!ker_reload_tx_owned(old,&m) && !m);}
    struct ker_reload_tx_stats s=stats(old);
    CHECK(!calls && !submitted && rte_ring_count(drain)==12);
    CHECK(s.accepted==12 && s.diverted==12 && !s.full && !s.divert_dropped_segments && !s.staged);
    /* A parked pass must not dequeue the ring it cannot transmit. */
    CHECK(!ker_reload_tx_drain(old,drain) && rte_ring_count(drain)==12 && !calls);
    printf("PARKED_DIVERT calls=%llu submitted=%llu ring=%u dropped=%llu\n",
        (unsigned long long)calls,(unsigned long long)submitted,rte_ring_count(drain),(unsigned long long)s.divert_dropped_segments);
    CHECK(drain_all()==12 && rte_ring_empty(drain) && calls==1 && submitted==12);
    CHECK(stats(owner).hardware_calls==1 && stats(owner).hardware_packets==12);
    received(12,0x31,0);
}
static void watermark_case(void)
{
    park();CHECK(!drain_all());unsigned char bytes[64];
    for(unsigned round=0;round<4;round++) {
        for(unsigned i=0;i<64;i++){memset(bytes,i,sizeof(bytes));CHECK(!ker_reload_tx_copy(old,bytes,sizeof(bytes)));}
        CHECK(rte_ring_count(drain)==64 && drain_all()==64);received(64,0,1);
    }
    struct ker_reload_tx_stats s=stats(old);
    CHECK(!s.full && !s.divert_dropped_segments && calls==8 && submitted==256);
    printf("WATERMARK_STEADY calls=%llu submitted=%llu full=%llu dropped=%llu\n",
        (unsigned long long)calls,(unsigned long long)submitted,(unsigned long long)s.full,(unsigned long long)s.divert_dropped_segments);
    unsigned cap=rte_ring_get_capacity(drain);CHECK(cap==255);
    for(unsigned i=0;i<cap;i++){memset(bytes,i,sizeof(bytes));CHECK(!ker_reload_tx_copy(old,bytes,sizeof(bytes)));}
    CHECK(rte_ring_count(drain)==cap && calls==8);
    unsigned before=rte_mempool_avail_count(pool);memset(bytes,0xee,sizeof(bytes));
    CHECK(!ker_reload_tx_copy(old,bytes,sizeof(bytes)));
    s=stats(old);CHECK(s.full==1 && s.divert_dropped_segments==1 && rte_ring_count(drain)==cap);
    CHECK(rte_mempool_avail_count(pool)==before && stats(owner).hardware_dropped_segments==0);
    printf("WATERMARK_OVERFLOW calls=%llu ring=%u full=%llu divert_drop=%llu owner_drop=%llu\n",
        (unsigned long long)calls,rte_ring_count(drain),(unsigned long long)s.full,(unsigned long long)s.divert_dropped_segments,
        (unsigned long long)stats(owner).hardware_dropped_segments);
    CHECK(drain_all()==cap && calls==16 && submitted==256+cap);received(cap,0,1);
    CHECK(stats(owner).hardware_calls==16 && stats(owner).hardware_packets==256+cap);
}
static int response(void *data,uint16_t *length,uint16_t queue,uint16_t queues,struct ker_dispatcher_context context)
{CHECK(data && *length==64 && !queue && queues==1 && !context.vlan.stripped);return -2;}
static void reply_batch(unsigned char value)
{
    for(unsigned i=0;i<KER_RELOAD_TX_BURST;i++) {
        struct rte_mbuf *m=packet(value);uint16_t length=0;
        CHECK(ker_packet_dispatch(m,&length,0,1)==-2 && length==64);
        CHECK(!ker_reload_tx_reply(old,&m,length) && !m);
    }
}
static void guard_case(void)
{
    park();CHECK(!ker_packet_dispatcher_register_context(response));
    reply_batch(0x52);
    CHECK(!calls && !submitted && !stats(old).staged && stats(old).guard_dropped_segments==32);
    CHECK(rte_mempool_avail_count(pool)==512 && rte_ring_empty(drain) && rte_ring_empty(wire));
    printf("PARKED_GUARD calls=%llu submitted=%llu dropped=%llu staged=%u pool=%u\n",
        (unsigned long long)calls,(unsigned long long)submitted,(unsigned long long)stats(old).guard_dropped_segments,
        stats(old).staged,rte_mempool_avail_count(pool));
    /* Positive control: the same reply path reaches the real PMD as owner. */
    CHECK(!ker_reload_rx_mark(0,0));CHECK(ker_reload_rx_allowed());reply_batch(0x53);
    CHECK(calls==1 && submitted==32 && stats(old).hardware_packets==32);
    received(32,0x53,0);CHECK(!ker_packet_dispatcher_unregister_context());
}
static void parked_pass_case(void)
{
    for(unsigned i=0;i<5;i++){struct rte_mbuf *m=packet((unsigned char)i);CHECK(!ker_reload_tx_owned(old,&m) && !m);}
    CHECK(stats(old).staged==5 && !calls && rte_ring_empty(drain));
    park();CHECK(!ker_reload_tx_pass(old));
    CHECK(!stats(old).staged && stats(old).diverted==5 && !stats(old).guard_dropped_segments);
    CHECK(!calls && !submitted && rte_ring_count(drain)==5);
    CHECK(!ker_reload_tx_drain(old,drain) && rte_ring_count(drain)==5 && !calls);
    printf("PARKED_PASS calls=%llu submitted=%llu ring=%u staged=%u\n",
        (unsigned long long)calls,(unsigned long long)submitted,rte_ring_count(drain),stats(old).staged);
    CHECK(drain_all()==5 && calls==1 && submitted==5);received(5,0,1);
}
static void ownership_case(void)
{
    /* Empty-only destruction and explicit FIFO cancellation preserve ownership. */
    struct rte_mbuf *m=packet(0x70),*original=m;
    CHECK(!ker_reload_tx_owned(old,&m) && !m);
    struct ker_reload_tx *same=old;CHECK(ker_reload_tx_destroy(&same)==-EBUSY && same==old);
    CHECK(ker_reload_tx_cancel(old,&m)==1 && m==original);rte_pktmbuf_free(m);
    m=NULL;CHECK(!ker_reload_tx_cancel(old,&m) && !m);
    /* A real PMD shortfall has different accounting from the parked guard. */
    for(unsigned i=0;i<255;i++)CHECK(!rte_ring_enqueue(wire,packet(0x71)));
    for(unsigned i=0;i<32;i++){m=packet(0x72);CHECK(!ker_reload_tx_owned(old,&m) && !m);}
    CHECK(calls==1 && submitted==32 && stats(old).hardware_packets==0);
    CHECK(stats(old).hardware_dropped_segments==32 && !stats(old).guard_dropped_segments);
    received(255,0x71,0);
    unsigned char too_large[1024]={0};CHECK(ker_reload_tx_copy(old,too_large,sizeof(too_large))==-ENOSPC);
    CHECK(rte_mempool_avail_count(pool)==512);
    m=packet(0x73);original=m;CHECK(ker_reload_tx_reply(old,&m,65)==-EINVAL && m==original);
    rte_pktmbuf_free(m);
    m=packet(0x74);struct rte_mbuf *tail=packet(0x75);CHECK(!rte_pktmbuf_chain(m,tail));original=m;
    CHECK(ker_reload_tx_reply(old,&m,64)==-ENOTSUP && m==original);rte_pktmbuf_free(m);
}
int main(int argc,char **argv)
{
    CHECK(argc==2);ker_test_eal_init();
    pool=rte_pktmbuf_pool_create("park_tx_pool",512,0,0,512,SOCKET_ID_ANY);CHECK(pool);
    drain=rte_ring_create("park_tx_g0",256,SOCKET_ID_ANY,0);
    wire=rte_ring_create("park_tx_wire",256,SOCKET_ID_ANY,0);
    rx=rte_ring_create("park_tx_rx",256,SOCKET_ID_ANY,0);CHECK(drain && wire && rx);
    struct rte_ring *in[]={rx},*out[]={wire};
    int created=rte_eth_from_rings("parked_tx",in,1,out,1,SOCKET_ID_ANY);CHECK(created>=0);port=(uint16_t)created;
    struct rte_eth_conf conf={0};CHECK(!rte_eth_dev_configure(port,1,1,&conf));
    CHECK(!rte_eth_rx_queue_setup(port,0,256,SOCKET_ID_ANY,NULL,pool));
    CHECK(!rte_eth_tx_queue_setup(port,0,256,SOCKET_ID_ANY,NULL));CHECK(!rte_eth_dev_start(port));
    const struct rte_eth_rxtx_callback *hook=rte_eth_add_tx_callback(port,0,count_burst,pool);CHECK(hook);
    size_t size=ker_reload_state_size();void *state=calloc(1,size);CHECK(state);
    CHECK(!ker_reload_state_init(state,size,0));CHECK(!ker_reload_bind_state(state,size,1,0));select_generation(0);
    CHECK(!ker_reload_tx_create(pool,drain,port,0,&old));CHECK(!ker_reload_tx_create(pool,drain,port,0,&owner));call_context=old;
    if(!strcmp(argv[1],"divert"))divert_case();
    else if(!strcmp(argv[1],"watermark"))watermark_case();
    else if(!strcmp(argv[1],"guard"))guard_case();
    else if(!strcmp(argv[1],"pass"))parked_pass_case();
    else {CHECK(!strcmp(argv[1],"ownership"));ownership_case();}
    CHECK(reentry_checks==calls && !stats(old).staged && !stats(owner).staged);
    CHECK(rte_ring_empty(drain) && rte_ring_empty(wire) && rte_mempool_avail_count(pool)==512);
    struct rte_mbuf *all[512];
    for(unsigned i=0;i<512;i++){all[i]=rte_pktmbuf_alloc(pool);CHECK(all[i]);for(unsigned j=0;j<i;j++)CHECK(all[i]!=all[j]);}
    CHECK(!rte_pktmbuf_alloc(pool));for(unsigned i=0;i<512;i++)rte_pktmbuf_free(all[i]);
    struct ker_reload_tx_stats old_stats=stats(old),owner_stats=stats(owner);
    struct rte_eth_stats pmd;CHECK(!rte_eth_stats_get(port,&pmd));
    CHECK(pmd.opackets==old_stats.hardware_packets+owner_stats.hardware_packets);
    printf("RESULT %s calls=%llu submitted=%llu diverted=%llu full=%llu divert_drop=%llu guard_drop=%llu sent=%llu owner_drop=%llu pool=512/512\n",argv[1],
        (unsigned long long)calls,(unsigned long long)submitted,(unsigned long long)old_stats.diverted,
        (unsigned long long)old_stats.full,(unsigned long long)old_stats.divert_dropped_segments,
        (unsigned long long)old_stats.guard_dropped_segments,
        (unsigned long long)(old_stats.hardware_packets+owner_stats.hardware_packets),
        (unsigned long long)(old_stats.hardware_dropped_segments+owner_stats.hardware_dropped_segments));
    CHECK(!ker_reload_tx_destroy(&old) && !old);CHECK(!ker_reload_tx_destroy(&owner) && !owner);
    ker_reload_unbind_state();free(state);
    CHECK(!rte_eth_remove_tx_callback(port,0,hook));rte_free((void *)hook);
    CHECK(!rte_eth_dev_stop(port));CHECK(!rte_eth_dev_close(port));
    rte_ring_free(drain);rte_ring_free(wire);rte_ring_free(rx);rte_mempool_free(pool);CHECK(!rte_eal_cleanup());
    puts("PASS: source-shaped parked TX assertions, real PMD hook/FIFO and unique pool512/512 cleanup");return 0;
}
