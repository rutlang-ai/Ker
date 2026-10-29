/* Source-shaped A10 mechanism qualification. The source harness itself
 * simulates metadata admission; this program does not execute a TCP stack. */
#define _GNU_SOURCE
#include "eal.h"
#include "a10-dispatch-policy.h"
#include <ker/peer-dispatcher.h>
#include <ker/reload.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
static struct rte_mempool *pool;
#define g_inj_pool pool
#include "fstack-a10-packets-source.inc"
#undef g_inj_pool
struct expected {struct rte_mbuf *pointer;unsigned length;uint8_t bytes[128];};
struct sink {unsigned generation,calls,expected_count;struct expected expected[16];};
static struct sink local_sink={.generation=0},peer_sink={.generation=1};
static struct rte_ring *hardware,*peer,*unused_tx;
static struct ker_peer_dispatch_stats peer_stats;
static uint16_t port;
static unsigned classifier_calls,hardware_passes,hardware_callbacks,hardware_packets;
static int next_disposition;
static void expect(struct sink *sink,struct rte_mbuf *packet)
{
    CHECK(sink->expected_count<16 && packet->pkt_len<=128);
    struct expected *e=&sink->expected[sink->expected_count++];
    e->pointer=packet;e->length=packet->pkt_len;
    memcpy(e->bytes,rte_pktmbuf_mtod(packet,void *),e->length);
}
static void input(struct rte_mbuf *packet,void *argument)
{
    struct sink *sink=argument;CHECK(sink && sink->calls<sink->expected_count);
    CHECK((sink->generation==0)==!!ker_reload_rx_allowed());
    struct expected *e=&sink->expected[sink->calls++];
    CHECK(packet==e->pointer && packet->pkt_len==e->length && rte_mbuf_refcnt_read(packet)==1);
    uint8_t bytes[128];const void *data=rte_pktmbuf_read(packet,0,e->length,bytes);
    CHECK(data && !memcmp(data,e->bytes,e->length));
    rte_pktmbuf_free(packet);
}
static int classify(void *data,uint16_t *length,uint16_t queue,uint16_t queues,
    struct ker_dispatcher_context context)
{
    ++classifier_calls;
    return example_a10_classifier(data,length,queue,queues,context);
}
static uint16_t rx_count(uint16_t device,uint16_t queue,struct rte_mbuf **packets,
    uint16_t count,uint16_t capacity,void *argument)
{
    CHECK(device==port && !queue && packets && count<=capacity && argument==pool);
    ++hardware_callbacks;hardware_packets+=count;return count;
}
static int hardware_input(void *argument)
{
    CHECK(argument==pool);++hardware_passes;
    struct rte_mbuf *packet=NULL;CHECK(rte_eth_rx_burst(port,0,&packet,1)==1 && packet);
    uint16_t length=0;int decision=99;
    int result=ker_packet_dispatch_peer(&packet,&length,0,1,peer,&decision,&peer_stats);
    CHECK(result==next_disposition);
    if(result==KER_PEER_PASSTHROUGH){CHECK(packet && decision==0);input(packet,&local_sink);}
    else CHECK(!packet && decision==KER_DISPATCH_PEER);
    return 0;
}
static void inject(struct rte_mbuf *packet,int disposition)
{
    next_disposition=disposition;
    CHECK(!rte_ring_enqueue(hardware,packet));
    CHECK(!ker_reload_poll(hardware_input,pool));
    CHECK(rte_ring_empty(hardware));
}
static void generation(unsigned value)
{CHECK(!ker_reload_worker_select((int)value,value));}
static void parked_consume(unsigned expected)
{
    unsigned before_classifiers=classifier_calls,before_hardware=hardware_callbacks;
    CHECK(!example_a10_parked_input(peer,32,input,&peer_sink)); /* owner cannot consume old's ring */
    CHECK(rte_ring_count(peer)==expected);
    generation(1);CHECK(!ker_reload_rx_allowed());
    unsigned before_passes=hardware_passes;
    CHECK(!ker_reload_poll(hardware_input,pool));CHECK(hardware_passes==before_passes);
    CHECK(example_a10_parked_input(peer,32,input,&peer_sink)==(int)expected);
    CHECK(!example_a10_parked_input(peer,32,input,&peer_sink));
    CHECK(classifier_calls==before_classifiers && hardware_callbacks==before_hardware && rte_ring_empty(peer));
    generation(0);CHECK(ker_reload_rx_allowed());
}
static void dispatch_case(void)
{
    const uint32_t cli=0xc0a80110,srv=0xc0a80120;ff_flow_key_t old,new;
    flow_key_v4(&old,cli,srv,htons(40001),htons(80));CHECK(!ff_flow_map_lookup(&old));
    struct rte_mbuf *packet=inj_mbuf(cli,srv,htons(40001),htons(80));CHECK(packet);expect(&peer_sink,packet);
    unsigned available=rte_mempool_avail_count(pool);
    inject(packet,KER_PEER_FORWARDED);
    CHECK(rte_ring_count(peer)==1 && rte_mempool_avail_count(pool)==available && !local_sink.calls);
    flow_key_v4(&new,cli,srv,htons(40002),htons(80));CHECK(!ff_flow_map_lookup(&new));
    CHECK(!ff_flow_map_insert(&new) && ff_flow_map_lookup(&new)==1); /* explicit caller admission before input */
    available=rte_mempool_avail_count(pool);
    packet=inj_mbuf(cli,srv,htons(40002),htons(80));CHECK(packet);expect(&local_sink,packet);
    inject(packet,KER_PEER_PASSTHROUGH);
    CHECK(rte_ring_count(peer)==1 && rte_mempool_avail_count(pool)==available && local_sink.calls==1);
    printf("DISPATCH_METADATA peer=%u local=%u classifiers=%u pool=%u\n",rte_ring_count(peer),local_sink.calls,classifier_calls,rte_mempool_avail_count(pool));
    parked_consume(1);CHECK(peer_sink.calls==1 && rte_mempool_avail_count(pool)==512);
}
static void mechanism_case(void)
{
    const uint32_t cli=0xc0a80111,srv=0xc0a80121;ff_flow_key_t key;
    flow_key_v4(&key,cli,srv,htons(40011),htons(80));CHECK(!ff_flow_map_lookup(&key));
    unsigned available=rte_mempool_avail_count(pool);
    for(unsigned phase=0;phase<2;phase++) {
        struct rte_mbuf *packet=inj_mbuf(cli,srv,htons(40011),htons(80));CHECK(packet);expect(&peer_sink,packet);
        inject(packet,KER_PEER_FORWARDED);
        CHECK(rte_ring_count(peer)==1 && rte_mempool_avail_count(pool)==available-1);
        parked_consume(1);CHECK(peer_sink.calls==phase+1 && rte_mempool_avail_count(pool)==available);
    }
    CHECK(!ker_reload_round_finish(0));CHECK(ker_reload_rx_allowed());
    struct rte_mbuf *packet=inj_mbuf(cli,srv,htons(40011),htons(80));CHECK(packet);
    inject(packet,KER_PEER_DROPPED);
    CHECK(rte_ring_empty(peer) && rte_mempool_avail_count(pool)==available && peer_stats.closed==1 && peer_stats.dropped_segments==1);
    CHECK(peer_sink.calls==2 && !local_sink.calls && classifier_calls==3);
    printf("WINDOW_MECHANISM peer_inputs=%u classifiers=%u closed=%llu drop_segments=%llu pool=%u\n",peer_sink.calls,classifier_calls,
        (unsigned long long)peer_stats.closed,(unsigned long long)peer_stats.dropped_segments,rte_mempool_avail_count(pool));
}
static void bounds_case(void)
{
    ff_flow_key_t key;flow_key_v4(&key,0x01020304,0x05060708,htons(41000),htons(80));
    CHECK(!ff_flow_map_insert(&key));
    /* Same real callback: bounded valid header hits; malformed layouts go to
     * the caller's local input policy without out-of-bounds tuple reads. */
    struct rte_mbuf *packet=inj_mbuf(key.src[0],key.dst[0],key.sport,key.dport);CHECK(packet);expect(&local_sink,packet);
    inject(packet,KER_PEER_PASSTHROUGH);
    packet=inj_mbuf(key.src[0],key.dst[0],key.sport,key.dport);CHECK(packet);
    rte_pktmbuf_mtod(packet,uint8_t *)[14]=0x4f;expect(&local_sink,packet);inject(packet,KER_PEER_PASSTHROUGH);
    packet=inj_mbuf(key.src[0],key.dst[0],key.sport,key.dport);CHECK(packet);
    rte_pktmbuf_mtod(packet,uint8_t *)[46]=0xf0;expect(&local_sink,packet);inject(packet,KER_PEER_PASSTHROUGH);
    packet=inj_mbuf(key.src[0],key.dst[0],key.sport,key.dport);CHECK(packet);
    packet->pkt_len=packet->data_len=20;expect(&local_sink,packet);inject(packet,KER_PEER_PASSTHROUGH);
    packet=inj_mbuf(key.src[0],key.dst[0],key.sport,key.dport);CHECK(packet);
    uint8_t *data=rte_pktmbuf_mtod(packet,uint8_t *);CHECK(rte_pktmbuf_append(packet,4));
    memmove(data+18,data+14,40);data[12]=0x81;data[13]=0;data[14]=0;data[15]=7;data[16]=8;data[17]=0;
    expect(&local_sink,packet);inject(packet,KER_PEER_PASSTHROUGH);
    CHECK(local_sink.calls==5 && !peer_stats.forwarded && rte_ring_empty(peer));
    struct rte_mbuf *retained=inj_mbuf(key.src[0],key.dst[0],key.sport,key.dport);CHECK(retained);
    CHECK(!rte_ring_enqueue(peer,retained));
    CHECK(example_a10_parked_input(peer,33,input,&peer_sink)==-EINVAL && rte_ring_count(peer)==1);
    CHECK(!ker_reload_rx_mark(0,1));
    CHECK(example_a10_parked_input(peer,32,input,&peer_sink)==-EAGAIN && rte_ring_count(peer)==1);
    CHECK(!ker_reload_rx_mark(0,0));expect(&peer_sink,retained);parked_consume(1);
    printf("BOUNDS local=%u peer=%u pool=%u\n",local_sink.calls,peer_sink.calls,rte_mempool_avail_count(pool));
}
int main(int argc,char **argv)
{
    CHECK(argc==2);ker_test_eal_init();
    pool=rte_pktmbuf_pool_create("a10_pool",512,0,0,512,SOCKET_ID_ANY);CHECK(pool);
    hardware=rte_ring_create("a10_rx0",64,SOCKET_ID_ANY,0);
    peer=rte_ring_create("a10_peer_g1",64,SOCKET_ID_ANY,0);
    unused_tx=rte_ring_create("a10_tx0",64,SOCKET_ID_ANY,0);CHECK(hardware && peer && unused_tx);
    struct rte_ring *rx[]={hardware},*tx[]={unused_tx};
    int created=rte_eth_from_rings("a10_mechanism",rx,1,tx,1,SOCKET_ID_ANY);CHECK(created>=0);port=(uint16_t)created;
    struct rte_eth_conf conf={0};CHECK(!rte_eth_dev_configure(port,1,1,&conf));
    CHECK(!rte_eth_rx_queue_setup(port,0,64,SOCKET_ID_ANY,NULL,pool));
    CHECK(!rte_eth_tx_queue_setup(port,0,64,SOCKET_ID_ANY,NULL));CHECK(!rte_eth_dev_start(port));
    const struct rte_eth_rxtx_callback *hook=rte_eth_add_rx_callback(port,0,rx_count,pool);CHECK(hook);
    size_t size=ker_reload_state_size();void *state=calloc(1,size);CHECK(state);
    CHECK(!ker_reload_state_init(state,size,0));CHECK(!ker_reload_bind_state(state,size,1,0));generation(0);
    uint32_t epoch,target;CHECK(!ker_reload_round_begin(&epoch,&target) && target==1 && ker_reload_rx_allowed());
    example_flow_enable(1);ff_flow_map_open();CHECK(ff_flow_map_active());
    CHECK(!ker_packet_dispatcher_register_context(classify));
    if(!strcmp(argv[1],"dispatch"))dispatch_case();
    else if(!strcmp(argv[1],"mechanism"))mechanism_case();
    else {CHECK(!strcmp(argv[1],"bounds"));bounds_case();}
    CHECK(hardware_passes==hardware_callbacks && hardware_callbacks==hardware_packets && hardware_packets==classifier_calls);
    struct rte_eth_stats statistics;CHECK(!rte_eth_stats_get(port,&statistics));
    CHECK(statistics.ipackets==hardware_packets && statistics.opackets==0);
    CHECK(local_sink.calls==local_sink.expected_count && peer_sink.calls==peer_sink.expected_count);
    CHECK(rte_mempool_avail_count(pool)==512 && rte_ring_empty(peer) && rte_ring_empty(hardware));
    struct rte_mbuf *all[512];
    for(unsigned i=0;i<512;i++){all[i]=rte_pktmbuf_alloc(pool);CHECK(all[i]);for(unsigned j=0;j<i;j++)CHECK(all[i]!=all[j]);}
    CHECK(!rte_pktmbuf_alloc(pool));for(unsigned i=0;i<512;i++)rte_pktmbuf_free(all[i]);
    CHECK(!ker_packet_dispatcher_unregister_context());ff_flow_map_close();example_flow_enable(0);
    struct ker_reload_runtime view;CHECK(!ker_reload_runtime_view(&view));if(view.reload_active)CHECK(!ker_reload_round_finish(0));
    ker_reload_unbind_state();free(state);
    CHECK(!rte_eth_remove_rx_callback(port,0,hook));rte_free((void *)hook);
    CHECK(!rte_eth_dev_stop(port));CHECK(!rte_eth_dev_close(port));
    rte_ring_free(hardware);rte_ring_free(peer);rte_ring_free(unused_tx);rte_mempool_free(pool);CHECK(!rte_eal_cleanup());
    printf("PASS: A10 %s synthetic metadata mechanism, original PMD RX=%u, local=%u, parked_input=%u, pool512/512; no TCP stack executed\n",
        argv[1],hardware_packets,local_sink.calls,peer_sink.calls);return 0;
}
