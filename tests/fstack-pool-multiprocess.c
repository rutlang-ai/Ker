/* Public-API caller: actual net_ring packets, typed messages and opaque
 * per-packet reference records. All policy and supervision stay in this app. */
#define _GNU_SOURCE
#include <ker/pools.h>
#include <ker/ipc.h>
#include "check.h"
#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#define META "ker_pool_meta"
#define RX "ker_pool_rx"
#define TX "ker_pool_tx"
#define CONTROL "ker_pool_control"
#define COMPLETE "ker_pool_completion"
#define PORT "net_ring_ker_pool"
#define MAGIC UINT64_C(0x4b4552504f4f4c31)
struct frame { uint64_t nonce; unsigned sequence; unsigned char bytes[84]; };
struct message_data { uint64_t nonce; unsigned sequence, generation; };
struct reference { uint64_t nonce; unsigned sequence,generation;struct rte_mbuf *input,*output;ker_ipc_message *message; };
struct identity { uint64_t magic,nonce;unsigned primary;atomic_uint inflight,done,packets; };
_Static_assert(ATOMIC_INT_LOCK_FREE==2,"process-shared counters must be lock-free");
static struct identity *identity;
static struct rte_mempool *rx_pool,*app[2],*messages,*references;
static struct rte_ring *rx,*tx,*control,*completion;
static uint16_t port;
static unsigned count;
static int shared_mode;
static struct reference *pending;
static unsigned pending_sequence;
static uint64_t nonce(void)
{
    const char *text=getenv("KER_POOL_NONCE");CHECK(text&&*text);char *end;uint64_t n=strtoull(text,&end,16);CHECK(!*end&&n);return n;
}
static void flush(void){CHECK(!fflush(stdout));}
static int selected(void)
{
    struct rte_mempool *pool=ker_mbuf_bank_pool(0);CHECK(pool);
    if(!shared_mode){CHECK(pool==rx_pool);return -1;}
    CHECK(pool==app[0]||pool==app[1]);return pool==app[1];
}
static void census(void)
{
    printf("COUNTS {\"available\":[%u,%u,%u,%u,%u],\"cache\":[%u,%u,%u,%u,%u],\"rx\":%u,\"tx\":%u,\"control\":%u,\"completion\":%u,\"inflight\":%u,\"done\":%u}\n",
        rte_mempool_avail_count(rx_pool),app[0]?rte_mempool_avail_count(app[0]):0,app[1]?rte_mempool_avail_count(app[1]):0,rte_mempool_avail_count(messages),rte_mempool_avail_count(references),
        rx_pool->cache_size,app[0]?app[0]->cache_size:0,app[1]?app[1]->cache_size:0,messages->cache_size,references->cache_size,
        rte_ring_count(rx),rte_ring_count(tx),rte_ring_count(control),rte_ring_count(completion),atomic_load(&identity->inflight),atomic_load(&identity->done));flush();
}
static void check_full(void)
{
    CHECK(rte_mempool_avail_count(rx_pool)==count&&rte_mempool_avail_count(messages)==count&&rte_mempool_avail_count(references)==count);
    if(shared_mode)CHECK(rte_mempool_avail_count(app[0])==count&&rte_mempool_avail_count(app[1])==count);
}
static struct rte_mempool *create(const char *name,enum ker_pool_kind kind,unsigned size)
{
    struct ker_pool_config config={.name=name,.count=count,.kind=kind,.size=size,.shared=shared_mode,.socket=SOCKET_ID_ANY};
    struct rte_mempool *pool=ker_pool_create(&config);CHECK(pool);return pool;
}
static void bank(void)
{
    CHECK(!ker_mbuf_bank_attach(shared_mode));CHECK(!ker_mbuf_bank_bind(0,rx_pool,app[0],app[1]));
}
static void frame_check(struct rte_mbuf *packet,unsigned sequence,int response)
{
    CHECK(packet&&rte_pktmbuf_pkt_len(packet)==sizeof(struct frame));const struct frame *frame=rte_pktmbuf_mtod(packet,const struct frame *);
    CHECK(frame->nonce==nonce()&&frame->sequence==sequence);
    for(unsigned i=0;i<sizeof(frame->bytes);++i)CHECK(frame->bytes[i]==(unsigned char)((sequence+i)^(response?0x5a:0)));
}
static void inject(unsigned sequence,unsigned generation)
{
    CHECK(!pending&&generation<2);struct rte_mbuf *packet=rte_pktmbuf_alloc(rx_pool);CHECK(packet);
    struct frame *frame=(void *)rte_pktmbuf_append(packet,sizeof(*frame));CHECK(frame);frame->nonce=nonce();frame->sequence=sequence;
    for(unsigned i=0;i<sizeof(frame->bytes);++i)frame->bytes[i]=(unsigned char)(sequence+i);
    void *object;CHECK(!rte_mempool_get(references,&object));pending=object;
    CHECK(!rte_mempool_get(messages,&object));ker_ipc_message *message=object;CHECK(message->buf_len>=sizeof(struct message_data));
    struct message_data data={nonce(),sequence,generation};memcpy(message->buf_addr,&data,sizeof(data));message->msg_type=FF_RELOAD;message->reload.cmd=FF_RELOAD_CMD_QUERY;message->ipc_owner_pid=identity->primary;message->ipc_cookie=sequence;
    *pending=(struct reference){nonce(),sequence,generation,packet,NULL,message};pending_sequence=sequence;
    CHECK(!rte_ring_enqueue(rx,packet)&&!rte_ring_enqueue(control,pending));
    printf("INJECTED {\"sequence\":%u,\"generation\":%u}\n",sequence,generation);flush();
}
static void process(void)
{
    CHECK(atomic_fetch_add(&identity->inflight,1)==0);
    void *object;CHECK(!rte_ring_dequeue(control,&object));struct reference *ref=object;
    CHECK(rte_mempool_from_obj(ref)==references&&ref->nonce==nonce());
    ker_ipc_message *message=ref->message;CHECK(rte_mempool_from_obj(message)==messages&&message->msg_type==FF_RELOAD&&message->reload.cmd==FF_RELOAD_CMD_QUERY&&message->ipc_owner_pid==identity->primary&&message->ipc_cookie==ref->sequence);
    struct message_data data;memcpy(&data,message->buf_addr,sizeof(data));CHECK(data.nonce==nonce()&&data.sequence==ref->sequence&&data.generation==ref->generation);
    int generation=selected();if(shared_mode)CHECK(generation==(int)ref->generation);
    struct rte_mbuf *input=NULL;CHECK(rte_eth_rx_burst(port,0,&input,1)==1&&input==ref->input&&input->pool==rx_pool);frame_check(input,ref->sequence,0);
    struct rte_mbuf *output=ker_mbuf_bank_alloc(0);CHECK(output&&output->pool==(shared_mode?app[generation]:rx_pool));
    struct frame *frame=(void *)rte_pktmbuf_append(output,sizeof(*frame));CHECK(frame);memcpy(frame,rte_pktmbuf_mtod(input,const void *),sizeof(*frame));
    for(unsigned i=0;i<sizeof(frame->bytes);++i)frame->bytes[i]^=0x5a;
    ref->input=NULL;ref->output=output;rte_pktmbuf_free(input);
    CHECK(ker_mbuf_bank_detach()==-EBUSY); /* outstanding output keeps bindings */
    unsigned sequence=ref->sequence;
    CHECK(rte_eth_tx_burst(port,0,&output,1)==1&&!rte_ring_enqueue(completion,ref));
    CHECK(atomic_fetch_sub(&identity->inflight,1)==1);atomic_fetch_add(&identity->packets,1);
    printf("PROCESSED {\"sequence\":%u,\"selected\":%d,\"pid\":%u}\n",sequence,generation,(unsigned)getpid());flush();
}
static void finish(void)
{
    void *object;CHECK(!rte_ring_dequeue(completion,&object));struct reference *ref=object;CHECK(rte_mempool_from_obj(ref)==references&&ref->nonce==nonce());
    CHECK(!rte_ring_dequeue(tx,&object)&&object==ref->output);struct rte_mbuf *packet=object;CHECK(packet->pool==(shared_mode?app[ref->generation]:rx_pool));frame_check(packet,ref->sequence,1);
    unsigned sequence=ref->sequence;rte_pktmbuf_free(packet);rte_mempool_put(messages,ref->message);rte_mempool_put(references,ref);atomic_store(&identity->done,sequence);
    printf("FINISHED {\"sequence\":%u,\"selected\":%d,\"pid\":%u}\n",sequence,selected(),(unsigned)getpid());flush();
}
static void caches(void)
{
    struct rte_mempool *pools[]={rx_pool,messages,references};unsigned expected[]={256,16,256};
    for(unsigned i=0;i<3;++i) {
        CHECK(pools[i]->cache_size==expected[i]);struct rte_mempool_cache *cache=rte_mempool_default_cache(pools[i],rte_lcore_id());CHECK(cache&&cache->len>0);
        rte_mempool_cache_flush(cache,pools[i]);CHECK(!cache->len&&rte_mempool_avail_count(pools[i])==count);
    }
    puts("CACHES {\"legacy\":[256,16,256],\"used_and_flushed\":true}");flush();
}
static void primary(int legacy)
{
    CHECK(rte_eal_process_type()==RTE_PROC_PRIMARY);shared_mode=!legacy;count=legacy?1023:63;
    const struct rte_memzone *meta=rte_memzone_reserve(META,sizeof(*identity),SOCKET_ID_ANY,0);CHECK(meta);identity=meta->addr;
    identity->magic=MAGIC;identity->nonce=nonce();identity->primary=getpid();atomic_init(&identity->inflight,0);atomic_init(&identity->done,0);atomic_init(&identity->packets,0);
    rx_pool=create("mbuf_pool_0",KER_POOL_MBUF,RTE_MBUF_DEFAULT_BUF_SIZE);messages=create("ker_pool_messages",KER_POOL_MESSAGE,64);references=create("ker_pool_references",KER_POOL_REFERENCE,sizeof(struct reference));
    bank();
    if(shared_mode) {
        errno=0;CHECK(!ker_mbuf_bank_pool(0)&&errno==ENOENT);CHECK(!ker_mbuf_bank_alloc(0));ker_mbuf_bank_select(1);CHECK(!ker_mbuf_bank_pool(0));ker_mbuf_bank_select(2);CHECK(!ker_mbuf_bank_pool(0));ker_mbuf_bank_select(0);
        for(unsigned g=0;g<2;++g){char name[64];CHECK(!ker_mbuf_generation_name(name,sizeof(name),0,(int)g));app[g]=create(name,KER_POOL_MBUF,RTE_MBUF_DEFAULT_BUF_SIZE);}
        CHECK(!ker_mbuf_bank_bind(0,rx_pool,app[0],app[1]));
    } else {ker_mbuf_bank_select(1);CHECK(ker_mbuf_bank_pool(0)==rx_pool);}
    rx=rte_ring_create(RX,32,SOCKET_ID_ANY,RING_F_SP_ENQ|RING_F_SC_DEQ);tx=rte_ring_create(TX,32,SOCKET_ID_ANY,RING_F_SP_ENQ|RING_F_SC_DEQ);
    control=rte_ring_create(CONTROL,32,SOCKET_ID_ANY,0);completion=rte_ring_create(COMPLETE,32,SOCKET_ID_ANY,0);CHECK(rx&&tx&&control&&completion);
    int created=rte_eth_from_rings("ker_pool",&rx,1,&tx,1,SOCKET_ID_ANY);CHECK(created>=0);port=(uint16_t)created;
    struct rte_eth_conf conf={0};CHECK(!rte_eth_dev_configure(port,1,1,&conf)&&!rte_eth_rx_queue_setup(port,0,128,SOCKET_ID_ANY,NULL,rx_pool)&&!rte_eth_tx_queue_setup(port,0,128,SOCKET_ID_ANY,NULL)&&!rte_eth_dev_start(port));
    struct rte_eth_dev_info info;CHECK(!rte_eth_dev_info_get(port,&info)&&!strcmp(info.driver_name,"net_ring"));
    printf("READY {\"pid\":%u,\"nonce\":\"%" PRIx64 "\",\"count\":%u,\"shared\":%d}\n",(unsigned)getpid(),nonce(),count,shared_mode);flush();
    if(legacy) {
        for(unsigned i=1;i<=4;++i){inject(i,0);process();finish();pending=NULL;check_full();}caches();
    } else {
        char command[96];
        while(fgets(command,sizeof(command),stdin)) {
            unsigned sequence,generation;int gen;
            if(sscanf(command,"inject %u %u",&sequence,&generation)==2)inject(sequence,generation);
            else if(!strcmp(command,"counts\n"))census();
            else if(!strcmp(command,"finish\n"))finish();
            else if(sscanf(command,"select %d",&gen)==1){ker_mbuf_bank_select(gen);printf("SELECTED {\"generation\":%d}\n",selected());flush();}
            else if(sscanf(command,"complete %u",&sequence)==1){CHECK(pending&&sequence==pending_sequence&&atomic_load(&identity->done)==sequence);pending=NULL;check_full();printf("COMPLETE {\"sequence\":%u}\n",sequence);flush();}
            else if(!strcmp(command,"quit\n"))break;
            else CHECK(0);
        }
    }
    check_full();CHECK(!pending&&rte_ring_empty(rx)&&rte_ring_empty(tx)&&rte_ring_empty(control)&&rte_ring_empty(completion)&&!atomic_load(&identity->inflight));
    struct rte_eth_stats stats;CHECK(!rte_eth_stats_get(port,&stats)&&stats.ipackets==4&&stats.opackets==4&&atomic_load(&identity->packets)==4);
    CHECK(!ker_mbuf_bank_detach()&&!rte_eth_dev_stop(port)&&!rte_eth_dev_close(port));
    rte_ring_free(rx);rte_ring_free(tx);rte_ring_free(control);rte_ring_free(completion);
    for(unsigned g=0;g<2;++g) { if(app[g])rte_mempool_free(app[g]); }
    rte_mempool_free(rx_pool);rte_mempool_free(messages);rte_mempool_free(references);
    CHECK(!rte_memzone_free(meta)&&!rte_eal_cleanup());puts("CLOSED {\"packets\":4,\"outstanding\":0}");flush();
}
static void worker(unsigned generation)
{
    CHECK(rte_eal_process_type()==RTE_PROC_SECONDARY&&generation<2);shared_mode=1;count=63;
    const struct rte_memzone *meta=rte_memzone_lookup(META);CHECK(meta);identity=meta->addr;
    const char *pid=getenv("KER_POOL_PRIMARY_PID");CHECK(pid&&identity->magic==MAGIC&&identity->nonce==nonce()&&identity->primary==strtoul(pid,NULL,10));
    rx_pool=rte_mempool_lookup("mbuf_pool_0");messages=rte_mempool_lookup("ker_pool_messages");references=rte_mempool_lookup("ker_pool_references");CHECK(rx_pool&&messages&&references);
    for(unsigned g=0;g<2;++g){char name[64];CHECK(!ker_mbuf_generation_name(name,sizeof(name),0,(int)g));app[g]=rte_mempool_lookup(name);CHECK(app[g]);}
    bank();ker_mbuf_bank_select((int)generation);CHECK(selected()==(int)generation);
    rx=rte_ring_lookup(RX);tx=rte_ring_lookup(TX);control=rte_ring_lookup(CONTROL);completion=rte_ring_lookup(COMPLETE);CHECK(rx&&tx&&control&&completion&&!rte_eth_dev_get_port_by_name(PORT,&port));
    struct rte_eth_dev_info info;CHECK(!rte_eth_dev_info_get(port,&info)&&!strcmp(info.driver_name,"net_ring"));
    printf("ATTACHED {\"pid\":%u,\"primary\":%u,\"generation\":%u}\n",(unsigned)getpid(),identity->primary,generation);flush();
    char command[96];while(fgets(command,sizeof(command),stdin)) {
        int gen;
        if(!strcmp(command,"process\n"))process();
        else if(!strcmp(command,"finish\n"))finish();
        else if(!strcmp(command,"counts\n"))census();
        else if(sscanf(command,"select %d",&gen)==1){ker_mbuf_bank_select(gen);printf("SELECTED {\"generation\":%d}\n",selected());flush();}
        else if(!strcmp(command,"exit\n")){check_full();CHECK(!ker_mbuf_bank_detach()&&!rte_eal_cleanup());puts("CLOSED {\"outstanding\":0}");flush();return;}
        else CHECK(0);
    }
    CHECK(0);
}
int main(int argc,char **argv)
{
    CHECK(argc>=3);int is_worker=!strcmp(argv[1],"worker"),legacy=!strcmp(argv[1],"legacy");CHECK(is_worker||legacy||!strcmp(argv[1],"primary"));
    unsigned generation=is_worker?(unsigned)strtoul(argv[2],NULL,10):0;int offset=is_worker?2:1;
    CHECK(rte_eal_init(argc-offset,argv+offset)>=0);if(is_worker)worker(generation);else primary(legacy);return 0;
}
