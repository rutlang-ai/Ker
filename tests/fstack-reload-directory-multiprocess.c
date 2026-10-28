/* Actual original EAL/PMD consumer of the cross-master directory adapter.
 * Parent/master identity, all buffers and supervision belong to this caller. */
#define _GNU_SOURCE
#include <ker/reload-directory.h>
#include "check.h"
#include <inttypes.h>
#include <errno.h>
#include <stdatomic.h>
#include <time.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define PORT "net_ring_ker_dir"
#define META "ker_directory_identity"
#define POOL "ker_directory_pool"
#define RX "ker_directory_rx"
#define TX "ker_directory_tx"
#define MAGIC UINT64_C(0x4b45524449523031)
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "process-shared counters must be lock-free");
struct shared {
    uint64_t magic, nonce;
    uint32_t primary;
    atomic_uint active[2], callbacks[4], received[4], completed[4];
    unsigned first[4][2], count[4][2];
    uintptr_t objects[4][2][4];
    atomic_uint consumed[4][2];
};
struct frame { uint64_t nonce; unsigned sequence; unsigned char bytes[84]; };
static struct shared *shared;
static struct rte_ring *rx, *tx, *drain[4][2];
static struct rte_mempool *pool;
static uint16_t port;
static unsigned slot, generation;
static int hold;
static struct rte_mempool *messages;
struct rpc_wire { uint64_t nonce; unsigned sequence, epoch, generation, process, type; };
static ker_ipc_message *rpc_pending;
static struct rpc_wire sent_wire;
static uint32_t sent_cookie;
static uint64_t nonce(void)
{
    const char *text = getenv("KER_DIRECTORY_NONCE"); CHECK(text && *text);
    char *end; uint64_t value = strtoull(text, &end, 16); CHECK(!*end && value); return value;
}
static void flush(void) { CHECK(!fflush(stdout)); }
static uint64_t now_ms(void)
{
    struct timespec stamp; CHECK(!clock_gettime(CLOCK_MONOTONIC, &stamp));
    return (uint64_t)stamp.tv_sec*1000 + (unsigned long)stamp.tv_nsec/1000000;
}
static void frame_check(struct rte_mbuf *packet, unsigned sequence)
{
    CHECK(packet && packet->pool == pool && rte_pktmbuf_pkt_len(packet) == sizeof(struct frame));
    const struct frame *frame = rte_pktmbuf_mtod(packet, const struct frame *);
    CHECK(frame->nonce == nonce() && frame->sequence == sequence);
    for (unsigned i = 0; i < sizeof(frame->bytes); ++i) CHECK(frame->bytes[i] == (unsigned char)(sequence+i));
}
static struct rte_mbuf *frame_alloc(unsigned sequence)
{
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool); CHECK(packet);
    struct frame *frame = (void *)rte_pktmbuf_append(packet, sizeof(*frame)); CHECK(frame);
    frame->nonce = nonce(); frame->sequence = sequence;
    for (unsigned i = 0; i < sizeof(frame->bytes); ++i) frame->bytes[i] = (unsigned char)(sequence+i);
    return packet;
}
/* These actual FF-named queues carry control records only. Non-QUERY command
 * families return EOPNOTSUPP; the test validates transport, not FreeBSD command
 * execution. The real QUERY locator selects the queue a caller will use. */
static struct rte_ring *rpc_ring(uint32_t epoch,unsigned gen,unsigned process,int output,int type)
{
    char name[64];struct ker_ipc_address address={(uint16_t)process,(int)gen,epoch};
    CHECK(!ker_ipc_format_ring(name,sizeof(name),&address,output,(enum FF_MSG_TYPE)type,1));
    return rte_ring_lookup(name);
}
static void rpc_names(uint32_t epoch,int create)
{
    static const unsigned procs[]={0,1,7,127};unsigned count=0;CHECK(!rpc_pending&&rte_mempool_avail_count(messages)==63);
    for(unsigned p=0;p<4;++p)for(unsigned g=0;g<2;++g)for(int type=0;type<FF_MSG_NUM;++type) {
        char name[64];struct ker_ipc_address address={(uint16_t)procs[p],(int)g,epoch};
        CHECK(!ker_ipc_format_ring(name,sizeof(name),&address,type!=0,(enum FF_MSG_TYPE)type,1));
        CHECK(strlen(name)<RTE_RING_NAMESIZE);
        if(create)CHECK(rte_ring_create(name,32,SOCKET_ID_ANY,RING_F_SP_ENQ|RING_F_SC_DEQ));
        else {struct rte_ring *ring=rte_ring_lookup(name);CHECK(ring&&rte_ring_empty(ring));rte_ring_free(ring);}
        ++count;
    }
    printf("NAMES {\"epoch\":%u,\"count\":%u,\"created\":%d}\n",epoch,count,create);flush();
}
static void rpc_send(uint32_t epoch,unsigned gen,unsigned process,unsigned type,unsigned sequence)
{
    CHECK(!rpc_pending&&gen<2&&process<=127&&type>=FF_SYSCTL&&type<FF_MSG_NUM);
    char address[64];snprintf(address,sizeof(address),"%u:%u:%u",process,gen,epoch);
    CHECK(ker_ipc_select_or_exit(address,NULL)==(int)process&&!ker_ipc_attach(messages));
    rpc_pending=ker_ipc_alloc();CHECK(rpc_pending&&rpc_pending->buf_len>=sizeof(sent_wire));
    sent_wire=(struct rpc_wire){nonce(),sequence,epoch,gen,process,type};
    memcpy(rpc_pending->buf_addr,&sent_wire,sizeof(sent_wire));
    ker_reload_message_fill(rpc_pending,FF_RELOAD_CMD_QUERY,0,0,7);
    rpc_pending->msg_type=(enum FF_MSG_TYPE)type;sent_cookie=rpc_pending->ipc_cookie;
    CHECK(!ker_ipc_send(rpc_pending));
    printf("SENT {\"epoch\":%u,\"generation\":%u,\"process\":%u,\"type\":%u,\"sequence\":%u,\"available\":%u}\n",epoch,gen,process,type,sequence,rte_mempool_avail_count(messages));flush();
}
static void rpc_receive(void)
{
    CHECK(rpc_pending);ker_ipc_message *message=NULL;CHECK(!ker_ipc_recv(&message,(enum FF_MSG_TYPE)sent_wire.type));
    CHECK(message==rpc_pending&&message->ipc_cookie==sent_cookie&&message->ipc_owner_pid==(uint32_t)getpid());
    CHECK(rte_mempool_from_obj(message)==messages&&!memcmp(message->buf_addr,&sent_wire,sizeof(sent_wire)));
    CHECK(message->result==(sent_wire.type==FF_RELOAD?0:EOPNOTSUPP));
    if(sent_wire.type==FF_RELOAD) {int command;uint64_t heartbeat;CHECK(!ker_reload_message_parse(message,&command,NULL,NULL,&heartbeat));CHECK(command==FF_RELOAD_CMD_QUERY&&heartbeat==7);}
    CHECK(!ker_ipc_free(message));rpc_pending=NULL;CHECK(!ker_ipc_detach());
    printf("RECEIVED {\"sequence\":%u,\"available\":%u}\n",sent_wire.sequence,rte_mempool_avail_count(messages));flush();
}
static void rpc_serve(unsigned process,unsigned gen,unsigned type)
{
    CHECK(gen<2&&process<=127&&type>=FF_SYSCTL&&type<FF_MSG_NUM);
    struct ker_reload_directory_view view;CHECK(!ker_reload_directory_view(&view));
    struct rte_ring *input=rpc_ring(view.self.epoch,gen,process,0,0),*output=rpc_ring(view.self.epoch,gen,process,1,(int)type);CHECK(input&&output);
    void *object;CHECK(!rte_ring_dequeue(input,&object));ker_ipc_message *message=object;struct rpc_wire wire;
    CHECK(rte_mempool_from_obj(message)==messages&&message->buf_len>=sizeof(wire));memcpy(&wire,message->buf_addr,sizeof(wire));
    CHECK(wire.nonce==nonce()&&wire.epoch==view.self.epoch&&wire.generation==gen&&wire.process==process&&wire.type==type);
    CHECK(message->msg_type==(enum FF_MSG_TYPE)type&&message->ipc_cookie&&message->ipc_owner_pid==shared->primary);
    if(type==FF_RELOAD) {int command;CHECK(!ker_reload_message_parse(message,&command,NULL,NULL,NULL)&&command==FF_RELOAD_CMD_QUERY);ker_reload_message_fill(message,command,0,0,7);}
    else message->result=EOPNOTSUPP;
    CHECK(!rte_ring_enqueue(output,message));
    printf("SERVED {\"epoch\":%u,\"generation\":%u,\"process\":%u,\"type\":%u,\"sequence\":%u}\n",view.self.epoch,gen,process,type,wire.sequence);flush();
}
static void peer_view(void)
{
    struct ker_reload_peer peer;CHECK(!ker_reload_directory_peer(&peer));
    printf("PEER {\"epoch\":%u,\"generation\":%u,\"published_epoch\":%u,\"published_generation\":%u,\"foreign\":%d,\"published_foreign\":%d,\"observer_matches\":%d}\n",
        peer.selected.epoch,peer.selected.generation,peer.published.epoch,peer.published.generation,peer.foreign,peer.published_foreign,peer.observation_owner_matches);flush();
}
static void directory_view(void)
{
    struct ker_reload_directory_view view; CHECK(!ker_reload_directory_view(&view));
    printf("VIEW {\"epoch\":%u,\"generation\":%u,\"slot\":%u,\"owner_epoch\":%u,\"owner_generation\":%u,\"stopped\":%u,\"refused\":%u,\"local_owner\":%d,\"local_stopped\":%d}\n",
        view.self.epoch,view.self.generation,view.slot,view.rx_owner.epoch,view.rx_owner.generation,
        view.stopped,view.reclaim_refused,ker_reload_rx_owner(),ker_reload_rx_stopped()); flush();
}
static void census(void)
{
    uint32_t live[4][2], dead[4][2]; CHECK(!ker_reload_directory_ring_census(live,dead,0));
    printf("CENSUS {\"live\":[");
    for (unsigned s=0;s<4;++s) printf("%s[%u,%u]",s?",":"",live[s][0],live[s][1]);
    printf("],\"dead\":[");
    for (unsigned s=0;s<4;++s) printf("%s[%u,%u]",s?",":"",dead[s][0],dead[s][1]);
    puts("]}"); flush();
}
static void status(void)
{
    struct rte_eth_stats stats; CHECK(!rte_eth_stats_get(port,&stats));
    unsigned queued=0; for(unsigned s=0;s<4;++s)for(unsigned g=0;g<2;++g)queued+=rte_ring_count(drain[s][g]);
    printf("STATUS {\"available\":%u,\"rx\":%u,\"tx\":%u,\"drain\":%u,\"inflight\":[%u,%u],\"callbacks\":[%u,%u,%u,%u],\"received\":[%u,%u,%u,%u],\"ipackets\":%" PRIu64 ",\"opackets\":%" PRIu64 "}\n",
        rte_mempool_avail_count(pool),rte_ring_count(rx),rte_ring_count(tx),queued,
        atomic_load(&shared->active[0]),atomic_load(&shared->active[1]),
        atomic_load(&shared->callbacks[0]),atomic_load(&shared->callbacks[1]),atomic_load(&shared->callbacks[2]),atomic_load(&shared->callbacks[3]),
        atomic_load(&shared->received[0]),atomic_load(&shared->received[1]),atomic_load(&shared->received[2]),atomic_load(&shared->received[3]),stats.ipackets,stats.opackets); flush();
}
static unsigned consume(unsigned s,unsigned g)
{
    unsigned total=0; void *object;
    while(!rte_ring_dequeue(drain[s][g],&object)) {
        unsigned index=atomic_fetch_add(&shared->consumed[s][g],1);
        CHECK(index<shared->count[s][g] && (uintptr_t)object==shared->objects[s][g][index]);
        frame_check(object,shared->first[s][g]+index); shared->objects[s][g][index]=0;
        rte_pktmbuf_free(object); ++total;
    }
    return total;
}
static void wait_stale(uint32_t epoch)
{
    uint64_t start=now_ms(); int live;
    do { live=ker_reload_directory_epoch_live(epoch); CHECK(live>=0);
        if(!live)break;
        struct timespec delay={.tv_nsec=20000000}; nanosleep(&delay,NULL);
    } while(now_ms()-start<6500);
    CHECK(!live);
    printf("STALE {\"epoch\":%u,\"elapsed_ms\":%" PRIu64 "}\n",epoch,now_ms()-start); flush();
}
static int observations(char *command)
{
    unsigned epoch,gen;
    if(!strcmp(command,"view\n")) directory_view();
    else if(!strcmp(command,"peer\n")) peer_view();
    else if(!strcmp(command,"parent\n")) {printf("PARENT {\"pid\":%u}\n",(unsigned)getppid());flush();}
    else if(!strcmp(command,"status\n")) status();
    else if(!strcmp(command,"census\n")) census();
    else if(sscanf(command,"users %u %u",&epoch,&gen)==2) {
        unsigned active;int clear;CHECK(!ker_reload_directory_users(epoch,(int)gen,&active,&clear));
        printf("USERS {\"active\":%u,\"clear\":%d}\n",active,clear); flush();
    } else if(sscanf(command,"live %u",&epoch)==1) {
        printf("LIVE {\"epoch\":%u,\"live\":%d}\n",epoch,ker_reload_directory_epoch_live(epoch));flush();
    } else if(sscanf(command,"wait-stale %u",&epoch)==1) wait_stale(epoch);
    else return 0;
    return 1;
}
static void rings(int create)
{
    for(unsigned s=0;s<4;++s)for(unsigned g=0;g<2;++g) {
        char name[64];snprintf(name,sizeof(name),"ker_directory_drain_%u_%u",s,g);
        drain[s][g]=create?rte_ring_create(name,32,SOCKET_ID_ANY,RING_F_SP_ENQ|RING_F_SC_DEQ):rte_ring_lookup(name);
        CHECK(drain[s][g]);
    }
}
static void primary(void)
{
    CHECK(rte_eal_process_type()==RTE_PROC_PRIMARY);
    const struct rte_memzone *states[2],*identity=rte_memzone_reserve(META,sizeof(*shared),SOCKET_ID_ANY,0);CHECK(identity);
    shared=identity->addr;memset(shared,0,sizeof(*shared));shared->magic=MAGIC;shared->nonce=nonce();shared->primary=getpid();
    for(unsigned g=0;g<2;++g){char name[64];snprintf(name,sizeof(name),"ker_directory_state_%u",g);
        states[g]=rte_memzone_reserve(name,ker_reload_state_size(),SOCKET_ID_ANY,0);CHECK(states[g]);
        CHECK(!ker_reload_state_init(states[g]->addr,states[g]->len,(int)g));atomic_init(&shared->active[g],0);
    }
    for(unsigned s=0;s<4;++s){atomic_init(&shared->callbacks[s],0);atomic_init(&shared->received[s],0);atomic_init(&shared->completed[s],0);
        for(unsigned g=0;g<2;++g)atomic_init(&shared->consumed[s][g],0);
    }
    CHECK(!ker_reload_bind_state(states[0]->addr,states[0]->len,0,0));CHECK(!ker_reload_worker_select(0,0));CHECK(!ker_reload_directory_attach());
    pool=rte_pktmbuf_pool_create(POOL,63,0,0,RTE_MBUF_DEFAULT_BUF_SIZE,SOCKET_ID_ANY);CHECK(pool);
    rx=rte_ring_create(RX,32,SOCKET_ID_ANY,RING_F_SP_ENQ|RING_F_SC_DEQ);tx=rte_ring_create(TX,32,SOCKET_ID_ANY,RING_F_SP_ENQ|RING_F_SC_DEQ);CHECK(rx&&tx);
    int created=rte_eth_from_rings("ker_dir",&rx,1,&tx,1,SOCKET_ID_ANY);CHECK(created>=0);port=(uint16_t)created;
    struct rte_eth_conf config={0};CHECK(!rte_eth_dev_configure(port,1,1,&config));
    CHECK(!rte_eth_rx_queue_setup(port,0,128,SOCKET_ID_ANY,NULL,pool));CHECK(!rte_eth_tx_queue_setup(port,0,128,SOCKET_ID_ANY,NULL));CHECK(!rte_eth_dev_start(port));
    rings(1);
    messages=ker_ipc_pool_create("ker_directory_messages",63,64);CHECK(messages);
    printf("READY {\"pid\":%u,\"nonce\":\"%" PRIx64 "\",\"available\":63,\"driver\":\"net_ring\"}\n",(unsigned)getpid(),nonce());flush();
    char command[128];struct rte_mbuf *pending=NULL;unsigned sequence=0;
    while(fgets(command,sizeof(command),stdin)) {
        if(observations(command))continue;
        if(!strncmp(command,"names ",6)||!strncmp(command,"drop ",5)) {
            unsigned e;int create=command[0]=='n';CHECK(sscanf(command+(create?6:5),"%u",&e)==1);rpc_names(e,create);
        } else if(!strcmp(command,"locate\n")) {
            ker_ipc_message message={0};ker_reload_message_fill(&message,FF_RELOAD_CMD_QUERY,0,0,7);
            printf("LOCATED {\"epoch\":%u,\"generation\":%u}\n",message.reload.epoch,message.reload.active_gen);flush();
        } else if(!strncmp(command,"probe ",6)) {
            unsigned process,type,seq;CHECK(sscanf(command,"probe %u %u %u",&process,&type,&seq)==3);
            ker_ipc_message message={0};ker_reload_message_fill(&message,FF_RELOAD_CMD_QUERY,0,0,7);
            rpc_send(message.reload.epoch,message.reload.active_gen,process,type,seq);
        } else if(!strncmp(command,"send ",5)) {
            unsigned e,g,process,type,seq;CHECK(sscanf(command,"send %u %u %u %u %u",&e,&g,&process,&type,&seq)==5);rpc_send(e,g,process,type,seq);
        } else if(!strcmp(command,"receive\n")) rpc_receive();
        else if(!strncmp(command,"init-state ",11)) {
            unsigned index,gen;CHECK(sscanf(command,"init-state %u %u",&index,&gen)==2&&index==1&&gen<2);
            CHECK(!ker_reload_state_init(states[index]->addr,states[index]->len,(int)gen));puts("RESULT {\"result\":0}");flush();
        } else if(sscanf(command,"inject %u",&sequence)==1) {
            CHECK(!pending);pending=frame_alloc(sequence);CHECK(!rte_ring_enqueue(rx,pending));
            printf("INJECTED {\"sequence\":%u,\"available\":%u}\n",sequence,rte_mempool_avail_count(pool));flush();
        } else if(!strcmp(command,"collect\n")) {
            void *object;CHECK(pending&&!rte_ring_dequeue(tx,&object)&&object==pending);frame_check(pending,sequence);rte_pktmbuf_free(pending);pending=NULL;
            printf("COLLECTED {\"sequence\":%u,\"available\":%u}\n",sequence,rte_mempool_avail_count(pool));flush();
        } else if(!strncmp(command,"queue ",6)) {
            unsigned epoch,g,first,count;CHECK(sscanf(command,"queue %u %u %u %u",&epoch,&g,&first,&count)==4&&g<2&&count<=4);
            unsigned s=ker_ipc_epoch_slot(epoch);CHECK(s<4&&rte_ring_empty(drain[s][g]));shared->first[s][g]=first;shared->count[s][g]=count;atomic_store(&shared->consumed[s][g],0);
            for(unsigned i=0;i<count;++i){struct rte_mbuf *packet=frame_alloc(first+i);shared->objects[s][g][i]=(uintptr_t)packet;CHECK(!rte_ring_enqueue(drain[s][g],packet));}
            printf("QUEUED {\"slot\":%u,\"generation\":%u,\"count\":%u,\"available\":%u}\n",s,g,count,rte_mempool_avail_count(pool));flush();
        } else if(!strcmp(command,"lock\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_purge_lock(5));flush();}
        else if(!strcmp(command,"unlock\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_purge_unlock());flush();}
        else if(!strcmp(command,"quit\n")) {
            CHECK(!pending&&!rpc_pending&&rte_mempool_avail_count(messages)==63&&rte_ring_empty(rx)&&rte_ring_empty(tx)&&rte_mempool_avail_count(pool)==63);
            CHECK(!atomic_load(&shared->active[0])&&!atomic_load(&shared->active[1]));
            for(unsigned s=0;s<4;++s)for(unsigned g=0;g<2;++g){CHECK(rte_ring_empty(drain[s][g]));rte_ring_free(drain[s][g]);}
            CHECK(!ker_reload_directory_destroy());ker_reload_unbind_state();CHECK(!rte_eth_dev_stop(port)&&!rte_eth_dev_close(port));rte_ring_free(rx);rte_ring_free(tx);rte_mempool_free(pool);rte_mempool_free(messages);
            CHECK(!rte_memzone_free(states[0])&&!rte_memzone_free(states[1])&&!rte_memzone_free(identity)&&!rte_eal_cleanup());
            puts("CLOSED {\"available\":63,\"outstanding\":0}");flush();return;
        } else CHECK(0);
    }
    CHECK(0);
}
static int packet_poll(void *argument)
{
    CHECK(argument == shared);
    CHECK(atomic_fetch_add(&shared->active[generation], 1) == 0);
    CHECK(!atomic_load(&shared->active[1-generation]));
    atomic_fetch_add(&shared->callbacks[slot], 1);
    if (hold) {
        printf("ENTERED {\"slot\":%u,\"generation\":%u}\n",slot,generation); flush();
        char resume[32]; CHECK(fgets(resume,sizeof(resume),stdin) && !strcmp(resume,"continue\n"));
    }
    struct rte_mbuf *packet = NULL;
    unsigned received = rte_eth_rx_burst(port, 0, &packet, 1);
    if (received) {
        CHECK(packet && packet->pool == pool && rte_pktmbuf_pkt_len(packet) == sizeof(struct frame));
        const struct frame *frame = rte_pktmbuf_mtod(packet, const struct frame *);
        CHECK(frame->nonce == nonce());
        atomic_fetch_add(&shared->received[slot], 1);
        CHECK(rte_eth_tx_burst(port, 0, &packet, 1) == 1);
        atomic_fetch_add(&shared->completed[slot], 1);
    }
    CHECK(atomic_fetch_sub(&shared->active[generation], 1) == 1);
    return (int)received;
}

static void worker(unsigned gen,unsigned worker_slot)
{
    CHECK(rte_eal_process_type()==RTE_PROC_SECONDARY&&gen<2&&worker_slot<4);
    const char *index_text=getenv("KER_DIRECTORY_STATE_INDEX");unsigned index=index_text?(unsigned)strtoul(index_text,NULL,10):gen;CHECK(index<2);
    char name[64];snprintf(name,sizeof(name),"ker_directory_state_%u",index);
    const struct rte_memzone *state=rte_memzone_lookup(name),*identity=rte_memzone_lookup(META);CHECK(state&&identity);shared=identity->addr;
    const char *pid=getenv("KER_DIRECTORY_PRIMARY_PID");CHECK(pid&&shared->magic==MAGIC&&shared->nonce==nonce()&&shared->primary==strtoul(pid,NULL,10));
    CHECK(!ker_reload_bind_state(state->addr,state->len,0,(int)gen));CHECK(!ker_reload_worker_select((int)gen,worker_slot));CHECK(!ker_reload_directory_attach());
    generation=gen;slot=worker_slot;pool=rte_mempool_lookup(POOL);messages=rte_mempool_lookup("ker_directory_messages");CHECK(pool&&messages);rings(0);CHECK(!rte_eth_dev_get_port_by_name(PORT,&port));
    struct rte_eth_dev_info info;CHECK(!rte_eth_dev_info_get(port,&info)&&!strcmp(info.driver_name,"net_ring"));
    struct ker_reload_directory_view view;CHECK(!ker_reload_directory_view(&view));
    printf("ATTACHED {\"pid\":%u,\"parent\":%u,\"primary\":%u,\"generation\":%u,\"slot\":%u,\"epoch\":%u,\"directory_slot\":%u}\n",(unsigned)getpid(),(unsigned)getppid(),shared->primary,gen,slot,view.self.epoch,view.slot);flush();
    char command[128];
    while(fgets(command,sizeof(command),stdin)) {
        if(observations(command))continue;
        if(!strncmp(command,"serve ",6)) {
            unsigned process,g,type;CHECK(sscanf(command,"serve %u %u %u",&process,&g,&type)==3);rpc_serve(process,g,type);
        } else if(!strcmp(command,"release-peer\n")) {
            struct ker_reload_peer peer;CHECK(!ker_reload_directory_peer(&peer)&&peer.foreign);
            uint64_t start=now_ms();int result=ker_reload_directory_release(peer.selected.epoch,(int)peer.selected.generation);
            printf("RELEASE {\"result\":%d,\"elapsed_ms\":%" PRIu64 ",\"local_owner\":%d,\"local_stopped\":%d}\n",result,now_ms()-start,ker_reload_rx_owner(),ker_reload_rx_stopped());flush();
        } else if(!strncmp(command,"poll",4)) {
            hold=!strcmp(command,"poll hold\n");int result=ker_reload_poll(packet_poll,shared);
            printf("POLL {\"result\":%d,\"callbacks\":%u,\"received\":%u,\"completed\":%u}\n",result,atomic_load(&shared->callbacks[slot]),atomic_load(&shared->received[slot]),atomic_load(&shared->completed[slot]));flush();
        } else if(!strncmp(command,"release ",8)) {
            unsigned e,g;CHECK(sscanf(command,"release %u %u",&e,&g)==2);uint64_t start=now_ms();int result=ker_reload_directory_release(e,(int)g);
            printf("RELEASE {\"result\":%d,\"elapsed_ms\":%" PRIu64 ",\"local_owner\":%d,\"local_stopped\":%d}\n",result,now_ms()-start,ker_reload_rx_owner(),ker_reload_rx_stopped());flush();
        } else if(!strncmp(command,"claim ",6)) {
            unsigned e,g;CHECK(sscanf(command,"claim %u %u",&e,&g)==2);printf("RESULT {\"result\":%d}\n",ker_reload_directory_claim(e,(int)g,20));flush();
        } else if(!strcmp(command,"reclaim\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_reclaim());flush();}
        else if(!strcmp(command,"stop\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_user_stop());flush();}
        else if(!strcmp(command,"detach\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_detach());flush();}
        else if(!strcmp(command,"ring-attach\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_ring_attach(20));flush();}
        else if(!strcmp(command,"ring-detach\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_ring_detach());flush();}
        else if(!strcmp(command,"lock\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_purge_lock(5));flush();}
        else if(!strcmp(command,"unlock\n")) {printf("RESULT {\"result\":%d}\n",ker_reload_directory_purge_unlock());flush();}
        else if(!strcmp(command,"drain\n")) {
            CHECK(!ker_reload_directory_view(&view));unsigned total=consume(view.slot,gen);
            printf("DRAINED {\"count\":%u,\"available\":%u}\n",total,rte_mempool_avail_count(pool));flush();
        } else if(!strcmp(command,"purge\n")) {
            uint32_t live[4][2],dead[4][2];CHECK(!ker_reload_directory_ring_census(live,dead,1));unsigned total=0,markers=0;
            for(unsigned s=0;s<4;++s){markers+=dead[s][0]+dead[s][1];if(live[s][0]+live[s][1])continue;for(unsigned g=0;g<2;++g)total+=consume(s,g);}
            printf("PURGED {\"count\":%u,\"dead_markers\":%u,\"available\":%u}\n",total,markers,rte_mempool_avail_count(pool));flush();
        } else if(!strcmp(command,"refresh\n")) {
            hold=0;
            for(unsigned i=0;i<4;++i){CHECK(ker_reload_poll(packet_poll,shared)>=0);struct timespec delay={.tv_nsec=800000000};nanosleep(&delay,NULL);}
            puts("REFRESHED {\"passes\":4}");flush();
        } else if(!strcmp(command,"idle\n")) {
            uint64_t start=now_ms();
            do { struct timespec delay={.tv_nsec=50000000};nanosleep(&delay,NULL); } while(now_ms()-start<2300);
            printf("IDLED {\"elapsed_ms\":%" PRIu64 "}\n",now_ms()-start);flush();
        } else if(!strcmp(command,"crash\n")) {puts("CRASHED {\"exit\":0}");flush();_exit(0);}
        else if(!strcmp(command,"exit\n")) {
            CHECK(!ker_reload_directory_ring_detach());CHECK(!ker_reload_directory_user_release());
            CHECK(ker_reload_poll(packet_poll,shared)==-ESHUTDOWN);
            CHECK(!ker_reload_directory_detach());ker_reload_unbind_state();CHECK(!rte_eal_cleanup());puts("CLOSED {\"outstanding\":0}");flush();return;
        } else CHECK(0);
    }
    CHECK(0);
}
int main(int argc,char **argv)
{
    CHECK(argc>=3);int is_primary=!strcmp(argv[1],"primary");CHECK(is_primary||(!strcmp(argv[1],"worker")&&argc>=5));
    unsigned gen=is_primary?0:(unsigned)strtoul(argv[2],NULL,10),worker_slot=is_primary?0:(unsigned)strtoul(argv[3],NULL,10);
    int offset=is_primary?1:3;CHECK(rte_eal_init(argc-offset,argv+offset)>=0);
    if(is_primary)primary();else worker(gen,worker_slot);return 0;
}
