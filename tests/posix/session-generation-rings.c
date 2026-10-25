/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "session-generation-rings.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/pidfd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#define TEST_ZONE "ker_nr19_test_control"
#define TEST_POOL "ker_nr19_test_pool"
#define TEST_SESSION UINT64_C(0x4e523139a4d0b117)
struct test_control {
    _Atomic unsigned stage, gen0_ready, crash_ready, producer_ready, consumer_ready, transition_release, producer_pid;
    _Atomic unsigned packet_case,packet_go,packet_ready[2],packet_writer_ready,packet_writer_complete,packet_commit_ready,packet_commit_release;
    _Atomic unsigned packet_enqueue_ready,packet_enqueue_release,packet_consumer_released;
    _Atomic unsigned packet_index;
    _Atomic uint64_t packet_lease;
    _Atomic int packet_producer_pid;
    uintptr_t retained_tx[3];
    _Atomic int failed;
};

static struct test_control *control(void)
{
    const struct rte_memzone *mz=rte_memzone_lookup(TEST_ZONE);
    return mz ? mz->addr : NULL;
}
static int packet_lease_core_test(struct ker_generation_rings *rings,
    struct rte_mempool *message_pool,const struct ker_generation_identity *producer,
    const struct ker_generation_identity *consumer)
{
    const uint32_t capacity=KER_GENERATION_RING_CAPACITY;
    uint32_t baseline=ker_generation_packet_pool_in_use(rings);
    unsigned message_baseline=rte_mempool_in_use_count(message_pool);
    struct rte_ring *packet_ring=rte_ring_lookup("drain_tx_p0_q1_g0");
    if(baseline==UINT32_MAX||baseline||!packet_ring||!ker_generation_packet_pool_tag(rings))return -1;
    uintptr_t original=0;
    if(ker_generation_test_packet_table_duplicate(rings,1,0,&original))return -1;
    struct ker_generation_rings *rejected=NULL;
    int rejected_status=ker_generation_rings_attach(TEST_SESSION,1,2,message_pool,&rejected);
    if(rejected_status!=-EPROTO||rejected||
        ker_generation_test_packet_table_restore(rings,1,original))return -1;
    uint32_t invalid_index=0;uint64_t invalid_lease=0;
    if(ker_generation_packet_prepare(rings,producer,consumer,0,1,&invalid_index,&invalid_lease))return -1;
    struct rte_mbuf *invalid=ker_generation_packet_resolve(rings,producer,invalid_index,invalid_lease);
    if(!invalid||!rte_pktmbuf_append(invalid,13)||
        ker_generation_packet_write_complete(rings,producer,invalid_index,invalid_lease)!=-EMSGSIZE||
        ker_generation_packet_cancel(rings,producer,invalid_index,invalid_lease)||
        ker_generation_packet_pool_in_use(rings)!=baseline)return -1;
    if(ker_generation_packet_prepare(rings,producer,consumer,0,1,&invalid_index,&invalid_lease)||
        ker_generation_test_packet_force_untracked_send(rings,invalid_index,invalid_lease)||
        ker_generation_packet_commit(rings,producer,0,1,invalid_index,invalid_lease)!=-EUCLEAN||
        ker_generation_packet_pool_in_use(rings)!=baseline+1||
        ker_generation_test_packet_restore_prepared(rings,invalid_index,invalid_lease)||
        ker_generation_packet_cancel(rings,producer,invalid_index,invalid_lease)||
        ker_generation_packet_pool_in_use(rings)!=baseline)return -1;
    struct rte_mbuf *packets[KER_GENERATION_RING_CAPACITY]={0};
    uint32_t indices[KER_GENERATION_RING_CAPACITY+1];
    uint64_t leases[KER_GENERATION_RING_CAPACITY+1];
    for(uint32_t i=0;i<=capacity;i++){
        if(ker_generation_packet_prepare(rings,producer,consumer,0,1,&indices[i],&leases[i])||
            !leases[i]||ker_generation_packet_pool_in_use(rings)!=baseline+i+1)return -1;
        if(i==0){
            uint32_t wrong_index=indices[i]+1;
            if(ker_generation_packet_resolve(rings,producer,wrong_index,leases[i])||
                ker_generation_packet_resolve(rings,producer,indices[i],leases[i]^UINT64_C(1)))return -1;
        }
        struct rte_mbuf *packet=ker_generation_packet_resolve(rings,producer,indices[i],leases[i]);
        if(!packet||packet->pool==message_pool)return -1;
        uint8_t *bytes=(uint8_t *)rte_pktmbuf_append(packet,14);
        if(!bytes)return -1;
        for(uint32_t k=0;k<14;k++)bytes[k]=(uint8_t)(0x80U+i+k);
        if(ker_generation_packet_write_complete(rings,producer,indices[i],leases[i]))return -1;
        if(i==0 && ker_generation_tx_enqueue(rings,producer,0,1,packet)!=-EINVAL)return -1;
        int commit=ker_generation_packet_commit(rings,producer,0,1,indices[i],leases[i]);
        if(i<capacity){
            if(commit||ker_generation_packet_commit(rings,producer,0,1,indices[i],leases[i]))return -1;
            packets[i]=packet;
        }else{
            if(commit!=-ENOBUFS||ker_generation_packet_cancel(rings,producer,indices[i],leases[i])||
                ker_generation_packet_pool_in_use(rings)!=baseline+capacity)return -1;
        }
    }
    for(uint32_t i=0;i<capacity;i++){
        struct rte_mbuf *packet=NULL;
        if(ker_generation_tx_dequeue_peer(rings,consumer,0,1,&packet)!=1||packet!=packets[i]||
            packet->pkt_len!=14||packet->data_len!=14)return -1;
        uint32_t observed_index=UINT32_MAX;uint64_t observed_lease=0;
        if(ker_generation_test_packet_lease_identity(rings,consumer,packet,&observed_index,&observed_lease)||
            observed_index!=indices[i]||observed_lease!=leases[i])return -1;
        if(i==0){
            struct ker_generation_identity wrong_consumer=*consumer;
            wrong_consumer.generation^=1;
            if(ker_generation_test_packet_lease_identity(rings,&wrong_consumer,packet,
                &observed_index,&observed_lease)!=-ESTALE)return -1;
        }
        const uint8_t *bytes=rte_pktmbuf_mtod(packet,const uint8_t *);
        for(uint32_t k=0;k<14;k++)if(bytes[k]!=(uint8_t)(0x80U+i+k))return -1;
        uint32_t pool_before=ker_generation_packet_pool_in_use(rings);
        unsigned ring_before=rte_ring_count(packet_ring);
        uint64_t drops_before=0,full_before=0,drops_after=0,full_after=0;
        if(pool_before==UINT32_MAX||ker_generation_test_packet_drop_count(rings,0,1,0,&drops_before)||
            ker_generation_test_packet_full_count(rings,0,1,0,&full_before))return -1;
        if(ker_generation_packet_pmd_accepted(rings,consumer,packet)!=-EOPNOTSUPP||
            ker_generation_packet_wire_pending(rings,consumer,packet)!=-EOPNOTSUPP||
            ker_generation_packet_pool_in_use(rings)!=pool_before||
            rte_ring_count(packet_ring)!=ring_before||
            ker_generation_test_packet_drop_count(rings,0,1,0,&drops_after)||drops_after!=drops_before||
            ker_generation_test_packet_full_count(rings,0,1,0,&full_after)||full_after!=full_before||
            ker_generation_packet_release(rings,consumer,packet)||
            ker_generation_packet_release(rings,consumer,packet)!=-ESTALE||
            ker_generation_packet_cancel(rings,producer,indices[i],leases[i])!=-ESTALE||
            ker_generation_packet_commit(rings,producer,0,1,indices[i],leases[i])!=-ESTALE||
            ker_generation_packet_resolve(rings,producer,indices[i],leases[i])!=NULL||
            ker_generation_packet_pool_in_use(rings)!=pool_before-1)return -1;
    }
    struct rte_mbuf *empty=NULL;
    if(ker_generation_tx_dequeue_peer(rings,consumer,0,1,&empty)!=0||empty||
        ker_generation_packet_pool_in_use(rings)!=baseline||
        rte_mempool_in_use_count(message_pool)!=message_baseline)return -1;
    printf("NR19_PACKET_LEASE_CORE_PASS capacity=%u full_plus_one_rejected=true fifo_identity_order=true cancel_stale_rejected=true pmd_wire_unsupported=true message_pool_before=%u message_pool_after=%u packet_pool_before=%u packet_pool_after=%u\n",
        capacity,message_baseline,rte_mempool_in_use_count(message_pool),baseline,
        ker_generation_packet_pool_in_use(rings));
    return 0;
}
static int fail(struct test_control *c, const char *what)
{
    fprintf(stderr,"NR19 secondary %d: %s\n",getpid(),what);
    if(c) atomic_store(&c->failed,1);
    return 1;
}
static int fail_packet_enqueue_race(struct test_control *c,const char *what)
{
    if(c)atomic_store_explicit(&c->packet_enqueue_release,1,memory_order_release);
    return fail(c,what);
}
static void wait_stage(struct test_control*c,unsigned stage)
{
    for(unsigned tick=0;tick<20000;tick++){
        if(atomic_load_explicit(&c->stage,memory_order_acquire)>=stage||atomic_load(&c->failed))return;
        usleep(1000);
    }
    fprintf(stderr,"NR19 secondary %ld timed out waiting for stage %u; current=%u\n",
        (long)getpid(),stage,atomic_load(&c->stage));
    atomic_store(&c->failed,1);
}
static int parent_wait_stage(struct test_control*c,unsigned stage,const pid_t*pids,unsigned count)
{
    for(unsigned tick=0;tick<20000;tick++){
        if(atomic_load(&c->failed))return -1;
        if(atomic_load_explicit(&c->stage,memory_order_acquire)>=stage)return 0;
        for(unsigned i=0;i<count;i++){
            siginfo_t info={0};
            if(waitid(P_PID,(id_t)pids[i],&info,WEXITED|WNOHANG|WNOWAIT))return -1;
            if(info.si_pid==pids[i]){
                fprintf(stderr,"NR19 primary: child %ld exited before stage %u (current=%u, waitid_code=%d, status=%d)\n",
                    (long)pids[i],stage,atomic_load(&c->stage),info.si_code,info.si_status);return -1;
            }
        }
        usleep(1000);
    }
    fprintf(stderr,"NR19 primary: timed out waiting for stage %u (current=%u)\n",
        stage,atomic_load(&c->stage));return -1;
}
static int parent_wait_gen0_ready(struct test_control*c,const pid_t*pids,unsigned count)
{
    for(unsigned tick=0;tick<20000;tick++){
        if(atomic_load(&c->failed))return -1;
        if(atomic_load_explicit(&c->gen0_ready,memory_order_acquire))return 0;
        for(unsigned i=0;i<count;i++){
            siginfo_t info={0};
            if(waitid(P_PID,(id_t)pids[i],&info,WEXITED|WNOHANG|WNOWAIT))return -1;
            if(info.si_pid==pids[i]){
                fprintf(stderr,"NR19 primary: child %ld exited before gen0 readiness (stage=%u, waitid_code=%d, status=%d)\n",
                    (long)pids[i],atomic_load(&c->stage),info.si_code,info.si_status);return -1;
            }
        }
        usleep(1000);
    }
    fprintf(stderr,"NR19 primary: timed out waiting for gen0 readiness (stage=%u)\n",atomic_load(&c->stage));
    return -1;
}
static int stop_children(const pid_t*pids,unsigned count,int*pidfds)
{
    int result=0;
    for(unsigned i=0;i<count;i++)if(pids[i]>0){
        kill(pids[i],SIGKILL);bool reaped=false;
        for(unsigned tick=0;tick<2000;tick++){
            pid_t got=waitpid(pids[i],NULL,WNOHANG);
            if(got==pids[i]){reaped=true;break;}
            if(got<0&&errno==ECHILD){reaped=true;break;}
            usleep(1000);
        }
        if(!reaped){fprintf(stderr,"NR19 primary: child %ld did not stop within 2s\n",(long)pids[i]);result=-ETIMEDOUT;}
        if(pidfds[i]>=0)close(pidfds[i]);
    }
    return result;
}
static int wait_child_bounded(pid_t pid,int*status)
{
    for(unsigned tick=0;tick<10000;tick++){
        pid_t got=waitpid(pid,status,WNOHANG);
        if(got==pid)return 0;
        if(got<0&&errno!=EINTR){int error=errno;fprintf(stderr,"NR19 primary: waitpid(%ld) failed: %s\n",(long)pid,strerror(error));return -error;}
        usleep(1000);
    }
    fprintf(stderr,"NR19 primary: child %ld did not exit within 10s\n",(long)pid);
    return -ETIMEDOUT;
}
static struct rte_mbuf *packet(struct rte_mempool*pool,uint8_t value)
{
    struct rte_mbuf*m=rte_pktmbuf_alloc(pool);if(!m)return NULL;
    uint8_t*p=(uint8_t*)rte_pktmbuf_append(m,1);if(!p){rte_pktmbuf_free(m);return NULL;}*p=value;return m;
}
static int ring_snapshot_verify(struct rte_ring *ring,unsigned count,
    struct rte_mbuf *const *expected,const uint8_t *values,const uint16_t *lengths)
{
    if(!ring||count>KER_GENERATION_RING_CAPACITY||rte_ring_count(ring)!=count)return -1;
    struct rte_mbuf *observed[KER_GENERATION_RING_CAPACITY];
    for(unsigned i=0;i<count;i++){
        if(rte_ring_dequeue(ring,(void **)&observed[i]))return -1;
        if(observed[i]!=expected[i])return -1; /* Do not dereference an unknown object. */
        if(!observed[i]||observed[i]->nb_segs!=1||observed[i]->pkt_len!=lengths[i]||
            observed[i]->data_len!=lengths[i])return -1;
        const uint8_t *bytes=rte_pktmbuf_mtod(observed[i],const uint8_t *);
        for(uint16_t k=0;k<lengths[i];k++)if(bytes[k]!=values[i])return -1;
    }
    if(!rte_ring_empty(ring))return -1;
    for(unsigned i=0;i<count;i++)if(rte_ring_enqueue(ring,observed[i]))return -1;
    return 0;
}
static struct rte_mbuf *packet_pair(struct rte_mempool *pool,uint8_t first,uint8_t second)
{
    struct rte_mbuf *head=packet(pool,first),*tail=packet(pool,second);
    if(!head||!tail){if(head)rte_pktmbuf_free(head);if(tail)rte_pktmbuf_free(tail);return NULL;}
    if(rte_pktmbuf_chain(head,tail)){rte_pktmbuf_free(head);rte_pktmbuf_free(tail);return NULL;}
    return head;
}
static int secondary(unsigned generation,int replacement)
{
    struct test_control*c=control();struct rte_mempool*pool=rte_mempool_lookup(TEST_POOL);
    if(!c||!pool)return fail(c,"shared control or pool lookup failed");
    struct ker_generation_rings*r=NULL;
    int attach=ker_generation_rings_attach(TEST_SESSION,1,2,pool,&r);
    if(attach){fprintf(stderr,"NR19 attach rc=%d gen=%u\n",attach,generation);return fail(c,"adapter attach failed");}
    struct ker_generation_identity id={.session=TEST_SESSION,
        .epoch=replacement?9:(generation?8:7),.slot=replacement?3:(generation?2:1),
        .generation=generation,.process=0,.pid=(uint32_t)getpid()};
    unsigned old_avail=rte_mempool_avail_count(pool);
    if(replacement){
        atomic_store_explicit(&c->stage,15,memory_order_release);wait_stage(c,16);
        struct rte_mbuf*m=NULL;
        if(ker_generation_rx_dequeue(r,&id,0,0,&m)!=0||m)
            return fail(c,"recycled target consumed a stale generation packet");
        atomic_store_explicit(&c->stage,17,memory_order_release);
        return 0;
    }
    if(generation==0){
        struct rte_mbuf*m=packet(pool,0x41);if(!m)return fail(c,"allocation failed");
        if(ker_generation_rx_enqueue(r,&id,0,0,0,m)!=-EINVAL){rte_pktmbuf_free(m);return fail(c,"self-generation RX was accepted");}
        if(ker_generation_rx_enqueue(r,&id,0,0,1,m)!=-EHOSTDOWN){rte_pktmbuf_free(m);return fail(c,"unadmitted target accepted RX");}
        if(ker_generation_rx_enqueue(r,&id,0,2,1,m)!=-EINVAL||rte_mbuf_refcnt_read(m)!=1)
            return fail(c,"invalid queue changed caller ownership");
        if(ker_generation_rx_enqueue(r,&id,0,0,1,(struct rte_mbuf *)(uintptr_t)1)!=-EINVAL)
            return fail(c,"unknown pool address was dereferenced or accepted");
        rte_pktmbuf_free(m);
        struct rte_mbuf *chain=packet_pair(pool,0x46,0x47);if(!chain)return fail(c,"chain allocation failed");
        struct rte_mbuf *tail=chain->next;uint16_t original_data_off=tail->data_off;
        tail->data_off=(uint16_t)(tail->buf_len+1);
        if(ker_generation_rx_enqueue(r,&id,0,0,1,chain)!=-EINVAL||
            rte_mbuf_refcnt_read(chain)!=1||rte_mbuf_refcnt_read(tail)!=1){
            tail->data_off=original_data_off;rte_pktmbuf_free(chain);return fail(c,"malformed chain changed caller ownership");
        }
        tail->data_off=original_data_off;rte_pktmbuf_free(chain);
        atomic_store_explicit(&c->stage,1,memory_order_release);wait_stage(c,2);
        m=packet(pool,0x42);if(!m)return fail(c,"RX packet allocation failed");
        if(ker_generation_rx_enqueue(r,&id,0,0,1,m))return fail(c,"RX target enqueue failed");
        chain=packet_pair(pool,0x46,0x47);if(!chain)return fail(c,"valid chain allocation failed");
        if(ker_generation_rx_enqueue(r,&id,0,0,1,chain))return fail(c,"valid multisegment chain was rejected");
        if(ker_generation_rx_dequeue(r,&id,0,0,&m)!=0)return fail(c,"source generation consumed peer RX");
        atomic_store_explicit(&c->stage,3,memory_order_release);wait_stage(c,4);
        m=packet(pool,0x43);if(!m)return fail(c,"TX packet allocation failed");
        if(ker_generation_tx_enqueue(r,&id,0,0,m))return fail(c,"TX enqueue failed");
        m=packet(pool,0x45);if(!m)return fail(c,"TX cleanup sentinel allocation failed");
        if(ker_generation_tx_enqueue(r,&id,0,0,m))return fail(c,"TX cleanup sentinel enqueue failed");
        atomic_store_explicit(&c->stage,5,memory_order_release);wait_stage(c,7);
        m=packet(pool,0x44);if(!m)return fail(c,"persistence sentinel allocation failed");
        if(ker_generation_rx_enqueue(r,&id,0,0,1,m))return fail(c,"persistence sentinel enqueue failed");
        m=packet(pool,0x46);if(!m)return fail(c,"reaper TX sentinel allocation failed");
        if(ker_generation_tx_enqueue(r,&id,0,0,m))return fail(c,"reaper TX sentinel enqueue failed");
        atomic_store_explicit(&c->gen0_ready,1,memory_order_release);wait_stage(c,10);
        uint64_t before=ker_generation_rx_full_count(r,0,0,1);
        for(unsigned i=0;i<KER_GENERATION_RING_CAPACITY;i++){
            m=packet(pool,(uint8_t)i);if(!m)return fail(c,"ring fill allocation failed");
            if(ker_generation_rx_enqueue(r,&id,0,0,1,m))return fail(c,"RX ring filled early");
        }
        m=packet(pool,0xee);if(!m)return fail(c,"full sentinel allocation failed");
        if(ker_generation_rx_enqueue(r,&id,0,0,1,m)!=-ENOBUFS||rte_mbuf_refcnt_read(m)!=1||
            ker_generation_rx_full_count(r,0,0,1)!=before+1)return fail(c,"full ring lost caller ownership or exact counter");
        rte_pktmbuf_free(m);atomic_store_explicit(&c->stage,11,memory_order_release);wait_stage(c,12);
        m=packet(pool,0x55);if(!m)return fail(c,"stale-target sentinel allocation failed");
        if(ker_generation_rx_enqueue(r,&id,0,0,1,m))return fail(c,"stale-target sentinel enqueue failed");
        atomic_store_explicit(&c->stage,13,memory_order_release);
    }else{
        atomic_store_explicit(&c->stage,2,memory_order_release);
        wait_stage(c,3);
        struct rte_mbuf*m=NULL;
        if(ker_generation_rx_dequeue(r,&id,0,0,&m)!=1||!m||rte_pktmbuf_mtod(m,uint8_t*)[0]!=0x42)
            return fail(c,"RX object identity or payload mismatch");
        struct rte_mbuf *owned=m, *probe=NULL;
        if(ker_generation_rx_dequeue(r,&id,0,1,&probe)!=0||probe)
            return fail(c,"RX queue isolation failed");
        if(ker_generation_packet_release(r,&id,owned))return fail(c,"RX release failed");
        m=NULL;if(ker_generation_rx_dequeue(r,&id,0,0,&m)!=1||!m||m->nb_segs!=2||m->pkt_len!=2||
            rte_pktmbuf_mtod(m,uint8_t*)[0]!=0x46||!m->next||rte_pktmbuf_mtod(m->next,uint8_t*)[0]!=0x47)
            return fail(c,"multisegment RX identity/payload mismatch");
        if(ker_generation_packet_release(r,&id,m))return fail(c,"multisegment RX release failed");
        m=NULL;
        if(ker_generation_tx_dequeue_peer(r,&id,0,0,&m)!=0||m)
            return fail(c,"empty peer TX drain was not empty");
        if(ker_generation_tx_dequeue_peer(r,&id,0,1,&m)!=0||m)
            return fail(c,"empty peer TX queue isolation failed");
        atomic_store_explicit(&c->stage,4,memory_order_release);wait_stage(c,5);
        m=NULL;if(ker_generation_tx_dequeue_peer(r,&id,0,0,&m)!=1||!m||rte_pktmbuf_mtod(m,uint8_t*)[0]!=0x43)
            return fail(c,"peer TX object mismatch");
        if(ker_generation_packet_release(r,&id,m))return fail(c,"TX release failed");
        atomic_store_explicit(&c->stage,6,memory_order_release);wait_stage(c,7);
        atomic_store_explicit(&c->stage,8,memory_order_release);wait_stage(c,9);
        m=NULL;if(ker_generation_rx_dequeue(r,&id,0,0,&m)!=1||!m||rte_pktmbuf_mtod(m,uint8_t*)[0]!=0x44)
            return fail(c,"unregister/re-admit did not preserve queued sentinel");
        if(ker_generation_packet_release(r,&id,m))return fail(c,"persistence sentinel release failed");
        if(ker_generation_rx_dequeue(r,&id,0,0,&m)!=0||m)
            return fail(c,"persistent sentinel was delivered more than once");
        atomic_store_explicit(&c->stage,10,memory_order_release);wait_stage(c,11);
        for(unsigned i=0;i<KER_GENERATION_RING_CAPACITY;i++){
            m=NULL;if(ker_generation_rx_dequeue(r,&id,0,0,&m)!=1||!m||rte_pktmbuf_mtod(m,uint8_t*)[0]!=(uint8_t)i)
                return fail(c,"RX full-ring FIFO mismatch");
            if(ker_generation_packet_release(r,&id,m))return fail(c,"RX full-ring release failed");
        }
        struct rte_ring *reaper_tx=rte_ring_lookup("drain_tx_p0_q0_g0");
        unsigned available=rte_mempool_avail_count(pool);
        if(old_avail==0||available!=old_avail-1||!reaper_tx||rte_ring_count(reaper_tx)!=1){
            fprintf(stderr,"NR19 secondary %ld: retained TX sentinel checkpoint baseline=%u available=%u tx_q0_g0=%u\n",
                (long)getpid(),old_avail,available,reaper_tx?rte_ring_count(reaper_tx):UINT_MAX);
            return fail(c,"expected one queued reaper TX sentinel after RX drain");
        }
        atomic_store_explicit(&c->stage,12,memory_order_release);wait_stage(c,14);
    }
    return atomic_load(&c->failed)?1:0;
}
static int secondary_packet_worker(unsigned generation)
{
    struct test_control *c=control();
    struct rte_mempool *pool=rte_mempool_lookup(TEST_POOL);
    if(!c||!pool||generation>1)return fail(c,"packet worker control/pool lookup failed");
    unsigned profile=atomic_load_explicit(&c->packet_case,memory_order_acquire);
    if(profile<1||profile>8)return fail(c,"packet worker profile invalid");
    struct ker_generation_rings *rings=NULL;
    if(ker_generation_rings_attach(TEST_SESSION,1,2,pool,&rings))
        return fail(c,"packet worker generation attach failed");
    struct ker_generation_identity id={.session=TEST_SESSION,.epoch=100+profile*2+generation,
        .slot=1+generation,.generation=generation,.process=0,.pid=(uint32_t)getpid()};
    atomic_store_explicit(&c->packet_ready[generation],1,memory_order_release);
    if(generation==1&&profile==8){
        while(!atomic_load_explicit(&c->packet_enqueue_ready,memory_order_acquire))usleep(1000);
        struct rte_mbuf *packet_out=NULL;
        if(ker_generation_tx_dequeue_peer(rings,&id,0,1,&packet_out)!=1||!packet_out||
            packet_out->pkt_len!=14||packet_out->data_len!=14)
            return fail_packet_enqueue_race(c,"race consumer could not dequeue committed packet");
        const uint8_t *bytes=rte_pktmbuf_mtod(packet_out,const uint8_t *);
        for(unsigned i=0;i<14;i++)if(bytes[i]!=(uint8_t)(0x90U+i))
            return fail_packet_enqueue_race(c,"race consumer packet bytes mismatch");
        if(ker_generation_packet_release(rings,&id,packet_out))
            return fail_packet_enqueue_race(c,"race consumer could not release committed packet");
        atomic_store_explicit(&c->packet_consumer_released,1,memory_order_release);
        atomic_store_explicit(&c->packet_enqueue_release,1,memory_order_release);
        while(atomic_load_explicit(&c->packet_go,memory_order_acquire)<2)usleep(1000);
        return 0;
    }
    if(generation==0&&profile==2){
        while(!atomic_load_explicit(&c->packet_go,memory_order_acquire))usleep(1000);
        uint32_t index=atomic_load_explicit(&c->packet_index,memory_order_acquire);
        uint64_t lease=atomic_load_explicit(&c->packet_lease,memory_order_acquire);
        struct rte_mbuf *packet_out=ker_generation_packet_resolve(rings,&id,index,lease);
        if(!packet_out)return fail(c,"packet writer could not resolve prepared lease");
        uint8_t *bytes=(uint8_t *)rte_pktmbuf_append(packet_out,14);
        if(!bytes)return fail(c,"packet writer could not append bytes");
        memset(bytes,0xa9,14);
        atomic_store_explicit(&c->packet_writer_ready,1,memory_order_release);
        while(atomic_load_explicit(&c->packet_go,memory_order_acquire)<2)usleep(1000);
        return fail(c,"packet writer escaped its intentional death barrier");
    }
    if(generation==0&&profile==7){
        while(!atomic_load_explicit(&c->packet_go,memory_order_acquire))usleep(1000);
        uint32_t index=atomic_load_explicit(&c->packet_index,memory_order_acquire);
        uint64_t lease=atomic_load_explicit(&c->packet_lease,memory_order_acquire);
        struct rte_mbuf *packet_out=ker_generation_packet_resolve(rings,&id,index,lease);
        uint8_t *bytes=packet_out?(uint8_t *)rte_pktmbuf_append(packet_out,14):NULL;
        if(!bytes)return fail(c,"detach-race writer could not append bytes");
        memset(bytes,0x77,14);
        atomic_store_explicit(&c->packet_writer_ready,1,memory_order_release);
        while(atomic_load_explicit(&c->packet_go,memory_order_acquire)<2)usleep(1000);
        if(ker_generation_packet_write_complete(rings,&id,index,lease))
            return fail(c,"write completion did not release operation through detach gate");
        atomic_store_explicit(&c->packet_writer_complete,1,memory_order_release);
        while(atomic_load_explicit(&c->packet_go,memory_order_acquire)<3)usleep(1000);
        return 0;
    }
    if(generation==1&&profile==3){
        while(!atomic_load_explicit(&c->packet_commit_ready,memory_order_acquire))usleep(1000);
        int producer=atomic_load_explicit(&c->packet_producer_pid,memory_order_acquire);
        if(producer<=0||kill((pid_t)producer,SIGKILL))return fail(c,"could not kill producer at COMMITTING barrier");
        atomic_store_explicit(&c->packet_commit_release,1,memory_order_release);
        while(atomic_load_explicit(&c->packet_go,memory_order_acquire)<3)usleep(1000);
        struct rte_mbuf *out=NULL;
        if(ker_generation_tx_dequeue_peer(rings,&id,0,1,&out)!=1||!out||
            out->pkt_len!=14||rte_pktmbuf_mtod(out,uint8_t*)[0]!=0xa9||
            ker_generation_packet_release(rings,&id,out))
            return fail(c,"live peer did not drain committed packet exactly once");
        atomic_store_explicit(&c->packet_go,4,memory_order_release);
        return 0;
    }
    if(generation==1&&profile!=3){
        while(atomic_load_explicit(&c->packet_go,memory_order_acquire)<2)usleep(1000);
        return 0;
    }
    while(atomic_load_explicit(&c->packet_go,memory_order_acquire)<2)usleep(1000);
    return 0;
}
static int secondary_dequeue_crash(const char *mode)
{
    struct test_control*c=control();struct rte_mempool*pool=rte_mempool_lookup(TEST_POOL);
    if(!c||!pool)return fail(c,"crash-window control or pool lookup failed");
    bool producer=!strncmp(mode,"producer-",9);
    bool enqueue_prepare=!strcmp(mode,"producer-enqueue");
    bool standby=!strcmp(mode,"standby");
    bool tx_live=!strcmp(mode,"producer-tx-live")||!strcmp(mode,"dequeue-tx-live");
    bool retained_tx=!strcmp(mode,"producer-tx-retain")||!strcmp(mode,"consumer-tx-retain");
    bool live_release=!strcmp(mode,"dequeue-pre-live")||!strcmp(mode,"dequeue-tx-live");
    bool cas=!strcmp(mode,"dequeue-cas")||!strcmp(mode,"producer-cas");
    unsigned generation=producer?0:1;
    uint64_t epoch=retained_tx?40U+generation:
        (enqueue_prepare||standby?24U:(cas?22U:(tx_live?26U:20U)))+generation;
    uint32_t slot=1U+generation;
    struct ker_generation_rings*r=NULL;
    int rc=ker_generation_rings_attach(TEST_SESSION,1,2,pool,&r);
    if(rc)return fail(c,"crash-window secondary attach failed");
    struct ker_generation_identity id={.session=TEST_SESSION,.epoch=epoch,.slot=slot,
        .generation=generation,.process=0,.pid=(uint32_t)getpid()};
    atomic_store_explicit(producer?&c->producer_ready:&c->consumer_ready,1,memory_order_release);
    if(producer){
        wait_stage(c,20);
        if(retained_tx){
            static const uint8_t payloads[]={0x71,0x72,0x73};
            for(size_t i=0;i<sizeof(payloads);i++){
                struct rte_mbuf *packet_out=packet(pool,payloads[i]);
                if(!packet_out)return fail(c,"dead-producer TX packet allocation failed");
                if(ker_generation_tx_enqueue(r,&id,0,0,packet_out)){
                    rte_pktmbuf_free(packet_out);return fail(c,"dead-producer TX enqueue failed");
                }
                c->retained_tx[i]=(uintptr_t)packet_out;
            }
            atomic_store_explicit(&c->stage,21,memory_order_release);
            return atomic_load(&c->failed)?1:0;
        }
        if(enqueue_prepare)ker_generation_test_hold_after_enqueue_prepare(&c->crash_ready);
        struct rte_mbuf*m=packet(pool,enqueue_prepare?0x63:(cas?0x62:0x61));
        if(!m)return fail(c,"crash-window packet allocation failed");
        int enqueue_rc=tx_live?ker_generation_tx_enqueue(r,&id,0,0,m):
            ker_generation_rx_enqueue(r,&id,0,0,1,m);
        if(enqueue_rc){rte_pktmbuf_free(m);return fail(c,"crash-window enqueue failed");}
        if(!enqueue_prepare&&!cas&&!strcmp(mode,"producer-pre-tx")){
            struct rte_mbuf *tx=packet(pool,0x65);
            if(!tx)return fail(c,"late-corruption TX fixture allocation failed");
            if(ker_generation_tx_enqueue(r,&id,0,0,tx)){rte_pktmbuf_free(tx);return fail(c,"late-corruption TX fixture enqueue failed");}
        }
        atomic_store_explicit(&c->stage,21,memory_order_release);wait_stage(c,22);
        return atomic_load(&c->failed)?1:0;
    }
    if(retained_tx){
        wait_stage(c,22);
        struct ker_generation_identity dead_producer={.session=TEST_SESSION,.epoch=40,
            .slot=1,.generation=0,.process=0,.pid=0};
        /* The parent has filled in the exact dead producer PID in shared
         * control before releasing this consumer. */
        dead_producer.pid=atomic_load_explicit(&c->producer_pid,memory_order_acquire);
        struct rte_mbuf *attempt=packet(pool,0x7f),*out=NULL;
        if(!attempt)return fail(c,"dead-producer rejection allocation failed");
        if(ker_generation_tx_enqueue(r,&dead_producer,0,0,attempt)!=-EINVAL||
            rte_mbuf_refcnt_read(attempt)!=1){rte_pktmbuf_free(attempt);return fail(c,"dead producer admitted a new TX enqueue");}
        rte_pktmbuf_free(attempt);
        if(ker_generation_tx_dequeue_peer(r,&dead_producer,0,0,&out)!=-EINVAL||out)
            return fail(c,"dead producer identity accessed peer TX ring");
        if(ker_generation_rx_dequeue(r,&dead_producer,0,0,&out)!=-EINVAL||out)
            return fail(c,"dead producer identity accessed RX ring");
        struct ker_generation_identity forged=id;forged.epoch++;
        if(ker_generation_tx_dequeue_peer(r,&forged,0,0,&out)!=-EINVAL||out)
            return fail(c,"forged consumer accessed retained TX ring");
        out=NULL;
        if(ker_generation_rx_dequeue(r,&id,0,0,&out)!=0||out)
            return fail(c,"live consumer RX empty-ring behavior changed");
        struct rte_ring *retained_ring=rte_ring_lookup("drain_tx_p0_q0_g0");
        if(!retained_ring||rte_ring_count(retained_ring)!=3||rte_mempool_in_use_count(pool)!=3)
            return fail(c,"rejected peer requests changed retained TX objects");
        static const uint8_t payloads[]={0x71,0x72,0x73};
        for(size_t i=0;i<sizeof(payloads);i++){
            out=NULL;
            if(ker_generation_tx_dequeue_peer(r,&id,0,0,&out)!=1||!out||
                (uintptr_t)out!=c->retained_tx[i]||
                rte_pktmbuf_mtod(out,uint8_t*)[0]!=payloads[i]||
                ker_generation_packet_release(r,&id,out))
                return fail(c,"live peer did not drain/release retained TX FIFO exactly once");
        }
        out=NULL;
        if(ker_generation_tx_dequeue_peer(r,&id,0,0,&out)!=0||out||
            rte_mempool_in_use_count(pool)!=0)
            return fail(c,"retained TX ring was not empty or pool did not return to baseline");
        atomic_store_explicit(&c->stage,23,memory_order_release);
        return atomic_load(&c->failed)?1:0;
    }
    if(standby){wait_stage(c,22);return atomic_load(&c->failed)?1:0;}
    wait_stage(c,21);
    if(cas)ker_generation_test_hold_after_dequeue_cas(&c->crash_ready);
    else ker_generation_test_hold_after_ring_remove(&c->crash_ready,live_release?&c->transition_release:NULL);
    struct rte_mbuf*m=NULL;
    rc=tx_live?ker_generation_tx_dequeue_peer(r,&id,0,0,&m):
        ker_generation_rx_dequeue(r,&id,0,0,&m);
    if(live_release&&rc==1&&m&&rte_pktmbuf_mtod(m,uint8_t*)[0]==0x61&&
        !ker_generation_packet_release(r,&id,m))return atomic_load(&c->failed)?1:0;
    if(rc==1&&m)ker_generation_packet_release(r,&id,m);
    return fail(c,"crash-window hook did not stop dequeue at requested point");
}
static int run_dequeue_crash_window(struct ker_generation_rings*r,struct rte_mempool*pool,
    const char *prefix,const char *exe,const char *mode)
{
    struct test_control*c=control();pid_t pids[2]={-1,-1};int pidfds[2]={-1,-1};int status=0,failed=0;
    bool cas=!strcmp(mode,"cas"),enqueue_prepare=!strcmp(mode,"enqueue");
    bool tx_live=!strcmp(mode,"tx-live");
    bool live_other=!strcmp(mode,"live")||tx_live,late_corruption=!strcmp(mode,"pre");
    uint64_t base_epoch=enqueue_prepare?24U:(cas?22U:(tx_live?26U:20U));uint32_t base_slot=1;
    struct ker_generation_identity producer={.session=TEST_SESSION,.epoch=base_epoch,
        .slot=base_slot,.generation=0,.process=0,.pid=0};
    struct ker_generation_identity consumer={.session=TEST_SESSION,.epoch=base_epoch+1,
        .slot=base_slot+1,.generation=1,.process=0,.pid=0};
    struct rte_ring*rx=rte_ring_lookup("drain_rx_p0_q0_g1");
    unsigned pool_before=rte_mempool_in_use_count(pool);uint64_t drop_before=0,drop_after=0;
    if(!c||!rx||rte_ring_count(rx)||pool_before||
        ker_generation_test_tx_drop_count(r,0,0,0,&drop_before))return -1;
    atomic_store(&c->stage,0);atomic_store(&c->crash_ready,0);
    atomic_store(&c->producer_ready,0);atomic_store(&c->consumer_ready,0);
    atomic_store(&c->transition_release,0);atomic_store(&c->failed,0);
#define CRASH_FAIL() do { failed=1;goto cleanup; } while(0)
    pids[0]=fork();if(pids[0]<0)CRASH_FAIL();
    if(!pids[0]){execl(exe,exe,"--no-pci",prefix,"--proc-type=secondary","--",
        enqueue_prepare?"producer-enqueue":(tx_live?"producer-tx-live":
            (cas?"producer-cas":(late_corruption?"producer-pre-tx":"producer-pre"))),(char*)NULL);_Exit(127);}
    pidfds[0]=syscall(SYS_pidfd_open,pids[0],0);if(pidfds[0]<0)CRASH_FAIL();producer.pid=(uint32_t)pids[0];
    pids[1]=fork();if(pids[1]<0)CRASH_FAIL();
    if(!pids[1]){execl(exe,exe,"--no-pci",prefix,"--proc-type=secondary","--",
        enqueue_prepare?"standby":(tx_live?"dequeue-tx-live":
            (live_other?"dequeue-pre-live":(cas?"dequeue-cas":"dequeue-pre"))),(char*)NULL);_Exit(127);}
    pidfds[1]=syscall(SYS_pidfd_open,pids[1],0);if(pidfds[1]<0)CRASH_FAIL();consumer.pid=(uint32_t)pids[1];
    if(ker_generation_admit(r,&producer,pidfds[0])||ker_generation_admit(r,&consumer,pidfds[1]))CRASH_FAIL();
    for(unsigned tick=0;tick<10000&&
        (!atomic_load_explicit(&c->producer_ready,memory_order_acquire)||
         !atomic_load_explicit(&c->consumer_ready,memory_order_acquire));tick++){
        for(unsigned i=0;i<2;i++){
            siginfo_t info={0};
            if(waitid(P_PID,(id_t)pids[i],&info,WEXITED|WNOHANG|WNOWAIT)||info.si_pid==pids[i])CRASH_FAIL();
        }
        usleep(1000);
    }
    if(!atomic_load(&c->producer_ready)||!atomic_load(&c->consumer_ready))CRASH_FAIL();
    atomic_store_explicit(&c->stage,20,memory_order_release);
    if(!enqueue_prepare&&parent_wait_stage(c,21,pids,2))CRASH_FAIL();
    for(unsigned tick=0;tick<10000&&!atomic_load_explicit(&c->crash_ready,memory_order_acquire);tick++){
        siginfo_t info={0};
        if(waitid(P_PID,(id_t)pids[1],&info,WEXITED|WNOHANG|WNOWAIT)||info.si_pid==pids[1])CRASH_FAIL();
        usleep(1000);
    }
    struct rte_ring *tx=rte_ring_lookup("drain_tx_p0_q0_g0");
    unsigned expected_objects=1U+(late_corruption?1U:0U);
    if(!atomic_load_explicit(&c->crash_ready,memory_order_acquire)||!tx||
        rte_ring_count(rx)!=0||rte_mempool_in_use_count(pool)!=pool_before+expected_objects||
        rte_ring_count(tx)!=(late_corruption?1U:0U))CRASH_FAIL();
    if(live_other){
        if(syscall(SYS_pidfd_send_signal,pidfds[0],SIGKILL,NULL,0)||
            wait_child_bounded(pids[0],&status)||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL||
            ker_generation_reap_ready(r,&producer)!=-EBUSY||
            rte_mempool_in_use_count(pool)!=pool_before+1||rte_ring_count(rx)||rte_ring_count(tx)||
            ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||drop_after!=drop_before)CRASH_FAIL();
        close(pidfds[0]);pidfds[0]=-1;pids[0]=-1;
        atomic_store_explicit(&c->transition_release,1,memory_order_release);
        if(wait_child_bounded(pids[1],&status)||!WIFEXITED(status)||WEXITSTATUS(status))CRASH_FAIL();
        pids[1]=-1;
        if(ker_generation_reap_ready(r,&producer)||ker_generation_reap_dead(r,&producer)||
            rte_mempool_in_use_count(pool)!=pool_before||
            rte_ring_count(rx)||rte_ring_count(tx)||
            ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||drop_after!=drop_before)CRASH_FAIL();
        if(ker_generation_reap_dead(r,&consumer))CRASH_FAIL();
        close(pidfds[1]);pidfds[1]=-1;pids[1]=-1;
    }else{
        /* Both registrations are exact-dead before the first reap. `pre`
         * deliberately reaps the idle producer first while the consumer's
         * active counter is stuck in a real dequeue transition. */
        if(syscall(SYS_pidfd_send_signal,pidfds[1],SIGKILL,NULL,0)||
            wait_child_bounded(pids[1],&status)||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL)CRASH_FAIL();
        if(syscall(SYS_pidfd_send_signal,pidfds[0],SIGKILL,NULL,0)||
            wait_child_bounded(pids[0],&status)||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL)CRASH_FAIL();
        if(late_corruption){
            ker_generation_test_corrupt_next_reap();
            if(ker_generation_reap_dead(r,&producer)!=-EUCLEAN||
                rte_mempool_in_use_count(pool)!=pool_before+2||rte_ring_count(tx)!=1||rte_ring_count(rx)||
                ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||drop_after!=drop_before)CRASH_FAIL();
            struct rte_mbuf *restored_tx=NULL;
            if(rte_ring_dequeue(tx,(void **)&restored_tx)||!restored_tx||
                rte_pktmbuf_mtod(restored_tx,uint8_t*)[0]!=0x65||rte_ring_enqueue(tx,restored_tx))CRASH_FAIL();
            ker_generation_test_restore_reap_corruption();
        }
        bool consumer_first=!strcmp(mode,"cas");
        const struct ker_generation_identity *first=consumer_first?&consumer:&producer;
        const struct ker_generation_identity *second=consumer_first?&producer:&consumer;
        if(ker_generation_reap_dead(r,first)||rte_ring_lookup("drain_rx_p0_q0_g1")!=rx||
            rte_ring_count(rx)||rte_ring_count(tx)||rte_mempool_in_use_count(pool)!=pool_before||
            ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||
            drop_after!=drop_before+(late_corruption?1U:0U))CRASH_FAIL();
        unsigned first_index=consumer_first?1U:0U;
        close(pidfds[first_index]);pidfds[first_index]=-1;pids[first_index]=-1;
        if(ker_generation_reap_dead(r,second)||rte_mempool_in_use_count(pool)!=pool_before||
            rte_ring_count(rx)||rte_ring_count(tx)||
            ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||
            drop_after!=drop_before+(late_corruption?1U:0U))CRASH_FAIL();
        unsigned second_index=consumer_first?0U:1U;
        close(pidfds[second_index]);pidfds[second_index]=-1;pids[second_index]=-1;
    }
    if(rte_mempool_in_use_count(pool)!=pool_before||ker_generation_rings_stats(r,&(struct ker_generation_ring_stats){0}))CRASH_FAIL();
    printf("NR19_REAPER_CRASH_WINDOW_PASS mode=%s dead_mask_recovery=true tx_drop_delta=%u\n",mode,late_corruption?1U:0U);
    goto cleanup;
cleanup:
    if(failed){
        for(unsigned i=0;i<2;i++)if(pidfds[i]>=0){
            siginfo_t info={0};
            if(waitid(P_PIDFD,(id_t)pidfds[i],&info,WEXITED|WNOHANG|WNOWAIT)==0&&info.si_pid==0)
                (void)syscall(SYS_pidfd_send_signal,pidfds[i],SIGKILL,NULL,0);
        }
        for(unsigned i=0;i<2;i++)if(pids[i]>0){
            (void)wait_child_bounded(pids[i],&status);
            if(pidfds[i]>=0){(void)ker_generation_reap_dead(r,i?&consumer:&producer);close(pidfds[i]);pidfds[i]=-1;}
        }
        for(unsigned i=0;i<2;i++)if(pidfds[i]>=0){close(pidfds[i]);pidfds[i]=-1;}
    }
#undef CRASH_FAIL
    return failed?-1:0;
}
static int run_dead_producer_tx(struct ker_generation_rings*r,struct rte_mempool*pool,
    const char *prefix,const char *exe)
{
    struct test_control*c=control();pid_t pids[2]={-1,-1};int pidfds[2]={-1,-1};
    int status=0,result=-1;uint64_t drop_before=0,drop_after=0;
    struct ker_generation_identity producer={.session=TEST_SESSION,.epoch=40,.slot=1,
        .generation=0,.process=0,.pid=0};
    struct ker_generation_identity consumer={.session=TEST_SESSION,.epoch=41,.slot=2,
        .generation=1,.process=0,.pid=0};
    struct rte_ring *tx=rte_ring_lookup("drain_tx_p0_q0_g0");
    unsigned pool_before=rte_mempool_in_use_count(pool);
    if(!c||!tx||pool_before||rte_ring_count(tx)||
        ker_generation_test_tx_drop_count(r,0,0,0,&drop_before))return -1;
    atomic_store(&c->stage,0);atomic_store(&c->producer_ready,0);
    atomic_store(&c->consumer_ready,0);atomic_store(&c->producer_pid,0);
    memset(c->retained_tx,0,sizeof(c->retained_tx));
    atomic_store(&c->failed,0);
#define DEAD_TX_FAIL() do { fprintf(stderr,"NR19 dead-producer TX failure at line %d stage=%u\n",__LINE__,atomic_load(&c->stage)); goto cleanup; } while(0)
    pids[0]=fork();if(pids[0]<0)DEAD_TX_FAIL();
    if(!pids[0]){execl(exe,exe,"--no-pci",prefix,"--proc-type=secondary","--","producer-tx-retain",(char*)NULL);_Exit(127);}
    pidfds[0]=syscall(SYS_pidfd_open,pids[0],0);if(pidfds[0]<0)DEAD_TX_FAIL();
    producer.pid=(uint32_t)pids[0];
    atomic_store_explicit(&c->producer_pid,producer.pid,memory_order_release);
    pids[1]=fork();if(pids[1]<0)DEAD_TX_FAIL();
    if(!pids[1]){execl(exe,exe,"--no-pci",prefix,"--proc-type=secondary","--","consumer-tx-retain",(char*)NULL);_Exit(127);}
    pidfds[1]=syscall(SYS_pidfd_open,pids[1],0);if(pidfds[1]<0)DEAD_TX_FAIL();
    consumer.pid=(uint32_t)pids[1];
    if(ker_generation_admit(r,&producer,pidfds[0])||ker_generation_admit(r,&consumer,pidfds[1]))DEAD_TX_FAIL();
    for(unsigned tick=0;tick<10000&&
        (!atomic_load_explicit(&c->producer_ready,memory_order_acquire)||
         !atomic_load_explicit(&c->consumer_ready,memory_order_acquire));tick++){
        for(unsigned i=0;i<2;i++){
            siginfo_t info={0};
            if(waitid(P_PID,(id_t)pids[i],&info,WEXITED|WNOHANG|WNOWAIT)||info.si_pid==pids[i])DEAD_TX_FAIL();
        }
        usleep(1000);
    }
    if(!atomic_load(&c->producer_ready)||!atomic_load(&c->consumer_ready))DEAD_TX_FAIL();
    atomic_store_explicit(&c->stage,20,memory_order_release);
    siginfo_t exited={0};
    for(unsigned tick=0;tick<10000;tick++){
        if(waitid(P_PID,(id_t)pids[0],&exited,WEXITED|WNOHANG|WNOWAIT))DEAD_TX_FAIL();
        if(exited.si_pid==pids[0])break;
        usleep(1000);
    }
    if(exited.si_pid!=pids[0]||exited.si_code!=CLD_EXITED||exited.si_status!=0)DEAD_TX_FAIL();
    struct pollfd dead={.fd=pidfds[0],.events=POLLIN};
    int ready;do ready=poll(&dead,1,0);while(ready<0&&errno==EINTR);
    char fdinfo_path[64],fdinfo[256];
    if(ready!=1||!(dead.revents&POLLIN)||
        snprintf(fdinfo_path,sizeof(fdinfo_path),"/proc/self/fdinfo/%d",pidfds[0])<0)DEAD_TX_FAIL();
    int fdinfo_fd=open(fdinfo_path,O_RDONLY|O_CLOEXEC);
    if(fdinfo_fd<0)DEAD_TX_FAIL();
    ssize_t fdinfo_size=read(fdinfo_fd,fdinfo,sizeof(fdinfo)-1);close(fdinfo_fd);
    if(fdinfo_size<=0)DEAD_TX_FAIL();
    fdinfo[fdinfo_size]='\0';char *pid_line=strstr(fdinfo,"Pid:");int fd_pid=-1;
    if(!pid_line||sscanf(pid_line+4,"%d",&fd_pid)!=1||(uint32_t)fd_pid!=producer.pid||
        rte_ring_lookup("drain_tx_p0_q0_g0")!=tx||rte_ring_count(tx)!=3||
        rte_mempool_in_use_count(pool)!=pool_before+3)DEAD_TX_FAIL();
    if(ker_generation_reap_dead(r,&producer)||rte_ring_lookup("drain_tx_p0_q0_g0")!=tx||
        rte_ring_count(tx)!=3||rte_mempool_in_use_count(pool)!=pool_before+3||
        ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||drop_after!=drop_before)DEAD_TX_FAIL();
    /* The PIDFD still names the unreaped zombie, so fdinfo identity matches;
     * only the liveness poll prevents re-admitting the retired generation. */
    if(ker_generation_admit(r,&producer,pidfds[0])!=-ESTALE||
        rte_ring_lookup("drain_tx_p0_q0_g0")!=tx||rte_ring_count(tx)!=3||
        rte_mempool_in_use_count(pool)!=pool_before+3||
        ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||drop_after!=drop_before)DEAD_TX_FAIL();
    if(wait_child_bounded(pids[0],&status)||!WIFEXITED(status)||WEXITSTATUS(status))DEAD_TX_FAIL();
    close(pidfds[0]);pidfds[0]=-1;pids[0]=-1;
    atomic_store_explicit(&c->stage,22,memory_order_release);
    if(parent_wait_stage(c,23,pids+1,1)||wait_child_bounded(pids[1],&status)||
        !WIFEXITED(status)||WEXITSTATUS(status)||rte_ring_lookup("drain_tx_p0_q0_g0")!=tx||
        rte_ring_count(tx)||rte_mempool_in_use_count(pool)!=pool_before||
        ker_generation_test_tx_drop_count(r,0,0,0,&drop_after)||drop_after!=drop_before)DEAD_TX_FAIL();
    if(ker_generation_reap_dead(r,&consumer))DEAD_TX_FAIL();
    close(pidfds[1]);pidfds[1]=-1;pids[1]=-1;
    result=0;
    printf("NR19_LIVE_PEER_DRAINS_RETAINED_TX_PASS packets=3 fifo=true pool_restored=true tx_drop_delta=0\n");
cleanup:
    if(result){
        for(unsigned i=0;i<2;i++)if(pidfds[i]>=0){
            siginfo_t info={0};
            if(waitid(P_PIDFD,(id_t)pidfds[i],&info,WEXITED|WNOHANG|WNOWAIT)==0&&info.si_pid==0)
                (void)syscall(SYS_pidfd_send_signal,pidfds[i],SIGKILL,NULL,0);
        }
        for(unsigned i=0;i<2;i++)if(pids[i]>0){
            (void)wait_child_bounded(pids[i],&status);
            if(pidfds[i]>=0){
                const struct ker_generation_identity *identity=i?&consumer:&producer;
                (void)ker_generation_reap_dead(r,identity);
            }
        }
        for(unsigned i=0;i<2;i++)if(pidfds[i]>=0)close(pidfds[i]);
    }
#undef DEAD_TX_FAIL
    return result;
}
static int run_packet_death_case(struct ker_generation_rings *rings,struct rte_mempool *pool,
    const char *prefix,const char *exe,unsigned profile)
{
    struct test_control *c=control();pid_t pids[2]={-1,-1};int pidfds[2]={-1,-1};
    int status=0,result=-1;uint32_t index=0;uint64_t lease=0;
    uint32_t post_race_active[4]={UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX};
    struct ker_generation_identity actors[2]={
        {.session=TEST_SESSION,.epoch=100+profile*2,.slot=1,.generation=0,.process=0,.pid=0},
        {.session=TEST_SESSION,.epoch=101+profile*2,.slot=2,.generation=1,.process=0,.pid=0}};
    struct rte_ring *tx=rte_ring_lookup("drain_tx_p0_q1_g0");
    uint32_t packet_baseline=ker_generation_packet_pool_in_use(rings);
    if(!c||!tx||rte_ring_count(tx)||packet_baseline!=0||rte_mempool_in_use_count(pool))return -1;
    atomic_store(&c->packet_case,profile);atomic_store(&c->packet_go,0);
    atomic_store(&c->packet_ready[0],0);atomic_store(&c->packet_ready[1],0);
    atomic_store(&c->packet_writer_ready,0);atomic_store(&c->packet_writer_complete,0);
    atomic_store(&c->packet_commit_ready,0);
    atomic_store(&c->packet_commit_release,0);atomic_store(&c->packet_index,0);
    atomic_store(&c->packet_enqueue_ready,0);atomic_store(&c->packet_enqueue_release,0);
    atomic_store(&c->packet_consumer_released,0);
    atomic_store(&c->packet_lease,0);atomic_store(&c->packet_producer_pid,0);
#define PACKET_CASE_FAIL() do { fprintf(stderr,"NR19 packet death profile=%u failure line=%d stage=%u\n",profile,__LINE__,atomic_load(&c->packet_go));goto cleanup; } while(0)
    for(unsigned g=0;g<2;g++){
        pids[g]=fork();if(pids[g]<0)PACKET_CASE_FAIL();
        if(!pids[g]){char mode[32];snprintf(mode,sizeof(mode),"packet-worker-%u",g);
            execl(exe,exe,"--no-pci",prefix,"--proc-type=secondary","--",mode,(char*)NULL);_Exit(127);}
        pidfds[g]=syscall(SYS_pidfd_open,pids[g],0);if(pidfds[g]<0)PACKET_CASE_FAIL();
        actors[g].pid=(uint32_t)pids[g];
    }
    atomic_store_explicit(&c->packet_producer_pid,(int)pids[0],memory_order_release);
    int admit_rc=ker_generation_admit(rings,&actors[0],pidfds[0]);
    if(admit_rc){
        fprintf(stderr,"NR19 packet profile=%u admit rc=%d slot=%u epoch=%llu generation=%u pid=%u message_pool_in_use=%u packet_pool_in_use=%u\n",
            profile,admit_rc,actors[0].slot,(unsigned long long)actors[0].epoch,
            actors[0].generation,actors[0].pid,rte_mempool_in_use_count(pool),
            ker_generation_packet_pool_in_use(rings));
        PACKET_CASE_FAIL();
    }
    admit_rc=ker_generation_admit(rings,&actors[1],pidfds[1]);
    if(admit_rc){
        fprintf(stderr,"NR19 packet profile=%u admit rc=%d slot=%u epoch=%llu generation=%u pid=%u message_pool_in_use=%u packet_pool_in_use=%u\n",
            profile,admit_rc,actors[1].slot,(unsigned long long)actors[1].epoch,
            actors[1].generation,actors[1].pid,rte_mempool_in_use_count(pool),
            ker_generation_packet_pool_in_use(rings));
        PACKET_CASE_FAIL();
    }
    for(unsigned tick=0;tick<10000&&(!atomic_load(&c->packet_ready[0])||!atomic_load(&c->packet_ready[1]));tick++){
        for(unsigned g=0;g<2;g++){
            siginfo_t info={0};if(waitid(P_PID,(id_t)pids[g],&info,WEXITED|WNOHANG|WNOWAIT)||info.si_pid==pids[g])PACKET_CASE_FAIL();
        }
        usleep(1000);
    }
    if(!atomic_load(&c->packet_ready[0])||!atomic_load(&c->packet_ready[1]))PACKET_CASE_FAIL();
    if(ker_generation_packet_prepare(rings,&actors[0],&actors[1],0,1,&index,&lease)||!lease)PACKET_CASE_FAIL();
    atomic_store_explicit(&c->packet_index,index,memory_order_release);
    atomic_store_explicit(&c->packet_lease,lease,memory_order_release);
    if(profile==2){
        atomic_store_explicit(&c->packet_go,1,memory_order_release);
        for(unsigned tick=0;tick<10000&&!atomic_load(&c->packet_writer_ready);tick++){
            siginfo_t info={0};if(waitid(P_PID,(id_t)pids[0],&info,WEXITED|WNOHANG|WNOWAIT)||info.si_pid==pids[0])PACKET_CASE_FAIL();
            usleep(1000);
        }
        struct ker_generation_cleanup_config selected_tx={.version=KER_GENERATION_CLEANUP_CONFIG_VERSION,
            .size=sizeof(selected_tx),.ports=1,.queues=2,.rx_queue_mask=0,
            .tx_queue_mask=UINT64_C(1)<<1};
        unsigned writer_ready=atomic_load(&c->packet_writer_ready);
        int detach_ready_rc=writer_ready?
            ker_generation_orderly_detach_ready(rings,&actors[0],&selected_tx):-ETIMEDOUT;
        if(!writer_ready||detach_ready_rc!=-EBUSY){
            fprintf(stderr,"NR19 packet profile=2 detach-ready rc=%d writer_ready=%u selected_tx_mask=%llu packet_pool_in_use=%u\n",
                detach_ready_rc,writer_ready,(unsigned long long)selected_tx.tx_queue_mask,
                ker_generation_packet_pool_in_use(rings));
            PACKET_CASE_FAIL();
        }
    }
    if(profile==3){
        struct rte_mbuf *packet_out=ker_generation_packet_resolve(rings,&actors[0],index,lease);
        uint8_t *bytes=packet_out?(uint8_t *)rte_pktmbuf_append(packet_out,14):NULL;
        if(!bytes)PACKET_CASE_FAIL();
        memset(bytes,0xa9,14);
        if(ker_generation_packet_write_complete(rings,&actors[0],index,lease))PACKET_CASE_FAIL();
        ker_generation_test_hold_packet_commit(&c->packet_commit_ready,&c->packet_commit_release);
        if(ker_generation_packet_commit(rings,&actors[0],0,1,index,lease))PACKET_CASE_FAIL();
        ker_generation_test_hold_packet_commit(NULL,NULL);
        if(wait_child_bounded(pids[0],&status)||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL||
            rte_ring_count(tx)!=1||ker_generation_packet_pool_in_use(rings)!=packet_baseline+1)PACKET_CASE_FAIL();
        if(ker_generation_reap_dead(rings,&actors[0])||rte_ring_lookup("drain_tx_p0_q1_g0")!=tx||
            rte_ring_count(tx)!=1||ker_generation_packet_pool_in_use(rings)!=packet_baseline+1)PACKET_CASE_FAIL();
        close(pidfds[0]);pidfds[0]=-1;pids[0]=-1;
        atomic_store_explicit(&c->packet_go,3,memory_order_release);
        for(unsigned tick=0;tick<10000&&atomic_load(&c->packet_go)<4;tick++)usleep(1000);
        if(atomic_load(&c->packet_go)!=4||wait_child_bounded(pids[1],&status)||!WIFEXITED(status)||WEXITSTATUS(status)||
            rte_ring_count(tx)||ker_generation_packet_pool_in_use(rings)!=packet_baseline)PACKET_CASE_FAIL();
        if(ker_generation_reap_dead(rings,&actors[1]))PACKET_CASE_FAIL();
        close(pidfds[1]);pidfds[1]=-1;pids[1]=-1;
    }else if(profile==6){
        struct rte_mbuf *packet_out=ker_generation_packet_resolve(rings,&actors[0],index,lease);
        uint8_t *bytes=packet_out?(uint8_t *)rte_pktmbuf_append(packet_out,14):NULL;
        struct rte_mbuf *message_tx=NULL,*message_rx=NULL;
        struct rte_ring *rx_ring=rte_ring_lookup("drain_rx_p0_q1_g1");
        struct rte_mbuf *expected_tx[2]={0},*expected_rx[1]={0};
        const uint8_t tx_values[2]={0xb6,0xc1},rx_values[1]={0xc2};
        const uint16_t tx_lengths[2]={14,1},rx_lengths[1]={1};
        uint64_t drop_before=0,drop_after=0,packet_drop_before=0,packet_drop_after=0;
        if(!bytes||!rx_ring)PACKET_CASE_FAIL();
        memset(bytes,0xb6,14);
        if(ker_generation_packet_write_complete(rings,&actors[0],index,lease)||
            ker_generation_packet_commit(rings,&actors[0],0,1,index,lease))PACKET_CASE_FAIL();
        message_tx=packet(pool,0xc1);message_rx=packet(pool,0xc2);
        if(!message_tx||!message_rx||
            ker_generation_tx_enqueue(rings,&actors[0],0,1,message_tx)||
            ker_generation_rx_enqueue(rings,&actors[0],0,1,1,message_rx)||
            ker_generation_test_tx_drop_count(rings,0,1,0,&drop_before)||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_before))PACKET_CASE_FAIL();
        expected_tx[0]=packet_out;expected_tx[1]=message_tx;expected_rx[0]=message_rx;
        if(syscall(SYS_pidfd_send_signal,pidfds[0],SIGKILL,NULL,0)||
            syscall(SYS_pidfd_send_signal,pidfds[1],SIGKILL,NULL,0))PACKET_CASE_FAIL();
        for(unsigned g=0;g<2;g++)if(wait_child_bounded(pids[g],&status)||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL)PACKET_CASE_FAIL();
        if(rte_ring_count(tx)!=2||rte_ring_count(rx_ring)!=1||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline+1||
            rte_mempool_in_use_count(pool)!=2||
            ring_snapshot_verify(tx,2,expected_tx,tx_values,tx_lengths)||
            ring_snapshot_verify(rx_ring,1,expected_rx,rx_values,rx_lengths))PACKET_CASE_FAIL();
        ker_generation_test_corrupt_next_reap();
        if(ker_generation_reap_dead(rings,&actors[0])!=-EUCLEAN||rte_ring_count(tx)!=2||
            rte_ring_count(rx_ring)!=1||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline+1||
            rte_mempool_in_use_count(pool)!=2||
            ring_snapshot_verify(tx,2,expected_tx,tx_values,tx_lengths)||
            ring_snapshot_verify(rx_ring,1,expected_rx,rx_values,rx_lengths)||
            ker_generation_test_tx_drop_count(rings,0,1,0,&drop_after)||drop_after!=drop_before||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_after)||packet_drop_after!=packet_drop_before)PACKET_CASE_FAIL();
        ker_generation_test_restore_reap_corruption();
        if(ker_generation_reap_dead(rings,&actors[0])||rte_ring_count(tx)||
            rte_ring_count(rx_ring)||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline||
            rte_mempool_in_use_count(pool)||
            ker_generation_test_tx_drop_count(rings,0,1,0,&drop_after)||drop_after!=drop_before+1||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_after)||packet_drop_after!=packet_drop_before+1)PACKET_CASE_FAIL();
        unsigned message_pool_before=rte_mempool_in_use_count(pool),tx_count_before=rte_ring_count(tx);
        unsigned rx_count_before=rte_ring_count(rx_ring);
        uint32_t packet_pool_before=ker_generation_packet_pool_in_use(rings);
        uint64_t legacy_drop_after_first=0,packet_drop_after_first=0;
        if(ker_generation_test_tx_drop_count(rings,0,1,0,&legacy_drop_after_first)||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_after_first)||
            ker_generation_reap_dead(rings,&actors[1])||
            rte_mempool_in_use_count(pool)!=message_pool_before||
            ker_generation_packet_pool_in_use(rings)!=packet_pool_before||
            rte_ring_count(tx)!=tx_count_before||rte_ring_count(rx_ring)!=rx_count_before||
            ker_generation_test_tx_drop_count(rings,0,1,0,&drop_after)||drop_after!=legacy_drop_after_first||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_after)||packet_drop_after!=packet_drop_after_first)
            PACKET_CASE_FAIL();
        for(unsigned g=0;g<2;g++){close(pidfds[g]);pidfds[g]=-1;pids[g]=-1;}
    }else if(profile==7){
        struct ker_generation_cleanup_config empty={.version=KER_GENERATION_CLEANUP_CONFIG_VERSION,
            .size=sizeof(empty),.ports=1,.queues=2,.rx_queue_mask=0,.tx_queue_mask=0};
        unsigned rx_reclaimed=UINT_MAX,tx_reclaimed=UINT_MAX;
        atomic_store_explicit(&c->packet_go,1,memory_order_release);
        for(unsigned tick=0;tick<10000&&!atomic_load(&c->packet_writer_ready);tick++){
            siginfo_t info={0};if(waitid(P_PID,(id_t)pids[0],&info,WEXITED|WNOHANG|WNOWAIT)||info.si_pid==pids[0])PACKET_CASE_FAIL();
            usleep(1000);
        }
        if(!atomic_load(&c->packet_writer_ready)||
            ker_generation_orderly_detach(rings,&actors[0],&empty,0,&rx_reclaimed,&tx_reclaimed)!=-EBUSY||
            rx_reclaimed||tx_reclaimed)PACKET_CASE_FAIL();
        atomic_store_explicit(&c->packet_go,2,memory_order_release);
        for(unsigned tick=0;tick<10000&&!atomic_load(&c->packet_writer_complete);tick++)usleep(1000);
        if(!atomic_load(&c->packet_writer_complete)||
            ker_generation_test_reopen_after_failed_detach(rings,0)||
            ker_generation_admit(rings,&actors[0],pidfds[0])||
            ker_generation_packet_cancel(rings,&actors[0],index,lease)||
            ker_generation_packet_write_complete(rings,&actors[0],index,lease)!=-ESTALE||
            ker_generation_unregister(rings,&actors[0])||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline)PACKET_CASE_FAIL();
        atomic_store_explicit(&c->packet_go,3,memory_order_release);
        for(unsigned g=0;g<2;g++)if(wait_child_bounded(pids[g],&status)||!WIFEXITED(status)||WEXITSTATUS(status))PACKET_CASE_FAIL();
        if(ker_generation_reap_dead(rings,&actors[0]))PACKET_CASE_FAIL();
        struct rte_ring *rx_ring=rte_ring_lookup("drain_rx_p0_q1_g1");
        uint64_t legacy_drop_before=0,packet_drop_before=0,legacy_drop_after=0,packet_drop_after=0;
        unsigned message_pool_before=rte_mempool_in_use_count(pool),tx_count_before=rte_ring_count(tx);
        unsigned rx_count_before=rx_ring?rte_ring_count(rx_ring):UINT_MAX;
        uint32_t packet_pool_before=ker_generation_packet_pool_in_use(rings);
        if(!rx_ring||ker_generation_test_tx_drop_count(rings,0,1,0,&legacy_drop_before)||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_before)||
            ker_generation_reap_dead(rings,&actors[1])||
            rte_mempool_in_use_count(pool)!=message_pool_before||
            ker_generation_packet_pool_in_use(rings)!=packet_pool_before||
            rte_ring_count(tx)!=tx_count_before||rte_ring_count(rx_ring)!=rx_count_before||
            ker_generation_test_tx_drop_count(rings,0,1,0,&legacy_drop_after)||legacy_drop_after!=legacy_drop_before||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_after)||packet_drop_after!=packet_drop_before)
            PACKET_CASE_FAIL();
        for(unsigned g=0;g<2;g++){close(pidfds[g]);pidfds[g]=-1;pids[g]=-1;}
    }else if(profile==8){
        struct rte_mbuf *packet_out=ker_generation_packet_resolve(rings,&actors[0],index,lease);
        uint8_t *bytes=packet_out?(uint8_t *)rte_pktmbuf_append(packet_out,14):NULL;
        if(!bytes)PACKET_CASE_FAIL();
        for(unsigned i=0;i<14;i++)bytes[i]=(uint8_t)(0x90U+i);
        if(ker_generation_packet_write_complete(rings,&actors[0],index,lease))PACKET_CASE_FAIL();
        ker_generation_test_hold_after_packet_enqueue(&c->packet_enqueue_ready,&c->packet_enqueue_release);
        int commit_rc=ker_generation_packet_commit(rings,&actors[0],0,1,index,lease);
        ker_generation_test_hold_after_packet_enqueue(NULL,NULL);
        int active_rc=ker_generation_test_active_counts(rings,post_race_active);
        if(commit_rc||!atomic_load_explicit(&c->packet_consumer_released,memory_order_acquire)||active_rc||
            post_race_active[0]||post_race_active[1]||post_race_active[2]||post_race_active[3]||
            rte_ring_count(tx)||ker_generation_packet_pool_in_use(rings)!=packet_baseline||
            rte_mempool_in_use_count(pool))PACKET_CASE_FAIL();
        if(ker_generation_packet_cancel(rings,&actors[0],index,lease)!=-ESTALE)PACKET_CASE_FAIL();
        int unregister_rc=ker_generation_unregister(rings,&actors[0]);
        if(unregister_rc){
            fprintf(stderr,"NR19 packet profile=8 producer unregister rc=%d after immediate peer release packet_pool_in_use=%u\n",
                unregister_rc,ker_generation_packet_pool_in_use(rings));
            PACKET_CASE_FAIL();
        }
        unregister_rc=ker_generation_unregister(rings,&actors[1]);
        if(unregister_rc){
            fprintf(stderr,"NR19 packet profile=8 consumer unregister rc=%d after immediate release packet_pool_in_use=%u\n",
                unregister_rc,ker_generation_packet_pool_in_use(rings));
            PACKET_CASE_FAIL();
        }
        if(ker_generation_admit(rings,&actors[0],pidfds[0])||
            ker_generation_admit(rings,&actors[1],pidfds[1]))PACKET_CASE_FAIL();
        struct ker_generation_cleanup_config selected_tx={.version=KER_GENERATION_CLEANUP_CONFIG_VERSION,
            .size=sizeof(selected_tx),.ports=1,.queues=2,.rx_queue_mask=0,
            .tx_queue_mask=UINT64_C(1)<<1};
        unsigned rx_reclaimed=UINT_MAX,tx_reclaimed=UINT_MAX;
        if(ker_generation_orderly_detach(rings,&actors[0],&selected_tx,0,&rx_reclaimed,&tx_reclaimed)||
            rx_reclaimed||tx_reclaimed||ker_generation_admit(rings,&actors[0],pidfds[0]))PACKET_CASE_FAIL();
        atomic_store_explicit(&c->packet_go,2,memory_order_release);
        for(unsigned g=0;g<2;g++)if(wait_child_bounded(pids[g],&status)||!WIFEXITED(status)||WEXITSTATUS(status))PACKET_CASE_FAIL();
        if(ker_generation_reap_dead(rings,&actors[0]))PACKET_CASE_FAIL();
        struct rte_ring *rx_ring=rte_ring_lookup("drain_rx_p0_q1_g1");
        uint64_t legacy_drop_before=0,packet_drop_before=0,legacy_drop_after=0,packet_drop_after=0;
        unsigned message_pool_before=rte_mempool_in_use_count(pool),tx_count_before=rte_ring_count(tx);
        unsigned rx_count_before=rx_ring?rte_ring_count(rx_ring):UINT_MAX;
        uint32_t packet_pool_before=ker_generation_packet_pool_in_use(rings);
        if(!rx_ring||ker_generation_test_tx_drop_count(rings,0,1,0,&legacy_drop_before)||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_before)||
            ker_generation_reap_dead(rings,&actors[1])||
            rte_mempool_in_use_count(pool)!=message_pool_before||
            ker_generation_packet_pool_in_use(rings)!=packet_pool_before||
            rte_ring_count(tx)!=tx_count_before||rte_ring_count(rx_ring)!=rx_count_before||
            ker_generation_test_tx_drop_count(rings,0,1,0,&legacy_drop_after)||legacy_drop_after!=legacy_drop_before||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_after)||packet_drop_after!=packet_drop_before)
            PACKET_CASE_FAIL();
        for(unsigned g=0;g<2;g++){close(pidfds[g]);pidfds[g]=-1;pids[g]=-1;}
    }else if(profile==5){
        struct rte_mbuf *denied=NULL;
        if(ker_generation_test_packet_force_untracked_send(rings,index,lease)||
            syscall(SYS_pidfd_send_signal,pidfds[1],SIGKILL,NULL,0)||wait_child_bounded(pids[1],&status)||
            !WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL||
            ker_generation_reap_dead(rings,&actors[1])!=-EUCLEAN||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline+1||rte_ring_count(tx)||
            ker_generation_tx_dequeue_peer(rings,&actors[1],0,1,&denied)!=-EINVAL||denied||
            ker_generation_test_reopen_after_failclosed_reap(rings)||
            ker_generation_test_packet_restore_prepared(rings,index,lease)||
            ker_generation_packet_cancel(rings,&actors[0],index,lease)||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline)PACKET_CASE_FAIL();
        uint64_t legacy_drop_before=0,packet_drop_before=0,legacy_drop_after=0,packet_drop_after=0;
        unsigned message_pool_before=rte_mempool_in_use_count(pool),tx_count_before=rte_ring_count(tx);
        uint32_t packet_pool_before=ker_generation_packet_pool_in_use(rings);
        if(ker_generation_test_tx_drop_count(rings,0,1,0,&legacy_drop_before)||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_before)||
            ker_generation_reap_dead(rings,&actors[1])||
            rte_mempool_in_use_count(pool)!=message_pool_before||
            ker_generation_packet_pool_in_use(rings)!=packet_pool_before||
            rte_ring_count(tx)!=tx_count_before||
            ker_generation_test_tx_drop_count(rings,0,1,0,&legacy_drop_after)||legacy_drop_after!=legacy_drop_before||
            ker_generation_test_packet_drop_count(rings,0,1,0,&packet_drop_after)||packet_drop_after!=packet_drop_before)
            PACKET_CASE_FAIL();
        close(pidfds[1]);pidfds[1]=-1;pids[1]=-1;
        atomic_store_explicit(&c->packet_go,2,memory_order_release);
        if(wait_child_bounded(pids[0],&status)||!WIFEXITED(status)||WEXITSTATUS(status)||
            ker_generation_reap_dead(rings,&actors[0]))PACKET_CASE_FAIL();
        close(pidfds[0]);pidfds[0]=-1;pids[0]=-1;
    }else if(profile==4){
        struct rte_mbuf *stale_packet=ker_generation_packet_resolve(rings,&actors[0],index,lease);
        uint8_t *stale_bytes=stale_packet?(uint8_t *)rte_pktmbuf_append(stale_packet,14):NULL;
        if(!stale_bytes)PACKET_CASE_FAIL();
        memset(stale_bytes,0x44,14);
        if(ker_generation_packet_write_complete(rings,&actors[0],index,lease)||
            syscall(SYS_pidfd_send_signal,pidfds[1],SIGKILL,NULL,0)||wait_child_bounded(pids[1],&status)||
            !WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL||ker_generation_reap_dead(rings,&actors[1])||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline+1||
            ker_generation_packet_cancel(rings,&actors[0],index,lease)||
            ker_generation_packet_resolve(rings,&actors[0],index,lease)!=NULL||
            ker_generation_packet_cancel(rings,&actors[0],index,lease)!=-ESTALE||
            ker_generation_packet_commit(rings,&actors[0],0,1,index,lease)!=-ESTALE||
            ker_generation_packet_release(rings,&actors[0],stale_packet)!=-ESTALE||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline)PACKET_CASE_FAIL();
        close(pidfds[1]);pidfds[1]=-1;pids[1]=-1;
        atomic_store_explicit(&c->packet_go,2,memory_order_release);
        if(wait_child_bounded(pids[0],&status)||!WIFEXITED(status)||WEXITSTATUS(status)||ker_generation_reap_dead(rings,&actors[0]))PACKET_CASE_FAIL();
        close(pidfds[0]);pidfds[0]=-1;pids[0]=-1;
    }else{
        unsigned victim=0;
        if(syscall(SYS_pidfd_send_signal,pidfds[victim],SIGKILL,NULL,0)||wait_child_bounded(pids[victim],&status)||
            !WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL||ker_generation_reap_dead(rings,&actors[victim])||
            ker_generation_packet_pool_in_use(rings)!=packet_baseline||
            ker_generation_packet_cancel(rings,&actors[0],index,lease)!=-ESTALE)PACKET_CASE_FAIL();
        close(pidfds[victim]);pidfds[victim]=-1;pids[victim]=-1;
        atomic_store_explicit(&c->packet_go,2,memory_order_release);
        if(wait_child_bounded(pids[1],&status)||!WIFEXITED(status)||WEXITSTATUS(status)||ker_generation_reap_dead(rings,&actors[1]))PACKET_CASE_FAIL();
        close(pidfds[1]);pidfds[1]=-1;pids[1]=-1;
    }
    if(ker_generation_packet_pool_in_use(rings)!=packet_baseline||rte_ring_count(tx)||
        rte_mempool_in_use_count(pool))PACKET_CASE_FAIL();
    if(profile==8)printf("NR19_PACKET_POST_ENQUEUE_PEER_RELEASE_PASS consumer_released=%u active=%u,%u,%u,%u packet_pool_in_use=%u message_pool_in_use=%u tx_ring_count=%u\n",
        atomic_load_explicit(&c->packet_consumer_released,memory_order_acquire),
        post_race_active[0],post_race_active[1],post_race_active[2],post_race_active[3],
        ker_generation_packet_pool_in_use(rings),rte_mempool_in_use_count(pool),rte_ring_count(tx));
    printf("NR19_PACKET_LEASE_DEATH_PASS profile=%u queued_retained=%u pool_baseline=true\n",profile,profile==3?1U:0U);
    result=0;
cleanup:
    ker_generation_test_hold_packet_commit(NULL,NULL);
    atomic_store_explicit(&c->packet_enqueue_release,1,memory_order_release);
    ker_generation_test_hold_after_packet_enqueue(NULL,NULL);
    if(result){
        for(unsigned g=0;g<2;g++)if(pidfds[g]>=0){siginfo_t info={0};
            if(waitid(P_PIDFD,(id_t)pidfds[g],&info,WEXITED|WNOHANG|WNOWAIT)==0&&info.si_pid==0)
                (void)syscall(SYS_pidfd_send_signal,pidfds[g],SIGKILL,NULL,0);}
        for(unsigned g=0;g<2;g++)if(pids[g]>0){(void)wait_child_bounded(pids[g],&status);
            if(pidfds[g]>=0)(void)ker_generation_reap_dead(rings,&actors[g]);}
    }
    for(unsigned g=0;g<2;g++)if(pidfds[g]>=0)close(pidfds[g]);
#undef PACKET_CASE_FAIL
    return result;
}
static int primary(const char *prefix,const char *exe)
{
    struct rte_mempool*pool=rte_pktmbuf_pool_create(TEST_POOL,256,0,0,2048,SOCKET_ID_ANY);
    if(!pool)return 77;
    const struct rte_memzone*mz=rte_memzone_reserve(TEST_ZONE,sizeof(struct test_control),SOCKET_ID_ANY,0);
    if(!mz)return 1;
    struct test_control*c=mz->addr;memset(c,0,sizeof(*c));atomic_init(&c->stage,0);
    atomic_init(&c->gen0_ready,0);atomic_init(&c->crash_ready,0);atomic_init(&c->producer_pid,0);
    atomic_init(&c->producer_ready,0);atomic_init(&c->consumer_ready,0);
    atomic_init(&c->transition_release,0);atomic_init(&c->failed,0);
    atomic_init(&c->packet_case,0);atomic_init(&c->packet_go,0);
    atomic_init(&c->packet_ready[0],0);atomic_init(&c->packet_ready[1],0);
    atomic_init(&c->packet_writer_ready,0);atomic_init(&c->packet_writer_complete,0);
    atomic_init(&c->packet_commit_ready,0);
    atomic_init(&c->packet_commit_release,0);atomic_init(&c->packet_index,0);
    atomic_init(&c->packet_enqueue_ready,0);atomic_init(&c->packet_enqueue_release,0);
    atomic_init(&c->packet_consumer_released,0);
    atomic_init(&c->packet_lease,0);atomic_init(&c->packet_producer_pid,0);
    struct ker_generation_rings*r=NULL;if(ker_generation_rings_create(TEST_SESSION,1,2,pool,&r))return 1;
    const struct rte_memzone *directory=rte_memzone_lookup("ker_gen_ring_directory");
    if(!directory)return 1;
    uint32_t directory_version,old_directory_version=3;
    memcpy(&directory_version,(char*)directory->addr+2*sizeof(uint64_t),sizeof(directory_version));
    memcpy((char*)directory->addr+2*sizeof(uint64_t),&old_directory_version,sizeof(old_directory_version));
    struct ker_generation_rings *old_abi=NULL;
    int old_abi_result=ker_generation_rings_attach(TEST_SESSION,1,2,pool,&old_abi);
    memcpy((char*)directory->addr+2*sizeof(uint64_t),&directory_version,sizeof(directory_version));
    if(old_abi_result!=-EPROTO||old_abi) return 1;
    pid_t pids[2]={-1,-1};int pidfds[2]={-1,-1};char file_prefix[128];
#define FAIL_CHILDREN() do { \
    fprintf(stderr,"NR19 primary: failure at line %d, stage=%u\n",__LINE__,atomic_load(&c->stage)); \
    for(unsigned failed_i=0;failed_i<2;failed_i++)if(pids[failed_i]>0){ \
        siginfo_t failed_info={0}; \
        if(waitid(P_PID,(id_t)pids[failed_i],&failed_info,WEXITED|WNOHANG|WNOWAIT)==0&&failed_info.si_pid==pids[failed_i]) \
            fprintf(stderr,"NR19 primary: child[%u]=%ld exited code=%d status=%d\n",failed_i,(long)pids[failed_i],failed_info.si_code,failed_info.si_status); \
        else fprintf(stderr,"NR19 primary: child[%u]=%ld still running\n",failed_i,(long)pids[failed_i]); \
    } \
    if(stop_children(pids,2,pidfds)) { _Exit(1); } \
    return 1; } while(0)
    snprintf(file_prefix,sizeof(file_prefix),"--file-prefix=%s",prefix);
    pids[0]=fork();if(pids[0]<0)FAIL_CHILDREN();
    if(!pids[0]){execl(exe,exe,"--no-pci",file_prefix,"--proc-type=secondary","--","0",(char*)NULL);_Exit(127);}
    pidfds[0]=syscall(SYS_pidfd_open,pids[0],0);if(pidfds[0]<0)FAIL_CHILDREN();
    struct ker_generation_identity id0={.session=TEST_SESSION,.epoch=7,.slot=1,.generation=0,.process=0,.pid=(uint32_t)pids[0]};
    if(ker_generation_admit(r,&id0,pidfds[0]))FAIL_CHILDREN();
    if(parent_wait_stage(c,1,pids,1))FAIL_CHILDREN();
    pids[1]=fork();if(pids[1]<0)FAIL_CHILDREN();
    if(!pids[1]){execl(exe,exe,"--no-pci",file_prefix,"--proc-type=secondary","--","1",(char*)NULL);_Exit(127);}
    pidfds[1]=syscall(SYS_pidfd_open,pids[1],0);if(pidfds[1]<0)FAIL_CHILDREN();
    struct ker_generation_identity id1={.session=TEST_SESSION,.epoch=8,.slot=2,.generation=1,.process=0,.pid=(uint32_t)pids[1]};
    if(ker_generation_admit(r,&id1,pidfds[1]))FAIL_CHILDREN();
    if(parent_wait_stage(c,6,pids,2))FAIL_CHILDREN();
    if(packet_lease_core_test(r,pool,&id0,&id1))FAIL_CHILDREN();
    struct ker_generation_cleanup_config cleanup={.version=KER_GENERATION_CLEANUP_CONFIG_VERSION,
        .size=sizeof(cleanup),.ports=1,.queues=2,.rx_queue_mask=0,.tx_queue_mask=1};
    unsigned rx_reclaimed=0,tx_reclaimed=0;
    struct rte_ring *tx_ring=rte_ring_lookup("drain_tx_p0_q0_g0");
    if(!tx_ring||ker_generation_orderly_detach(r,&id0,&cleanup,1,&rx_reclaimed,&tx_reclaimed)||
        rx_reclaimed!=0||tx_reclaimed!=1||rte_ring_count(tx_ring)!=0||
        ker_generation_admit(r,&id0,pidfds[0]))FAIL_CHILDREN();
    atomic_store_explicit(&c->stage,7,memory_order_release);
    if(parent_wait_stage(c,8,pids,2)||parent_wait_gen0_ready(c,pids,2))FAIL_CHILDREN();
    if(ker_generation_unregister(r,&id1)||ker_generation_unregister(r,&id1))FAIL_CHILDREN();
    struct rte_ring*stable=rte_ring_lookup("drain_rx_p0_q0_g1");if(!stable)FAIL_CHILDREN();
    if(rte_ring_count(stable)!=1)FAIL_CHILDREN();
    struct rte_mbuf*held=NULL;
    if(ker_generation_rx_dequeue(r,&id1,0,0,&held)!=-EINVAL||held)FAIL_CHILDREN();
    if(ker_generation_admit(r,&id1,pidfds[1]))FAIL_CHILDREN();
    if(rte_ring_lookup("drain_rx_p0_q0_g1")!=stable)FAIL_CHILDREN();
    atomic_store_explicit(&c->stage,9,memory_order_release);
    if(parent_wait_stage(c,12,pids,2))FAIL_CHILDREN();
    if(parent_wait_stage(c,13,pids,2))FAIL_CHILDREN();
    int status=0;
    if(wait_child_bounded(pids[0],&status)||!WIFEXITED(status)||WEXITSTATUS(status))FAIL_CHILDREN();
    if(ker_generation_reap_dead(r,&id0))FAIL_CHILDREN();
    struct rte_ring *reaper_tx=rte_ring_lookup("drain_tx_p0_q0_g0");
    if(!reaper_tx||rte_ring_count(reaper_tx)!=1)FAIL_CHILDREN();
    close(pidfds[0]);pidfds[0]=-1;pids[0]=-1;
    if(rte_ring_lookup("drain_rx_p0_q0_g1")!=stable||rte_ring_count(stable)!=1)FAIL_CHILDREN();
    if(kill(pids[1],SIGKILL)||wait_child_bounded(pids[1],&status)||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL)FAIL_CHILDREN();
    unsigned in_use_before_failed_reap=rte_mempool_in_use_count(pool);
    uint64_t tx_drop_before_failed_reap=0,tx_drop_after_failed_reap=0;
    struct rte_mbuf *expected_tx=NULL,*expected_rx=NULL;
    if(ker_generation_test_tx_drop_count(r,0,0,0,&tx_drop_before_failed_reap)||
        rte_ring_count(reaper_tx)!=1||rte_ring_count(stable)!=1||
        rte_ring_dequeue(reaper_tx,(void **)&expected_tx)||!expected_tx||
        rte_pktmbuf_mtod(expected_tx,uint8_t*)[0]!=0x46||rte_ring_enqueue(reaper_tx,expected_tx)||
        rte_ring_dequeue(stable,(void **)&expected_rx)||!expected_rx||
        rte_pktmbuf_mtod(expected_rx,uint8_t*)[0]!=0x55||rte_ring_enqueue(stable,expected_rx))FAIL_CHILDREN();
    ker_generation_test_corrupt_next_reap();
    if(ker_generation_reap_dead(r,&id1)!=-EUCLEAN||
        rte_mempool_in_use_count(pool)!=in_use_before_failed_reap||
        rte_ring_count(reaper_tx)!=1||rte_ring_count(stable)!=1||
        ker_generation_test_tx_drop_count(r,0,0,0,&tx_drop_after_failed_reap)||
        tx_drop_after_failed_reap!=tx_drop_before_failed_reap)FAIL_CHILDREN();
    struct rte_mbuf *retained=NULL;
    if(rte_ring_dequeue(reaper_tx,(void **)&retained)||retained!=expected_tx||
        rte_pktmbuf_mtod(retained,uint8_t*)[0]!=0x46||rte_ring_enqueue(reaper_tx,retained))FAIL_CHILDREN();
    retained=NULL;
    if(rte_ring_dequeue(stable,(void **)&retained)||retained!=expected_rx||
        rte_pktmbuf_mtod(retained,uint8_t*)[0]!=0x55||rte_ring_enqueue(stable,retained))FAIL_CHILDREN();
    ker_generation_test_restore_reap_corruption();
    if(ker_generation_reap_dead(r,&id1))FAIL_CHILDREN();
    close(pidfds[1]);pidfds[1]=-1;pids[1]=-1;
    if(rte_ring_count(stable)!=0||rte_ring_count(reaper_tx)!=0||
        atomic_load(&c->failed)||rte_mempool_in_use_count(pool)!=0)FAIL_CHILDREN();
    pids[0]=fork();if(pids[0]<0)FAIL_CHILDREN();
    if(!pids[0]){execl(exe,exe,"--no-pci",file_prefix,"--proc-type=secondary","--","r",(char*)NULL);_Exit(127);}
    pidfds[0]=syscall(SYS_pidfd_open,pids[0],0);if(pidfds[0]<0)FAIL_CHILDREN();
    if(parent_wait_stage(c,15,pids,1))FAIL_CHILDREN();
    struct ker_generation_identity recycled={.session=TEST_SESSION,.epoch=9,.slot=3,.generation=1,.process=0,.pid=(uint32_t)pids[0]};
    if(ker_generation_admit(r,&recycled,pidfds[0]))FAIL_CHILDREN();
    atomic_store_explicit(&c->stage,16,memory_order_release);
    if(parent_wait_stage(c,17,pids,1))FAIL_CHILDREN();
    if(wait_child_bounded(pids[0],&status)||!WIFEXITED(status)||WEXITSTATUS(status))FAIL_CHILDREN();
    if(ker_generation_reap_dead(r,&recycled))FAIL_CHILDREN();
    close(pidfds[0]);pidfds[0]=-1;pids[0]=-1;
    struct ker_generation_ring_stats stats;
    if(run_dequeue_crash_window(r,pool,file_prefix,exe,"live")||
        run_dequeue_crash_window(r,pool,file_prefix,exe,"tx-live")||
        run_dequeue_crash_window(r,pool,file_prefix,exe,"enqueue")||
        run_dequeue_crash_window(r,pool,file_prefix,exe,"pre")||
        run_dequeue_crash_window(r,pool,file_prefix,exe,"cas")||
        run_dead_producer_tx(r,pool,file_prefix,exe)||
        run_packet_death_case(r,pool,file_prefix,exe,1)||
        run_packet_death_case(r,pool,file_prefix,exe,2)||
        run_packet_death_case(r,pool,file_prefix,exe,3)||
        run_packet_death_case(r,pool,file_prefix,exe,4)||
        run_packet_death_case(r,pool,file_prefix,exe,5)||
        run_packet_death_case(r,pool,file_prefix,exe,6)||
        run_packet_death_case(r,pool,file_prefix,exe,7)||
        run_packet_death_case(r,pool,file_prefix,exe,8))FAIL_CHILDREN();
    uint32_t final_packet_pool_in_use=ker_generation_packet_pool_in_use(r);
    unsigned final_message_pool_in_use=rte_mempool_in_use_count(pool);
    if(atomic_load(&c->failed)||final_message_pool_in_use!=0||final_packet_pool_in_use!=0||
        ker_generation_rings_stats(r,&stats)||stats.tx_full!=0||stats.packet_full!=1||stats.packet_drop!=1||stats.tx_drop!=4||
        stats.rx_full!=1||stats.tx_peak<2||stats.rx_peak<KER_GENERATION_RING_CAPACITY)
        FAIL_CHILDREN();
    printf("NR19_PACKET_LEASE_FINAL_STATS tx_full=%llu rx_full=%llu tx_drop=%llu packet_full=%llu packet_drop=%llu tx_peak=%u rx_peak=%u message_pool_in_use=%u packet_pool_in_use=%u\n",
        (unsigned long long)stats.tx_full,(unsigned long long)stats.rx_full,
        (unsigned long long)stats.tx_drop,(unsigned long long)stats.packet_full,
        (unsigned long long)stats.packet_drop,stats.tx_peak,stats.rx_peak,
        final_message_pool_in_use,final_packet_pool_in_use);
    if(ker_generation_rings_destroy(r))FAIL_CHILDREN();
    rte_memzone_free(mz);rte_mempool_free(pool);
    puts("NR19 two-secondary ring contract passed");return 0;
#undef FAIL_CHILDREN
}
int main(int argc,char**argv)
{
    if(argc<2)return 2;
    char mode[32];snprintf(mode,sizeof(mode),"%s",argv[argc-1]);
    int consumed=rte_eal_init(argc,argv);if(consumed<0)return 77;
    int rc;
    if(!strcmp(mode,"primary")){
        const char*prefix=NULL;for(int i=1;i<argc;i++)if(!strncmp(argv[i],"--file-prefix=",14))prefix=argv[i]+14;
        if(!prefix)rc=2;else{char exe[PATH_MAX];if(!realpath(argv[0],exe))rc=2;else rc=primary(prefix,exe);}
    }else if(!strcmp(mode,"0")||!strcmp(mode,"1"))rc=secondary((unsigned)atoi(mode),0);
    else if(!strcmp(mode,"r"))rc=secondary(1,1);
    else if(!strncmp(mode,"packet-worker-",14))rc=secondary_packet_worker((unsigned)atoi(mode+14));
    else if(!strcmp(mode,"producer-enqueue")||!strcmp(mode,"producer-pre")||!strcmp(mode,"producer-pre-tx")||
        !strcmp(mode,"producer-tx-live")||!strcmp(mode,"dequeue-tx-live")||
        !strcmp(mode,"producer-tx-retain")||!strcmp(mode,"consumer-tx-retain")||
        !strcmp(mode,"dequeue-pre")||!strcmp(mode,"dequeue-pre-live")||!strcmp(mode,"producer-cas")||
        !strcmp(mode,"dequeue-cas")||!strcmp(mode,"standby"))rc=secondary_dequeue_crash(mode);
    else rc=2;
    rte_eal_cleanup();return rc;
}
