/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "session-generation-rings.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <sched.h>
#include <time.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include <rte_memzone.h>
#include <rte_errno.h>
#include <rte_spinlock.h>

#define DIRECTORY_MAGIC UINT64_C(0x4b455247524e4731)
#define DIRECTORY_VERSION 5U
#define JOURNAL_MULTIPLIER 2U
#define DIRECTORY_NAME "ker_gen_ring_directory"
enum journal_state { JOURNAL_FREE, JOURNAL_RESERVED, JOURNAL_PREPARED, JOURNAL_QUEUED,
    JOURNAL_DEQUEUEING, JOURNAL_INFLIGHT, JOURNAL_RELEASING,
    JOURNAL_PACKET_WRITING, JOURNAL_PACKET_COMMITTING,
    JOURNAL_PACKET_PMD_ACCEPTED, JOURNAL_PACKET_WIRE_PENDING };

struct journal_entry {
    _Atomic unsigned state;
    struct rte_mbuf *packet;
    struct ker_generation_identity owner;
    struct ker_generation_identity producer;
    struct ker_generation_identity consumer;
    uint8_t direction;
    uint8_t actor_generation, ring_generation;
    uint8_t seen;
    uint8_t dedicated_packet;
    uint64_t lease_id;
    uint32_t ring_slot;
};
struct ring_directory {
    uint64_t magic, session;
    uint32_t version, ports, queues, capacity, journal_count;
    _Atomic unsigned ready;
    rte_spinlock_t lock;
    char pool_name[RTE_MEMPOOL_NAMESIZE];
    uint32_t pool_size, pool_elt_size;
    char packet_pool_name[RTE_MEMPOOL_NAMESIZE];
    uint32_t packet_pool_size, packet_pool_elt_size, packet_pool_data_room, packet_pool_headroom;
    uint32_t packet_object_count;
    uint64_t packet_object_table_identity, packet_pool_tag;
};
struct ring_stats_shared {
    _Atomic uint64_t rx_full, tx_full, tx_drop, packet_drop, packet_full;
    _Atomic uint32_t rx_peak, tx_peak;
};
struct ker_generation_rings {
    struct ring_directory *directory;
    size_t directory_size;
    struct rte_ring **rx;
    struct rte_ring **tx;
    uint16_t ports, queues;
    uint64_t session;
    int primary;
    int pidfd[KER_GENERATION_RING_GENERATIONS];
    struct ker_generation_identity registered[KER_GENERATION_RING_GENERATIONS];
    struct ring_stats_shared *stats;
    struct ker_generation_identity *identity;
    _Atomic unsigned char *admitted;
    _Atomic uint32_t *active;
    _Atomic unsigned *gate;
    struct journal_entry *journal;
    uintptr_t *packet_object_table;
    struct rte_mempool *pool;
    struct rte_mempool *packet_pool;
    struct rte_mbuf **objects;
    uint32_t object_count, packet_object_base, packet_object_count;
};

#define KER_GENERATION_PACKET_POOL_PREFIX "ker_gp_"
#define KER_GENERATION_PACKET_MARGIN 32U /* four slots * two generations * four processes */
static size_t coordinates(uint16_t ports, uint16_t queues);

static int packet_pool_name(char *name, size_t size, uint64_t session)
{
    int n=snprintf(name,size,KER_GENERATION_PACKET_POOL_PREFIX "%016llx",
        (unsigned long long)session);
    return n<0||(size_t)n>=size?-ENAMETOOLONG:0;
}

static int packet_pool_objects(uint16_t ports,uint16_t queues,uint32_t *count)
{
    size_t rings=coordinates(ports,queues), resident=rings*KER_GENERATION_RING_CAPACITY;
    if(rings && resident/rings!=KER_GENERATION_RING_CAPACITY)return -EOVERFLOW;
    if(resident>UINT32_MAX-KER_GENERATION_PACKET_MARGIN)return -EOVERFLOW;
    *count=(uint32_t)resident+KER_GENERATION_PACKET_MARGIN;
    return *count?0:-EOVERFLOW;
}

static uint64_t packet_table_identity(const uintptr_t *table,uint32_t count)
{
    uint64_t hash=UINT64_C(1469598103934665603);
    for(uint32_t i=0;i<count;i++){
        uint64_t value=(uint64_t)table[i];
        for(unsigned byte=0;byte<sizeof(value);byte++){
            hash^=(uint8_t)(value>>(byte*8));hash*=UINT64_C(1099511628211);
        }
    }
    return hash?hash:1;
}

static uint64_t packet_pool_tag(uint64_t session,uint64_t table_identity)
{
    uint64_t tag=table_identity^session^UINT64_C(0xa09f57a11e5e2d31);
    return tag?tag:UINT64_C(1);
}

static int identity_valid(const struct ker_generation_rings *r,const struct ker_generation_identity *id);
static int same_identity(const struct ker_generation_identity *a,const struct ker_generation_identity *b);
static size_t full_index(const struct ker_generation_rings *r,uint16_t p,uint16_t q,uint32_t g);
#ifdef KER_SESSION_TEST_HOOKS
static _Atomic unsigned test_hold_next_dequeue;
static _Atomic unsigned test_corrupt_next_detach;
static _Atomic unsigned test_corrupt_next_reap;
static struct journal_entry *test_reap_corrupt_entry;
static uint32_t test_reap_original_ring_slot;
static _Atomic unsigned *test_ring_remove_ready;
static _Atomic unsigned *test_ring_remove_release;
static _Atomic unsigned *test_dequeue_cas_ready;
static _Atomic unsigned *test_enqueue_prepare_ready;
void ker_generation_test_hold_next_dequeue(void)
{ atomic_store_explicit(&test_hold_next_dequeue,1,memory_order_release); }
void ker_generation_test_corrupt_next_detach(void)
{ atomic_store_explicit(&test_corrupt_next_detach,1,memory_order_release); }
void ker_generation_test_corrupt_next_reap(void)
{ atomic_store_explicit(&test_corrupt_next_reap,1,memory_order_release); }
void ker_generation_test_hold_after_ring_remove(_Atomic unsigned *ready,_Atomic unsigned *release)
{ test_ring_remove_ready=ready;test_ring_remove_release=release; }
void ker_generation_test_hold_after_dequeue_cas(_Atomic unsigned *ready)
{ test_dequeue_cas_ready=ready; }
void ker_generation_test_hold_after_enqueue_prepare(_Atomic unsigned *ready)
{ test_enqueue_prepare_ready=ready; }
static void test_pause_at_transition(_Atomic unsigned **ready,_Atomic unsigned **release)
{
    if(!*ready)return;
    atomic_store_explicit(*ready,1,memory_order_release);
    const struct timespec nap={.tv_nsec=1000000};
    while(!release||!*release||!atomic_load_explicit(*release,memory_order_acquire))nanosleep(&nap,NULL);
    *ready=NULL;*release=NULL;
}
int ker_generation_test_corrupt_late_queued_rx(struct ker_generation_rings *r,
    const struct ker_generation_identity *owner,uint32_t after_ring_slot)
{
    if(!r||!r->primary||!identity_valid(r,owner)||test_reap_corrupt_entry)return -EINVAL;
    for(uint32_t i=0;i<r->directory->journal_count;i++){
        struct journal_entry *j=&r->journal[i];
        if(atomic_load_explicit(&j->state,memory_order_acquire)==JOURNAL_QUEUED&&
            !j->direction&&j->ring_slot>after_ring_slot&&same_identity(&j->owner,owner)){
            test_reap_corrupt_entry=j;test_reap_original_ring_slot=j->ring_slot;j->ring_slot++;
            return 0;
        }
    }
    return -ENOENT;
}
void ker_generation_test_restore_reap_corruption(void)
{
    if(test_reap_corrupt_entry){
        test_reap_corrupt_entry->ring_slot=test_reap_original_ring_slot;
        test_reap_corrupt_entry=NULL;
    }
}
int ker_generation_test_tx_drop_count(struct ker_generation_rings *r,uint16_t p,uint16_t q,
    uint32_t g,uint64_t *count)
{
    if(!r||!r->primary||!count||p>=r->ports||q>=r->queues||g>=2)return -EINVAL;
    *count=atomic_load_explicit(&r->stats[full_index(r,p,q,g)].tx_drop,memory_order_relaxed);
    return 0;
}
static void test_hold_dequeue_lease(void)
{
    if (!atomic_exchange_explicit(&test_hold_next_dequeue,0,memory_order_acq_rel)) return;
    static const char marker[]="KER_GENERATION_ACTIVE_DEQUEUE_HELD {}\n";
    (void)write(STDOUT_FILENO,marker,sizeof(marker)-1);
    const struct timespec nap={.tv_nsec=1000000};
    for (;;) nanosleep(&nap,NULL);
}
#endif
struct object_registry_builder {
    struct rte_mbuf **objects;
    uint32_t capacity, count;
    bool overflow;
};
static void remember_mbuf_object(struct rte_mempool *pool, void *opaque, void *object, unsigned index)
{
    (void)pool;
    (void)index;
    struct object_registry_builder *builder=opaque;
    if(builder->count>=builder->capacity){builder->overflow=true;return;}
    builder->objects[builder->count++]=object;
}
static int known_pool_object(const struct ker_generation_rings *r,const struct rte_mbuf *object)
{
    for(uint32_t i=0;i<r->object_count;i++)if(r->objects[i]==object)return 1;
    return 0;
}
static int pool_object_index(const struct ker_generation_rings *r,const struct rte_mbuf *object,uint32_t *index)
{
    for(uint32_t i=0;i<r->object_count;i++)if(r->objects[i]==object){*index=i;return 1;}
    return 0;
}
static int packet_claim_chain(const struct ker_generation_rings *r,const struct rte_mbuf *m,
    unsigned char *claimed)
{
    if(!m||!known_pool_object(r,m)||(m->pool!=r->pool&&m->pool!=r->packet_pool)||
        !m->nb_segs||m->nb_segs>r->object_count)return 0;
    const struct rte_mbuf *segment=m;
    uint64_t total=0;
    for(uint16_t i=0;i<m->nb_segs;i++){
        uint32_t index;
        if(!pool_object_index(r,segment,&index)||claimed[index])return 0;
        claimed[index]=1;
        if(segment->pool!=m->pool||rte_mbuf_refcnt_read(segment)!=1||
            (segment->ol_flags&(RTE_MBUF_F_EXTERNAL|RTE_MBUF_F_INDIRECT))||
            !segment->buf_addr||segment->data_off>segment->buf_len||
            segment->data_len>segment->buf_len-segment->data_off)return 0;
        total+=segment->data_len;
        if(total>UINT32_MAX)return 0;
        segment=segment->next;
    }
    return !segment&&total==m->pkt_len;
}

static size_t coordinates(uint16_t ports, uint16_t queues)
{ return (size_t)ports * queues * KER_GENERATION_RING_GENERATIONS; }
static size_t coord_index(const struct ker_generation_rings *r, uint16_t p, uint16_t q, uint32_t g)
{ return ((size_t)p * r->queues + q) * KER_GENERATION_RING_GENERATIONS + g; }
static size_t ring_index(const struct ker_generation_rings *r, uint16_t p, uint16_t q, uint32_t g)
{ return coord_index(r, p, q, g); }
static size_t ring_count(const struct ker_generation_rings *r)
{ return coordinates(r->ports, r->queues); }
static size_t full_index(const struct ker_generation_rings *r, uint16_t p, uint16_t q, uint32_t g)
{ return coord_index(r, p, q, g); }
static void peak_observe(_Atomic uint32_t *peak, unsigned observed, unsigned capacity)
{
    if (observed > capacity) observed = capacity;
    uint32_t old = atomic_load_explicit(peak, memory_order_relaxed);
    while (old < observed && !atomic_compare_exchange_weak_explicit(peak, &old, observed,
            memory_order_relaxed, memory_order_relaxed)) {}
}
static int identity_valid(const struct ker_generation_rings *r, const struct ker_generation_identity *id)
{ return id && id->session == r->session && id->slot < 4 && id->generation < 2 && id->process < 4 && id->epoch && id->pid; }
static int same_identity(const struct ker_generation_identity *a, const struct ker_generation_identity *b)
{ return a->session == b->session && a->epoch == b->epoch && a->slot == b->slot && a->generation == b->generation && a->process == b->process && a->pid == b->pid; }
#define ALIGN_UP(v, a) (((v) + ((a) - 1)) & ~((a) - 1))
static size_t layout_size(uint16_t ports, uint16_t queues, uint32_t journal_count,
    uint32_t packet_object_count)
{
    size_t n = coordinates(ports, queues), j = journal_count;
    if (n > SIZE_MAX / sizeof(struct ring_stats_shared) || n > SIZE_MAX / sizeof(struct ker_generation_identity) ||
        n > SIZE_MAX / sizeof(_Atomic unsigned char) || j > SIZE_MAX / sizeof(struct journal_entry) ||
        packet_object_count>SIZE_MAX/sizeof(uintptr_t)) return 0;
    size_t off = ALIGN_UP(sizeof(struct ring_directory), _Alignof(struct ring_stats_shared));
    off += n * sizeof(struct ring_stats_shared); off = ALIGN_UP(off, _Alignof(struct ker_generation_identity));
    off += n * sizeof(struct ker_generation_identity); off += n * sizeof(_Atomic unsigned char);
    off = ALIGN_UP(off, _Alignof(_Atomic uint32_t)); off += 4 * sizeof(_Atomic uint32_t);
    off = ALIGN_UP(off, _Alignof(_Atomic unsigned)); off += 2 * sizeof(_Atomic unsigned);
    off = ALIGN_UP(off, _Alignof(struct journal_entry));
    if(j>(SIZE_MAX-off)/sizeof(struct journal_entry))return 0;
    off+=j*sizeof(struct journal_entry);off=ALIGN_UP(off,_Alignof(uintptr_t));
    if(packet_object_count>(SIZE_MAX-off)/sizeof(uintptr_t))return 0;
    return off+(size_t)packet_object_count*sizeof(uintptr_t);
}
static int ring_name(char *name, size_t size, const char *dir, uint16_t p, uint16_t q, uint32_t g)
{
    int n = snprintf(name, size, "drain_%s_p%u_q%u_g%u", dir, p, q, g);
    return n < 0 || (size_t)n >= size ? -ENAMETOOLONG : 0;
}
static void directory_pointers(struct ker_generation_rings *r)
{
    struct ring_directory *d=r->directory;size_t n=coordinates(d->ports,d->queues);
    size_t off=ALIGN_UP(sizeof(*d),_Alignof(struct ring_stats_shared));
    r->stats=(struct ring_stats_shared*)((char*)d+off);off+=n*sizeof(*r->stats);
    off=ALIGN_UP(off,_Alignof(struct ker_generation_identity));
    r->identity=(struct ker_generation_identity*)((char*)d+off);off+=n*sizeof(*r->identity);
    r->admitted=(_Atomic unsigned char*)((char*)d+off);off+=n*sizeof(*r->admitted);
    off=ALIGN_UP(off,_Alignof(_Atomic uint32_t));r->active=(_Atomic uint32_t*)((char*)d+off);off+=4*sizeof(*r->active);
    off=ALIGN_UP(off,_Alignof(_Atomic unsigned));r->gate=(_Atomic unsigned*)((char*)d+off);off+=2*sizeof(*r->gate);
    off=ALIGN_UP(off,_Alignof(struct journal_entry));r->journal=(struct journal_entry*)((char*)d+off);
    off+=(size_t)d->journal_count*sizeof(*r->journal);off=ALIGN_UP(off,_Alignof(uintptr_t));
    r->packet_object_table=(uintptr_t*)((char*)d+off);
}
static int unregister_wait_active(struct ker_generation_rings *r,uint32_t generation)
{
    struct timespec until,now,nap={.tv_nsec=1000000};
    if(clock_gettime(CLOCK_MONOTONIC,&until))return -errno;
    until.tv_sec+=1;
    for(;;){
        bool busy=false;
        for(unsigned actor=0;actor<2;actor++)for(unsigned ring=0;ring<2;ring++)
            if(actor==generation||ring==generation)
                busy|=atomic_load_explicit(&r->active[actor*2+ring],memory_order_acquire)!=0;
        if(!busy)return 0;
        if(clock_gettime(CLOCK_MONOTONIC,&now))return -errno;
        if(now.tv_sec>until.tv_sec||(now.tv_sec==until.tv_sec&&now.tv_nsec>=until.tv_nsec))return -EBUSY;
        nanosleep(&nap,NULL);
    }
}
static const struct rte_memzone *lookup_directory(void)
{
    return rte_memzone_lookup(DIRECTORY_NAME);
}
#ifdef KER_SESSION_TEST_HOOKS
uint32_t ker_generation_packet_pool_in_use(struct ker_generation_rings *r)
{ return r&&r->primary&&r->packet_pool?rte_mempool_in_use_count(r->packet_pool):UINT32_MAX; }
int ker_generation_test_packet_table_duplicate(struct ker_generation_rings *r,
    uint32_t index,uint32_t duplicate_index,uintptr_t *original)
{
    if(!r||!r->primary||!original||index>=r->packet_object_count||
        duplicate_index>=r->packet_object_count||index==duplicate_index)return -EINVAL;
    *original=r->packet_object_table[index];
    r->packet_object_table[index]=r->packet_object_table[duplicate_index];
    return 0;
}
int ker_generation_test_packet_table_restore(struct ker_generation_rings *r,
    uint32_t index,uintptr_t original)
{
    if(!r||!r->primary||index>=r->packet_object_count||!original)return -EINVAL;
    r->packet_object_table[index]=original;return 0;
}
int ker_generation_rings_test_directory_present(void)
{
    int saved_errno = rte_errno;
    int present = lookup_directory() != NULL;
    rte_errno = saved_errno;
    return present;
}
#endif

static int attach_common(uint64_t session, uint16_t ports, uint16_t queues,
    struct rte_mempool *pool, struct rte_mempool *packet_pool,
    struct ker_generation_rings **out, int primary)
{
    if (!out || !session || !ports || !queues || !pool || !packet_pool || pool==packet_pool ||
        ports > 256 || queues > 256) return -EINVAL;
    *out = NULL;
    uint32_t expected_packet_objects;
    if(packet_pool_objects(ports,queues,&expected_packet_objects)||
        packet_pool->size!=expected_packet_objects)return -EPROTO;
    size_t n=coordinates(ports,queues);
    if(n>SIZE_MAX/(KER_GENERATION_RING_CAPACITY*JOURNAL_MULTIPLIER))return -EOVERFLOW;
    size_t ring_journal=n*KER_GENERATION_RING_CAPACITY*JOURNAL_MULTIPLIER;
    size_t object_journal=(size_t)pool->size+packet_pool->size;
    size_t journal_capacity=ring_journal>object_journal?ring_journal:object_journal;
    if(journal_capacity>UINT32_MAX)return -EOVERFLOW;
    size_t bytes = layout_size(ports, queues,(uint32_t)journal_capacity,packet_pool->size);
    if (!bytes) return -EOVERFLOW;
    struct ker_generation_rings *r = calloc(1, sizeof(*r));
    if (!r) return -ENOMEM;
    r->rx = calloc(n, sizeof(*r->rx)); r->tx = calloc(n, sizeof(*r->tx));
    if (!r->rx || !r->tx) { free(r->rx); free(r->tx); free(r); return -ENOMEM; }
    if (pool->size>UINT32_MAX-packet_pool->size) { free(r->rx);free(r->tx);free(r);return -EOVERFLOW; }
    uint32_t object_capacity=pool->size+packet_pool->size;
    r->objects=calloc(object_capacity,sizeof(*r->objects));
    if(!r->objects){free(r->rx);free(r->tx);free(r);return -ENOMEM;}
    struct object_registry_builder builder={.objects=r->objects,.capacity=pool->size};
    if(rte_mempool_obj_iter(pool,remember_mbuf_object,&builder)!=pool->size||
        builder.overflow||builder.count!=pool->size){free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;}
    builder.capacity=object_capacity;
    if(rte_mempool_obj_iter(packet_pool,remember_mbuf_object,&builder)!=packet_pool->size||
        builder.overflow||builder.count!=object_capacity){free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;}
    const struct rte_memzone *mz = primary ? rte_memzone_reserve(DIRECTORY_NAME, bytes, SOCKET_ID_ANY, 0) :
        lookup_directory();
    if (!mz) { int error=rte_errno? -rte_errno:-ENOENT;free(r->objects);free(r->rx); free(r->tx); free(r); return error; }
    if (!primary && mz->len < bytes) { fprintf(stderr,"generation rings: directory too short got=%zu expected-at-least=%zu\n",(size_t)mz->len,bytes);free(r->objects);free(r->rx); free(r->tx); free(r); return -EPROTO; }
    r->directory = mz->addr; r->directory_size = bytes; r->ports = ports; r->queues = queues;
    r->session = session; r->primary = primary;
    r->pool = pool; r->packet_pool=packet_pool; r->object_count=builder.count;
    r->packet_object_base=pool->size;r->packet_object_count=packet_pool->size;
    r->pidfd[0] = r->pidfd[1] = -1;
    if (primary) {
        memset(r->directory, 0, bytes);
        r->directory->magic = DIRECTORY_MAGIC; r->directory->version = DIRECTORY_VERSION;
        r->directory->session = session; r->directory->ports = ports; r->directory->queues = queues;
        r->directory->capacity = KER_GENERATION_RING_CAPACITY;
        r->directory->journal_count = (uint32_t)journal_capacity;
        snprintf(r->directory->pool_name,sizeof(r->directory->pool_name),"%s",pool->name);
        r->directory->pool_size=pool->size;r->directory->pool_elt_size=pool->elt_size;
        snprintf(r->directory->packet_pool_name,sizeof(r->directory->packet_pool_name),"%s",packet_pool->name);
        r->directory->packet_pool_size=packet_pool->size;r->directory->packet_pool_elt_size=packet_pool->elt_size;
        r->directory->packet_pool_data_room=rte_pktmbuf_data_room_size(packet_pool);
        r->directory->packet_pool_headroom=RTE_PKTMBUF_HEADROOM;
        r->directory->packet_object_count=packet_pool->size;
        directory_pointers(r); rte_spinlock_init(&r->directory->lock);
        for(uint32_t i=0;i<packet_pool->size;i++)
            r->packet_object_table[i]=(uintptr_t)r->objects[r->packet_object_base+i];
        r->directory->packet_object_table_identity=
            packet_table_identity(r->packet_object_table,r->directory->packet_object_count);
        r->directory->packet_pool_tag=packet_pool_tag(session,
            r->directory->packet_object_table_identity);
        atomic_init(&r->directory->ready, 0);
        for (size_t i = 0; i < n; ++i) {
            atomic_init(&r->stats[i].rx_full, 0); atomic_init(&r->stats[i].tx_full, 0);
            atomic_init(&r->stats[i].tx_drop, 0); atomic_init(&r->stats[i].rx_peak, 0);
            atomic_init(&r->stats[i].packet_drop,0);
            atomic_init(&r->stats[i].packet_full,0);
            atomic_init(&r->stats[i].tx_peak, 0); atomic_init(&r->admitted[i], 0);
        }
        for (unsigned i=0;i<4;i++) atomic_init(&r->active[i],0);
        for (unsigned i=0;i<2;i++) atomic_init(&r->gate[i],0);
        for (uint32_t i = 0; i < r->directory->journal_count; ++i)
            atomic_init(&r->journal[i].state, JOURNAL_FREE);
    }
    if (primary && (!atomic_is_lock_free(&r->directory->ready) ||
        !atomic_is_lock_free(&r->stats[0].rx_full) || !atomic_is_lock_free(&r->stats[0].tx_full) ||
        !atomic_is_lock_free(&r->stats[0].tx_drop) || !atomic_is_lock_free(&r->stats[0].rx_peak) ||
        !atomic_is_lock_free(&r->stats[0].packet_drop) ||
        !atomic_is_lock_free(&r->stats[0].packet_full) ||
        !atomic_is_lock_free(&r->stats[0].tx_peak) || !atomic_is_lock_free(&r->admitted[0]) ||
        !atomic_is_lock_free(&r->active[0]) || !atomic_is_lock_free(&r->gate[0]) ||
        !atomic_is_lock_free(&r->journal[0].state))) {
        free(r->objects);free(r->rx); free(r->tx); free(r); return -EOPNOTSUPP;
    }
    if (r->directory->magic != DIRECTORY_MAGIC || r->directory->version != DIRECTORY_VERSION ||
        r->directory->session != session || r->directory->ports != ports || r->directory->queues != queues ||
        r->directory->capacity != KER_GENERATION_RING_CAPACITY ||
        r->directory->journal_count!=(uint32_t)journal_capacity ||
        strcmp(r->directory->pool_name,pool->name) || r->directory->pool_size!=pool->size ||
        r->directory->pool_elt_size!=pool->elt_size || rte_mempool_lookup(r->directory->pool_name)!=pool ||
        strcmp(r->directory->packet_pool_name,packet_pool->name) ||
        r->directory->packet_pool_size!=packet_pool->size ||
        r->directory->packet_pool_elt_size!=packet_pool->elt_size ||
        r->directory->packet_pool_data_room!=rte_pktmbuf_data_room_size(packet_pool) ||
        r->directory->packet_pool_headroom!=RTE_PKTMBUF_HEADROOM ||
        r->directory->packet_object_count!=packet_pool->size ||
        rte_mempool_lookup(r->directory->packet_pool_name)!=packet_pool ||
        (!atomic_load_explicit(&r->directory->ready, memory_order_acquire) && !primary)) {
        fprintf(stderr,"generation rings: directory header mismatch magic=%llx version=%u session=%llx ports=%u queues=%u cap=%u ready=%u\n",
            (unsigned long long)r->directory->magic,r->directory->version,(unsigned long long)r->directory->session,
            r->directory->ports,r->directory->queues,r->directory->capacity,atomic_load(&r->directory->ready));
        free(r->objects);free(r->rx); free(r->tx); free(r); return -EPROTO;
    }
    if(!primary)directory_pointers(r);
    size_t journal_end=(size_t)((char*)r->journal-(char*)r->directory)+
        (size_t)r->directory->journal_count*sizeof(*r->journal);
    size_t packet_table_end=(size_t)((char*)r->packet_object_table-(char*)r->directory)+
        (size_t)packet_pool->size*sizeof(*r->packet_object_table);
    if(journal_end>mz->len||packet_table_end>mz->len){free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;}
    struct rte_mbuf **canonical=calloc(packet_pool->size,sizeof(*canonical));
    if(!canonical){free(r->objects);free(r->rx);free(r->tx);free(r);return -ENOMEM;}
    int table_valid=1;
    for(uint32_t i=0;i<packet_pool->size&&table_valid;i++){
        uintptr_t published=r->packet_object_table[i];
        if(!published){table_valid=0;break;}
        for(uint32_t k=0;k<i;k++)if(r->packet_object_table[k]==published){table_valid=0;break;}
        unsigned found=0;
        for(uint32_t j=0;j<packet_pool->size;j++)
            if((uintptr_t)r->objects[r->packet_object_base+j]==published){canonical[i]=r->objects[r->packet_object_base+j];found++;}
        if(found!=1)table_valid=0;
    }
    if(table_valid)memcpy(r->objects+r->packet_object_base,canonical,
        packet_pool->size*sizeof(*canonical));
    free(canonical);
    if(!table_valid){free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;}
    if(!r->directory->packet_object_table_identity ||
        packet_table_identity(r->packet_object_table,r->directory->packet_object_count)!=
            r->directory->packet_object_table_identity){
        free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;
    }
    if(r->directory->packet_pool_tag!=packet_pool_tag(session,
        r->directory->packet_object_table_identity)){
        free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;
    }
    char name[RTE_RING_NAMESIZE];
    int failure=-EPROTO;
    for (uint16_t p = 0; p < ports; ++p) for (uint16_t q = 0; q < queues; ++q)
        for (uint32_t g = 0; g < 2; ++g) {
            size_t i = ring_index(r, p, q, g);
            if (ring_name(name, sizeof(name), "rx", p, q, g)) {failure=-EINVAL;goto fail;}
            if (primary) r->rx[i] = rte_ring_create(name, KER_GENERATION_RING_CAPACITY, SOCKET_ID_ANY,
                RING_F_EXACT_SZ | RING_F_SC_DEQ);
            else r->rx[i] = rte_ring_lookup(name);
            if (!r->rx[i]) {fprintf(stderr,"generation rings: RX lookup/create failed: %s\n",name);failure=primary?(rte_errno?-rte_errno:-ENOMEM):-ENOENT;goto fail;}
            if (ring_name(name, sizeof(name), "tx", p, q, g)) {failure=-EINVAL;goto fail;}
            if (primary) r->tx[i] = rte_ring_create(name, KER_GENERATION_RING_CAPACITY, SOCKET_ID_ANY,
                RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
            else r->tx[i] = rte_ring_lookup(name);
            if (!r->tx[i]) {fprintf(stderr,"generation rings: TX lookup/create failed: %s\n",name);failure=primary?(rte_errno?-rte_errno:-ENOMEM):-ENOENT;goto fail;}
            if (rte_ring_get_capacity(r->rx[i]) != KER_GENERATION_RING_CAPACITY ||
                rte_ring_is_prod_single(r->rx[i]) || !rte_ring_is_cons_single(r->rx[i]) ||
                rte_ring_get_capacity(r->tx[i]) != KER_GENERATION_RING_CAPACITY ||
                !rte_ring_is_prod_single(r->tx[i]) || !rte_ring_is_cons_single(r->tx[i])) {
                fprintf(stderr,"generation rings: ring flags/capacity mismatch at p%u q%u g%u\n",p,q,g);failure=-EPROTO;goto fail;
            }
        }
    if (primary) atomic_store_explicit(&r->directory->ready, 1, memory_order_release);
    *out = r; return 0;
fail:
    /* A partial primary creation is intentionally left fail-closed. DPDK ring
     * names are process-global and freeing only part would permit stale reuse. */
    free(r->objects);free(r->rx); free(r->tx); free(r); return failure;
}
int ker_generation_rings_create(uint64_t s, uint16_t p, uint16_t q, struct rte_mempool *pool, struct ker_generation_rings **o)
{
    if (!pool || !o || !s) return -EINVAL;
    char name[RTE_MEMPOOL_NAMESIZE]; uint32_t count;
    int rc=packet_pool_name(name,sizeof(name),s); if(rc)return rc;
    if((rc=packet_pool_objects(p,q,&count)))return rc;
    struct rte_mempool *packets=rte_pktmbuf_pool_create(name,count,0,0,RTE_MBUF_DEFAULT_BUF_SIZE,SOCKET_ID_ANY);
    if(!packets)return rte_errno?-rte_errno:-ENOMEM;
    rc=attach_common(s,p,q,pool,packets,o,1);
    if(rc){
        const struct rte_memzone *mz=lookup_directory();
        const struct ring_directory *d=mz&&mz->len>=sizeof(*d)?mz->addr:NULL;
        if(!d||d->session!=s||strcmp(d->packet_pool_name,name))rte_mempool_free(packets);
    }
    return rc;
}
int ker_generation_rings_attach(uint64_t s, uint16_t p, uint16_t q, struct rte_mempool *pool, struct ker_generation_rings **o)
{
    if (!pool || !o || !s) return -EINVAL;
    char name[RTE_MEMPOOL_NAMESIZE]; int rc=packet_pool_name(name,sizeof(name),s); if(rc)return rc;
    struct rte_mempool *packets=rte_mempool_lookup(name);
    if(!packets)return rte_errno?-rte_errno:-ENOENT;
    return attach_common(s,p,q,pool,packets,o,0);
}
#ifdef KER_SESSION_TEST_HOOKS
int ker_generation_rings_test_replay(struct ker_generation_rings *original)
{
    if (!original || original->primary) return -EINVAL;
    struct ker_generation_rings *repeated = NULL;
    int result = ker_generation_rings_attach(original->session, original->ports,
        original->queues, original->pool, &repeated);
    if (result) return result;
    bool same = repeated->directory == original->directory &&
        repeated->directory_size == original->directory_size &&
        repeated->session == original->session && repeated->ports == original->ports &&
        repeated->queues == original->queues && repeated->pool == original->pool &&
        repeated->object_count == original->object_count;
    for (size_t i = 0; same && i < ring_count(original); ++i)
        same = repeated->rx[i] == original->rx[i] && repeated->tx[i] == original->tx[i];
    int detached = ker_generation_rings_detach(repeated);
    if (detached) return detached;
    return same ? 0 : -ESTALE;
}
#endif
int ker_generation_rings_detach(struct ker_generation_rings *r)
{
    if (!r || r->primary) return -EPERM;
    free(r->objects); free(r->rx); free(r->tx); free(r); return 0;
}
static int admitted(struct ker_generation_rings *r, const struct ker_generation_identity *id, uint16_t p, uint16_t q, uint32_t g)
{
    if (!identity_valid(r,id) || p >= r->ports || q >= r->queues || g >= 2 || id->generation != g) return 0;
    size_t i = coord_index(r,p,q,g);
    return atomic_load_explicit(&r->directory->ready,memory_order_acquire) &&
        atomic_load_explicit(&r->admitted[i],memory_order_acquire) &&
        same_identity(&r->identity[i],id);
}
static int operation_enter(struct ker_generation_rings *r, const struct ker_generation_identity *id,
    uint16_t p, uint16_t q, uint32_t ring_generation)
{
    if (!r || !identity_valid(r,id) || p>=r->ports || q>=r->queues || ring_generation>=2 ||
        !admitted(r,id,p,q,id->generation)) return -EINVAL;
    size_t ring=coord_index(r,p,q,ring_generation);
    if (atomic_load_explicit(&r->gate[ring_generation],memory_order_acquire)) return -EBUSY;
    if (!atomic_load_explicit(&r->admitted[ring],memory_order_acquire)) return -EHOSTDOWN;
    unsigned active_index=id->generation*2U+ring_generation;
    atomic_fetch_add_explicit(&r->active[active_index],1,memory_order_acq_rel);
    if (!admitted(r,id,p,q,id->generation) ||
        !atomic_load_explicit(&r->admitted[ring],memory_order_acquire) ||
        atomic_load_explicit(&r->gate[ring_generation],memory_order_acquire)) {
        atomic_fetch_sub_explicit(&r->active[active_index],1,memory_order_release);
        return -EHOSTDOWN;
    }
    return 0;
}
/* A TX peer consumes a producer-generation ring using its own authenticated
 * identity. Reaping the producer intentionally clears that generation's
 * admission while preserving queued packets owned by a live consumer, so
 * this path gates the producer ring but authenticates and counts only the
 * exact admitted consumer. */
static int operation_enter_tx_peer(struct ker_generation_rings *r,
    const struct ker_generation_identity *consumer,uint16_t p,uint16_t q,
    uint32_t producer_generation)
{
    if(!r||!identity_valid(r,consumer)||p>=r->ports||q>=r->queues||
        producer_generation>=2||producer_generation==consumer->generation||
        !admitted(r,consumer,p,q,consumer->generation)) return -EINVAL;
    if(atomic_load_explicit(&r->gate[producer_generation],memory_order_acquire))return -EBUSY;
    unsigned active_index=consumer->generation*2U+producer_generation;
    atomic_fetch_add_explicit(&r->active[active_index],1,memory_order_acq_rel);
    if(!admitted(r,consumer,p,q,consumer->generation)){
        atomic_fetch_sub_explicit(&r->active[active_index],1,memory_order_release);
        return -EHOSTDOWN;
    }
    if(atomic_load_explicit(&r->gate[producer_generation],memory_order_acquire)){
        atomic_fetch_sub_explicit(&r->active[active_index],1,memory_order_release);
        return -EBUSY;
    }
    return 0;
}
static void operation_leave(struct ker_generation_rings *r,
    const struct ker_generation_identity *id,uint32_t ring_generation)
{ atomic_fetch_sub_explicit(&r->active[id->generation*2U+ring_generation],1,memory_order_release); }
int ker_generation_admit(struct ker_generation_rings *r, const struct ker_generation_identity *id, int registered_pidfd)
{
    if (!r || !r->primary || !identity_valid(r,id) || registered_pidfd < 0 || !atomic_load(&r->directory->ready)) return -EINVAL;
    if (atomic_load_explicit(&r->gate[0],memory_order_acquire) ||
        atomic_load_explicit(&r->gate[1],memory_order_acquire)) return -EBUSY;
    char path[64],buf[256];
    if(snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",registered_pidfd)<0)return -EINVAL;
    int infofd=open(path,O_RDONLY|O_CLOEXEC);if(infofd<0)return -errno;
    ssize_t nr=read(infofd,buf,sizeof(buf)-1);close(infofd);if(nr<=0)return -EINVAL;buf[nr]='\0';
    char *line=strstr(buf,"Pid:");int fd_pid=-1;
    if(!line||sscanf(line+4,"%d",&fd_pid)!=1||fd_pid<0||(uint32_t)fd_pid!=id->pid)return -ESTALE;
    int owned_pidfd=fcntl(registered_pidfd,F_DUPFD_CLOEXEC,3);if(owned_pidfd<0)return -errno;
    rte_spinlock_lock(&r->directory->lock);
    if(atomic_load_explicit(&r->gate[0],memory_order_acquire) ||
        atomic_load_explicit(&r->gate[1],memory_order_acquire)){
        rte_spinlock_unlock(&r->directory->lock);close(owned_pidfd);return -EBUSY;
    }
    for (uint16_t p=0;p<r->ports;p++) for(uint16_t q=0;q<r->queues;q++) {
        size_t i=coord_index(r,p,q,id->generation);
        if (atomic_load(&r->admitted[i]) && !same_identity(&r->identity[i],id)) {
            rte_spinlock_unlock(&r->directory->lock); close(owned_pidfd); return -EBUSY;
        }
    }
    uint32_t g=id->generation;
    if (r->pidfd[g] >= 0 && !same_identity(&r->registered[g], id)) {
        for (uint32_t i=0;i<r->directory->journal_count;i++) {
            struct journal_entry *j=&r->journal[i];
            if (atomic_load(&j->state)!=JOURNAL_FREE &&
                (same_identity(&j->owner,&r->registered[g]) || same_identity(&j->producer,&r->registered[g]))) {
                rte_spinlock_unlock(&r->directory->lock); close(owned_pidfd); return -EBUSY;
            }
        }
    }
    if(r->pidfd[g]>=0&&!same_identity(&r->registered[g],id)){
        rte_spinlock_unlock(&r->directory->lock);close(owned_pidfd);return -EBUSY;
    }
    /* pidfd identity matching alone does not prove the registered process is
     * still live. Reaping clears the old registration; reject a ready pidfd
     * rather than allowing a caller to re-admit that dead identity. */
    struct pollfd liveness={.fd=owned_pidfd,.events=POLLIN};
    int live;do live=poll(&liveness,1,0);while(live<0&&errno==EINTR);
    if(live<0){int error=-errno;rte_spinlock_unlock(&r->directory->lock);close(owned_pidfd);return error;}
    if(live||(liveness.revents&(POLLIN|POLLHUP|POLLERR|POLLNVAL))){
        rte_spinlock_unlock(&r->directory->lock);close(owned_pidfd);return -ESTALE;
    }
    if(r->pidfd[g]<0){r->pidfd[g]=owned_pidfd;r->registered[g]=*id;owned_pidfd=-1;}
    for (uint16_t p=0;p<r->ports;p++) for(uint16_t q=0;q<r->queues;q++) {
        size_t i=coord_index(r,p,q,id->generation); r->identity[i]=*id;
        atomic_store_explicit(&r->admitted[i],1,memory_order_release);
    }
    rte_spinlock_unlock(&r->directory->lock);if(owned_pidfd>=0)close(owned_pidfd);return 0;
}
int ker_generation_unregister(struct ker_generation_rings *r, const struct ker_generation_identity *id)
{
    if (!r || !r->primary || !identity_valid(r,id)) return -EINVAL;
    rte_spinlock_lock(&r->directory->lock);
    for(uint16_t p=0;p<r->ports;p++) for(uint16_t q=0;q<r->queues;q++) {
        size_t i=coord_index(r,p,q,id->generation);
        if (atomic_load(&r->admitted[i]) && !same_identity(&r->identity[i],id)) {
            rte_spinlock_unlock(&r->directory->lock); return -ESTALE;
        }
    }
    for(uint16_t p=0;p<r->ports;p++) for(uint16_t q=0;q<r->queues;q++)
        atomic_store_explicit(&r->admitted[coord_index(r,p,q,id->generation)],0,memory_order_release);
    int wait_result=unregister_wait_active(r,id->generation);
    if(wait_result){rte_spinlock_unlock(&r->directory->lock);return wait_result;}
    rte_spinlock_unlock(&r->directory->lock); return 0;
}
static int packet_reclaimable(const struct ker_generation_rings *r, const struct rte_mbuf *m);
static struct journal_entry *journal_find(struct ker_generation_rings *r, struct rte_mbuf *m);
static int detach_collect(struct ker_generation_rings *r, const struct ker_generation_identity *id,
    struct rte_ring *ring, size_t slot, int tx, struct rte_mbuf **packets,
    struct journal_entry **entries, unsigned *count)
{
    *count=0;
    while (*count<KER_GENERATION_RING_CAPACITY) {
        struct rte_mbuf *m=NULL;
        if (rte_ring_dequeue(ring,(void **)&m)) break;
        packets[(*count)++]=m;
    }
    if (!rte_ring_empty(ring)) return -EUCLEAN;
    for (unsigned i=0;i<*count;i++) {
        struct rte_mbuf *m=packets[i];
        if (!known_pool_object(r,m) || !packet_reclaimable(r,m)) return -EUCLEAN;
        struct journal_entry *j=journal_find(r,m);
        if (!j || atomic_load_explicit(&j->state,memory_order_acquire)!=JOURNAL_QUEUED ||
            j->seen || j->ring_slot!=slot || j->direction!=(uint8_t)tx ||
            !(tx ? same_identity(&j->producer,id) : same_identity(&j->owner,id))) return -EUCLEAN;
        j->seen=1;
        entries[i]=j;
    }
    return 0;
}
struct detach_batch {
    struct rte_ring *ring;
    size_t slot;
    struct rte_mbuf *packets[KER_GENERATION_RING_CAPACITY];
    struct journal_entry *entries[KER_GENERATION_RING_CAPACITY];
    unsigned count;
    unsigned restored;
};
static int detach_batch_restore(struct detach_batch *batch)
{
    if (!batch->ring || batch->restored>batch->count ||
        rte_ring_free_count(batch->ring)<batch->count-batch->restored) return -EUCLEAN;
    while (batch->restored<batch->count) {
        if (rte_ring_enqueue(batch->ring,batch->packets[batch->restored])) return -EUCLEAN;
        batch->restored++;
    }
    batch->count=0;
    batch->restored=0;
    return 0;
}
static int detach_batch_validate(struct ker_generation_rings *r,
    const struct ker_generation_identity *id, struct detach_batch *batch, int tx)
{
    if (!batch->ring || !rte_ring_empty(batch->ring)) return -EUCLEAN;
    for (unsigned i=0;i<batch->count;i++) {
        struct rte_mbuf *m=batch->packets[i];
        struct journal_entry *j=batch->entries[i];
        if (!m || !j || !known_pool_object(r,m) || !packet_reclaimable(r,m) ||
            journal_find(r,m)!=j || atomic_load_explicit(&j->state,memory_order_acquire)!=JOURNAL_QUEUED ||
            !j->seen || j->ring_slot!=batch->slot || j->direction!=(uint8_t)tx ||
            !(tx ? same_identity(&j->producer,id) : same_identity(&j->owner,id))) return -EUCLEAN;
        for (unsigned previous=0;previous<i;previous++)
            if (batch->packets[previous]==m || batch->entries[previous]==j) return -EUCLEAN;
    }
    return 0;
}
static void detach_batch_clear_seen(struct detach_batch *batch)
{
    for (unsigned i=0;i<batch->count;i++)
        if (batch->entries[i]) batch->entries[i]->seen=0;
}
static void detach_batch_free(struct ker_generation_rings *r, struct detach_batch *batch, int tx)
{
    for (unsigned i=0;i<batch->count;i++) {
        struct rte_mbuf *m=batch->packets[i];
        struct journal_entry *j=batch->entries[i];
        size_t ring_slot=j->ring_slot;
        j->packet=NULL;
        j->seen=0;
        atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
        rte_pktmbuf_free(m);
        if(tx&&j->dedicated_packet)
            atomic_fetch_add_explicit(&r->stats[ring_slot].packet_drop,1,memory_order_relaxed);
        else if(tx)atomic_fetch_add_explicit(&r->stats[ring_slot].tx_drop,1,memory_order_relaxed);
    }
    batch->count=0;
}
int ker_generation_orderly_detach(struct ker_generation_rings *r,
    const struct ker_generation_identity *id,
    const struct ker_generation_cleanup_config *cleanup, int drain_tx,
    unsigned *rx_reclaimed, unsigned *tx_reclaimed)
{
    if (rx_reclaimed) *rx_reclaimed=0;
    if (tx_reclaimed) *tx_reclaimed=0;
    if (!r || !r->primary || !identity_valid(r,id) || !cleanup ||
        cleanup->version!=KER_GENERATION_CLEANUP_CONFIG_VERSION ||
        cleanup->size!=sizeof(*cleanup) || cleanup->ports!=r->ports ||
        cleanup->queues!=r->queues || cleanup->ports!=1 || !cleanup->queues || cleanup->queues>64 ||
        (drain_tx!=0 && drain_tx!=1) || !rx_reclaimed || !tx_reclaimed)
        return -EINVAL;
    uint64_t valid_mask=cleanup->queues==64 ? UINT64_MAX :
        ((UINT64_C(1)<<cleanup->queues)-1);
    if ((cleanup->rx_queue_mask&~valid_mask) || (cleanup->tx_queue_mask&~valid_mask))
        return -EINVAL;
    uint32_t g=id->generation;
    if (r->pidfd[g]<0 || !same_identity(&r->registered[g],id)) return -ESTALE;
    struct pollfd live={.fd=r->pidfd[g],.events=POLLIN};
    int ready; do ready=poll(&live,1,0); while (ready<0 && errno==EINTR);
    if (ready<0) return -errno;
    if (ready || (live.revents&(POLLERR|POLLHUP|POLLNVAL))) return -ESTALE;
    rte_spinlock_lock(&r->directory->lock);
    if (atomic_load_explicit(&r->gate[g],memory_order_acquire)) {
        rte_spinlock_unlock(&r->directory->lock); return -EBUSY;
    }
    for (uint16_t p=0;p<r->ports;p++) for(uint16_t q=0;q<r->queues;q++) {
        size_t i=coord_index(r,p,q,g);
        if (!atomic_load_explicit(&r->admitted[i],memory_order_acquire) ||
            !same_identity(&r->identity[i],id)) {
            rte_spinlock_unlock(&r->directory->lock); return -ESTALE;
        }
    }
    atomic_store_explicit(&r->gate[g],1,memory_order_release);
    for (uint16_t p=0;p<r->ports;p++) for(uint16_t q=0;q<r->queues;q++)
        atomic_store_explicit(&r->admitted[coord_index(r,p,q,g)],0,memory_order_release);
    int result=unregister_wait_active(r,g);
    if (result) { rte_spinlock_unlock(&r->directory->lock); return result; }
    struct detach_batch rx[64]={0}, tx[64]={0};
    unsigned nrx=0,ntx=0;
    for (uint16_t q=0;q<r->queues;q++) {
        if (cleanup->rx_queue_mask&(UINT64_C(1)<<q)) {
            rx[q].slot=ring_index(r,0,q,g); rx[q].ring=r->rx[rx[q].slot];
            result=detach_collect(r,id,rx[q].ring,rx[q].slot,0,
                rx[q].packets,rx[q].entries,&rx[q].count);
            if (result) goto rollback;
            nrx+=rx[q].count;
        }
        if (cleanup->tx_queue_mask&(UINT64_C(1)<<q)) {
            tx[q].slot=ring_index(r,0,q,g); tx[q].ring=r->tx[tx[q].slot];
            result=detach_collect(r,id,tx[q].ring,tx[q].slot,1,
                tx[q].packets,tx[q].entries,&tx[q].count);
            if (result) goto rollback;
            ntx+=tx[q].count;
        }
    }
#ifdef KER_SESSION_TEST_HOOKS
    if (atomic_exchange_explicit(&test_corrupt_next_detach,0,memory_order_acq_rel)) {
        struct journal_entry *selected=NULL;
        for (uint16_t q=r->queues;q>0 && !selected;) {
            q--;
            if ((cleanup->tx_queue_mask&(UINT64_C(1)<<q)) && tx[q].count)
                selected=tx[q].entries[tx[q].count-1];
            else if ((cleanup->rx_queue_mask&(UINT64_C(1)<<q)) && rx[q].count)
                selected=rx[q].entries[rx[q].count-1];
        }
        if (!selected) { result=-EUCLEAN; goto rollback; }
        selected->ring_slot++;
    }
#endif
    /* Validate every selected ring and journal batch before reclaiming the
     * first object. A later-batch error must restore all earlier dequeues. */
    for (uint16_t q=0;q<r->queues;q++) {
        if ((cleanup->rx_queue_mask&(UINT64_C(1)<<q)) &&
            (result=detach_batch_validate(r,id,&rx[q],0))) goto rollback;
        if ((cleanup->tx_queue_mask&(UINT64_C(1)<<q)) &&
            (result=detach_batch_validate(r,id,&tx[q],1))) goto rollback;
    }
    if (drain_tx) {
        for (uint16_t q=0;q<r->queues;q++)
            if (cleanup->tx_queue_mask&(UINT64_C(1)<<q)) detach_batch_free(r,&tx[q],1);
    } else {
        for (uint16_t q=0;q<r->queues;q++) if (cleanup->tx_queue_mask&(UINT64_C(1)<<q)) {
            detach_batch_clear_seen(&tx[q]);
            if (detach_batch_restore(&tx[q])) { result=-EUCLEAN; goto rollback; }
        }
    }
    for (uint16_t q=0;q<r->queues;q++) if (cleanup->rx_queue_mask&(UINT64_C(1)<<q))
        detach_batch_free(r,&rx[q],0);
    if (!result) {
        *rx_reclaimed=nrx;
        *tx_reclaimed=drain_tx?ntx:0;
        atomic_store_explicit(&r->gate[g],0,memory_order_release);
    }
    rte_spinlock_unlock(&r->directory->lock);
    return result;
rollback:
    for (uint16_t q=0;q<r->queues;q++) {
        if (rx[q].ring) {
            detach_batch_clear_seen(&rx[q]);
            if (detach_batch_restore(&rx[q])) result=-EUCLEAN;
        }
        if (tx[q].ring) {
            detach_batch_clear_seen(&tx[q]);
            if (detach_batch_restore(&tx[q])) result=-EUCLEAN;
        }
    }
    rte_spinlock_unlock(&r->directory->lock);
    return result;
}

int ker_generation_orderly_detach_ready(struct ker_generation_rings *r,
    const struct ker_generation_identity *id,
    const struct ker_generation_cleanup_config *cleanup)
{
    if (!r || !r->primary || !identity_valid(r,id) || !cleanup ||
        cleanup->version!=KER_GENERATION_CLEANUP_CONFIG_VERSION ||
        cleanup->size!=sizeof(*cleanup) || cleanup->ports!=r->ports ||
        cleanup->queues!=r->queues || cleanup->ports!=1 || !cleanup->queues || cleanup->queues>64 ||
        (cleanup->rx_queue_mask&~(cleanup->queues==64?UINT64_MAX:((UINT64_C(1)<<cleanup->queues)-1))) ||
        (cleanup->tx_queue_mask&~(cleanup->queues==64?UINT64_MAX:((UINT64_C(1)<<cleanup->queues)-1))) ||
        r->pidfd[id->generation]<0 || !same_identity(&r->registered[id->generation],id)) return -EINVAL;
    struct pollfd live={.fd=r->pidfd[id->generation],.events=POLLIN};
    int ready; do ready=poll(&live,1,0); while(ready<0&&errno==EINTR);
    if(ready<0)return -errno;
    if(ready||(live.revents&(POLLERR|POLLHUP|POLLNVAL)))return -ESTALE;
    rte_spinlock_lock(&r->directory->lock);
    for(uint16_t q=0;q<r->queues;q++) {
        if ((cleanup->rx_queue_mask&(UINT64_C(1)<<q)) &&
            !rte_ring_empty(r->rx[ring_index(r,0,q,id->generation)])) {
            rte_spinlock_unlock(&r->directory->lock);return -EBUSY;
        }
        if ((cleanup->tx_queue_mask&(UINT64_C(1)<<q)) &&
            !rte_ring_empty(r->tx[ring_index(r,0,q,id->generation)])) {
            rte_spinlock_unlock(&r->directory->lock);return -EBUSY;
        }
    }
    if (cleanup->rx_queue_mask || cleanup->tx_queue_mask) {
        size_t n=ring_count(r);
        for(uint32_t i=0;i<r->directory->journal_count;i++) {
            struct journal_entry *j=&r->journal[i];
            unsigned state=atomic_load_explicit(&j->state,memory_order_acquire);
            if(state==JOURNAL_FREE)continue;
            if(state==JOURNAL_RESERVED || j->ring_slot>=n || j->direction>1) {
                rte_spinlock_unlock(&r->directory->lock);return -EBUSY;
            }
            for(uint16_t q=0;q<r->queues;q++) {
                size_t slot=ring_index(r,0,q,id->generation);
                if ((j->direction==0 && (cleanup->rx_queue_mask&(UINT64_C(1)<<q)) && j->ring_slot==slot) ||
                    (j->direction==1 && (cleanup->tx_queue_mask&(UINT64_C(1)<<q)) && j->ring_slot==slot)) {
                    rte_spinlock_unlock(&r->directory->lock);return -EBUSY;
                }
            }
        }
    }
    rte_spinlock_unlock(&r->directory->lock);return 0;
}

static struct journal_entry *journal_reserve(struct ker_generation_rings *r)
{
    for (uint32_t i=0;i<r->directory->journal_count;i++) { unsigned expected=JOURNAL_FREE;
        if (atomic_compare_exchange_strong(&r->journal[i].state,&expected,JOURNAL_RESERVED)) return &r->journal[i]; }
    return NULL;
}
static struct journal_entry *journal_find(struct ker_generation_rings *r, struct rte_mbuf *m)
{ for(uint32_t i=0;i<r->directory->journal_count;i++) { unsigned s=atomic_load_explicit(&r->journal[i].state,memory_order_acquire); if(s>=JOURNAL_PREPARED && s!=JOURNAL_FREE && s!=JOURNAL_RESERVED && r->journal[i].packet==m) return &r->journal[i]; } return NULL; }
static int enqueue(struct ker_generation_rings *r, const struct ker_generation_identity *producer,
    uint16_t p,uint16_t q,uint32_t g,struct rte_mbuf *m,int tx)
{
    if (!r || !m || !producer || !admitted(r,producer,p,q,producer->generation) ||
        (tx ? g!=producer->generation : g==producer->generation)) return -EINVAL;
    if (m->pool!=r->pool || !packet_reclaimable(r,m)) return -EINVAL;
    uint32_t ring_generation=g;
    int enter=operation_enter(r,producer,p,q,ring_generation);if(enter)return enter;
    bool peer_entered=false;
    if (tx) {
        size_t peer=coord_index(r,p,q,g^1U);
        if (!atomic_load_explicit(&r->admitted[peer],memory_order_acquire)) {
            operation_leave(r,producer,ring_generation); return -EHOSTDOWN;
        }
        enter=operation_enter(r,producer,p,q,g^1U);
        if(enter){operation_leave(r,producer,ring_generation);return enter;}
        peer_entered=true;
    } else {
        size_t target=coord_index(r,p,q,g);
        if (!atomic_load_explicit(&r->admitted[target],memory_order_acquire)) {
            operation_leave(r,producer,ring_generation); return -EHOSTDOWN;
        }
    }
    size_t i=ring_index(r,p,q,g);struct journal_entry*j;
    if (journal_find(r,m)) { if(peer_entered)operation_leave(r,producer,g^1U);operation_leave(r,producer,ring_generation);return -EALREADY; }
    j=journal_reserve(r); if(!j) { if(peer_entered)operation_leave(r,producer,g^1U);operation_leave(r,producer,ring_generation);return -ENOBUFS; }
    j->packet=m; j->producer=*producer; j->owner=*producer; j->direction=(uint8_t)tx;
    j->dedicated_packet=0;j->lease_id=0;
    j->ring_slot=(uint32_t)i;
    j->actor_generation=producer->generation;j->ring_generation=(uint8_t)ring_generation;
    memset(&j->consumer,0,sizeof(j->consumer));j->seen=0;
    if (!tx) j->owner=r->identity[coord_index(r,p,q,g)];
    else {
        j->consumer=r->identity[coord_index(r,p,q,g^1U)];
        j->owner=j->consumer;
    }
    atomic_store_explicit(&j->state,JOURNAL_QUEUED,memory_order_release);
#ifdef KER_SESSION_TEST_HOOKS
    test_pause_at_transition(&test_enqueue_prepare_ready,NULL);
#endif
    int rc=tx?rte_ring_enqueue(r->tx[i],m):rte_ring_enqueue(r->rx[i],m);
    if (rc) { j->packet=NULL; atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
        if (rc == -ENOBUFS) {
            struct rte_ring *ring=tx?r->tx[i]:r->rx[i];
            unsigned capacity=rte_ring_get_capacity(ring);
            peak_observe(tx?&r->stats[i].tx_peak:&r->stats[i].rx_peak,capacity,capacity);
            atomic_fetch_add_explicit(tx?&r->stats[i].tx_full:&r->stats[i].rx_full,1,memory_order_relaxed);
        }
        if(peer_entered) operation_leave(r,producer,g^1U);
        operation_leave(r,producer,ring_generation);return rc; }
    {
        struct rte_ring *ring=tx?r->tx[i]:r->rx[i];
        peak_observe(tx?&r->stats[i].tx_peak:&r->stats[i].rx_peak,
            rte_ring_count(ring),rte_ring_get_capacity(ring));
    }
    if(peer_entered) operation_leave(r,producer,g^1U);
    operation_leave(r,producer,ring_generation);return 0;
}
int ker_generation_rx_enqueue(struct ker_generation_rings*r,const struct ker_generation_identity*i,uint16_t p,uint16_t q,uint32_t g,struct rte_mbuf*m)
{ return enqueue(r,i,p,q,g,m,0); }
int ker_generation_tx_enqueue(struct ker_generation_rings*r,const struct ker_generation_identity*i,uint16_t p,uint16_t q,struct rte_mbuf*m)
{ return enqueue(r,i,p,q,i?i->generation:UINT32_MAX,m,1); }
static struct journal_entry *packet_lease_find(struct ker_generation_rings *r,
    uint32_t object_index,uint64_t lease_id)
{
    if(!r||object_index>=r->packet_object_count||!lease_id)return NULL;
    struct rte_mbuf *packet=r->objects[r->packet_object_base+object_index];
    if((uintptr_t)packet!=r->packet_object_table[object_index]||packet->pool!=r->packet_pool)return NULL;
    for(uint32_t i=0;i<r->directory->journal_count;i++){
        struct journal_entry *j=&r->journal[i];
        unsigned state=atomic_load_explicit(&j->state,memory_order_acquire);
        if(state!=JOURNAL_FREE&&state!=JOURNAL_RESERVED&&j->dedicated_packet&&
            j->packet==packet&&j->lease_id==lease_id)return j;
    }
    return NULL;
}
uint64_t ker_generation_packet_pool_tag(const struct ker_generation_rings *r)
{ return r&&r->directory?r->directory->packet_pool_tag:0; }
static int packet_lease_identity(struct ker_generation_rings *r,
    const struct journal_entry *j,const struct ker_generation_identity *actor,int producer)
{
    if(!r||!j||!actor||!identity_valid(r,actor)||!j->dedicated_packet||!j->lease_id||
        !j->packet||j->packet->pool!=r->packet_pool||!known_pool_object(r,j->packet))return 0;
    return same_identity(producer?&j->producer:&j->consumer,actor);
}
int ker_generation_packet_prepare(struct ker_generation_rings *r,
    const struct ker_generation_identity *producer,const struct ker_generation_identity *consumer,
    uint16_t p,uint16_t q,uint32_t *object_index,uint64_t *lease_id)
{
    if(object_index)*object_index=0;
    if(lease_id)*lease_id=0;
    if(!r||!r->primary||!producer||!consumer||!object_index||!lease_id||p>=r->ports||q>=r->queues||
        !identity_valid(r,producer)||!identity_valid(r,consumer)||
        producer->generation==consumer->generation||consumer->generation!=(producer->generation^1U)||
        producer->session!=consumer->session)return -EINVAL;
    int entered=operation_enter(r,producer,p,q,producer->generation);if(entered)return entered;
    entered=operation_enter_tx_peer(r,consumer,p,q,producer->generation);
    if(entered){operation_leave(r,producer,producer->generation);return entered;}
    struct rte_mbuf *packet=rte_pktmbuf_alloc(r->packet_pool);
    if(!packet){operation_leave(r,consumer,producer->generation);operation_leave(r,producer,producer->generation);return -ENOMEM;}
    uint32_t index=UINT32_MAX;
    for(uint32_t i=0;i<r->packet_object_count;i++)
        if(r->objects[r->packet_object_base+i]==packet){index=i;break;}
    struct journal_entry *j=journal_reserve(r);
    if(index==UINT32_MAX||!j){rte_pktmbuf_free(packet);operation_leave(r,consumer,producer->generation);
        operation_leave(r,producer,producer->generation);return index==UINT32_MAX?-EUCLEAN:-ENOBUFS;}
    uint64_t id=0;ssize_t random_bytes;
    do random_bytes=getrandom(&id,sizeof(id),0);while(random_bytes<0&&errno==EINTR);
    bool collision=false;
    if(random_bytes==(ssize_t)sizeof(id)&&id&&id!=UINT64_MAX)
        for(uint32_t i=0;i<r->directory->journal_count;i++)
            if(atomic_load_explicit(&r->journal[i].state,memory_order_acquire)!=JOURNAL_FREE&&
                r->journal[i].lease_id==id){collision=true;break;}
    if(random_bytes!=(ssize_t)sizeof(id)||!id||id==UINT64_MAX||collision){
        atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
        rte_pktmbuf_free(packet);operation_leave(r,consumer,producer->generation);
        operation_leave(r,producer,producer->generation);return random_bytes<0?-errno:-EAGAIN;}
    rte_pktmbuf_reset(packet);
    j->packet=packet;j->producer=*producer;j->consumer=*consumer;j->owner=*consumer;
    j->direction=1;j->actor_generation=(uint8_t)producer->generation;
    j->ring_generation=(uint8_t)producer->generation;j->ring_slot=(uint32_t)ring_index(r,p,q,producer->generation);
    j->dedicated_packet=1;j->lease_id=id;j->seen=0;
    atomic_store_explicit(&j->state,JOURNAL_PREPARED,memory_order_release);
    *object_index=index;*lease_id=id;
    operation_leave(r,consumer,producer->generation);operation_leave(r,producer,producer->generation);
    return 0;
}
static int packet_lease_coordinates(const struct ker_generation_rings *r,
    const struct journal_entry *j,uint16_t *port,uint16_t *queue)
{
    if(!r||!j||j->ring_slot>=ring_count(r))return -EINVAL;
    *port=(uint16_t)(j->ring_slot/(r->queues*KER_GENERATION_RING_GENERATIONS));
    *queue=(uint16_t)((j->ring_slot/KER_GENERATION_RING_GENERATIONS)%r->queues);
    return 0;
}
struct rte_mbuf *ker_generation_packet_resolve(struct ker_generation_rings *r,
    const struct ker_generation_identity *producer,uint32_t index,uint64_t id)
{
    struct journal_entry *j=packet_lease_find(r,index,id);uint16_t p,q;
    if(!j||!packet_lease_identity(r,j,producer,1)||packet_lease_coordinates(r,j,&p,&q)||
        j->producer.generation!=j->ring_generation||
        atomic_load_explicit(&j->state,memory_order_acquire)!=JOURNAL_PREPARED||
        operation_enter(r,producer,p,q,j->ring_generation))return NULL;
    unsigned expected=JOURNAL_PREPARED;
    int claimed=atomic_compare_exchange_strong_explicit(&j->state,&expected,JOURNAL_PACKET_WRITING,
        memory_order_acq_rel,memory_order_acquire);
    /* Keep the producer operation active while it owns the returned mbuf.
     * The resident reaper must not reclaim a live writer's object between
     * resolve and write_complete. A dead producer is covered by pidfd recovery. */
    if(!claimed)operation_leave(r,producer,j->ring_generation);
    return claimed?j->packet:NULL;
}
int ker_generation_packet_write_complete(struct ker_generation_rings *r,
    const struct ker_generation_identity *producer,uint32_t index,uint64_t id)
{
    struct journal_entry *j=packet_lease_find(r,index,id);uint16_t p,q;
    if(!j||!packet_lease_identity(r,j,producer,1)||packet_lease_coordinates(r,j,&p,&q))return -ESTALE;
    (void)p;(void)q;
    if(atomic_load_explicit(&j->state,memory_order_acquire)!=JOURNAL_PACKET_WRITING)return -ESTALE;
    int valid=packet_reclaimable(r,j->packet)&&j->packet->pool==r->packet_pool&&
        j->packet->nb_segs==1&&j->packet->pkt_len>=14&&j->packet->pkt_len<=1518&&
        j->packet->data_len==j->packet->pkt_len;
    if(!packet_reclaimable(r,j->packet)||j->packet->pool!=r->packet_pool){
        operation_leave(r,producer,j->ring_generation);return -EUCLEAN;
    }
    unsigned expected=JOURNAL_PACKET_WRITING;
    int rc=atomic_compare_exchange_strong_explicit(&j->state,&expected,JOURNAL_PREPARED,
        memory_order_release,memory_order_acquire)?0:-ESTALE;
    operation_leave(r,producer,j->ring_generation);return rc?rc:(valid?0:-EMSGSIZE);
}
int ker_generation_packet_commit(struct ker_generation_rings *r,
    const struct ker_generation_identity *producer,uint16_t p,uint16_t q,
    uint32_t index,uint64_t id)
{
    if(!r||!r->primary||!producer||p>=r->ports||q>=r->queues)return -EINVAL;
    struct journal_entry *j=packet_lease_find(r,index,id);
    if(!j||!packet_lease_identity(r,j,producer,1)||j->ring_slot!=ring_index(r,p,q,producer->generation))return -ESTALE;
    unsigned state=atomic_load_explicit(&j->state,memory_order_acquire);
    if(state==JOURNAL_QUEUED||state==JOURNAL_DEQUEUEING||state==JOURNAL_INFLIGHT||
        state==JOURNAL_PACKET_PMD_ACCEPTED||state==JOURNAL_PACKET_WIRE_PENDING)return 0;
    if(state!=JOURNAL_PREPARED||!packet_reclaimable(r,j->packet)||j->packet->nb_segs!=1||
        j->packet->pkt_len<14||j->packet->pkt_len>1518||j->packet->data_len!=j->packet->pkt_len)return -EMSGSIZE;
    int entered=operation_enter(r,producer,p,q,producer->generation);if(entered)return entered;
    entered=operation_enter_tx_peer(r,&j->consumer,p,q,producer->generation);
    if(entered){operation_leave(r,producer,producer->generation);return entered;}
    unsigned expected=JOURNAL_PREPARED;
    if(!atomic_compare_exchange_strong_explicit(&j->state,&expected,JOURNAL_PACKET_COMMITTING,
        memory_order_acq_rel,memory_order_acquire)){
        operation_leave(r,&j->consumer,producer->generation);operation_leave(r,producer,producer->generation);
        return expected==JOURNAL_QUEUED||expected==JOURNAL_DEQUEUEING||expected==JOURNAL_INFLIGHT?0:-ESTALE;
    }
    j->owner=j->consumer;
    atomic_store_explicit(&j->state,JOURNAL_QUEUED,memory_order_release);
    size_t slot=ring_index(r,p,q,producer->generation);
    int rc=rte_ring_enqueue(r->tx[slot],j->packet);
    if(rc){atomic_store_explicit(&j->state,JOURNAL_PREPARED,memory_order_release);
        if(rc==-ENOBUFS)atomic_fetch_add_explicit(&r->stats[slot].packet_full,1,memory_order_relaxed);}
    else peak_observe(&r->stats[slot].tx_peak,rte_ring_count(r->tx[slot]),rte_ring_get_capacity(r->tx[slot]));
    operation_leave(r,&j->consumer,producer->generation);operation_leave(r,producer,producer->generation);
    return rc;
}
int ker_generation_packet_cancel(struct ker_generation_rings *r,
    const struct ker_generation_identity *producer,uint32_t index,uint64_t id)
{
    if(!r||!r->primary||!producer)return -EINVAL;
    struct journal_entry *j=packet_lease_find(r,index,id);uint16_t p,q;
    if(!j||!packet_lease_identity(r,j,producer,1)||packet_lease_coordinates(r,j,&p,&q))return -ESTALE;
    int enter=operation_enter(r,producer,p,q,j->ring_generation);if(enter)return enter;
    unsigned expected=JOURNAL_PREPARED;
    if(!atomic_compare_exchange_strong_explicit(&j->state,&expected,JOURNAL_RELEASING,
        memory_order_acq_rel,memory_order_acquire)){
        operation_leave(r,producer,j->ring_generation);return expected==JOURNAL_PACKET_WRITING?-EBUSY:-ESTALE;
    }
    struct rte_mbuf *packet=j->packet;
    if(!packet_reclaimable(r,packet)||packet->pool!=r->packet_pool){
        operation_leave(r,producer,j->ring_generation);return -EUCLEAN;
    }
    rte_pktmbuf_reset(packet);rte_pktmbuf_free(packet);j->packet=NULL;j->lease_id=0;j->dedicated_packet=0;
    memset(&j->producer,0,sizeof(j->producer));memset(&j->consumer,0,sizeof(j->consumer));
    atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
    operation_leave(r,producer,j->ring_generation);return 0;
}
int ker_generation_packet_pmd_accepted(struct ker_generation_rings *r,
    const struct ker_generation_identity *consumer,struct rte_mbuf *packet)
{
    (void)r;(void)consumer;(void)packet;
    /* No external PMD completion registry is connected to this API yet. */
    return -EOPNOTSUPP;
}
int ker_generation_packet_wire_pending(struct ker_generation_rings *r,
    const struct ker_generation_identity *consumer,struct rte_mbuf *packet)
{
    (void)r;(void)consumer;(void)packet;
    /* A syscall/driver send outcome must be journaled by a real adapter. */
    return -EOPNOTSUPP;
}
static int dequeue(struct ker_generation_rings*r,const struct ker_generation_identity*id,uint16_t p,uint16_t q,uint32_t g,struct rte_mbuf**out,int tx)
{
    if (out) *out = NULL;
    if (!r || !out || !id || g >= 2 || !admitted(r, id, p, q, id->generation)) return -EINVAL;
    /* TX peer dequeue receives g as the producer/ring generation; the
     * consumer identity remains id->generation. */
    uint32_t ring_generation=g;
    int enter=tx?operation_enter_tx_peer(r,id,p,q,ring_generation):
        operation_enter(r,id,p,q,ring_generation);
    if(enter)return enter;
    size_t i=ring_index(r,p,q,g); struct rte_mbuf*m=NULL;
    int rc=tx?rte_ring_dequeue(r->tx[i],(void**)&m):rte_ring_dequeue(r->rx[i],(void**)&m);
    if(rc){operation_leave(r,id,ring_generation);return 0;}
#ifdef KER_SESSION_TEST_HOOKS
    test_pause_at_transition(&test_ring_remove_ready,&test_ring_remove_release);
#endif
    struct journal_entry*j=journal_find(r,m);
    int ownership_ok = j && (tx ? (j->direction && j->producer.generation == g &&
        same_identity(&j->consumer,id)) : (!j->direction && same_identity(&j->owner,id)));
    unsigned expected=JOURNAL_QUEUED;
    if(!ownership_ok||!atomic_compare_exchange_strong_explicit(&j->state,&expected,JOURNAL_DEQUEUEING,memory_order_acq_rel,memory_order_acquire)){
        int restore=tx?rte_ring_enqueue(r->tx[i],m):rte_ring_enqueue(r->rx[i],m);
        operation_leave(r,id,ring_generation);return restore?-EUCLEAN:(expected==JOURNAL_PREPARED?-EAGAIN:-EPROTO);
    }
#ifdef KER_SESSION_TEST_HOOKS
    test_pause_at_transition(&test_dequeue_cas_ready,NULL);
#endif
    j->consumer=*id;
    if (tx) j->owner = *id;
    j->actor_generation=id->generation;j->ring_generation=(uint8_t)ring_generation;
    atomic_store_explicit(&j->state,JOURNAL_INFLIGHT,memory_order_release); *out=m;
#ifdef KER_SESSION_TEST_HOOKS
    test_hold_dequeue_lease();
#endif
    return 1;
}
int ker_generation_rx_dequeue(struct ker_generation_rings*r,const struct ker_generation_identity*i,uint16_t p,uint16_t q,struct rte_mbuf**o)
{return dequeue(r,i,p,q,i?i->generation:UINT32_MAX,o,0);}
int ker_generation_tx_dequeue_peer(struct ker_generation_rings*r,const struct ker_generation_identity*i,uint16_t p,uint16_t q,struct rte_mbuf**o)
{return dequeue(r,i,p,q,i?i->generation^1U:UINT32_MAX,o,1);}
uint64_t ker_generation_rx_full_count(struct ker_generation_rings*r,uint16_t p,uint16_t q,uint32_t g)
{if(!r||p>=r->ports||q>=r->queues||g>=2)return 0;return atomic_load(&r->stats[full_index(r,p,q,g)].rx_full);}
int ker_generation_rings_stats(struct ker_generation_rings *r, struct ker_generation_ring_stats *out)
{
    if (!r || !out || !r->primary) return -EINVAL;
    struct ker_generation_ring_stats result={0};
    rte_spinlock_lock(&r->directory->lock);
    size_t n=ring_count(r);
    for (unsigned i=0;i<4;i++) if (atomic_load_explicit(&r->active[i],memory_order_acquire)) {
        rte_spinlock_unlock(&r->directory->lock); return -EBUSY;
    }
    for (unsigned i=0;i<2;i++) if (atomic_load_explicit(&r->gate[i],memory_order_acquire)) {
        rte_spinlock_unlock(&r->directory->lock); return -EBUSY;
    }
    for (size_t i=0;i<n;i++) if (atomic_load_explicit(&r->admitted[i],memory_order_acquire)) {
        rte_spinlock_unlock(&r->directory->lock); return -EBUSY;
    }
    for (size_t i=0;i<n;i++) {
        uint64_t rx=atomic_load_explicit(&r->stats[i].rx_full,memory_order_relaxed);
        uint64_t tx=atomic_load_explicit(&r->stats[i].tx_full,memory_order_relaxed);
        uint64_t drop=atomic_load_explicit(&r->stats[i].tx_drop,memory_order_relaxed);
        uint64_t packet_drop=atomic_load_explicit(&r->stats[i].packet_drop,memory_order_relaxed);
        uint64_t packet_full=atomic_load_explicit(&r->stats[i].packet_full,memory_order_relaxed);
        if (UINT64_MAX-result.rx_full<rx || UINT64_MAX-result.tx_full<tx ||
            UINT64_MAX-result.tx_drop<drop || UINT64_MAX-result.packet_drop<packet_drop ||
            UINT64_MAX-result.packet_full<packet_full) {
            rte_spinlock_unlock(&r->directory->lock); return -EOVERFLOW;
        }
        result.rx_full+=rx; result.tx_full+=tx; result.tx_drop+=drop;result.packet_drop+=packet_drop;
        result.packet_full+=packet_full;
        uint32_t rx_peak=atomic_load_explicit(&r->stats[i].rx_peak,memory_order_relaxed);
        uint32_t tx_peak=atomic_load_explicit(&r->stats[i].tx_peak,memory_order_relaxed);
        if (rx_peak>result.rx_peak) result.rx_peak=rx_peak;
        if (tx_peak>result.tx_peak) result.tx_peak=tx_peak;
        uint32_t rx_capacity=rte_ring_get_capacity(r->rx[i]);
        uint32_t tx_capacity=rte_ring_get_capacity(r->tx[i]);
        if ((result.rx_capacity&&result.rx_capacity!=rx_capacity) ||
            (result.tx_capacity&&result.tx_capacity!=tx_capacity)) {
            rte_spinlock_unlock(&r->directory->lock); return -EPROTO;
        }
        result.rx_capacity=rx_capacity; result.tx_capacity=tx_capacity;
    }
    result.rx_rings=(uint32_t)n; result.tx_rings=(uint32_t)n;
    *out=result;
    rte_spinlock_unlock(&r->directory->lock);
    return 0;
}
int ker_generation_packet_release(struct ker_generation_rings*r,const struct ker_generation_identity*owner,struct rte_mbuf*m)
{
    if (!r || !identity_valid(r, owner) || !m) return -EINVAL;
    struct journal_entry*j=journal_find(r,m);
    unsigned state=j?atomic_load_explicit(&j->state,memory_order_acquire):JOURNAL_FREE;
    if(!j||!same_identity(&j->owner,owner)||
        state!=JOURNAL_INFLIGHT||
        !packet_reclaimable(r,m))return -ESTALE;
    uint8_t ring_generation=j->ring_generation;unsigned expected=state;
    if(!atomic_compare_exchange_strong_explicit(&j->state,&expected,JOURNAL_RELEASING,memory_order_acq_rel,memory_order_acquire))return -ESTALE;
    rte_pktmbuf_free(m);j->packet=NULL;j->lease_id=0;j->dedicated_packet=0;
    memset(&j->producer,0,sizeof(j->producer));memset(&j->consumer,0,sizeof(j->consumer));
    atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
    operation_leave(r,owner,ring_generation);return 0;
}
static int packet_reclaimable(const struct ker_generation_rings *r, const struct rte_mbuf *m)
{
    if (!known_pool_object(r,m)) return 0;
    if ((m->pool != r->pool && m->pool != r->packet_pool) || !m->nb_segs || m->nb_segs > r->object_count) return 0;
    const struct rte_mbuf *segment=m;
    uint64_t total=0;
    for(uint16_t i=0;i<m->nb_segs;i++){
        if(!known_pool_object(r,segment))return 0;
        if(segment->pool!=m->pool || rte_mbuf_refcnt_read(segment)!=1 ||
            (segment->ol_flags&(RTE_MBUF_F_EXTERNAL|RTE_MBUF_F_INDIRECT)) ||
            !segment->buf_addr || segment->data_off>segment->buf_len ||
            segment->data_len>segment->buf_len-segment->data_off) return 0;
        total+=segment->data_len;
        if(total>UINT32_MAX)return 0;
        segment=segment->next;
    }
    return !segment && total==m->pkt_len;
}
struct reap_ring_batch {
    struct rte_ring *ring;
    size_t slot;
    uint8_t direction;
    unsigned count;
    unsigned collected;
    struct rte_mbuf *packets[KER_GENERATION_RING_CAPACITY];
    struct journal_entry *entries[KER_GENERATION_RING_CAPACITY];
};
static void reap_clear_seen(struct ker_generation_rings *r)
{
    for (uint32_t i=0;i<r->directory->journal_count;i++) r->journal[i].seen=0;
}
static int reap_restore_rings(struct reap_ring_batch *batches,size_t count,int drain_first)
{
    void *discard[KER_GENERATION_RING_CAPACITY];
    if(drain_first)for(size_t i=0;i<count;i++){
        struct reap_ring_batch *batch=&batches[i];
        if(!batch->collected)continue;
        unsigned current=rte_ring_count(batch->ring);
        if(current>KER_GENERATION_RING_CAPACITY||
            (current&&rte_ring_dequeue_bulk(batch->ring,discard,current,NULL)!=current))return -EUCLEAN;
    }
    for(size_t i=0;i<count;i++){
        struct reap_ring_batch *batch=&batches[i];
        if(!batch->collected||!batch->count)continue;
        if(rte_ring_enqueue_bulk(batch->ring,(void * const *)batch->packets,batch->count,NULL)!=batch->count)
            return -EUCLEAN;
    }
    return 0;
}

int ker_generation_reap_dead(struct ker_generation_rings*r,const struct ker_generation_identity*owner)
{
    if(!r||!r->primary||!identity_valid(r,owner))return -EINVAL;
    uint32_t g=owner->generation;
    size_t count_rings=ring_count(r);
    if(count_rings>SIZE_MAX/2 || count_rings*2>SIZE_MAX/sizeof(struct reap_ring_batch) ||
        count_rings>SIZE_MAX/sizeof(uint64_t)) return -EOVERFLOW;
    size_t batch_count=count_rings*2;
    struct reap_ring_batch *batches=calloc(batch_count,sizeof(*batches));
    uint64_t *tx_drops=calloc(count_rings,sizeof(*tx_drops));
    unsigned char *claimed=calloc(r->object_count,sizeof(*claimed));
    if(!batches||!tx_drops||!claimed){free(batches);free(tx_drops);free(claimed);return -ENOMEM;}
    rte_spinlock_lock(&r->directory->lock);
    if(r->pidfd[g]<0||!same_identity(&r->registered[g],owner)){
        rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return -ESTALE;
    }
    /* A dead peer may still have an active counter if it died in a fast-path
     * operation. Only the resident-owned pidfd proves which counters and
     * registrations can safely be abandoned. */
    unsigned dead_mask=0;
    for(unsigned actor=0;actor<KER_GENERATION_RING_GENERATIONS;actor++){
        if(r->pidfd[actor]<0)continue;
        struct pollfd pfd={.fd=r->pidfd[actor],.events=POLLIN};
        int n;do n=poll(&pfd,1,0);while(n<0&&errno==EINTR);
        if(n<0){int error=-errno;rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return error;}
        if(n>0&&(pfd.revents&POLLIN)){
            if(!identity_valid(r,&r->registered[actor])||r->registered[actor].generation!=actor){
                rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return -EUCLEAN;
            }
            dead_mask|=1U<<actor;
        }
    }
    if(!(dead_mask&(1U<<g))){
        rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return -EBUSY;
    }
    atomic_store_explicit(&r->gate[0],1,memory_order_release);
    atomic_store_explicit(&r->gate[1],1,memory_order_release);
    for(unsigned dead_generation=0;dead_generation<2;dead_generation++)if(dead_mask&(1U<<dead_generation))
        for(uint16_t p=0;p<r->ports;p++)for(uint16_t q=0;q<r->queues;q++)
            atomic_store_explicit(&r->admitted[coord_index(r,p,q,dead_generation)],0,memory_order_release);
    struct timespec wait_until,wait_now,wait_nap={.tv_nsec=1000000};
    if(clock_gettime(CLOCK_MONOTONIC,&wait_until)){
        int error=-errno;rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return error;
    }
    wait_until.tv_sec+=1;
    for(;;){
        bool busy=false;
        for(unsigned actor=0;actor<2;actor++)if(!(dead_mask&(1U<<actor)))
            for(unsigned ring=0;ring<2;ring++)
                busy|=atomic_load_explicit(&r->active[actor*2+ring],memory_order_acquire)!=0;
        if(!busy)break;
        if(clock_gettime(CLOCK_MONOTONIC,&wait_now)){
            int error=-errno;rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return error;
        }
        if(wait_now.tv_sec>wait_until.tv_sec||(wait_now.tv_sec==wait_until.tv_sec&&wait_now.tv_nsec>=wait_until.tv_nsec)){
            rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return -EBUSY;
        }
        nanosleep(&wait_nap,NULL);
    }
    for(unsigned actor=0;actor<2;actor++)if(dead_mask&(1U<<actor)){
        atomic_store_explicit(&r->active[actor*2],0,memory_order_release);
        atomic_store_explicit(&r->active[actor*2+1],0,memory_order_release);
    }
    reap_clear_seen(r);
#define REAP_ABORT(error) do { \
        int restore_result=reap_restore_rings(batches,batch_count,0); \
        reap_clear_seen(r); \
        memset(claimed,0,r->object_count); \
        rte_spinlock_unlock(&r->directory->lock); \
        free(batches);free(tx_drops);free(claimed); \
        return restore_result ? -EUCLEAN : (error); \
    } while(0)
    /* Collect and validate every original ring before reclaiming anything. */
    for(size_t i=0;i<count_rings;i++)for(unsigned dir=0;dir<2;dir++){
        struct reap_ring_batch *batch=&batches[i*2+dir];
        batch->slot=i;batch->direction=(uint8_t)dir;
        batch->ring=dir?r->tx[i]:r->rx[i];
        batch->count=rte_ring_count(batch->ring);
        if(batch->count>KER_GENERATION_RING_CAPACITY||
            (batch->count&&rte_ring_dequeue_bulk(batch->ring,(void **)batch->packets,batch->count,NULL)!=batch->count))
            REAP_ABORT(-EUCLEAN);
        batch->collected=1;
        for(unsigned k=0;k<batch->count;k++){
            struct rte_mbuf *m=batch->packets[k];
            if(!packet_claim_chain(r,m,claimed)) REAP_ABORT(-EUCLEAN);
            struct journal_entry *j=journal_find(r,m);
            unsigned state=j?atomic_load_explicit(&j->state,memory_order_acquire):JOURNAL_FREE;
            if(!j||j->packet!=m||j->seen||j->ring_slot!=i||j->direction!=(uint8_t)dir||
                (state!=JOURNAL_QUEUED&&state!=JOURNAL_DEQUEUEING)) REAP_ABORT(-EUCLEAN);
            j->seen=1;
            batch->entries[k]=j;
        }
    }
    /* Validate all on-ring and off-ring journal states before any free or
     * counter update. seen=1 means ring member; seen=2 means validated reclaim. */
#ifdef KER_SESSION_TEST_HOOKS
    if(atomic_exchange_explicit(&test_corrupt_next_reap,0,memory_order_acq_rel)) {
        /* A late invalid RX coordinate tests that earlier queued TX is not
         * reclaimed before global journal validation completes. */
        const struct ker_generation_identity *corrupt_owner=owner;
        unsigned other=g^1U;
        if((dead_mask&(1U<<other))&&r->pidfd[other]>=0)corrupt_owner=&r->registered[other];
        if(ker_generation_test_corrupt_late_queued_rx(r,corrupt_owner,0)) REAP_ABORT(-EUCLEAN);
    }
#endif
    for(size_t i=0;i<batch_count;i++){
        struct reap_ring_batch *batch=&batches[i];
        for(unsigned k=0;k<batch->count;k++){
            struct journal_entry *j=batch->entries[k];
            if(j->ring_slot!=batch->slot||j->direction!=batch->direction) REAP_ABORT(-EUCLEAN);
        }
    }
    for(uint32_t i=0;i<r->directory->journal_count;i++){
        struct journal_entry *j=&r->journal[i];
        unsigned state=atomic_load_explicit(&j->state,memory_order_acquire);
        if(state==JOURNAL_FREE){if(j->packet)REAP_ABORT(-EUCLEAN);continue;}
        if(j->ring_slot>=count_rings||j->direction>1||j->ring_generation>=2||
            j->ring_generation!=(j->ring_slot%2)||j->actor_generation>=2||!j->packet||
            journal_find(r,j->packet)!=j||!identity_valid(r,&j->owner)||
            !identity_valid(r,&j->producer)||
            (j->direction?(j->producer.generation!=j->ring_generation||
                j->owner.generation!=(j->ring_generation^1U)):
                (j->owner.generation!=j->ring_generation||
                j->producer.generation!=(j->ring_generation^1U)))) REAP_ABORT(-EUCLEAN);
        if(!j->seen&&!packet_claim_chain(r,j->packet,claimed)) REAP_ABORT(-EUCLEAN);
        int dead_owner=0,dead_producer=0;
        for(unsigned actor=0;actor<2;actor++)if(dead_mask&(1U<<actor)){
            const struct ker_generation_identity *dead=&r->registered[actor];
            dead_owner|=same_identity(&j->owner,dead);
            dead_producer|=same_identity(&j->producer,dead);
        }
        int reclaim=0;
        if(j->dedicated_packet&&(state==JOURNAL_PREPARED||state==JOURNAL_PACKET_WRITING||
            state==JOURNAL_PACKET_COMMITTING)){
            if(!identity_valid(r,&j->consumer)||!same_identity(&j->consumer,&j->owner)||
                j->producer.generation!=j->ring_generation||j->ring_slot%2!=j->ring_generation||j->seen)
                REAP_ABORT(-EUCLEAN);
            if(dead_producer){
                if(!packet_reclaimable(r,j->packet))REAP_ABORT(-EUCLEAN);
                reclaim=1;
            }else{
                /* A prepared object is resident-journaled but not visible to
                 * the TX ring. Preserve it while its exact producer is live;
                 * a dead consumer makes commit stale, so producer may cancel. */
                continue;
            }
        }else if(state==JOURNAL_QUEUED){
            if(j->actor_generation!=j->producer.generation) REAP_ABORT(-EUCLEAN);
            if(j->seen) {
                /* A queued packet in its ring belongs to the live consumer
                 * when only its producer died. Reclaim it only when the
                 * exact registered ring owner is the dead process. */
                reclaim=dead_owner;
            } else {
                /* Off-ring QUEUED covers both the producer dying before
                 * enqueue and the consumer dying after dequeue but before
                 * the state CAS. Neither case is a completed TX drop. */
                reclaim=dead_owner||dead_producer;
            }
        }else if(state==JOURNAL_DEQUEUEING){
            /* The ring dequeue precedes the QUEUED->DEQUEUEING CAS. The
             * consumer struct is not release-published until INFLIGHT, so
             * RX recovery authenticates this window through the exact dead
             * owner plus immutable enqueue coordinates and source identity.
             * TX consumer/owner metadata was published at enqueue time, so
             * validate it even though actor_generation may still be producer. */
            if(j->seen||!dead_owner||(j->actor_generation!=j->producer.generation&&
                j->actor_generation!=j->owner.generation)) REAP_ABORT(-EUCLEAN);
            if(j->direction&&(!identity_valid(r,&j->consumer)||
                !same_identity(&j->consumer,&j->owner))) REAP_ABORT(-EUCLEAN);
            reclaim=1;
        }else if(j->dedicated_packet&&
            (state==JOURNAL_PACKET_PMD_ACCEPTED||state==JOURNAL_PACKET_WIRE_PENDING)){
            /* These states require a real external-send completion ledger.
             * Until one exists, freeing could duplicate or lose a frame. */
            REAP_ABORT(-EUCLEAN);
        }else if(state==JOURNAL_INFLIGHT){
            if(j->seen||!identity_valid(r,&j->consumer)||!same_identity(&j->consumer,&j->owner)||
                j->actor_generation!=j->consumer.generation) REAP_ABORT(-EUCLEAN);
            reclaim=dead_owner;
            if(!reclaim) REAP_ABORT(-EUCLEAN);
        }else{
            /* RESERVED/PREPARED/RELEASING do not identify a recoverable owner. */
            REAP_ABORT(-EUCLEAN);
        }
        if(j->seen){
            if(!reclaim&&state==JOURNAL_QUEUED)continue;
            if(!reclaim) REAP_ABORT(-EUCLEAN);
            j->seen=2;
        }else if(reclaim){
            if(!packet_reclaimable(r,j->packet)) REAP_ABORT(-EUCLEAN);
            j->seen=2;
        }else{
            REAP_ABORT(-EUCLEAN);
        }
    }
    /* Rebuild every survivor ring before freeing any queued object. If one
     * enqueue unexpectedly fails, drain all rebuilt rings and restore every
     * original FIFO batch with journals and counters still untouched. */
#define REAP_COMMIT_ABORT() do { \
        int restore_result=reap_restore_rings(batches,batch_count,1); \
        reap_clear_seen(r); \
        memset(claimed,0,r->object_count); \
        rte_spinlock_unlock(&r->directory->lock); \
        free(batches);free(tx_drops);free(claimed); \
        (void)restore_result; \
        return -EUCLEAN; \
    } while(0)
    void *survivors[KER_GENERATION_RING_CAPACITY];
    for(size_t i=0;i<batch_count;i++){
        struct reap_ring_batch *batch=&batches[i];
        unsigned survivor_count=0;
        for(unsigned k=0;k<batch->count;k++)
            if(batch->entries[k]->seen==1)survivors[survivor_count++]=batch->packets[k];
        if(survivor_count&&rte_ring_enqueue_bulk(batch->ring,survivors,survivor_count,NULL)!=survivor_count)
            REAP_COMMIT_ABORT();
    }
    /* Ring rebuild succeeded globally; now commit validated on-ring and
     * off-ring frees. Only on-ring queued TX entries contribute tx_drop. */
    for(size_t i=0;i<batch_count;i++){
        struct reap_ring_batch *batch=&batches[i];
        for(unsigned k=0;k<batch->count;k++){
            struct journal_entry *j=batch->entries[k];
            if(j->seen!=2)continue;
            size_t ring_slot=batch->slot;int tx=batch->direction;
            struct rte_mbuf *m=batch->packets[k];
            j->packet=NULL;j->seen=0;
            atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
            rte_pktmbuf_free(m);
            if(tx&&j->dedicated_packet)
                atomic_fetch_add_explicit(&r->stats[ring_slot].packet_drop,1,memory_order_relaxed);
            else if(tx)tx_drops[ring_slot]++;
        }
    }
    for(uint32_t i=0;i<r->directory->journal_count;i++){
        struct journal_entry *j=&r->journal[i];
        if(j->seen!=2)continue;
        struct rte_mbuf *m=j->packet;
        j->packet=NULL;j->seen=0;
        atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
        rte_pktmbuf_free(m);
    }
    reap_clear_seen(r);
    for(size_t i=0;i<count_rings;i++) if(tx_drops[i])
        atomic_fetch_add_explicit(&r->stats[i].tx_drop,tx_drops[i],memory_order_relaxed);
    /* Retire exactly the requested registration before reopening the gates;
     * another resident request cannot race a second close of this pidfd. */
    close(r->pidfd[g]);r->pidfd[g]=-1;memset(&r->registered[g],0,sizeof(r->registered[g]));
    atomic_store_explicit(&r->gate[0],0,memory_order_release);
    atomic_store_explicit(&r->gate[1],0,memory_order_release);
    rte_spinlock_unlock(&r->directory->lock);
    free(batches);free(tx_drops);free(claimed);
#undef REAP_ABORT
#undef REAP_COMMIT_ABORT
    return 0;
}

int ker_generation_rings_destroy(struct ker_generation_rings*r)
{
    if (!r) return 0;
    if (!r->primary) return -EPERM;
    rte_spinlock_lock(&r->directory->lock);
    for(size_t i=0;i<coordinates(r->ports,r->queues);i++)
        if(atomic_load_explicit(&r->admitted[i],memory_order_acquire)){
            rte_spinlock_unlock(&r->directory->lock);return -EBUSY;
        }
    for(unsigned g=0;g<2;g++)if(r->pidfd[g]>=0){
        rte_spinlock_unlock(&r->directory->lock);return -EBUSY;
    }
    for(size_t i=0;i<ring_count(r);i++)if(!rte_ring_empty(r->rx[i])||!rte_ring_empty(r->tx[i])){rte_spinlock_unlock(&r->directory->lock);return -EBUSY;}
    for(uint32_t i=0;i<r->directory->journal_count;i++)if(atomic_load(&r->journal[i].state)!=JOURNAL_FREE){rte_spinlock_unlock(&r->directory->lock);return -EBUSY;}
    if(rte_mempool_avail_count(r->packet_pool)!=r->packet_pool->size){rte_spinlock_unlock(&r->directory->lock);return -EBUSY;}
    for(size_t i=0;i<ring_count(r);i++){rte_ring_free(r->rx[i]);rte_ring_free(r->tx[i]);}
    atomic_store(&r->directory->ready,0);rte_spinlock_unlock(&r->directory->lock);
    for(unsigned g=0;g<2;g++)if(r->pidfd[g]>=0)close(r->pidfd[g]);
    rte_memzone_free(rte_memzone_lookup(DIRECTORY_NAME));rte_mempool_free(r->packet_pool);
    free(r->objects);free(r->rx);free(r->tx);free(r);return 0;
}
