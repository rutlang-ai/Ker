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
#include <rte_memzone.h>
#include <rte_errno.h>
#include <rte_spinlock.h>

#define DIRECTORY_MAGIC UINT64_C(0x4b455247524e4731)
#define DIRECTORY_VERSION 4U
#define JOURNAL_MULTIPLIER 2U
#define DIRECTORY_NAME "ker_gen_ring_directory"
enum journal_state { JOURNAL_FREE, JOURNAL_RESERVED, JOURNAL_PREPARED, JOURNAL_QUEUED,
    JOURNAL_DEQUEUEING, JOURNAL_INFLIGHT, JOURNAL_RELEASING };

struct journal_entry {
    _Atomic unsigned state;
    struct rte_mbuf *packet;
    struct ker_generation_identity owner;
    struct ker_generation_identity producer;
    struct ker_generation_identity consumer;
    uint8_t direction;
    uint8_t actor_generation, ring_generation;
    uint8_t seen;
    uint32_t ring_slot;
};
struct ring_directory {
    uint64_t magic, session;
    uint32_t version, ports, queues, capacity, journal_count;
    _Atomic unsigned ready;
    rte_spinlock_t lock;
    char pool_name[RTE_MEMPOOL_NAMESIZE];
    uint32_t pool_size, pool_elt_size;
};
struct ring_stats_shared {
    _Atomic uint64_t rx_full, tx_full, tx_drop;
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
    struct rte_mempool *pool;
    struct rte_mbuf **objects;
    uint32_t object_count;
};

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
static _Atomic unsigned *test_dequeue_cas_ready;
static _Atomic unsigned *test_enqueue_prepare_ready;
void ker_generation_test_hold_next_dequeue(void)
{ atomic_store_explicit(&test_hold_next_dequeue,1,memory_order_release); }
void ker_generation_test_corrupt_next_detach(void)
{ atomic_store_explicit(&test_corrupt_next_detach,1,memory_order_release); }
void ker_generation_test_corrupt_next_reap(void)
{ atomic_store_explicit(&test_corrupt_next_reap,1,memory_order_release); }
void ker_generation_test_hold_after_ring_remove(_Atomic unsigned *ready)
{ test_ring_remove_ready=ready; }
void ker_generation_test_hold_after_dequeue_cas(_Atomic unsigned *ready)
{ test_dequeue_cas_ready=ready; }
void ker_generation_test_hold_after_enqueue_prepare(_Atomic unsigned *ready)
{ test_enqueue_prepare_ready=ready; }
static void test_pause_at_transition(_Atomic unsigned **ready)
{
    if(!*ready)return;
    atomic_store_explicit(*ready,1,memory_order_release);
    const struct timespec nap={.tv_nsec=1000000};
    for(;;)nanosleep(&nap,NULL);
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
    if(!m||!known_pool_object(r,m)||m->pool!=r->pool||!m->nb_segs||m->nb_segs>r->object_count)return 0;
    const struct rte_mbuf *segment=m;
    uint64_t total=0;
    for(uint16_t i=0;i<m->nb_segs;i++){
        uint32_t index;
        if(!pool_object_index(r,segment,&index)||claimed[index])return 0;
        claimed[index]=1;
        if(segment->pool!=r->pool||rte_mbuf_refcnt_read(segment)!=1||
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
static size_t layout_size(uint16_t ports, uint16_t queues)
{
    size_t n = coordinates(ports, queues), j = n * KER_GENERATION_RING_CAPACITY * JOURNAL_MULTIPLIER;
    if (n > SIZE_MAX / sizeof(struct ring_stats_shared) || n > SIZE_MAX / sizeof(struct ker_generation_identity) ||
        n > SIZE_MAX / sizeof(_Atomic unsigned char) || j > SIZE_MAX / sizeof(struct journal_entry)) return 0;
    size_t off = ALIGN_UP(sizeof(struct ring_directory), _Alignof(struct ring_stats_shared));
    off += n * sizeof(struct ring_stats_shared); off = ALIGN_UP(off, _Alignof(struct ker_generation_identity));
    off += n * sizeof(struct ker_generation_identity); off += n * sizeof(_Atomic unsigned char);
    off = ALIGN_UP(off, _Alignof(_Atomic uint32_t)); off += 4 * sizeof(_Atomic uint32_t);
    off = ALIGN_UP(off, _Alignof(_Atomic unsigned)); off += 2 * sizeof(_Atomic unsigned);
    off = ALIGN_UP(off, _Alignof(struct journal_entry));
    if (j > (SIZE_MAX - off) / sizeof(struct journal_entry)) return 0;
    return off + j * sizeof(struct journal_entry);
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
int ker_generation_rings_test_directory_present(void)
{
    int saved_errno = rte_errno;
    int present = lookup_directory() != NULL;
    rte_errno = saved_errno;
    return present;
}
#endif

static int attach_common(uint64_t session, uint16_t ports, uint16_t queues,
    struct rte_mempool *pool, struct ker_generation_rings **out, int primary)
{
    if (!out || !session || !ports || !queues || !pool || ports > 256 || queues > 256) return -EINVAL;
    *out = NULL;
    size_t bytes = layout_size(ports, queues);
    if (!bytes) return -EOVERFLOW;
    struct ker_generation_rings *r = calloc(1, sizeof(*r));
    if (!r) return -ENOMEM;
    size_t n = coordinates(ports, queues);
    r->rx = calloc(n, sizeof(*r->rx)); r->tx = calloc(n, sizeof(*r->tx));
    if (!r->rx || !r->tx) { free(r->rx); free(r->tx); free(r); return -ENOMEM; }
    r->objects=calloc(pool->size,sizeof(*r->objects));
    if(!r->objects){free(r->rx);free(r->tx);free(r);return -ENOMEM;}
    struct object_registry_builder builder={.objects=r->objects,.capacity=pool->size};
    if(rte_mempool_obj_iter(pool,remember_mbuf_object,&builder)!=pool->size||
        builder.overflow||builder.count!=pool->size){free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;}
    r->object_count=builder.count;
    const struct rte_memzone *mz = primary ? rte_memzone_reserve(DIRECTORY_NAME, bytes, SOCKET_ID_ANY, 0) :
        lookup_directory();
    if (!mz) { int error=rte_errno? -rte_errno:-ENOENT;free(r->objects);free(r->rx); free(r->tx); free(r); return error; }
    if (!primary && mz->len < bytes) { fprintf(stderr,"generation rings: directory too short got=%zu expected-at-least=%zu\n",(size_t)mz->len,bytes);free(r->objects);free(r->rx); free(r->tx); free(r); return -EPROTO; }
    r->directory = mz->addr; r->directory_size = bytes; r->ports = ports; r->queues = queues;
    r->session = session; r->primary = primary;
    r->pool = pool;
    r->pidfd[0] = r->pidfd[1] = -1;
    if (primary) {
        memset(r->directory, 0, bytes);
        r->directory->magic = DIRECTORY_MAGIC; r->directory->version = DIRECTORY_VERSION;
        r->directory->session = session; r->directory->ports = ports; r->directory->queues = queues;
        r->directory->capacity = KER_GENERATION_RING_CAPACITY;
        r->directory->journal_count = (uint32_t)(n * KER_GENERATION_RING_CAPACITY * JOURNAL_MULTIPLIER);
        snprintf(r->directory->pool_name,sizeof(r->directory->pool_name),"%s",pool->name);
        r->directory->pool_size=pool->size;r->directory->pool_elt_size=pool->elt_size;
        directory_pointers(r); rte_spinlock_init(&r->directory->lock);
        atomic_init(&r->directory->ready, 0);
        for (size_t i = 0; i < n; ++i) {
            atomic_init(&r->stats[i].rx_full, 0); atomic_init(&r->stats[i].tx_full, 0);
            atomic_init(&r->stats[i].tx_drop, 0); atomic_init(&r->stats[i].rx_peak, 0);
            atomic_init(&r->stats[i].tx_peak, 0); atomic_init(&r->admitted[i], 0);
        }
        for (unsigned i=0;i<4;i++) atomic_init(&r->active[i],0);
        for (unsigned i=0;i<2;i++) atomic_init(&r->gate[i],0);
        for (uint32_t i = 0; i < r->directory->journal_count; ++i)
            atomic_init(&r->journal[i].state, JOURNAL_FREE);
    } else directory_pointers(r);
    if (primary && (!atomic_is_lock_free(&r->directory->ready) ||
        !atomic_is_lock_free(&r->stats[0].rx_full) || !atomic_is_lock_free(&r->stats[0].tx_full) ||
        !atomic_is_lock_free(&r->stats[0].tx_drop) || !atomic_is_lock_free(&r->stats[0].rx_peak) ||
        !atomic_is_lock_free(&r->stats[0].tx_peak) || !atomic_is_lock_free(&r->admitted[0]) ||
        !atomic_is_lock_free(&r->active[0]) || !atomic_is_lock_free(&r->gate[0]) ||
        !atomic_is_lock_free(&r->journal[0].state))) {
        free(r->objects);free(r->rx); free(r->tx); free(r); return -EOPNOTSUPP;
    }
    if (r->directory->magic != DIRECTORY_MAGIC || r->directory->version != DIRECTORY_VERSION ||
        r->directory->session != session || r->directory->ports != ports || r->directory->queues != queues ||
        r->directory->capacity != KER_GENERATION_RING_CAPACITY ||
        strcmp(r->directory->pool_name,pool->name) || r->directory->pool_size!=pool->size ||
        r->directory->pool_elt_size!=pool->elt_size || rte_mempool_lookup(r->directory->pool_name)!=pool ||
        (!atomic_load_explicit(&r->directory->ready, memory_order_acquire) && !primary)) {
        fprintf(stderr,"generation rings: directory header mismatch magic=%llx version=%u session=%llx ports=%u queues=%u cap=%u ready=%u\n",
            (unsigned long long)r->directory->magic,r->directory->version,(unsigned long long)r->directory->session,
            r->directory->ports,r->directory->queues,r->directory->capacity,atomic_load(&r->directory->ready));
        free(r->objects);free(r->rx); free(r->tx); free(r); return -EPROTO;
    }
    size_t journal_end=(size_t)((char*)r->journal-(char*)r->directory)+
        (size_t)r->directory->journal_count*sizeof(*r->journal);
    if(journal_end>mz->len){free(r->objects);free(r->rx);free(r->tx);free(r);return -EPROTO;}
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
{ return attach_common(s,p,q,pool,o,1); }
int ker_generation_rings_attach(uint64_t s, uint16_t p, uint16_t q, struct rte_mempool *pool, struct ker_generation_rings **o)
{ return attach_common(s,p,q,pool,o,0); }
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
        if (tx) atomic_fetch_add_explicit(&r->stats[ring_slot].tx_drop, 1, memory_order_relaxed);
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
    if (!packet_reclaimable(r,m)) return -EINVAL;
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
    test_pause_at_transition(&test_enqueue_prepare_ready);
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
static int dequeue(struct ker_generation_rings*r,const struct ker_generation_identity*id,uint16_t p,uint16_t q,uint32_t g,struct rte_mbuf**out,int tx)
{
    if (out) *out = NULL;
    if (!r || !out || !id || g >= 2 || !admitted(r, id, p, q, id->generation)) return -EINVAL;
    /* TX peer dequeue receives g as the producer/ring generation; the
     * consumer identity remains id->generation. */
    uint32_t ring_generation=g;
    int enter=operation_enter(r,id,p,q,ring_generation);if(enter)return enter;
    size_t i=ring_index(r,p,q,g); struct rte_mbuf*m=NULL;
    int rc=tx?rte_ring_dequeue(r->tx[i],(void**)&m):rte_ring_dequeue(r->rx[i],(void**)&m);
    if(rc){operation_leave(r,id,ring_generation);return 0;}
#ifdef KER_SESSION_TEST_HOOKS
    test_pause_at_transition(&test_ring_remove_ready);
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
    test_pause_at_transition(&test_dequeue_cas_ready);
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
        if (UINT64_MAX-result.rx_full<rx || UINT64_MAX-result.tx_full<tx ||
            UINT64_MAX-result.tx_drop<drop) {
            rte_spinlock_unlock(&r->directory->lock); return -EOVERFLOW;
        }
        result.rx_full+=rx; result.tx_full+=tx; result.tx_drop+=drop;
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
    if(!j||!same_identity(&j->owner,owner)||atomic_load(&j->state)!=JOURNAL_INFLIGHT||!packet_reclaimable(r,m))return -ESTALE;
    uint8_t ring_generation=j->ring_generation;unsigned expected=JOURNAL_INFLIGHT;
    if(!atomic_compare_exchange_strong_explicit(&j->state,&expected,JOURNAL_RELEASING,memory_order_acq_rel,memory_order_acquire))return -ESTALE;
    rte_pktmbuf_free(m);j->packet=NULL;atomic_store_explicit(&j->state,JOURNAL_FREE,memory_order_release);
    operation_leave(r,owner,ring_generation);return 0;
}
static int packet_reclaimable(const struct ker_generation_rings *r, const struct rte_mbuf *m)
{
    if (!known_pool_object(r,m)) return 0;
    if (m->pool != r->pool || !m->nb_segs || m->nb_segs > r->object_count) return 0;
    const struct rte_mbuf *segment=m;
    uint64_t total=0;
    for(uint16_t i=0;i<m->nb_segs;i++){
        if(!known_pool_object(r,segment))return 0;
        if(segment->pool!=r->pool || rte_mbuf_refcnt_read(segment)!=1 ||
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
    if(r->pidfd[g]<0||!same_identity(&r->registered[g],owner))return -ESTALE;
    int n;
    struct pollfd pfd={.fd=r->pidfd[g],.events=POLLIN};
    do n=poll(&pfd,1,0);while(n<0&&errno==EINTR);if(n<=0||!(pfd.revents&POLLIN))return n<0?-errno:-EBUSY;
    size_t count_rings=ring_count(r);
    if(count_rings>SIZE_MAX/2 || count_rings*2>SIZE_MAX/sizeof(struct reap_ring_batch) ||
        count_rings>SIZE_MAX/sizeof(uint64_t)) return -EOVERFLOW;
    size_t batch_count=count_rings*2;
    struct reap_ring_batch *batches=calloc(batch_count,sizeof(*batches));
    uint64_t *tx_drops=calloc(count_rings,sizeof(*tx_drops));
    unsigned char *claimed=calloc(r->object_count,sizeof(*claimed));
    if(!batches||!tx_drops||!claimed){free(batches);free(tx_drops);free(claimed);return -ENOMEM;}
    rte_spinlock_lock(&r->directory->lock);
    atomic_store_explicit(&r->gate[0],1,memory_order_release);
    atomic_store_explicit(&r->gate[1],1,memory_order_release);
    for(uint16_t p=0;p<r->ports;p++)for(uint16_t q=0;q<r->queues;q++)
        atomic_store_explicit(&r->admitted[coord_index(r,p,q,g)],0,memory_order_release);
    struct timespec wait_until,wait_now,wait_nap={.tv_nsec=1000000};
    if(clock_gettime(CLOCK_MONOTONIC,&wait_until)){
        int error=-errno;rte_spinlock_unlock(&r->directory->lock);free(batches);free(tx_drops);free(claimed);return error;
    }
    wait_until.tv_sec+=1;
    for(;;){
        bool busy=false;
        for(unsigned actor=0;actor<2;actor++)if(actor!=g)
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
    atomic_store_explicit(&r->active[g*2],0,memory_order_release);
    atomic_store_explicit(&r->active[g*2+1],0,memory_order_release);
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
        if(ker_generation_test_corrupt_late_queued_rx(r,owner,0)) REAP_ABORT(-EUCLEAN);
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
        int dead_owner=same_identity(&j->owner,owner);
        int dead_producer=same_identity(&j->producer,owner);
        int reclaim=0;
        if(state==JOURNAL_QUEUED){
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
            if(tx)tx_drops[ring_slot]++;
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
    atomic_store_explicit(&r->gate[0],0,memory_order_release);
    atomic_store_explicit(&r->gate[1],0,memory_order_release);
    rte_spinlock_unlock(&r->directory->lock);
    free(batches);free(tx_drops);free(claimed);
    close(r->pidfd[g]);r->pidfd[g]=-1;memset(&r->registered[g],0,sizeof(r->registered[g]));
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
    for(size_t i=0;i<ring_count(r);i++){rte_ring_free(r->rx[i]);rte_ring_free(r->tx[i]);}
    atomic_store(&r->directory->ready,0);rte_spinlock_unlock(&r->directory->lock);
    for(unsigned g=0;g<2;g++)if(r->pidfd[g]>=0)close(r->pidfd[g]);
    rte_memzone_free(rte_memzone_lookup(DIRECTORY_NAME));free(r->objects);free(r->rx);free(r->tx);free(r);return 0;
}
