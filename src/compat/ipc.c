/* Ker-owned lifetime/symbol adapter around the unchanged upstream client.
 * Include its translation unit to adapt private EAL lifetime state and track
 * the origin ring for upstream-stashed replies without patching imported code. */
#define _GNU_SOURCE
#include <ker/ipc.h>
#include <errno.h>
#include <limits.h>
#include <rte_errno.h>
#include <rte_ring.h>
static int ker_ipc_ring_enqueue_tracked(struct rte_ring *ring, void *object);
/* Interpose only this imported translation unit; the wrapper calls real DPDK. */
#define rte_ring_enqueue ker_ipc_ring_enqueue_tracked
#include "ff_ipc.c"
#undef rte_ring_enqueue

#define KER_IPC_STASH_ORIGINS (FF_IPC_STASH_MAX + 1)
static struct {
    struct ff_msg *message;
    struct rte_ring *ring;
} ker_ipc_stash_origins[KER_IPC_STASH_ORIGINS];

#ifdef KER_IPC_TESTING
static void (*ker_ipc_test_enqueue_hook)(struct rte_ring *, void *);

void ker_ipc_test_set_enqueue_hook(void (*hook)(struct rte_ring *, void *))
{
    ker_ipc_test_enqueue_hook = hook;
}
#endif

static int ker_ipc_stash_index(const void *object)
{
    for (int i = 0; i < ff_ipc_stash_n; ++i)
        if (ff_ipc_stash[i] == object) return i;
    return -1;
}

static int ker_ipc_stash_origin_index(const struct ff_msg *message)
{
    for (int i = 0; i < KER_IPC_STASH_ORIGINS; ++i)
        if (ker_ipc_stash_origins[i].message == message) return i;
    return -1;
}

static void ker_ipc_stash_origin_forget(const struct ff_msg *message)
{
    int i = ker_ipc_stash_origin_index(message);
    if (i >= 0) {
        ker_ipc_stash_origins[i].message = NULL;
        ker_ipc_stash_origins[i].ring = NULL;
    }
}

static void ker_ipc_stash_origins_prune(void)
{
    for (int i = 0; i < KER_IPC_STASH_ORIGINS; ++i) {
        struct ff_msg *message = ker_ipc_stash_origins[i].message;
        if (message && ker_ipc_stash_index(message) < 0) {
            ker_ipc_stash_origins[i].message = NULL;
            ker_ipc_stash_origins[i].ring = NULL;
        }
    }
}

static int ker_ipc_stash_origin_remember(struct ff_msg *message, struct rte_ring *ring)
{
    int i = ker_ipc_stash_origin_index(message);
    if (i < 0) {
        for (i = 0; i < KER_IPC_STASH_ORIGINS; ++i)
            if (!ker_ipc_stash_origins[i].message) break;
        if (i == KER_IPC_STASH_ORIGINS) return -ENOBUFS;
    }
    ker_ipc_stash_origins[i].message = message;
    ker_ipc_stash_origins[i].ring = ring;
    return 0;
}

/* Preserve exact origin-ring ownership for the upstream bounded reply stash. */
static int ker_ipc_ring_enqueue_tracked(struct rte_ring *ring, void *object)
{
    ker_ipc_stash_origins_prune();
    struct ff_msg *message = object;
    int stashed = ker_ipc_stash_index(message) >= 0;
    int origin = ker_ipc_stash_origin_index(message);
    struct rte_ring *destination = ring;

    if (stashed) {
        /* Missing provenance must never route a reply to an unrelated ring. */
        if (origin < 0 || !ker_ipc_stash_origins[origin].ring) return -ENOBUFS;
        destination = ker_ipc_stash_origins[origin].ring;
    }

#ifdef KER_IPC_TESTING
    if (ker_ipc_test_enqueue_hook)
        ker_ipc_test_enqueue_hook(destination, object);
#endif
    int result = rte_ring_enqueue(destination, object);
    if (result == 0) {
        if (stashed) ker_ipc_stash_origin_forget(message);
    } else if (!stashed) {
        /* Tentative until the next enqueue confirms stash membership. This
         * also safely discards ordinary failed send/probe enqueues. */
        (void)ker_ipc_stash_origin_remember(message, ring);
    }
    return result;
}

static int eal_ready(void)
{
    enum rte_proc_type_t role = rte_eal_process_type();
    return role == RTE_PROC_PRIMARY || role == RTE_PROC_SECONDARY;
}
/* Reject wide-number truncation before the upstream int setters. */
static void argument_or_exit(const char *text, unsigned first_limit, unsigned maximum_parts)
{
    for (unsigned part = 0; ; ++part) {
        char *end;
        errno = 0;
        unsigned long long value = strtoull(text, &end, 10);
        unsigned long long limit = part == 0 ? first_limit :
            maximum_parts == 3 && part == 1 ? FF_RELOAD_GEN_MAX-1 : FF_RELOAD_EPOCH_NONE-1ULL;
        if (part >= maximum_parts || end == text || errno == ERANGE || value > limit ||
            (*end && *end != ':')) {
            fprintf(stderr, "ker ipc: invalid coordinate\n"); exit(1);
        }
        if (!*end) return;
        text = end + 1;
    }
}
int ker_ipc_select_or_exit(const char *process, const char *generation)
{
    if (inited) return -EBUSY;
    if (process) argument_or_exit(process, 65535, 3);
    if (generation) argument_or_exit(generation, FF_RELOAD_GEN_MAX-1, 2);
    ff_proc_id = 0;
    ff_gen_arg = FF_IPC_GEN_AUTO;
    ff_ring_gen = FF_IPC_GEN_AUTO;
    ff_epoch_arg = FF_RELOAD_EPOCH_NONE;
    ff_ring_epoch = 0;
    if (process) ff_set_proc_id_str(process);
    if (generation) ff_set_gen_str(generation);
    return ff_proc_id;
}
int ker_ipc_epoch_or_exit(uint32_t epoch)
{
    if (inited) return -EBUSY;
    ff_set_epoch(epoch);
    return 0;
}
int ker_ipc_address(struct ker_ipc_address *address)
{
    if (!address) return -EINVAL;
    *address = (struct ker_ipc_address){ff_proc_id, ff_gen_arg, ff_epoch_arg};
    return 0;
}
unsigned ker_ipc_epoch_slot(uint32_t epoch) { return ff_reload_epoch_slot_of(epoch); }
int ker_ipc_format_ring(char *buffer, size_t size, const struct ker_ipc_address *address,
    int output, enum FF_MSG_TYPE type, int generation_aware)
{
    if (!address || !buffer || !size || size > UINT_MAX ||
        (output != 0 && output != 1) || (generation_aware != 0 && generation_aware != 1) ||
        (output && (type < FF_UNKNOWN || type >= FF_MSG_NUM))) return -EINVAL;
    if (generation_aware && (address->generation < 0 || address->generation >= FF_RELOAD_GEN_MAX))
        return -EINVAL;
    return ff_msg_ring_name(buffer, (unsigned)size, output ? FF_MSG_RING_OUT : FF_MSG_RING_IN,
        address->process, output ? (int)type : -1, address->generation, address->epoch, generation_aware);
}
int ker_ipc_ring_name(char *buffer, size_t size, int output, enum FF_MSG_TYPE type)
{
    if (!buffer || !size || size > UINT_MAX || (output != 0 && output != 1) ||
        (output && (type < FF_UNKNOWN || type >= FF_MSG_NUM))) return -EINVAL;
    const char *base = output ? FF_MSG_RING_OUT : FF_MSG_RING_IN;
    int message_type = output ? (int)type : -1;
    if (inited) return ff_ipc_ring_name(buffer, (unsigned)size, base, message_type);
    if (ff_gen_arg == FF_IPC_GEN_AUTO) return -EAGAIN;
    struct ker_ipc_address address = {ff_proc_id, ff_gen_arg, ff_epoch_arg};
    return ker_ipc_format_ring(buffer, size, &address, output, type, 1);
}
static void initialize_message(struct rte_mempool *pool, void *opaque, void *object, unsigned index)
{
    (void)opaque; (void)index;
    memset(object, 0, pool->elt_size);
    struct ff_msg *message = object;
    message->buf_addr = (char *)object + sizeof(*message);
    message->buf_len = pool->elt_size - sizeof(*message);
}
struct rte_mempool *ker_ipc_pool_create(const char *name, unsigned count, unsigned payload)
{
    if (!eal_ready() || !name || !count || payload > MAX_MSG_BUF_SIZE) {
        rte_errno = EINVAL; return NULL;
    }
    return rte_mempool_create(name, count, sizeof(struct ff_msg) + payload, 0, 0,
        NULL, NULL, initialize_message, NULL, SOCKET_ID_ANY, 0);
}
int ker_ipc_attach(struct rte_mempool *pool)
{
    if (inited) return -EBUSY;
    if (!eal_ready() || !pool || pool->cache_size || pool->elt_size < sizeof(struct ff_msg)) return -EINVAL;
    if (ff_gen_arg == FF_IPC_GEN_AUTO) {
        char legacy[RTE_RING_NAMESIZE];
        struct ker_ipc_address primary = {0, 0, 0};
        if (ker_ipc_format_ring(legacy, sizeof(legacy), &primary, 0, FF_UNKNOWN, 0) ||
            !rte_ring_lookup(legacy)) return -EOPNOTSUPP;
    }
    message_pool = pool;
    ff_pending_msg = NULL;
    ff_ipc_stash_n = 0;
    memset(ff_ipc_stash, 0, sizeof(ff_ipc_stash));
    memset(ker_ipc_stash_origins, 0, sizeof(ker_ipc_stash_origins));
    memset(ff_ipc_foreign, 0, sizeof(ff_ipc_foreign));
    ff_ipc_foreign_requeued = ff_ipc_orphan_dropped = ff_ipc_reply_lost = 0;
    inited = 1;
    return 0;
}
int ker_ipc_detach(void)
{
    if (!inited) return 0;
    if (ff_pending_msg || ff_ipc_stash_n || rte_mempool_in_use_count(message_pool)) return -EBUSY;
    inited = 0;
    message_pool = NULL;
    memset(ker_ipc_stash_origins, 0, sizeof(ker_ipc_stash_origins));
    ff_ring_gen = FF_IPC_GEN_AUTO;
    ff_ring_epoch = 0;
    return 0;
}
ker_ipc_message *ker_ipc_alloc(void)
{
    if (!inited) { errno = ENOTCONN; return NULL; }
    ker_ipc_message *message = ff_ipc_msg_alloc();
    if (message) ker_ipc_stash_origin_forget(message);
    return message;
}
int ker_ipc_free(ker_ipc_message *message)
{
    if (!inited) return -ENOTCONN;
    if (!message || message->ipc_owner_pid != (uint32_t)getpid() ||
        !message->ipc_cookie || rte_mempool_from_obj(message) != message_pool) return -EINVAL;
    if (message == ff_pending_msg) return -EBUSY;
    ker_ipc_stash_origin_forget(message);
    return ff_ipc_msg_free(message);
}
int ker_ipc_send(const ker_ipc_message *message)
{
    if (!inited) return -ENOTCONN;
    if (!message || message->ipc_owner_pid != (uint32_t)getpid() ||
        !message->ipc_cookie || rte_mempool_from_obj((void *)message) != message_pool) return -EINVAL;
    if (ff_pending_msg) return -EBUSY;
    return ff_ipc_send(message);
}
int ker_ipc_recv(ker_ipc_message **message, enum FF_MSG_TYPE type)
{
    if (!inited) return -ENOTCONN;
    if (!message || type < FF_UNKNOWN || type >= FF_MSG_NUM) return -EINVAL;
    return ff_ipc_recv(message, type);
}
int ker_ipc_probe(uint32_t *epoch, int *generation)
{
    if (!inited) return -ENOTCONN;
    if (ff_proc_id) return -EOPNOTSUPP;
    if (ff_pending_msg || ff_ipc_stash_n) return -EBUSY;
    return ff_ipc_probe_coord(epoch, generation);
}
void ker_ipc_reply_stats(uint64_t *requeued, uint64_t *orphan, uint64_t *lost)
{
    ff_ipc_reply_stats(requeued, orphan, lost);
}
