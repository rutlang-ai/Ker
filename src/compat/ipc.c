/* Ker-owned lifetime/symbol adapter around the unchanged upstream client.
 * Include its translation unit to adapt private EAL lifetime state without
 * patching the imported source or duplicating the reply-ownership algorithm. */
#define _GNU_SOURCE
#include <ker/ipc.h>
#include <errno.h>
#include <limits.h>
#include <rte_errno.h>
#include "ff_ipc.c"

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
int ker_ipc_ring_name(char *buffer, size_t size, int output, enum FF_MSG_TYPE type)
{
    if (!buffer || !size || size > UINT_MAX || (output != 0 && output != 1) ||
        (output && (type < FF_UNKNOWN || type >= FF_MSG_NUM))) return -EINVAL;
    const char *base = output ? FF_MSG_RING_OUT : FF_MSG_RING_IN;
    int message_type = output ? type : -1;
    if (inited) return ff_ipc_ring_name(buffer, (unsigned)size, base, message_type);
    if (ff_gen_arg == FF_IPC_GEN_AUTO) return -EAGAIN;
    return ff_msg_ring_name(buffer, (unsigned)size, base, ff_proc_id, message_type,
        ff_gen_arg, ff_epoch_arg, 1);
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
    if (ff_gen_arg == FF_IPC_GEN_AUTO) return -EOPNOTSUPP;
    message_pool = pool;
    ff_pending_msg = NULL;
    ff_ipc_stash_n = 0;
    memset(ff_ipc_stash, 0, sizeof(ff_ipc_stash));
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
    ff_ring_gen = FF_IPC_GEN_AUTO;
    ff_ring_epoch = 0;
    return 0;
}
ker_ipc_message *ker_ipc_alloc(void)
{
    if (!inited) { errno = ENOTCONN; return NULL; }
    return ff_ipc_msg_alloc();
}
int ker_ipc_free(ker_ipc_message *message)
{
    if (!inited) return -ENOTCONN;
    if (!message || message->ipc_owner_pid != (uint32_t)getpid() ||
        !message->ipc_cookie || rte_mempool_from_obj(message) != message_pool) return -EINVAL;
    if (message == ff_pending_msg) return -EBUSY;
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
