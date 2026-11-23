#include <ker/pools.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include "ff_config.h"
#include "ff_msg.h"
struct ff_config ff_global_cfg;
/* Exact original constants/helpers/selector globals and functions, with their
 * full unchanged sources retained. No FreeBSD packet implementation linked. */
#include "pool-runtime.inc"
static int bank_attached;

static int eal_ready(void)
{
    enum rte_proc_type_t role = rte_eal_process_type();
    return rte_lcore_count() && (role == RTE_PROC_PRIMARY || role == RTE_PROC_SECONDARY);
}
static void initialize_message(struct rte_mempool *pool, void *opaque,
    void *object, unsigned index)
{
    (void)opaque; (void)index;
    memset(object, 0, pool->elt_size);
    struct ff_msg *message = object;
    message->buf_addr = (char *)object + sizeof(*message);
    message->buf_len = pool->elt_size - sizeof(*message);
}
struct rte_mempool *ker_pool_create(const struct ker_pool_config *config)
{
    if (!eal_ready() || !config || !config->name || !config->count ||
        (config->shared != 0 && config->shared != 1)) {
        rte_errno = EINVAL; return NULL;
    }
    unsigned legacy;
    switch (config->kind) {
    case KER_POOL_MBUF:
        if (config->size > UINT16_MAX || config->size <= RTE_PKTMBUF_HEADROOM) {
            rte_errno = EINVAL; return NULL;
        }
        return rte_pktmbuf_pool_create(config->name, config->count,
            ff_shared_pool_cache_size(config->shared, MEMPOOL_CACHE_SIZE), 0,
            (uint16_t)config->size, config->socket);
    case KER_POOL_MESSAGE:
        if (config->size > MAX_MSG_BUF_SIZE) { rte_errno = EINVAL; return NULL; }
        legacy = MSG_RING_SIZE / 2;
        return rte_mempool_create(config->name, config->count,
            sizeof(struct ff_msg) + config->size,
            ff_shared_pool_cache_size(config->shared, legacy), 0,
            NULL, NULL, initialize_message, NULL, config->socket, 0);
    case KER_POOL_REFERENCE:
        if (!config->size) { rte_errno = EINVAL; return NULL; }
        return rte_mempool_create(config->name, config->count, config->size,
            ff_shared_pool_cache_size(config->shared, MEMPOOL_CACHE_SIZE), 0,
            NULL, NULL, NULL, NULL, config->socket, 0);
    default: rte_errno = EINVAL; return NULL;
    }
}
int ker_mbuf_generation_name(char *buffer, size_t size, int socket, int generation)
{
    if (!buffer || !size || size > UINT_MAX) return -1;
    return ff_mbuf_gen_pool_name(buffer, (unsigned)size, socket, generation);
}
int ker_mbuf_bank_attach(int shared)
{
    if (bank_attached) return -EBUSY;
    if (!eal_ready()) return -ENODEV;
    if (shared != 0 && shared != 1) return -EINVAL;
    ff_global_cfg.dpdk.graceful_reload = shared;
    bank_attached = 1;
    return 0;
}
static int busy(struct rte_mempool *pool)
{
    return pool && rte_mempool_in_use_count(pool);
}
static int valid_mbuf_pool(struct rte_mempool *pool)
{
    return !pool || (pool->private_data_size >= sizeof(struct rte_pktmbuf_pool_private) &&
        rte_pktmbuf_data_room_size(pool) > RTE_PKTMBUF_HEADROOM &&
        (!ff_global_cfg.dpdk.graceful_reload || !pool->cache_size));
}
int ker_mbuf_bank_bind(unsigned socket, struct rte_mempool *legacy,
    struct rte_mempool *gen0, struct rte_mempool *gen1)
{
    if (!bank_attached) return -ENOTCONN;
    if (socket >= NB_SOCKETS || !valid_mbuf_pool(legacy) ||
        !valid_mbuf_pool(gen0) || !valid_mbuf_pool(gen1)) return -EINVAL;
    if (busy(pktmbuf_pool[socket]) || busy(app_pktmbuf_pool[0][socket]) ||
        busy(app_pktmbuf_pool[1][socket])) return -EBUSY;
    pktmbuf_pool[socket] = legacy;
    app_pktmbuf_pool[0][socket] = gen0;
    app_pktmbuf_pool[1][socket] = gen1;
    return 0;
}
void ker_mbuf_bank_select(int generation) { ff_app_mbuf_set_gen(generation); }
struct rte_mempool *ker_mbuf_bank_pool(unsigned socket)
{
    if (!bank_attached) { errno = ENOTCONN; return NULL; }
    if (socket >= NB_SOCKETS) { errno = EINVAL; return NULL; }
    struct rte_mempool *pool = ff_app_mbuf_pool(socket);
    if (!pool) errno = ENOENT;
    return pool;
}
struct rte_mbuf *ker_mbuf_bank_alloc(unsigned socket)
{
    struct rte_mempool *pool = ker_mbuf_bank_pool(socket);
    return pool ? rte_pktmbuf_alloc(pool) : NULL;
}
int ker_mbuf_bank_detach(void)
{
    if (!bank_attached) return -ENOTCONN;
    for (unsigned socket = 0; socket < NB_SOCKETS; ++socket)
        if (busy(pktmbuf_pool[socket]) || busy(app_pktmbuf_pool[0][socket]) ||
            busy(app_pktmbuf_pool[1][socket])) return -EBUSY;
    memset(pktmbuf_pool, 0, sizeof(pktmbuf_pool));
    memset(app_pktmbuf_pool, 0, sizeof(app_pktmbuf_pool));
    ff_app_mbuf_set_gen(0);
    ff_global_cfg.dpdk.graceful_reload = 0;
    bank_attached = 0;
    return 0;
}
