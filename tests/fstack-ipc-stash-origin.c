/* Deterministic real-ring proof that a full-ring stash returns to its origin. */
#define _GNU_SOURCE
#include <ker/ipc.h>
#include "check.h"
#include "eal.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <rte_mempool.h>
#include <rte_ring.h>

void ker_ipc_test_set_enqueue_hook(void (*hook)(struct rte_ring *, void *));

#define POOL_SIZE 64
#define TARGET_COUNT 5
#define TARGET_STASHED 4

static struct rte_mempool *pool;
static struct rte_ring *sysctl_ring, *reload_ring;
static ker_ipc_message *targets[TARGET_COUNT];
static ker_ipc_message *fillers[TARGET_COUNT];
static uint32_t target_cookies[TARGET_COUNT];
static unsigned hook_next;

static struct rte_ring *create_reply_ring(enum FF_MSG_TYPE type)
{
    char name[RTE_RING_NAMESIZE];
    CHECK(!ker_ipc_ring_name(name, sizeof(name), 1, type));
    struct rte_ring *ring = rte_ring_create(name, 32, SOCKET_ID_ANY, 0);
    CHECK(ring && rte_ring_lookup(name) == ring);
    return ring;
}

static ker_ipc_message *make_foreign(const char *payload)
{
    ker_ipc_message *message = ker_ipc_alloc();
    CHECK(message && message->ipc_cookie);
    message->ipc_owner_pid = (uint32_t)getppid();
    message->msg_type = FF_SYSCTL;
    CHECK(strlen(payload) + 1 <= message->buf_len);
    strcpy(message->buf_addr, payload);
    return message;
}

static void occupy_freed_slot(struct rte_ring *ring, void *object)
{
    if (hook_next < TARGET_COUNT && ring == sysctl_ring && object == targets[hook_next]) {
        CHECK(!rte_ring_enqueue(ring, fillers[hook_next]));
        hook_next++;
    }
}

static void verify_targets_in_origin_ring(void)
{
    unsigned found[TARGET_COUNT] = {0};
    unsigned count = rte_ring_count(sysctl_ring);
    CHECK(count == rte_ring_get_capacity(sysctl_ring));
    for (unsigned i = 0; i < count; ++i) {
        void *object = NULL;
        CHECK(!rte_ring_dequeue(sysctl_ring, &object));
        ker_ipc_message *message = object;
        int matched = 0;
        for (unsigned t = 0; t < TARGET_COUNT; ++t) {
            if (message != targets[t]) continue;
            CHECK(t != 0); /* The bounded stash evicted exactly its oldest entry. */
            CHECK(!found[t]);
            CHECK(message->ipc_owner_pid == (uint32_t)getppid());
            CHECK(message->ipc_cookie == target_cookies[t]);
            CHECK(message->msg_type == FF_SYSCTL);
            char expected[32];
            CHECK(snprintf(expected, sizeof(expected), "target-%u", t) > 0);
            CHECK(!strcmp(message->buf_addr, expected));
            found[t] = 1;
            matched = 1;
        }
        CHECK(matched || message != targets[0]);
        rte_mempool_put(pool, object);
    }
    for (unsigned i = 1; i < TARGET_COUNT; ++i) CHECK(found[i]);
    CHECK(rte_ring_empty(reload_ring));
}

int main(void)
{
    CHECK(ker_ipc_select_or_exit("1:0", NULL) == 1);
    ker_test_eal_init();
    pool = ker_ipc_pool_create("ker_ipc_stash_origin_pool", POOL_SIZE, 64);
    CHECK(pool && !ker_ipc_attach(pool));
    sysctl_ring = create_reply_ring(FF_SYSCTL);
    reload_ring = create_reply_ring(FF_RELOAD);
    CHECK(rte_ring_get_capacity(sysctl_ring) >= 31);

    for (unsigned i = 0; i < TARGET_COUNT; ++i) {
        char payload[32];
        CHECK(snprintf(payload, sizeof(payload), "target-%u", i) > 0);
        targets[i] = make_foreign(payload);
        target_cookies[i] = targets[i]->ipc_cookie;
    }
    for (unsigned i = 0; i < 26; ++i) {
        char payload[32];
        CHECK(snprintf(payload, sizeof(payload), "initial-filler-%u", i) > 0);
        ker_ipc_message *message = make_foreign(payload);
        CHECK(!rte_ring_enqueue(sysctl_ring, message));
    }
    for (unsigned i = 0; i < TARGET_COUNT; ++i) {
        char payload[32];
        CHECK(snprintf(payload, sizeof(payload), "replacement-%u", i) > 0);
        fillers[i] = make_foreign(payload);
    }
    for (unsigned i = 0; i < TARGET_COUNT; ++i)
        CHECK(!rte_ring_enqueue(sysctl_ring, targets[i]));
    /* The full ring's 26 fillers cycle behind the five target replies. */
    CHECK(rte_ring_count(sysctl_ring) == rte_ring_get_capacity(sysctl_ring));

    ker_ipc_test_set_enqueue_hook(occupy_freed_slot);
    ker_ipc_message *received = (void *)(uintptr_t)1;
    CHECK(ker_ipc_recv(&received, FF_SYSCTL) == -ENOENT);
    ker_ipc_test_set_enqueue_hook(NULL);
    CHECK(received == (void *)(uintptr_t)1 && hook_next == TARGET_COUNT);
    CHECK(rte_ring_count(sysctl_ring) == rte_ring_get_capacity(sysctl_ring));
    CHECK(rte_ring_empty(reload_ring));
    CHECK(ker_ipc_detach() == -EBUSY);

    uint64_t requeued_before, orphan, lost;
    ker_ipc_reply_stats(&requeued_before, &orphan, &lost);
    CHECK(!orphan && lost == 1);

    /* A different-type receive must keep all four retained replies stashed. */
    CHECK(ker_ipc_recv(&received, FF_RELOAD) == -ENOENT);
    uint64_t requeued_after;
    ker_ipc_reply_stats(&requeued_after, &orphan, &lost);
    CHECK(requeued_after == requeued_before && !orphan && lost == 1);
    CHECK(rte_ring_empty(reload_ring));
    CHECK(rte_ring_count(sysctl_ring) == rte_ring_get_capacity(sysctl_ring));
    CHECK(ker_ipc_detach() == -EBUSY);

    /* Reclaim the evicted object plus four opened slots, exercising reuse. */
    for (unsigned i = 0; i < TARGET_STASHED; ++i) {
        void *object = NULL;
        CHECK(!rte_ring_dequeue(sysctl_ring, &object));
        CHECK(object != targets[0]);
        rte_mempool_put(pool, object);
    }
    CHECK(rte_mempool_avail_count(pool) == 33);
    ker_ipc_message *reused[33];
    unsigned saw_evicted_pointer = 0;
    for (unsigned i = 0; i < 33; ++i) {
        reused[i] = ker_ipc_alloc();
        CHECK(reused[i]);
        if (reused[i] == targets[0]) saw_evicted_pointer = 1;
    }
    CHECK(saw_evicted_pointer);
    for (unsigned i = 0; i < 33; ++i) CHECK(!ker_ipc_free(reused[i]));

    /* Flush must route across message types to the exact original ring. */
    CHECK(ker_ipc_recv(&received, FF_RELOAD) == -ENOENT);
    CHECK(rte_ring_empty(reload_ring));
    ker_ipc_reply_stats(&requeued_after, &orphan, &lost);
    CHECK(requeued_after == requeued_before + TARGET_STASHED && !orphan && lost == 1);
    verify_targets_in_origin_ring();
    CHECK(rte_mempool_avail_count(pool) == POOL_SIZE);
    CHECK(!ker_ipc_detach());
    rte_ring_free(sysctl_ring);
    rte_ring_free(reload_ring);
    rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    puts("PASS: stashed foreign replies return to their original reply ring");
    return 0;
}
