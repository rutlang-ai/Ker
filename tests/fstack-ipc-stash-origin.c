/* Deterministic real-ring proof that a full-ring stash returns to its origin. */
#define _GNU_SOURCE
#include <ker/ipc.h>
#include "check.h"
#include "eal.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
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
static struct rte_ring *probe_in0, *probe_in, *probe_out;
static ker_ipc_message *probe_target;
static int probe_response_ready;
static int probe_open_origin;

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

static void occupy_probe_slot(struct rte_ring *ring, void *object)
{
    if (ring == sysctl_ring && object == probe_target && !hook_next) {
        CHECK(!rte_ring_enqueue(ring, fillers[0]));
        hook_next = 1;
    }
}

static void *answer_probe(void *unused)
{
    (void)unused;
    for (unsigned attempt = 0; attempt < 5000; ++attempt) {
        void *object = NULL;
        if (rte_ring_dequeue(probe_in, &object) != 0) {
            usleep(1000);
            continue;
        }
        ker_ipc_message *query = object;
        query->result = 0;
        query->reload.active_gen = 0;
        query->reload.epoch = 1;
        if (probe_open_origin) {
            void *filler = NULL;
            CHECK(!rte_ring_dequeue(sysctl_ring, &filler));
            CHECK(filler != probe_target);
            rte_mempool_put(pool, filler);
        }
        CHECK(!rte_ring_enqueue(probe_out, query));
        probe_response_ready = 1;
        return NULL;
    }
    CHECK(0 && "probe responder timed out");
    return NULL;
}

static void create_probe_rings(void)
{
    struct ker_ipc_address address = {0, 0, 0};
    char name[RTE_RING_NAMESIZE];
    CHECK(!ker_ipc_format_ring(name, sizeof(name), &address, 0, FF_UNKNOWN, 1));
    probe_in0 = rte_ring_create(name, 32, SOCKET_ID_ANY, 0);
    CHECK(probe_in0);
    CHECK(!ker_ipc_format_ring(name, sizeof(name), &address, 1, FF_RELOAD, 1));
    sysctl_ring = rte_ring_create(name, 32, SOCKET_ID_ANY, 0);
    CHECK(sysctl_ring);
    address.epoch = 1;
    CHECK(!ker_ipc_format_ring(name, sizeof(name), &address, 0, FF_UNKNOWN, 1));
    probe_in = rte_ring_create(name, 32, SOCKET_ID_ANY, 0);
    CHECK(probe_in);
    CHECK(!ker_ipc_format_ring(name, sizeof(name), &address, 1, FF_RELOAD, 1));
    probe_out = rte_ring_create(name, 32, SOCKET_ID_ANY, 0);
    CHECK(probe_out);
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

    /* Probe can stash on one candidate and succeed on another. The next
     * probe must recover that reply after origin capacity opens. */
    CHECK(ker_ipc_select_or_exit("0:0", "0") == 0);
    CHECK(!ker_ipc_epoch_or_exit(0));
    pool = ker_ipc_pool_create("ker_ipc_probe_stash_pool", POOL_SIZE, 64);
    CHECK(pool && !ker_ipc_attach(pool));
    hook_next = 0;
    probe_response_ready = 0;
    create_probe_rings();
    /* The pending guard must preserve the ordinary send/receive ownership
     * contract even while probe rings are available. */
    ker_ipc_message *pending = ker_ipc_alloc();
    CHECK(pending);
    pending->msg_type = FF_RELOAD;
    CHECK(!ker_ipc_send(pending));
    void *pending_object = NULL;
    CHECK(!rte_ring_dequeue(probe_in0, &pending_object) && pending_object == pending);
    CHECK(!rte_ring_enqueue(sysctl_ring, pending_object));
    CHECK(ker_ipc_probe(NULL, NULL) == -EBUSY);
    ker_ipc_message *pending_reply = NULL;
    int pending_recv_rc = ker_ipc_recv(&pending_reply, FF_RELOAD);
    CHECK(!pending_recv_rc && pending_reply == pending);
    CHECK(!ker_ipc_free(pending_reply));
    probe_target = make_foreign("probe-origin");
    target_cookies[0] = probe_target->ipc_cookie;
    CHECK(!rte_ring_enqueue(sysctl_ring, probe_target));
    for (unsigned i = 0; i < 30; ++i) {
        ker_ipc_message *filler = make_foreign("probe-filler");
        CHECK(!rte_ring_enqueue(sysctl_ring, filler));
    }
    CHECK(rte_ring_count(sysctl_ring) == rte_ring_get_capacity(sysctl_ring));
    fillers[0] = make_foreign("probe-slot-filler");
    ker_ipc_test_set_enqueue_hook(occupy_probe_slot);
    pthread_t responder;
    probe_open_origin = 1;
    CHECK(!pthread_create(&responder, NULL, answer_probe, NULL));
    uint32_t found_epoch = UINT32_MAX;
    int found_generation = -1;
    CHECK(!ker_ipc_probe(&found_epoch, &found_generation));
    CHECK(found_epoch == 1 && found_generation == 0);
    CHECK(!pthread_join(responder, NULL));
    probe_open_origin = 0;
    ker_ipc_test_set_enqueue_hook(NULL);
    CHECK(hook_next == 1 && probe_response_ready && rte_ring_count(sysctl_ring) == rte_ring_get_capacity(sysctl_ring));
    /* The post-probe flush returned the reply during the probe after the
     * responder opened origin capacity. */
    unsigned target_seen = 0;
    unsigned origin_count = rte_ring_count(sysctl_ring);
    for (unsigned i = 0; i < origin_count; ++i) {
        void *entry = NULL;
        CHECK(!rte_ring_dequeue(sysctl_ring, &entry));
        if (entry == probe_target) target_seen = 1;
        CHECK(!rte_ring_enqueue(sysctl_ring, entry));
    }
    CHECK(target_seen);

    /* A later probe can stash the same target again when its origin becomes
     * full between dequeue and requeue. */
    fillers[0] = make_foreign("probe-slot-filler-again");
    hook_next = 0;
    ker_ipc_test_set_enqueue_hook(occupy_probe_slot);
    probe_response_ready = 0;
    CHECK(!pthread_create(&responder, NULL, answer_probe, NULL));
    CHECK(!ker_ipc_probe(&found_epoch, &found_generation));
    CHECK(!pthread_join(responder, NULL));
    ker_ipc_test_set_enqueue_hook(NULL);
    CHECK(ker_ipc_probe(&found_epoch, &found_generation) == -EBUSY);
    CHECK(ker_ipc_detach() == -EBUSY);

    void *object = NULL;
    CHECK(!rte_ring_dequeue(sysctl_ring, &object));
    CHECK(object != probe_target);
    rte_mempool_put(pool, object);
    uint64_t requeued_before_detach;
    ker_ipc_reply_stats(&requeued_before_detach, &orphan, &lost);
    CHECK(ker_ipc_detach() == -EBUSY);
    uint64_t requeued_after_detach;
    ker_ipc_reply_stats(&requeued_after_detach, &orphan, &lost);
    CHECK(requeued_after_detach == requeued_before_detach + 1 && !orphan && !lost);

    /* Detach returned the stashed reply to its now-available origin, but the
     * live foreign object still prevents pool teardown. Exercise probe's
     * subsequent full-ring stash and capacity-open retry independently. */
    fillers[0] = make_foreign("probe-slot-filler-final");
    hook_next = 0;
    ker_ipc_test_set_enqueue_hook(occupy_probe_slot);
    probe_response_ready = 0;
    CHECK(!pthread_create(&responder, NULL, answer_probe, NULL));
    CHECK(!ker_ipc_probe(&found_epoch, &found_generation));
    CHECK(!pthread_join(responder, NULL));
    ker_ipc_test_set_enqueue_hook(NULL);
    CHECK(ker_ipc_probe(&found_epoch, &found_generation) == -EBUSY);
    CHECK(ker_ipc_detach() == -EBUSY);
    CHECK(!rte_ring_dequeue(sysctl_ring, &object));
    CHECK(object != probe_target);
    rte_mempool_put(pool, object);
    CHECK(!pthread_create(&responder, NULL, answer_probe, NULL));
    CHECK(!ker_ipc_probe(&found_epoch, &found_generation));
    CHECK(!pthread_join(responder, NULL));
    CHECK(found_epoch == 1 && found_generation == 0);
    CHECK(rte_ring_count(sysctl_ring) == rte_ring_get_capacity(sysctl_ring));

    /* Detach flushes only after the pending guard and still observes every
     * reply as in-use until the origin owner actually reclaims it. */
    CHECK(ker_ipc_detach() == -EBUSY);
    unsigned saw_probe_target = 0;
    while (rte_ring_dequeue(sysctl_ring, &object) == 0) {
        if (object == probe_target) {
            ker_ipc_message *message = object;
            CHECK(message->ipc_cookie == target_cookies[0]);
            CHECK(message->ipc_owner_pid == (uint32_t)getppid());
            CHECK(!strcmp(message->buf_addr, "probe-origin"));
            saw_probe_target = 1;
        }
        rte_mempool_put(pool, object);
    }
    CHECK(saw_probe_target);
    while (rte_ring_dequeue(probe_in0, &object) == 0) CHECK(!ker_ipc_free(object));
    while (rte_ring_dequeue(probe_in, &object) == 0) CHECK(!ker_ipc_free(object));
    CHECK(rte_ring_empty(probe_out));
    CHECK(rte_mempool_avail_count(pool) == POOL_SIZE);
    CHECK(!ker_ipc_detach());
    rte_ring_free(probe_in0);
    rte_ring_free(probe_in);
    rte_ring_free(sysctl_ring);
    rte_ring_free(probe_out);
    rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    puts("PASS: receive and probe stashes return to their original reply rings");
    return 0;
}
