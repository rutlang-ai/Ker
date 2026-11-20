#define _GNU_SOURCE
#include <ker/ipc.h>
#include "check.h"
#include "eal.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <rte_mempool.h>
#include <rte_ring.h>

enum { MESSAGE_COUNT = 64, PAYLOAD_SIZE = 64 };
static struct rte_mempool *pool;
static struct rte_ring *input_ring;
static struct rte_ring *output_ring;
static struct rte_ring *reload_ring;

static struct rte_ring *create_ring(int output, enum FF_MSG_TYPE type)
{
    char name[RTE_RING_NAMESIZE];
    CHECK(ker_ipc_ring_name(name, sizeof(name), output, type) == 0);
    struct rte_ring *ring = rte_ring_create(name, 32, SOCKET_ID_ANY, 0);
    CHECK(ring != NULL && rte_ring_lookup(name) == ring);
    CHECK(!rte_ring_is_prod_single(ring) && !rte_ring_is_cons_single(ring));
    return ring;
}

static void setup(void)
{
    CHECK(ker_ipc_alloc() == NULL && errno == ENOTCONN);
    CHECK(ker_ipc_select_or_exit("0:0", NULL) == 0);
    ker_test_eal_init();
    pool = ker_ipc_pool_create("ker_ipc_case_pool", MESSAGE_COUNT, PAYLOAD_SIZE);
    CHECK(pool != NULL && rte_mempool_avail_count(pool) == MESSAGE_COUNT);
    CHECK(ker_ipc_attach(pool) == 0);
    CHECK(ker_ipc_attach(pool) == -EBUSY);
    input_ring = create_ring(0, FF_UNKNOWN);
    output_ring = create_ring(1, FF_SYSCTL);
    reload_ring = create_ring(1, FF_RELOAD);
}

static void teardown(void)
{
    CHECK(rte_ring_empty(input_ring) && rte_ring_empty(output_ring));
    CHECK(ker_ipc_detach() == 0 && ker_ipc_detach() == 0);
    CHECK(rte_mempool_avail_count(pool) == MESSAGE_COUNT);
    CHECK(rte_mempool_in_use_count(pool) == 0);
    rte_ring_free(input_ring);
    rte_ring_free(output_ring);
    CHECK(rte_ring_empty(reload_ring));
    rte_ring_free(reload_ring);
    rte_mempool_free(pool);
    CHECK(rte_eal_cleanup() == 0);
    CHECK(ker_ipc_alloc() == NULL && errno == ENOTCONN);
}

static ker_ipc_message *allocate(void)
{
    ker_ipc_message *message = ker_ipc_alloc();
    CHECK(message != NULL);
    CHECK(message->ipc_owner_pid == (uint32_t)getpid() && message->ipc_cookie != 0);
    CHECK(message->buf_len >= PAYLOAD_SIZE);
    CHECK(message->buf_addr == (char *)message + sizeof(*message));
    return message;
}

static void own_reply(void)
{
    static const char payload[] = "owned-request";
    ker_ipc_message *request = allocate();
    request->msg_type = FF_SYSCTL;
    memcpy(request->buf_addr, payload, sizeof(payload));
    CHECK(ker_ipc_send(request) == 0);
    CHECK(ker_ipc_free(request) == -EBUSY && ker_ipc_detach() == -EBUSY);

    void *object;
    CHECK(rte_ring_dequeue(input_ring, &object) == 0 && object == request);
    CHECK(memcmp(request->buf_addr, payload, sizeof(payload)) == 0);
    CHECK(rte_ring_enqueue(output_ring, object) == 0);

    ker_ipc_message *reply = (void *)(uintptr_t)1;
    CHECK(ker_ipc_recv(&reply, FF_SYSCTL) == 0 && reply == request);
    CHECK(memcmp(reply->buf_addr, payload, sizeof(payload)) == 0);
    CHECK(ker_ipc_free(reply) == 0);

    uint64_t requeued = 1, orphaned = 1, lost = 1;
    ker_ipc_reply_stats(&requeued, &orphaned, &lost);
    CHECK(requeued == 0 && orphaned == 0 && lost == 0);
}


static const char foreign_payload[] = "foreign-owned";

static ker_ipc_message *foreign_reply(pid_t owner)
{
    ker_ipc_message *message = allocate();
    message->ipc_owner_pid = (uint32_t)owner;
    memcpy(message->buf_addr, foreign_payload, sizeof(foreign_payload));
    return message;
}

static void expect_foreign_requeue(void)
{
    ker_ipc_message *other = foreign_reply(getppid());
    CHECK(ker_ipc_free(other) == -EINVAL);
    CHECK(rte_ring_enqueue(output_ring, other) == 0);

    ker_ipc_message *reply = (void *)(uintptr_t)1;
    CHECK(ker_ipc_recv(&reply, FF_SYSCTL) < 0 && reply == (void *)(uintptr_t)1);
    uint64_t requeued = 0, orphaned = 1, lost = 1;
    ker_ipc_reply_stats(&requeued, &orphaned, &lost);
    CHECK(requeued >= 1 && orphaned == 0 && lost == 0);
    CHECK(rte_ring_count(output_ring) == 1 && ker_ipc_detach() == -EBUSY);

    void *object;
    CHECK(rte_ring_dequeue(output_ring, &object) == 0 && object == other);
    CHECK(memcmp(other->buf_addr, foreign_payload, sizeof(foreign_payload)) == 0);
    rte_mempool_put(pool, other);
}

static void foreign_live(void)
{
    ker_ipc_message *request = allocate();
    request->msg_type = FF_SYSCTL;
    CHECK(ker_ipc_send(request) == 0);
    expect_foreign_requeue();

    /* The provider retains ownership of the queued request after timeout. */
    void *object;
    CHECK(rte_ring_dequeue(input_ring, &object) == 0 && object == request);
    rte_mempool_put(pool, request);
}


static void orphan_reply(void)
{
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0)
        _exit(0);
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    ker_ipc_message *other = foreign_reply(child);
    CHECK(rte_ring_enqueue(output_ring, other) == 0);

    ker_ipc_message *reply = (void *)(uintptr_t)1;
    CHECK(ker_ipc_recv(&reply, FF_SYSCTL) < 0 && reply == (void *)(uintptr_t)1);
    uint64_t requeued = 1, reclaimed = 0, lost = 1;
    ker_ipc_reply_stats(&requeued, &reclaimed, &lost);
    /* The original receiver confirms the dead owner across observations. */
    CHECK(requeued >= 1 && reclaimed == 1 && lost == 0);
    CHECK(rte_ring_empty(output_ring) && rte_mempool_avail_count(pool) == MESSAGE_COUNT);
}


static void assert_owned_query(const ker_ipc_message *query)
{
    CHECK(query->msg_type == FF_RELOAD && query->reload.cmd == FF_RELOAD_CMD_QUERY);
    CHECK(query->ipc_cookie != 0 && query->ipc_owner_pid == (uint32_t)getpid());
}

static void *answer_query(void *unused)
{
    (void)unused;
    struct timespec before;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    for (;;) {
        void *object;
        if (rte_ring_dequeue(input_ring, &object) == 0) {
            ker_ipc_message *query = object;
            assert_owned_query(query);
            query->result = 0;
            query->reload.active_gen = 1;
            query->reload.epoch = 3;
            CHECK(rte_ring_enqueue(reload_ring, query) == 0);
            return NULL;
        }

        struct timespec now;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK(now.tv_sec - before.tv_sec < 3);
        usleep(1000);
    }
}

static void probe_ownership(void)
{
    ker_ipc_message *other = foreign_reply(getppid());
    CHECK(rte_ring_enqueue(reload_ring, other) == 0);

    uint32_t epoch = 77;
    int generation = 77;
    CHECK(ker_ipc_probe(&epoch, &generation) < 0 && epoch == 77 && generation == 77);

    uint64_t reclaimed = 1, lost = 1;
    ker_ipc_reply_stats(NULL, &reclaimed, &lost);
    CHECK(reclaimed == 0 && lost == 0 && rte_ring_count(reload_ring) == 1);

    void *object;
    CHECK(rte_ring_dequeue(reload_ring, &object) == 0 && object == other);
    CHECK(memcmp(other->buf_addr, foreign_payload, sizeof(foreign_payload)) == 0);
    rte_mempool_put(pool, other);

    CHECK(rte_ring_count(input_ring) == 1);
    CHECK(rte_ring_dequeue(input_ring, &object) == 0);
    assert_owned_query(object);
    CHECK(ker_ipc_detach() == -EBUSY);
    rte_mempool_put(pool, object);

    pthread_t provider;
    CHECK(pthread_create(&provider, NULL, answer_query, NULL) == 0);
    CHECK(ker_ipc_probe(&epoch, &generation) == 0 && epoch == 3 && generation == 1);
    CHECK(pthread_join(provider, NULL) == 0);
    CHECK(rte_mempool_avail_count(pool) == MESSAGE_COUNT);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    setup();
    if (strcmp(argv[1], "own-reply") == 0)
        own_reply();
    else if (strcmp(argv[1], "foreign-live") == 0)
        foreign_live();
    else if (strcmp(argv[1], "foreign-no-send") == 0) {
        expect_foreign_requeue();
        CHECK(rte_ring_empty(input_ring));
    }
    else if (strcmp(argv[1], "orphan-reply") == 0)
        orphan_reply();
    else if (strcmp(argv[1], "probe-ownership") == 0)
        probe_ownership();
    else
        CHECK(0);
    teardown();
    return 0;
}
