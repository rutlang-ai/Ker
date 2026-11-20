#define _GNU_SOURCE
#include <ker/ipc.h>
#include "check.h"
#include "eal.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <rte_mempool.h>
#include <rte_ring.h>

enum { MESSAGE_COUNT = 64, PAYLOAD_SIZE = 64 };
static struct rte_mempool *pool;
static struct rte_ring *input_ring;
static struct rte_ring *output_ring;

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
}

static void teardown(void)
{
    CHECK(rte_ring_empty(input_ring) && rte_ring_empty(output_ring));
    CHECK(ker_ipc_detach() == 0 && ker_ipc_detach() == 0);
    CHECK(rte_mempool_avail_count(pool) == MESSAGE_COUNT);
    CHECK(rte_mempool_in_use_count(pool) == 0);
    rte_ring_free(input_ring);
    rte_ring_free(output_ring);
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

int main(int argc, char **argv)
{
    CHECK(argc == 2 && strcmp(argv[1], "own-reply") == 0);
    setup();
    own_reply();
    teardown();
    return 0;
}
