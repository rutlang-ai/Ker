#define _GNU_SOURCE
#include <ker/ipc.h>
#include "eal.h"
#include <errno.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { POOL_SIZE = 15, STASH_SIZE = 4, REPLIES = STASH_SIZE + 2 };

static _Thread_local struct {
    struct rte_ring *ring;
    ker_ipc_message *messages[REPLIES];
    pid_t owner;
    unsigned next;
} refill;

/* The pinned client checks liveness after dequeue and before requeue. Give
 * a provider deterministic access to the newly open slot at that point. */
int kill(pid_t pid, int signal)
{
    if (refill.ring && pid == refill.owner && signal == 0 && refill.next < REPLIES) {
        CHECK(rte_ring_enqueue(refill.ring, refill.messages[refill.next]) == 0);
        refill.next++;
    }
    return (int)syscall(SYS_kill, pid, signal);
}

static struct rte_ring *make_ring(int output, enum FF_MSG_TYPE type)
{
    char name[RTE_RING_NAMESIZE];
    CHECK(ker_ipc_ring_name(name, sizeof(name), output, type) == 0);
    struct rte_ring *ring = rte_ring_create(name, 1, SOCKET_ID_ANY, RING_F_EXACT_SZ);
    CHECK(ring);
    return ring;
}

static ker_ipc_message *dequeue(struct rte_ring *ring)
{
    void *object;
    CHECK(rte_ring_dequeue(ring, &object) == 0);
    return object;
}

static ker_ipc_message *make_reply(struct rte_mempool *pool, pid_t owner,
    enum FF_MSG_TYPE type, unsigned cookie)
{
    void *object;
    CHECK(rte_mempool_get(pool, &object) == 0);
    ker_ipc_message *reply = object;
    reply->ipc_owner_pid = (uint32_t)owner;
    reply->ipc_cookie = cookie;
    reply->msg_type = type;
    reply->result = (int)cookie;
    return reply;
}

static void check_orphan(struct rte_mempool *attached, struct rte_mempool *foreign)
{
    struct rte_ring *output = make_ring(1, FF_SYSCTL);
    pid_t owner = fork();
    CHECK(owner >= 0);
    if (owner == 0) _exit(0);
    int status;
    CHECK(waitpid(owner, &status, 0) == owner && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(kill(owner, 0) == -1 && errno == ESRCH);

    ker_ipc_message *orphan = make_reply(foreign, owner, FF_SYSCTL, 1);
    size_t original_length = orphan->buf_len;
    CHECK(rte_ring_enqueue(output, orphan) == 0);
    ker_ipc_message *reply = NULL;
    CHECK(ker_ipc_recv(&reply, FF_SYSCTL) == -ENOENT && reply == NULL);

    uint64_t dropped, lost;
    ker_ipc_reply_stats(NULL, &dropped, &lost);
    CHECK(dropped == 1 && lost == 0 && rte_ring_empty(output));
    CHECK(rte_mempool_avail_count(attached) == POOL_SIZE);
    void *objects[POOL_SIZE];
    CHECK(rte_mempool_get_bulk(foreign, objects, POOL_SIZE) == 0);
    CHECK(orphan->buf_len == original_length);
    CHECK(orphan->buf_addr == (char *)orphan + sizeof(*orphan));
    rte_mempool_put_bulk(foreign, objects, POOL_SIZE);
    CHECK(ker_ipc_detach() == 0);
    rte_ring_free(output);
}

static void reclaim_live_reply(struct rte_mempool *pool, struct rte_ring *ring, unsigned index)
{
    ker_ipc_message *reply = dequeue(ring);
    CHECK(reply == refill.messages[index]);
    CHECK(reply->ipc_owner_pid == (uint32_t)refill.owner);
    CHECK(reply->ipc_cookie == index + 1 && reply->result == (int)index + 1);
    rte_mempool_put(pool, reply);
}

static void check_backpressure(struct rte_mempool *foreign, int probe)
{
    enum FF_MSG_TYPE type = probe ? FF_RELOAD : FF_SYSCTL;
    enum FF_MSG_TYPE other_type = probe ? FF_SYSCTL : FF_RELOAD;
    struct rte_ring *input = make_ring(0, FF_UNKNOWN);
    struct rte_ring *output = make_ring(1, type);
    struct rte_ring *other_output = make_ring(1, other_type);

    refill.owner = getppid();
    CHECK(kill(refill.owner, 0) == 0);
    for (unsigned i = 0; i < REPLIES; ++i)
        refill.messages[i] = make_reply(foreign, refill.owner, type, i + 1);
    CHECK(rte_ring_enqueue(output, refill.messages[0]) == 0);
    refill.ring = output;
    refill.next = 1;

    ker_ipc_message *reply = NULL;
    if (probe) {
        CHECK(ker_ipc_probe(NULL, NULL) == -1);
        /* The test provider discards the expired QUERY and returns its buffer. */
        ker_ipc_message *query = dequeue(input);
        CHECK(query->msg_type == FF_RELOAD && query->reload.cmd == FF_RELOAD_CMD_QUERY);
        CHECK(ker_ipc_free(query) == 0);
    } else {
        CHECK(ker_ipc_recv(&reply, type) == -ENOENT && reply == NULL);
    }
    refill.ring = NULL;

    uint64_t requeued, dropped, lost;
    ker_ipc_reply_stats(&requeued, &dropped, &lost);
    CHECK(refill.next == STASH_SIZE + 1 && requeued == 0 && dropped == 0 && lost == 0);
    CHECK(rte_mempool_in_use_count(foreign) == REPLIES);
    CHECK(ker_ipc_detach() == -EBUSY);
    reclaim_live_reply(foreign, output, STASH_SIZE);

    /* Capacity on the original ring lets another receive proceed. */
    ker_ipc_message *request = ker_ipc_alloc();
    CHECK(request);
    request->msg_type = other_type;
    CHECK(ker_ipc_send(request) == 0);
    CHECK(dequeue(input) == request && rte_ring_enqueue(other_output, request) == 0);
    CHECK(ker_ipc_recv(&reply, other_type) == 0 && reply == request);
    CHECK(ker_ipc_free(reply) == 0);
    reclaim_live_reply(foreign, output, 0);

    for (unsigned i = 1; i < STASH_SIZE; ++i) {
        CHECK(ker_ipc_detach() == (i == STASH_SIZE - 1 ? 0 : -EBUSY));
        reclaim_live_reply(foreign, output, i);
    }
    rte_mempool_put(foreign, refill.messages[STASH_SIZE + 1]);
    ker_ipc_reply_stats(&requeued, &dropped, &lost);
    CHECK(requeued == STASH_SIZE && dropped == 0 && lost == 0);
    CHECK(rte_mempool_in_use_count(foreign) == 0);
    CHECK(rte_ring_empty(input) && rte_ring_empty(output) && rte_ring_empty(other_output));
    rte_ring_free(other_output);
    rte_ring_free(output);
    rte_ring_free(input);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    ker_test_eal_init();
    CHECK(ker_ipc_select_or_exit("0:0", NULL) == 0);
    struct rte_mempool *attached = ker_ipc_pool_create("ker_ipc_attached", POOL_SIZE, 128);
    struct rte_mempool *foreign = ker_ipc_pool_create("ker_ipc_foreign", POOL_SIZE, 512);
    CHECK(attached && foreign && attached->elt_size != foreign->elt_size);
    CHECK(ker_ipc_attach(attached) == 0);
    if (strcmp(argv[1], "orphan") == 0) {
        check_orphan(attached, foreign);
    } else {
        CHECK(strcmp(argv[1], "receive") == 0 || strcmp(argv[1], "probe") == 0);
        check_backpressure(foreign, strcmp(argv[1], "probe") == 0);
    }
    rte_mempool_free(foreign);
    rte_mempool_free(attached);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
