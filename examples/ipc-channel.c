/* Caller-owned EAL/pool/rings. The peer explicitly rejects an unsupported
 * command while the generic transport preserves bytes and reply ownership. */
#define _GNU_SOURCE
#include <ker/ipc.h>
#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr,"IPC example failed: %s\n",#x); exit(1); } } while(0)
int main(int argc, char **argv)
{
    REQUIRE(rte_eal_init(argc, argv) >= 0);
    REQUIRE(ker_ipc_select_or_exit("0:0", NULL) == 0);
    struct rte_mempool *pool = ker_ipc_pool_create("ker_ipc_example", 64, 64); REQUIRE(pool);
    char name[RTE_RING_NAMESIZE];
    REQUIRE(!ker_ipc_ring_name(name, sizeof(name), 0, FF_UNKNOWN));
    struct rte_ring *input = rte_ring_create(name, 32, SOCKET_ID_ANY, 0); REQUIRE(input);
    REQUIRE(!ker_ipc_ring_name(name, sizeof(name), 1, FF_UNKNOWN));
    struct rte_ring *output = rte_ring_create(name, 32, SOCKET_ID_ANY, 0); REQUIRE(output);
    REQUIRE(!ker_ipc_attach(pool));
    ker_ipc_message *message = ker_ipc_alloc(); REQUIRE(message && message->buf_len >= 20);
    message->msg_type = FF_UNKNOWN;
    strcpy(message->buf_addr, "caller-owned bytes");
    REQUIRE(!ker_ipc_send(message));
    void *object;
    REQUIRE(!rte_ring_dequeue(input, &object) && object == message);
    /* This caller's example provider implements no control command. */
    ((ker_ipc_message *)object)->result = -EOPNOTSUPP;
    REQUIRE(!rte_ring_enqueue(output, object));
    ker_ipc_message *reply = NULL;
    REQUIRE(!ker_ipc_recv(&reply, FF_UNKNOWN));
    REQUIRE(reply == message && reply->result == -EOPNOTSUPP);
    REQUIRE(!strcmp(reply->buf_addr, "caller-owned bytes"));
    REQUIRE(!ker_ipc_free(reply) && !ker_ipc_detach());
    REQUIRE(rte_mempool_avail_count(pool) == 64);
    rte_ring_free(input); rte_ring_free(output); rte_mempool_free(pool);
    REQUIRE(!rte_eal_cleanup());
    puts("PASS: caller-owned IPC transport and explicit unsupported-command reply");
    return 0;
}
