/* Caller-owned EAL/pool/rings and a borrowed original reload state.
 * The provider implements only read-only QUERY observation. */
#define _GNU_SOURCE
#include <ker/reload.h>
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
    REQUIRE(ker_ipc_select_or_exit("0:1:2", NULL) == 0);
    struct rte_mempool *pool = ker_ipc_pool_create("ker_reload_example", 64, 64); REQUIRE(pool);
    char name[RTE_RING_NAMESIZE];
    REQUIRE(!ker_ipc_ring_name(name, sizeof(name), 0, FF_RELOAD));
    struct rte_ring *input = rte_ring_create(name, 32, SOCKET_ID_ANY, 0); REQUIRE(input);
    REQUIRE(!ker_ipc_ring_name(name, sizeof(name), 1, FF_RELOAD));
    struct rte_ring *output = rte_ring_create(name, 32, SOCKET_ID_ANY, 0); REQUIRE(output);
    REQUIRE(!ker_ipc_attach(pool));
    void *state = calloc(1, ker_reload_state_size()); REQUIRE(state);
    REQUIRE(!ker_reload_state_init(state, ker_reload_state_size(), 1));
    REQUIRE(!ker_reload_bind_state(state, ker_reload_state_size(), 2, 1));
    ker_ipc_message *message = ker_ipc_alloc(); REQUIRE(message && message->buf_len >= 20);
    ker_reload_message_fill(message, FF_RELOAD_CMD_QUERY, 1, 7, 12345);
    strcpy(message->buf_addr, "caller-owned bytes");
    REQUIRE(!ker_ipc_send(message));
    void *object;
    REQUIRE(!rte_ring_dequeue(input, &object) && object == message);
    int command, generation, status; uint64_t heartbeat;
    ker_ipc_message *request = object;
    if (!ker_reload_message_parse(request, &command, &generation, &status, &heartbeat) &&
        command == FF_RELOAD_CMD_QUERY)
        ker_reload_message_fill(request, command, generation, status, heartbeat);
    else request->result = -EOPNOTSUPP;
    REQUIRE(!rte_ring_enqueue(output, object));
    ker_ipc_message *reply = NULL;
    REQUIRE(!ker_ipc_recv(&reply, FF_RELOAD));
    REQUIRE(reply == message && reply->result == 0);
    REQUIRE(!ker_reload_message_parse(reply, &command, &generation, &status, &heartbeat));
    REQUIRE(command == FF_RELOAD_CMD_QUERY && generation == 1 && status == 7 && heartbeat == 12345);
    REQUIRE(reply->reload.epoch == 2 && reply->reload.active_gen == 1);
    REQUIRE(!strcmp(reply->buf_addr, "caller-owned bytes"));
    REQUIRE(!ker_ipc_free(reply) && !ker_ipc_detach());
    ker_reload_unbind_state(); free(state);
    REQUIRE(rte_mempool_avail_count(pool) == 64);
    rte_ring_free(input); rte_ring_free(output); rte_mempool_free(pool);
    REQUIRE(!rte_eal_cleanup());
    puts("PASS: borrowed reload state and actual read-only QUERY transport");
    return 0;
}
