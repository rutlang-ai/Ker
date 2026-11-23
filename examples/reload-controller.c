/* Caller application: original nginx reload policy drives Ker runtime APIs.
 * Complete raw-record transport is provided by original EAL/net_ring. */
#define _GNU_SOURCE
#include <ker/reload.h>
#include "reload-controller-policy.h"
#include <stdio.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s errno=%d\n",__FILE__,__LINE__,#x,errno); exit(1); } } while (0)
#include <inttypes.h>
#include <errno.h>
#include <stdatomic.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <time.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define PORT "net_ring_ker_reload_poll"
#define STATE "ker_reload_poll_state"
#define META "ker_reload_poll_identity"
#define POOL "ker_reload_poll_pool"
#define RX "ker_reload_poll_rx"
#define TX "ker_reload_poll_tx"
#define MAGIC UINT64_C(0x4b45524354524c31)
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "process-shared counters must be lock-free");
struct shared {
    uint64_t magic, nonce;
    uint32_t primary;
    atomic_uint active[2], callbacks[4], received[4], completed[4], retiring[4];
};
struct frame { uint64_t nonce; unsigned sequence; unsigned char bytes[84]; };
static struct shared *shared;
static struct rte_ring *rx, *tx;
static struct rte_mempool *pool;
static uint16_t port;
static unsigned slot, generation;
static int hold;
static uint64_t nonce(void)
{
    const char *text = getenv("KER_RELOAD_POLL_NONCE"); CHECK(text && *text);
    char *end; uint64_t n = strtoull(text, &end, 16); CHECK(!*end && n); return n;
}
static void flush(void) { CHECK(!fflush(stdout)); }
static void status(void)
{
    struct rte_eth_stats statistics; CHECK(!rte_eth_stats_get(port, &statistics));
    printf("STATUS {\"available\":%u,\"rx\":%u,\"tx\":%u,\"owner\":%d,\"stopped\":%d,\"inflight\":[%u,%u],\"callbacks\":[%u,%u,%u,%u],\"ipackets\":%" PRIu64 ",\"opackets\":%" PRIu64 "}\n",
        rte_mempool_avail_count(pool), rte_ring_count(rx), rte_ring_count(tx),
        ker_reload_rx_owner(), ker_reload_rx_stopped(), atomic_load(&shared->active[0]), atomic_load(&shared->active[1]),
        atomic_load(&shared->callbacks[0]), atomic_load(&shared->callbacks[1]),
        atomic_load(&shared->callbacks[2]), atomic_load(&shared->callbacks[3]), statistics.ipackets, statistics.opackets); flush();
}
static void runtime(void)
{
    struct ker_reload_runtime v; CHECK(!ker_reload_runtime_view(&v));
    printf("RUNTIME {\"attached\":%d,\"active\":%d,\"target\":%d,\"worker\":%d,\"window\":%d,\"observation_owner\":%d,\"owner\":%d,\"stopped\":%d,\"epoch\":%u,\"heartbeat\":%" PRIu64 ",\"stalls\":%" PRIu64 "}\n",
        v.attached,v.active_generation,v.target_generation,v.worker_generation,v.reload_active,
        v.observation_owner_generation,v.rx_owner,v.rx_stopped,v.round_epoch,v.heartbeat,v.heartbeat_stalls); flush();
}
static int quiescent(void *context)
{
    CHECK(context == shared); return !atomic_load(&shared->active[0]) && !atomic_load(&shared->active[1]);
}
static int drained(void *context)
{
    return quiescent(context) && rte_ring_empty(rx) && rte_ring_empty(tx) && rte_mempool_avail_count(pool)==63;
}
static int retire_workers(void *context,const struct example_reload_worker *workers,unsigned count)
{
    CHECK(context == shared);
    for (unsigned i=0;i<count;i++) atomic_store(&shared->retiring[workers[i].slot],1);
    return 0;
}
static void policy(const struct example_reload_controller *c,int result)
{
    struct ker_reload_runtime v; CHECK(!ker_reload_runtime_view(&v));
    printf("POLICY {\"result\":%d,\"state\":%d,\"name\":\"%s\",\"round\":%u,\"target\":%u,\"park\":%u,\"rollback\":%u,\"active\":%d,\"owner\":%d,\"stopped\":%d,\"window\":%d}\n",
        result,c->state,example_reload_state_name(c->state),c->round,c->target,c->park,c->rollback,
        v.active_generation,v.rx_owner,v.rx_stopped,v.reload_active); flush();
}
static void primary(void)
{
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);
    const struct rte_memzone *state = rte_memzone_reserve(STATE, ker_reload_state_size(), SOCKET_ID_ANY, 0);
    const struct rte_memzone *identity = rte_memzone_reserve(META, sizeof(*shared), SOCKET_ID_ANY, 0);
    CHECK(state && identity); shared = identity->addr;
    memset(shared, 0, sizeof(*shared));
    for (unsigned i = 0; i < 2; i++) atomic_init(&shared->active[i], 0);
    for (unsigned i = 0; i < 4; i++) {
        atomic_init(&shared->retiring[i], 0); atomic_init(&shared->callbacks[i], 0); atomic_init(&shared->received[i], 0); atomic_init(&shared->completed[i], 0);
    }
    shared->magic = MAGIC; shared->nonce = nonce(); shared->primary = getpid();
    CHECK(!ker_reload_state_init(state->addr, state->len, 0));
    CHECK(!ker_reload_bind_state(state->addr, state->len, 0, 0));
    pool = rte_pktmbuf_pool_create(POOL, 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY); CHECK(pool);
    rx = rte_ring_create(RX, 32, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
    tx = rte_ring_create(TX, 32, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ); CHECK(rx && tx);
    int created = rte_eth_from_rings("ker_reload_poll", &rx, 1, &tx, 1, SOCKET_ID_ANY); CHECK(created >= 0);
    port = (uint16_t)created;
    struct rte_eth_conf config = {0};
    CHECK(!rte_eth_dev_configure(port, 1, 1, &config));
    CHECK(!rte_eth_rx_queue_setup(port, 0, 128, SOCKET_ID_ANY, NULL, pool));
    CHECK(!rte_eth_tx_queue_setup(port, 0, 128, SOCKET_ID_ANY, NULL) && !rte_eth_dev_start(port));
    struct rte_eth_dev_info info; CHECK(!rte_eth_dev_info_get(port, &info) && !strcmp(info.driver_name, "net_ring"));
    printf("READY {\"pid\":%u,\"nonce\":\"%" PRIx64 "\",\"available\":63,\"driver\":\"net_ring\"}\n", (unsigned)getpid(), nonce()); flush();
    struct example_reload_ops ops={quiescent,drained,retire_workers};
    struct example_reload_controller controller; CHECK(!example_reload_controller_init(&controller,&ops,shared));
    char command[96]; struct rte_mbuf *pending = NULL; unsigned sequence = 0;
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "status\n")) status();
        else if (!strcmp(command, "runtime\n")) runtime();
        else if (!strncmp(command,"register ",9)) {
            unsigned worker_slot,gen; int pid; CHECK(sscanf(command,"register %u %d %u",&worker_slot,&pid,&gen)==3);
            int result=example_reload_controller_add(&controller,worker_slot,pid,gen);
            if (!result) atomic_store(&shared->retiring[worker_slot],0);
            printf("REGISTER {\"result\":%d}\n",result); flush();
        } else if (!strncmp(command,"event ",6)) {
            int event; CHECK(sscanf(command,"event %d",&event)==1);
            int result=example_reload_controller_event(&controller,event); policy(&controller,result);
        } else if (!strcmp(command,"handover\n")) {
            int result=example_reload_controller_release(&controller); policy(&controller,result);
        } else if (!strcmp(command,"policy\n")) policy(&controller,0);
        else if (!strncmp(command, "inject ", 7)) {
            CHECK(controller.state==NGX_FF_RELOAD_T0_IDLE || controller.state==NGX_FF_RELOAD_T3_DRAIN || controller.state==NGX_FF_RELOAD_T5_GOLD_QUIT);
            CHECK(!pending && sscanf(command, "inject %u", &sequence) == 1);
            pending = rte_pktmbuf_alloc(pool); CHECK(pending);
            struct frame *frame = (void *)rte_pktmbuf_append(pending, sizeof(*frame)); CHECK(frame);
            frame->nonce = nonce(); frame->sequence = sequence;
            for (unsigned i = 0; i < sizeof(frame->bytes); i++) frame->bytes[i] = (unsigned char)(sequence + i);
            CHECK(!rte_ring_enqueue(rx, pending));
            printf("INJECTED {\"sequence\":%u,\"available\":%u}\n", sequence, rte_mempool_avail_count(pool)); flush();
        } else if (!strcmp(command, "collect\n")) {
            void *object; CHECK(pending && !rte_ring_dequeue(tx, &object) && object == pending);
            CHECK(rte_pktmbuf_pkt_len(pending) == sizeof(struct frame));
            const struct frame *frame = rte_pktmbuf_mtod(pending, const struct frame *);
            CHECK(frame->nonce == nonce() && frame->sequence == sequence);
            for (unsigned i = 0; i < sizeof(frame->bytes); i++) CHECK(frame->bytes[i] == (unsigned char)(sequence+i));
            rte_pktmbuf_free(pending); pending = NULL;
            printf("COLLECTED {\"sequence\":%u,\"available\":%u}\n", sequence, rte_mempool_avail_count(pool)); flush();
        } else if (!strcmp(command, "quit\n")) {
            CHECK(!pending && rte_ring_empty(rx) && rte_ring_empty(tx) && rte_mempool_avail_count(pool) == 63);
            CHECK(!atomic_load(&shared->active[0]) && !atomic_load(&shared->active[1]));
            CHECK(!example_reload_controller_destroy(&controller));
            CHECK(!rte_eth_dev_stop(port) && !rte_eth_dev_close(port));
            rte_ring_free(rx); rte_ring_free(tx); rte_mempool_free(pool);
            ker_reload_unbind_state(); CHECK(!rte_memzone_free(state) && !rte_memzone_free(identity) && !rte_eal_cleanup());
            puts("CLOSED {\"available\":63,\"outstanding\":0}"); flush(); return;
        } else CHECK(0);
    }
    CHECK(0);
}
static int packet_poll(void *argument)
{
    CHECK(argument == shared);
    CHECK(atomic_fetch_add(&shared->active[generation], 1) == 0);
    CHECK(!atomic_load(&shared->active[1-generation]));
    atomic_fetch_add(&shared->callbacks[slot], 1);
    if (hold) {
        printf("ENTERED {\"slot\":%u,\"generation\":%u}\n",slot,generation); flush();
        char resume[32]; CHECK(fgets(resume,sizeof(resume),stdin) && !strcmp(resume,"continue\n"));
    }
    struct rte_mbuf *packet = NULL;
    unsigned received = rte_eth_rx_burst(port, 0, &packet, 1);
    if (received) {
        CHECK(packet && packet->pool == pool && rte_pktmbuf_pkt_len(packet) == sizeof(struct frame));
        const struct frame *frame = rte_pktmbuf_mtod(packet, const struct frame *);
        CHECK(frame->nonce == nonce());
        atomic_fetch_add(&shared->received[slot], 1);
        CHECK(rte_eth_tx_burst(port, 0, &packet, 1) == 1);
        atomic_fetch_add(&shared->completed[slot], 1);
    }
    CHECK(atomic_fetch_sub(&shared->active[generation], 1) == 1);
    return (int)received;
}
static void worker(unsigned gen, unsigned worker_slot)
{
    CHECK(rte_eal_process_type() == RTE_PROC_SECONDARY && gen < 2 && worker_slot < 4);
    const struct rte_memzone *state = rte_memzone_lookup(STATE), *identity = rte_memzone_lookup(META); CHECK(state && identity);
    shared = identity->addr; const char *pid = getenv("KER_RELOAD_POLL_PRIMARY_PID"); CHECK(pid);
    CHECK(shared->magic == MAGIC && shared->nonce == nonce() && shared->primary == strtoul(pid,NULL,10));
    CHECK(!ker_reload_bind_state(state->addr,state->len,0,(int)gen));
    CHECK(!ker_reload_worker_select((int)gen, worker_slot)); generation = gen; slot = worker_slot;
    pool = rte_mempool_lookup(POOL); CHECK(pool);
    CHECK(!rte_eth_dev_get_port_by_name(PORT, &port));
    struct rte_eth_dev_info info; CHECK(!rte_eth_dev_info_get(port,&info) && !strcmp(info.driver_name,"net_ring"));
    printf("ATTACHED {\"pid\":%u,\"primary\":%u,\"generation\":%u,\"slot\":%u}\n",(unsigned)getpid(),shared->primary,generation,slot); flush();
    char command[96];
    while (fgets(command,sizeof(command),stdin)) {
        if (!strncmp(command,"poll",4)) {
            hold = !strcmp(command,"poll hold\n");
            int result = ker_reload_poll(packet_poll,shared);
            printf("POLL {\"result\":%d,\"callbacks\":%u,\"received\":%u,\"completed\":%u}\n", result,atomic_load(&shared->callbacks[slot]),atomic_load(&shared->received[slot]),atomic_load(&shared->completed[slot])); flush();
        } else if (!strncmp(command,"claim ",6)) {
            unsigned from; CHECK(sscanf(command,"claim %u",&from)==1);
            int result = ker_reload_rx_claim((int)from,(int)gen,20);
            printf("CLAIM {\"result\":%d,\"owner\":%d,\"stopped\":%d}\n",result,ker_reload_rx_owner(),ker_reload_rx_stopped()); flush();
        } else if (!strcmp(command,"ready\n")) {
            CHECK(!ker_reload_ready_publish(slot,getpid()));
            printf("WORKER_READY {\"pid\":%u,\"slot\":%u}\n",(unsigned)getpid(),slot); flush();
        } else if (!strcmp(command,"exit\n") || !strcmp(command,"retire\n")) {
            if (!strcmp(command,"retire\n")) CHECK(atomic_load(&shared->retiring[slot]) && !ker_reload_rx_allowed());
            ker_reload_unbind_state(); CHECK(!rte_eal_cleanup());
            puts("CLOSED {\"outstanding\":0}"); flush(); return;
        } else CHECK(0);
    }
    CHECK(0);
}
int main(int argc,char **argv)
{
    CHECK(argc >= 3);
    int is_primary = !strcmp(argv[1],"primary");
    CHECK(is_primary || (!strcmp(argv[1],"worker") && argc >= 5));
    unsigned gen = is_primary ? 0 : (unsigned)strtoul(argv[2],NULL,10);
    unsigned worker_slot = is_primary ? 0 : (unsigned)strtoul(argv[3],NULL,10);
    int offset = is_primary ? 1 : 3;
    CHECK(rte_eal_init(argc-offset,argv+offset) >= 0);
    if (is_primary) primary(); else worker(gen,worker_slot);
    return 0;
}
