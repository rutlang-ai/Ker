/* Original-EAL caller of the exported same-master poll adapter. All Ethernet
 * packet ownership stays in actual original net_ring RX/TX and its mbuf pool. */
#define _GNU_SOURCE
#include <ker/reload.h>
#include "check.h"
#include <inttypes.h>
#include <errno.h>
#include <stdatomic.h>
#include <rte_eal.h>
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
#define MAGIC UINT64_C(0x4b4552504f4c4c31)
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "process-shared counters must be lock-free");
struct shared {
    uint64_t magic, nonce;
    uint32_t primary;
    atomic_uint active[2], callbacks[4], received[4], completed[4];
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
static void primary(void)
{
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);
    const struct rte_memzone *state = rte_memzone_reserve(STATE, ker_reload_state_size(), SOCKET_ID_ANY, 0);
    const struct rte_memzone *identity = rte_memzone_reserve(META, sizeof(*shared), SOCKET_ID_ANY, 0);
    CHECK(state && identity); shared = identity->addr;
    memset(shared, 0, sizeof(*shared)); shared->magic = MAGIC; shared->nonce = nonce(); shared->primary = getpid();
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
    char command[96]; struct rte_mbuf *pending = NULL; unsigned sequence = 0; uint32_t armed = 0;
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "status\n")) status();
        else if (!strncmp(command, "inject ", 7)) {
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
        } else if (!strcmp(command, "park\n")) {
            CHECK(!ker_reload_rx_mark(ker_reload_rx_owner(), 1));
            uint32_t epoch; CHECK(!ker_reload_park_arm(&epoch)); armed = epoch;
            printf("PARK {\"epoch\":%u}\n", epoch); flush();
        } else if (!strncmp(command, "release ", 8)) {
            unsigned to, epoch; CHECK(sscanf(command, "release %u %u", &to, &epoch) == 2 && to < 2);
            unsigned owner = ker_reload_rx_owner(); CHECK(owner < 2);
            int result = -EAGAIN;
            /* This caller's registration is two old workers (slots0/1) and
             * one new worker (slot2). No marker mutation before exact proof. */
            int proven = owner == 0 ? ker_reload_parked(0, epoch) && ker_reload_parked(1, epoch) : ker_reload_parked(2, epoch);
            if (epoch == armed && proven && !atomic_load(&shared->active[owner])) {
                result = ker_reload_rx_release((int)to);
                if (!result) armed = 0;
            }
            printf("RELEASE {\"result\":%d,\"owner\":%d,\"stopped\":%d}\n", result, ker_reload_rx_owner(), ker_reload_rx_stopped()); flush();
        } else if (!strncmp(command, "acks ", 5)) {
            unsigned epoch; CHECK(sscanf(command, "acks %u", &epoch) == 1);
            printf("ACKS {\"slots\":[%d,%d,%d]}\n",ker_reload_parked(0,epoch),ker_reload_parked(1,epoch),ker_reload_parked(2,epoch)); flush();
        } else if (!strcmp(command, "quit\n")) {
            CHECK(!pending && rte_ring_empty(rx) && rte_ring_empty(tx) && rte_mempool_avail_count(pool) == 63);
            CHECK(!atomic_load(&shared->active[0]) && !atomic_load(&shared->active[1]));
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
        } else if (!strcmp(command,"exit\n")) {
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
