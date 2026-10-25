/* Resident-component adaptation of F-Stack RX-15 orphan-ring cleanup.
 * Children supply real process lifetimes/pidfds; all adapter calls run in
 * the primary. This is not a secondary-EAL or packet-worker integration. */
#define _GNU_SOURCE
#include "session-generation-rings.h"
#include "check.h"
#include "eal.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define SESSION UINT64_C(0x525831356f727068)
#define POOL_SIZE 127U
#define PAYLOAD_SIZE 32U
#define QUEUED 16U

struct actor { pid_t pid; int control, pidfd; };
static struct actor spawn_actor(void)
{
    int channel[2];
    CHECK(pipe(channel) == 0);
    pid_t parent = getpid();
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(channel[1]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(2);
        char command;
        ssize_t n;
        do n = read(channel[0], &command, 1); while (n < 0 && errno == EINTR);
        _exit(n == 0 ? 0 : 3);
    }
    close(channel[0]);
    int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    CHECK(pidfd >= 0);
    return (struct actor){child, channel[1], pidfd};
}
static void stop_actor(struct actor *actor)
{
    CHECK(close(actor->control) == 0);
    actor->control = -1;
    struct pollfd pfd = {.fd = actor->pidfd, .events = POLLIN};
    int n;
    do n = poll(&pfd, 1, 5000); while (n < 0 && errno == EINTR);
    CHECK(n == 1 && (pfd.revents & POLLIN));
    int status;
    CHECK(waitpid(actor->pid, &status, 0) == actor->pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static struct rte_ring *observed_ring(unsigned tx, unsigned generation, unsigned queue)
{
    char name[RTE_RING_NAMESIZE];
    snprintf(name, sizeof(name), "drain_%s_p0_q%u_g%u", tx ? "tx" : "rx", queue, generation);
    struct rte_ring *ring = rte_ring_lookup(name);
    CHECK(ring != NULL);
    return ring;
}
static void verify_packet(struct rte_mbuf *m, unsigned tx, unsigned generation,
    unsigned queue, unsigned sequence)
{
    CHECK(m && m->pkt_len == PAYLOAD_SIZE && m->data_len == PAYLOAD_SIZE &&
        m->nb_segs == 1 && !m->next && rte_mbuf_refcnt_read(m) == 1);
    const unsigned char *bytes = rte_pktmbuf_mtod(m, const unsigned char *);
    for (unsigned i = 0; i < PAYLOAD_SIZE; ++i)
        CHECK(bytes[i] == (unsigned char)((tx * 128 + generation * 64 + queue * 16 + sequence) ^ i));
}
static void verify_preserved(struct ker_generation_rings *rings, struct rte_mempool *pool,
    struct rte_mbuf *packets[2][2][2][2], unsigned held_mask, unsigned released_mask)
{
    unsigned released = (released_mask & 1U) + ((released_mask >> 1) & 1U);
    CHECK(rte_mempool_avail_count(pool) == POOL_SIZE - QUEUED + released);
    for (unsigned tx = 0; tx < 2; ++tx)
        for (unsigned g = 0; g < 2; ++g)
            for (unsigned q = 0; q < 2; ++q) {
                unsigned held = q == 0 && g == (tx ? 1U : 0U) && (held_mask & (1U << tx));
                CHECK(rte_ring_count(observed_ring(tx, g, q)) == (held ? 1U : 2U));
                for (unsigned sequence = 0; sequence < 2; ++sequence) {
                    if (held && sequence == 0 && (released_mask & (1U << tx))) continue;
                    verify_packet(packets[tx][g][q][sequence], tx, g, q, sequence);
                }
            }
    /* Telemetry is intentionally unavailable while identities are admitted. */
    struct ker_generation_ring_stats stats = {.tx_drop = UINT64_MAX};
    CHECK(ker_generation_rings_stats(rings, &stats) == -EBUSY);
    CHECK(stats.tx_drop == UINT64_MAX);
}
static void verify_untouched(struct ker_generation_rings *rings, struct rte_mempool *pool,
    struct rte_mbuf *packets[2][2][2][2])
{
    verify_preserved(rings, pool, packets, 0, 0);
}
static void verify_forged_reaps(struct ker_generation_rings *rings, struct rte_mempool *pool,
    struct rte_mbuf *packets[2][2][2][2], const struct ker_generation_identity ids[2])
{
    for (unsigned field = 0; field < 6; ++field) {
        struct ker_generation_identity forged = ids[1];
        if (field == 0) forged.session++;
        if (field == 1) forged.epoch++;
        if (field == 2) forged.slot = 3;
        if (field == 3) forged.generation = 0;
        if (field == 4) forged.process = 1;
        if (field == 5) forged.pid = ids[0].pid;
        CHECK(ker_generation_reap_dead(rings, &forged) == (field == 0 ? -EINVAL : -ESTALE));
        verify_untouched(rings, pool, packets);
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    unsigned held_mask = !strcmp(argv[1], "inflight-rx") ? 1U :
        !strcmp(argv[1], "inflight-tx") ? 2U : !strcmp(argv[1], "inflight-both") ? 3U : 0U;
    CHECK(held_mask || (!strcmp(argv[1], "live") || !strcmp(argv[1], "identity") ||
        !strcmp(argv[1], "reap")));
    /* Fork before EAL starts host threads. Each child only blocks on a pipe. */
    struct actor actors[2];
    actors[0] = spawn_actor();
    actors[1] = spawn_actor();
    ker_test_eal_init();
    struct rte_mempool *pool = rte_pktmbuf_pool_create("orphan_safety_pool", POOL_SIZE,
        0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(pool != NULL);
    struct ker_generation_rings *rings = NULL;
    CHECK(ker_generation_rings_create(SESSION, 1, 2, pool, &rings) == 0);
    struct ker_generation_identity ids[2];
    for (unsigned g = 0; g < 2; ++g) {
        ids[g] = (struct ker_generation_identity){.session = SESSION, .epoch = 10,
            .slot = 1, .generation = g, .process = 0, .pid = (uint32_t)actors[g].pid};
        CHECK(ker_generation_admit(rings, &ids[g], actors[g].pidfd) == 0);
    }
    struct rte_mbuf *packets[2][2][2][2];
    for (unsigned tx = 0; tx < 2; ++tx)
        for (unsigned g = 0; g < 2; ++g)
            for (unsigned q = 0; q < 2; ++q)
                for (unsigned sequence = 0; sequence < 2; ++sequence) {
                    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
                    CHECK(m != NULL);
                    unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(m, PAYLOAD_SIZE);
                    CHECK(bytes != NULL);
                    for (unsigned i = 0; i < PAYLOAD_SIZE; ++i)
                        bytes[i] = (unsigned char)((tx * 128 + g * 64 + q * 16 + sequence) ^ i);
                    packets[tx][g][q][sequence] = m;
                    CHECK((tx ? ker_generation_tx_enqueue(rings, &ids[g], 0, q, m) :
                        ker_generation_rx_enqueue(rings, &ids[g ^ 1U], 0, q, g, m)) == 0);
                }
    verify_untouched(rings, pool, packets);
    if (!strcmp(argv[1], "identity")) verify_forged_reaps(rings, pool, packets, ids);
    /* A live pidfd is not proof of death, even with an exact registered ID. */
    CHECK(ker_generation_reap_dead(rings, &ids[1]) == -EBUSY);
    verify_untouched(rings, pool, packets);
    if (!strcmp(argv[1], "live")) {
        for (unsigned g = 0; g < 2; ++g) {
            CHECK(ker_generation_reap_dead(rings, &ids[g]) == -EBUSY);
            verify_untouched(rings, pool, packets);
        }
    }
    struct rte_mbuf *held[2] = {NULL, NULL};
    for (unsigned tx = 0; tx < 2; ++tx) if (held_mask & (1U << tx)) {
        CHECK((tx ? ker_generation_tx_dequeue_peer(rings, &ids[0], 0, 0, &held[tx]) :
            ker_generation_rx_dequeue(rings, &ids[0], 0, 0, &held[tx])) == 1);
        CHECK(held[tx] == packets[tx][tx ? 1 : 0][0][0]);
        verify_packet(held[tx], tx, tx ? 1 : 0, 0, 0);
    }
    stop_actor(&actors[1]);
    if (!strcmp(argv[1], "identity")) verify_forged_reaps(rings, pool, packets, ids);
    if (held_mask) {
        unsigned released_mask = 0;
        CHECK(ker_generation_reap_ready(rings, &ids[1]) == -EBUSY);
        CHECK(ker_generation_reap_dead(rings, &ids[1]) == -EBUSY);
        verify_preserved(rings, pool, packets, held_mask, released_mask);
        /* A successful exact admission replay proves the timed-out reap
         * restored both operation gates, without consuming more packets. */
        CHECK(ker_generation_admit(rings, &ids[0], actors[0].pidfd) == 0);
        verify_preserved(rings, pool, packets, held_mask, released_mask);
        for (unsigned tx = 0; tx < 2; ++tx) if (held_mask & (1U << tx)) {
            CHECK(ker_generation_packet_release(rings, &ids[0], held[tx]) == 0);
            released_mask |= 1U << tx;
            verify_preserved(rings, pool, packets, held_mask, released_mask);
            if (released_mask != held_mask) {
                CHECK(ker_generation_reap_ready(rings, &ids[1]) == -EBUSY);
                CHECK(ker_generation_reap_dead(rings, &ids[1]) == -EBUSY);
                CHECK(ker_generation_admit(rings, &ids[0], actors[0].pidfd) == 0);
                verify_preserved(rings, pool, packets, held_mask, released_mask);
            }
        }
        CHECK(ker_generation_reap_ready(rings, &ids[1]) == 0);
        verify_preserved(rings, pool, packets, held_mask, released_mask);
    }
    unsigned released = (held_mask & 1U) + ((held_mask >> 1) & 1U);
    CHECK(ker_generation_reap_dead(rings, &ids[1]) == 0);
    CHECK(rte_mempool_avail_count(pool) == POOL_SIZE - QUEUED / 2 + released);
    CHECK(ker_generation_reap_dead(rings, &ids[1]) == -ESTALE);
    CHECK(rte_mempool_avail_count(pool) == POOL_SIZE - QUEUED / 2 + released);
    int all_dead = !strcmp(argv[1], "reap");
    if (all_dead) {
        stop_actor(&actors[0]);
        CHECK(ker_generation_reap_dead(rings, &ids[0]) == 0);
        CHECK(rte_mempool_avail_count(pool) == POOL_SIZE);
    }
    for (unsigned q = 0; q < 2; ++q) {
        CHECK(rte_ring_count(observed_ring(0, 1, q)) == 0);
        CHECK(rte_ring_count(observed_ring(1, 0, q)) == 0);
        CHECK(rte_ring_count(observed_ring(0, 0, q)) ==
            (all_dead ? 0U : 2U - (q == 0 && (held_mask & 1U) ? 1U : 0U)));
        CHECK(rte_ring_count(observed_ring(1, 1, q)) ==
            (all_dead ? 0U : 2U - (q == 0 && (held_mask & 2U) ? 1U : 0U)));
        if (all_dead) continue;
        for (unsigned tx = 0; tx < 2; ++tx)
            for (unsigned sequence = q == 0 && (held_mask & (1U << tx)) ? 1U : 0U;
                 sequence < 2; ++sequence) {
                struct rte_mbuf *m = NULL;
                CHECK((tx ? ker_generation_tx_dequeue_peer(rings, &ids[0], 0, q, &m) :
                    ker_generation_rx_dequeue(rings, &ids[0], 0, q, &m)) == 1);
                CHECK(m == packets[tx][tx ? 1 : 0][q][sequence]);
                verify_packet(m, tx, tx ? 1 : 0, q, sequence);
                CHECK(ker_generation_packet_release(rings, &ids[0], m) == 0);
            }
    }
    CHECK(rte_mempool_avail_count(pool) == POOL_SIZE);
    if (!all_dead) {
        stop_actor(&actors[0]);
        CHECK(ker_generation_reap_dead(rings, &ids[0]) == 0);
    }
    struct ker_generation_ring_stats stats;
    CHECK(ker_generation_rings_stats(rings, &stats) == 0 && stats.tx_drop == (all_dead ? 8U : 4U) &&
        stats.tx_full == 0 && stats.rx_full == 0 && stats.packet_drop == 0);
    CHECK(ker_generation_rings_destroy(rings) == 0);
    CHECK(rte_mempool_avail_count(pool) == POOL_SIZE);
    rte_mempool_free(pool);
    CHECK(close(actors[0].pidfd) == 0 && close(actors[1].pidfd) == 0);
    CHECK(rte_eal_cleanup() == 0);
    printf("PASS: orphan safety profile=%s exact pidfd death and complete reclamation\n", argv[1]);
    return 0;
}
