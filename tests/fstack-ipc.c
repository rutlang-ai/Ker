/* Exact unfinished IPC argument and real-EAL ownership source scenarios. */
#define _GNU_SOURCE
#include <ker/ipc.h>
#include "check.h"
#include "eal.h"
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_ring.h>

static struct rte_mempool *pool;
static struct rte_ring *input_ring, *output_ring, *reload_ring;
static void address(const char *process, const char *generation, unsigned expected_process,
    int expected_generation, uint32_t expected_epoch, const char *expected_name)
{
    CHECK(ker_ipc_select_or_exit(process, generation) == (int)expected_process);
    struct ker_ipc_address snapshot;
    CHECK(!ker_ipc_address(&snapshot));
    CHECK(snapshot.process == expected_process && snapshot.generation == expected_generation &&
        snapshot.epoch == expected_epoch);
    char name[RTE_RING_NAMESIZE];
    memset(name, 0x5a, sizeof(name));
    int result = ker_ipc_ring_name(name, sizeof(name), 0, FF_UNKNOWN);
    if (expected_name) { CHECK(!result && !strcmp(name, expected_name)); }
    else { CHECK(result == -EAGAIN && name[0] == 0x5a); }
}
static void malformed(void)
{
    const char *invalid[] = {"1:0:3:4", "1:0:", "1:0:x", "1:x", "x",
        "1:0:4294967295", "1:0:-1", "4294967296", "1:4294967296", "65536"};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]) + 2; ++i) {
        CHECK(!fflush(NULL));
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) {
            if (i < sizeof(invalid)/sizeof(invalid[0])) ker_ipc_select_or_exit(invalid[i], NULL);
            else if (i == sizeof(invalid)/sizeof(invalid[0])) ker_ipc_select_or_exit(NULL, "x");
            else ker_ipc_epoch_or_exit(KER_IPC_EPOCH_NONE);
            _exit(99);
        }
        int status; CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);
    }
    address("2:1:1", NULL, 2, 1, 1, "ff_msg_ring_in_2_e1_g1");
}
static struct rte_ring *create_ring(int output, enum FF_MSG_TYPE type)
{
    char name[RTE_RING_NAMESIZE];
    CHECK(!ker_ipc_ring_name(name, sizeof(name), output, type));
    struct rte_ring *ring = rte_ring_create(name, 32, SOCKET_ID_ANY, 0);
    CHECK(ring && rte_ring_lookup(name) == ring);
    CHECK(!rte_ring_is_prod_single(ring) && !rte_ring_is_cons_single(ring));
    return ring;
}
static void setup(void)
{
    CHECK(ker_ipc_alloc() == NULL && errno == ENOTCONN);
    address("0:0", NULL, 0, 0, KER_IPC_EPOCH_NONE, "ff_msg_ring_in_0_g0");
    ker_test_eal_init();
    pool = ker_ipc_pool_create("ker_ipc_case_pool", 64, 64);
    CHECK(pool && rte_mempool_avail_count(pool) == 64);
    CHECK(!ker_ipc_attach(pool));
    CHECK(ker_ipc_attach(pool) == -EBUSY);
    input_ring = create_ring(0, FF_UNKNOWN);
    output_ring = create_ring(1, FF_SYSCTL);
    reload_ring = create_ring(1, FF_RELOAD);
}
static void drain(struct rte_ring *ring)
{
    void *object;
    while (!rte_ring_dequeue(ring, &object)) {
        CHECK(rte_mempool_from_obj(object) == pool);
        rte_mempool_put(pool, object);
    }
}
static void teardown(void)
{
    drain(input_ring); drain(output_ring); drain(reload_ring);
    CHECK(!ker_ipc_detach() && !ker_ipc_detach());
    CHECK(rte_mempool_avail_count(pool) == 64 && !rte_mempool_in_use_count(pool));
    rte_ring_free(input_ring); rte_ring_free(output_ring); rte_ring_free(reload_ring);
    rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    CHECK(ker_ipc_alloc() == NULL && errno == ENOTCONN);
}
static ker_ipc_message *allocate(void)
{
    ker_ipc_message *m = ker_ipc_alloc(); CHECK(m);
    CHECK(m->ipc_owner_pid == (uint32_t)getpid() && m->ipc_cookie);
    CHECK(m->buf_len >= 64 && m->buf_addr == (char *)m + sizeof(*m));
    return m;
}
static void own_reply(void)
{
    ker_ipc_message *request = allocate(), *got = (void *)(uintptr_t)1;
    request->msg_type = FF_SYSCTL;
    memcpy(request->buf_addr, "owned-request", 14);
    CHECK(!ker_ipc_send(request));
    CHECK(ker_ipc_free(request) == -EBUSY && ker_ipc_detach() == -EBUSY);
    void *object;
    CHECK(!rte_ring_dequeue(input_ring, &object) && object == request);
    CHECK(!memcmp(request->buf_addr, "owned-request", 14));
    CHECK(!rte_ring_enqueue(output_ring, object));
    CHECK(!ker_ipc_recv(&got, FF_SYSCTL) && got == request);
    CHECK(!memcmp(got->buf_addr, "owned-request", 14));
    CHECK(!ker_ipc_free(got));
    uint64_t requeued = 1, orphan = 1, lost = 1;
    ker_ipc_reply_stats(&requeued, &orphan, &lost);
    CHECK(!requeued && !orphan && !lost);
}
static ker_ipc_message *foreign(pid_t owner)
{
    ker_ipc_message *m = allocate();
    m->ipc_owner_pid = (uint32_t)owner;
    memcpy(m->buf_addr, "foreign-owned", 14);
    return m;
}
static void foreign_live(int with_pending)
{
    ker_ipc_message *request = NULL;
    if (with_pending) {
        request = allocate(); request->msg_type = FF_SYSCTL;
        CHECK(!ker_ipc_send(request));
    }
    ker_ipc_message *other = foreign(getppid()), *got = (void *)(uintptr_t)1;
    CHECK(ker_ipc_free(other) == -EINVAL);
    CHECK(!rte_ring_enqueue(output_ring, other));
    CHECK(ker_ipc_recv(&got, FF_SYSCTL) < 0 && got == (void *)(uintptr_t)1);
    uint64_t requeued = 0, orphan = 1, lost = 1;
    ker_ipc_reply_stats(&requeued, &orphan, &lost);
    CHECK(requeued >= 1 && !orphan && !lost && rte_ring_count(output_ring) == 1);
    CHECK(ker_ipc_detach() == -EBUSY);
    void *object;
    CHECK(!rte_ring_dequeue(output_ring, &object) && object == other);
    CHECK(!memcmp(other->buf_addr, "foreign-owned", 14));
    rte_mempool_put(pool, other);
    if (with_pending) {
        /* A failed wait abandoned the request identity, but not its queued
         * object's ownership. The provider reclaims that exact request. */
        CHECK(!rte_ring_dequeue(input_ring, &object) && object == request);
        rte_mempool_put(pool, request);
    }
}
static void orphan(void)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) _exit(0);
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
    ker_ipc_message *other = foreign(child), *got = (void *)(uintptr_t)1;
    /* No valid local heap allocation is supplied for a foreign-process buffer.
     * Reclamation must clear these references, never try rte_free on them. */
    other->original_buf = (void *)(uintptr_t)0xdeadbeef;
    other->buf_addr = (void *)(uintptr_t)1;
    other->original_buf_len = 123;
    CHECK(!rte_ring_enqueue(output_ring, other));
    CHECK(ker_ipc_recv(&got, FF_SYSCTL) < 0 && got == (void *)(uintptr_t)1);
    uint64_t requeued = 0, reclaimed = 0, lost = 1;
    ker_ipc_reply_stats(&requeued, &reclaimed, &lost);
    CHECK(reclaimed == 1 && !lost && rte_ring_empty(output_ring));
    CHECK(rte_mempool_avail_count(pool) == 64);
}
static void *answer_query(void *unused)
{
    (void)unused;
    struct timespec before, now; CHECK(!clock_gettime(CLOCK_MONOTONIC, &before));
    for (;;) {
        void *object;
        if (!rte_ring_dequeue(input_ring, &object)) {
            ker_ipc_message *query = object;
            CHECK(query->msg_type == FF_RELOAD && query->reload.cmd == FF_RELOAD_CMD_QUERY);
            CHECK(query->ipc_cookie && query->ipc_owner_pid == (uint32_t)getpid());
            query->result = 0; query->reload.active_gen = 1; query->reload.epoch = 3;
            CHECK(!rte_ring_enqueue(reload_ring, query));
            return NULL;
        }
        CHECK(!clock_gettime(CLOCK_MONOTONIC, &now) && now.tv_sec-before.tv_sec < 3);
        usleep(1000);
    }
}
static void probe_preserves_foreign(void)
{
    ker_ipc_message *other = foreign(getppid());
    CHECK(!rte_ring_enqueue(reload_ring, other));
    uint32_t epoch = 77; int generation = 77;
    CHECK(ker_ipc_probe(&epoch, &generation) < 0 && epoch == 77 && generation == 77);
    uint64_t reclaimed = 1, lost = 1;
    ker_ipc_reply_stats(NULL, &reclaimed, &lost);
    CHECK(!reclaimed && !lost && rte_ring_count(reload_ring) == 1);
    void *object;
    CHECK(!rte_ring_dequeue(reload_ring, &object) && object == other);
    CHECK(!memcmp(other->buf_addr, "foreign-owned", 14));
    rte_mempool_put(pool, other);
    /* The timeout must have sent a real QUERY, not short-circuited. */
    CHECK(rte_ring_count(input_ring) == 1);
    CHECK(!rte_ring_dequeue(input_ring, &object));
    ker_ipc_message *query = object;
    CHECK(query->msg_type == FF_RELOAD && query->reload.cmd == FF_RELOAD_CMD_QUERY);
    CHECK(query->ipc_cookie && query->ipc_owner_pid == (uint32_t)getpid());
    CHECK(ker_ipc_detach() == -EBUSY); /* This accepted timeout still owns an object. */
    rte_mempool_put(pool, query);
    /* A real provider response is the positive control for the same probe. */
    pthread_t provider; CHECK(!pthread_create(&provider, NULL, answer_query, NULL));
    CHECK(!ker_ipc_probe(&epoch, &generation) && epoch == 3 && generation == 1);
    CHECK(!pthread_join(provider, NULL));
    CHECK(rte_mempool_avail_count(pool) == 64);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    const char *profile = argv[1];
    if (!strcmp(profile, "process")) address("1", NULL, 1, KER_IPC_GEN_AUTO, KER_IPC_EPOCH_NONE, NULL);
    else if (!strcmp(profile, "generation")) address("1:0", NULL, 1, 0, KER_IPC_EPOCH_NONE, "ff_msg_ring_in_1_g0");
    else if (!strcmp(profile, "generation-epoch")) {
        address("1:0:3", NULL, 1, 0, 3, "ff_msg_ring_in_1_e3_g0");
        CHECK(ker_ipc_epoch_slot(3) == 3);
    } else if (!strcmp(profile, "coordinate")) {
        address("2:1:1", NULL, 2, 1, 1, "ff_msg_ring_in_2_e1_g1");
        CHECK(ker_ipc_epoch_slot(1) == 1);
    } else if (!strcmp(profile, "generation-option-epoch")) address(NULL, "1:2", 0, 1, 2, "ff_msg_ring_in_0_e2_g1");
    else if (!strcmp(profile, "generation-option")) address(NULL, "0", 0, 0, KER_IPC_EPOCH_NONE, "ff_msg_ring_in_0_g0");
    else if (!strcmp(profile, "malformed")) malformed();
    else {
        setup();
        if (!strcmp(profile, "own-reply")) own_reply();
        else if (!strcmp(profile, "foreign-live")) foreign_live(1);
        else if (!strcmp(profile, "foreign-no-send")) foreign_live(0);
        else if (!strcmp(profile, "orphan")) orphan();
        else if (!strcmp(profile, "probe")) probe_preserves_foreign();
        else CHECK(0);
        teardown();
    }
    printf("PASS: original IPC coordinate/ownership contract %s\n", profile);
    return 0;
}
