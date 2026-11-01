#define _GNU_SOURCE
#include <ker/reload.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "check.h"
#include "kni-bridge-internal.h"
#include "ff_reload.h"

#define KNI_TEST_POOL_SZ 64
static int eal_initialized = 1;
static struct rte_mempool *test_pool;
static uint32_t fixture_epoch;
static int fixture_generation;

static void init_eal(void)
{
    cpu_set_t allowed;
    CHECK(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
    int cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); ++cpu) {}
    CHECK(cpu < CPU_SETSIZE);
    char mapping[64], prefix[64];
    snprintf(mapping, sizeof(mapping), "--lcores=0@%d", cpu);
    snprintf(prefix, sizeof(prefix), "--file-prefix=ker-kni-owner-%ld", (long)getpid());
    char *args[] = {"ker-kni-owner-test", mapping, prefix, "--no-huge", "--no-pci",
        "--no-shconf", "--iova-mode=va", "--no-telemetry", "-m", "64",
        "--vdev=net_ring0"};
    CHECK(rte_eal_init((int)(sizeof(args) / sizeof(args[0])), args) >= 0);
}

#define assert_true(x) CHECK((x) != 0)
#define assert_null(x) CHECK((x) == NULL)
#define assert_non_null(x) CHECK((x) != NULL)
#define assert_int_equal(a,b) CHECK((a) == (b))
#define assert_ptr_equal(a,b) CHECK((a) == (b))
#define mock_assert(expression, message, file, line) \
    do { (void)(message); (void)(file); (void)(line); CHECK(expression); } while (0)

extern void *__real_rte_zmalloc(const char *, size_t, unsigned);

int ff_reload_state_attached(void)
{
    return example_kni_reload_state_attached();
}
int ff_reload_kni_owner_match(void)
{
    return example_kni_reload_owner_matches();
}
void ff_reload_set_epoch(uint32_t epoch)
{
    fixture_epoch = epoch;
}
void ff_reload_set_gen(int generation)
{
    fixture_generation = generation;
    if (example_kni_reload_state_attached())
        CHECK(ker_reload_worker_select(generation, 0) == 0);
}
void ff_reload_attach_state(void *state)
{
    if (!state) {
        example_kni_unbind_reload();
        return;
    }
    CHECK(example_kni_bind_reload(state, sizeof(struct ff_reload_state),
        fixture_epoch, fixture_generation) == 0);
}
void ff_reload_dir_sync_enable(int enable)
{
    /* The retained source fixture explicitly uses the supported no-directory scope. */
    CHECK(enable == 0);
}
int ff_reload_gendir_install(void *directory, size_t size)
{
    CHECK(directory == NULL && size == 0);
    return 0;
}
void ff_reload_master_complete(void)
{
    CHECK(example_kni_reload_owner_matches() == 0);
    CHECK(example_kni_activate_reload_owner() == 0);
    CHECK(example_kni_reload_owner_matches() == 1);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" /* exact source cases land in the next stacked tranche */
#include "fstack-kni-owner-source.inc"
#pragma GCC diagnostic pop

static void run_case(void (*test)(void **), int check_future_owner)
{
    void *state = NULL;
    CHECK(ker_reload_kni_owner_matches() == -ENOTCONN);
    CHECK(example_kni_prepare() == 0);
    CHECK(p1_cold_setup(&state) == 0);
    CHECK(ker_reload_kni_owner_matches() == 0);
    test(&state);
    if (check_future_owner) {
        CHECK(example_kni_reload_owner_matches() == 1);
        CHECK(p1_tx_calls == 1 && p1_tx_limit == 3);
    }
    CHECK(p1_cold_teardown(&state) == 0);
    CHECK(ker_reload_kni_owner_matches() == -ENOTCONN);
}

int main(void)
{
    init_eal();
    test_pool = rte_pktmbuf_pool_create("kni_owner_source_pool", KNI_TEST_POOL_SZ,
        0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(test_pool);

    run_case(test_p1_future_kni_owner, 1);
    run_case(test_p1_kni_nonowner, 0);

    CHECK(rte_mempool_avail_count(test_pool) == KNI_TEST_POOL_SZ);
    rte_mempool_free(test_pool);
    CHECK(rte_vdev_uninit("net_ring0") == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("PASS: original KNI future owner activation and nonowner contracts");
    return 0;
}
