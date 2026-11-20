/* The original A14 fixture drives real EAL and the byte-pinned directory.
 * Link only its required device, drain-ring and reload message paths. */
#define _GNU_SOURCE
#include <ker/ipc.h>
#include <errno.h>
#include <limits.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "check.h"
#include "ff_config.h"
#include "ff_memory.h"
#include "ff_reload.h"

struct ff_config ff_global_cfg;
#include "../third_party/fstack-reload/ff_reload.c"
#include "../third_party/fstack-reload/ff_reload_gendir.c"
#include "../third_party/fstack-reload/ff_drain_ring.c"
#include "fstack-drain-create-ring.inc"

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

int ff_log(uint32_t level, uint32_t type, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = rte_vlog(level, type, format, args);
    va_end(args);
    return result;
}

void ff_dpdk_process_packets(uint16_t port, uint16_t queue, struct rte_mbuf **packets,
    uint16_t count, struct ff_dpdk_if_context *context, int from_ring)
{
    (void)port; (void)queue; (void)packets; (void)count; (void)context; (void)from_ring;
    fputs("Unexpected FreeBSD input in A14 directory and IPC fixture\n", stderr);
    abort();
}

uint16_t nb_dev_ports;
static struct rte_ring *requests[FF_RELOAD_EPOCH_SLOT_MAX][FF_RELOAD_GEN_MAX][2];
static struct rte_ring *replies[FF_RELOAD_EPOCH_SLOT_MAX][FF_RELOAD_GEN_MAX][2];
static struct rte_mempool *message_pool;
static struct rte_mempool *device_pool;
static bool running;

static int qualified_eal_init(int argc, char **argv)
{
    cpu_set_t mask;
    CHECK(!sched_getaffinity(0, sizeof(mask), &mask));
    int cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &mask); ++cpu) {}
    CHECK(cpu < CPU_SETSIZE && argc < 24);
    char core[40], huge[PATH_MAX + 12];
    snprintf(core, sizeof(core), "--lcores=0@%d", cpu);
    const char *directory = getenv("KER_FSTACK_HUGEPAGE_DIR");
    CHECK(directory && *directory && snprintf(huge, sizeof(huge), "--huge-dir=%s", directory) < (int)sizeof(huge));
    char *options[32];
    int count = 0;
    options[count++] = argv[0];
    options[count++] = core;
    options[count++] = huge;
    options[count++] = "--iova-mode=va";
    options[count++] = "--no-telemetry";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-l")) {
            ++i;
        } else if (!strcmp(argv[i], "-m")) {
            CHECK(++i < argc);
            options[count++] = "-m";
            options[count++] = "128";
        } else {
            options[count++] = argv[i];
        }
    }
    options[count] = NULL;
    return rte_eal_init(count, options);
}

static int caller_primary_init(int argc, char **argv)
{
    if (qualified_eal_init(argc, argv) < 0) return -1;
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);
    nb_dev_ports = rte_eth_dev_count_avail();
    CHECK(nb_dev_ports == 1);
    ff_reload_gendir_attach();
    CHECK(!ff_drain_ring_init());

    for (unsigned slot = 0; slot < FF_RELOAD_EPOCH_SLOT_MAX; ++slot)
        for (int gen = 0; gen < FF_RELOAD_GEN_MAX; ++gen)
            for (unsigned proc = 0; proc < 2; ++proc) {
                char name[RTE_RING_NAMESIZE];
                CHECK(!ff_reload_msg_ring_name_e(name, sizeof(name), FF_MSG_RING_IN, proc, -1, gen, slot, 1));
                requests[slot][gen][proc] = create_ring(name, 64, SOCKET_ID_ANY, 0);
                CHECK(!ff_reload_msg_ring_name_e(name, sizeof(name), FF_MSG_RING_OUT, proc, FF_RELOAD, gen, slot, 1));
                replies[slot][gen][proc] = create_ring(name, 64, SOCKET_ID_ANY, 0);
            }
    CHECK(create_ring("dispatch_ring_p0_q0", 64, SOCKET_ID_ANY, RING_F_SC_DEQ));
    message_pool = ker_ipc_pool_create(FF_MSG_POOL, 127, 0);
    return message_pool ? 0 : -1;
}

static void caller_device_start(void)
{
    struct rte_eth_conf config = {0};
    device_pool = rte_pktmbuf_pool_create("ker_a14_device_rx", 127, 0, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(device_pool);
    CHECK(!rte_eth_dev_configure(0, 1, 1, &config));
    CHECK(!rte_eth_rx_queue_setup(0, 0, 64, SOCKET_ID_ANY, NULL, device_pool));
    CHECK(!rte_eth_tx_queue_setup(0, 0, 64, SOCKET_ID_ANY, NULL));
    CHECK(!rte_eth_dev_start(0));
}

static void caller_stop(void)
{
    running = false;
}

static void caller_run(int (*cycle)(void *), void *state)
{
    running = true;
    while (running) {
        for (unsigned slot = 0; slot < FF_RELOAD_EPOCH_SLOT_MAX; ++slot)
            for (int gen = 0; gen < FF_RELOAD_GEN_MAX; ++gen)
                for (unsigned proc = 0; proc < 2; ++proc) {
                    void *object;
                    if (rte_ring_dequeue(requests[slot][gen][proc], &object)) continue;
                    struct ff_msg *message = object;
                    int command;
                    CHECK(!ff_reload_msg_parse(message, &command, NULL, NULL, NULL));
                    CHECK(command == FF_RELOAD_CMD_QUERY);
                    ff_reload_msg_fill(message, command, ff_reload_gen(), 0, ff_reload_heartbeat_counter());
                    CHECK(!rte_ring_enqueue(replies[slot][gen][proc], object));
                }
        cycle(state);
        const struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
}

static int caller_eal_cleanup(void)
{
    CHECK(message_pool && rte_mempool_avail_count(message_pool) == 127);
    if (device_pool) {
        CHECK(!rte_eth_dev_stop(0) && !rte_eth_dev_close(0));
        CHECK(rte_mempool_avail_count(device_pool) == 127);
        rte_mempool_free(device_pool);
    }
    rte_mempool_free(message_pool);
    return rte_eal_cleanup();
}

struct CMUnitTest {
    const char *name;
    void (*test)(void **);
    int (*setup)(void **);
    int (*teardown)(void **);
};
static int run_cases(const struct CMUnitTest *cases, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        void *state = NULL;
        if (cases[i].setup) CHECK(!cases[i].setup(&state));
        cases[i].test(&state);
        if (cases[i].teardown) CHECK(!cases[i].teardown(&state));
        printf("A14_SOURCE_CASE %s\n", cases[i].name);
        fflush(stdout);
    }
    return 0;
}

#define ff_dpdk_init caller_primary_init
#define ff_dpdk_if_up caller_device_start
#define ff_dpdk_run caller_run
#define ff_dpdk_stop caller_stop
#define rte_eal_init qualified_eal_init
#define rte_eal_cleanup caller_eal_cleanup
#define cmocka_unit_test_setup_teardown(test, setup, teardown) {#test, test, setup, teardown}
#define cmocka_run_group_tests(tests, setup, teardown) run_cases(tests, sizeof(tests) / sizeof(tests[0]))
#define print_message(...) fprintf(stderr, __VA_ARGS__)
#define skip() CHECK(0)
#define assert_true(expr) CHECK(expr)
#define assert_non_null(expr) CHECK((expr) != NULL)
#define assert_int_equal(a, b) CHECK((uintmax_t)(a) == (uintmax_t)(b))
#define assert_int_not_equal(a, b) CHECK((uintmax_t)(a) != (uintmax_t)(b))
#define assert_ptr_equal(a, b) CHECK((a) == (b))
#define assert_string_equal(a, b) CHECK(!strcmp((a), (b)))
#include "fstack-a14-source.inc"
