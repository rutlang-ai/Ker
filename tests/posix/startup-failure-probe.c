#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <rte_malloc.h>

static _Atomic(void *) allocated_rx_queues;

void *rte_zmalloc(const char *type, size_t size, unsigned int align)
{
    void *(*next_alloc)(const char *, size_t, unsigned int) = dlsym(RTLD_NEXT, "rte_zmalloc");
    if (!next_alloc) return NULL;
    const char *mode = getenv("KER_TEST_PORT_QUEUE_ALLOCATION");
    if (!mode || !type) return next_alloc(type, size, align);
    const char *queue;
    if (!strcmp(type, "ethdev->rx_queues")) queue = "rx";
    else if (!strcmp(type, "ethdev->tx_queues")) queue = "tx";
    else return next_alloc(type, size, align);

    if (!strcmp(mode, queue)) {
        fprintf(stderr, "ker-test: %s queue allocation injected ENOMEM\n", queue);
        return NULL;
    }
    void *result = next_alloc(type, size, align);
    fprintf(stderr, "ker-test: %s queue allocation real %s\n", queue, result ? "ok" : "failed");
    if (result && !strcmp(mode, "tx") && !strcmp(queue, "rx"))
        atomic_store(&allocated_rx_queues, result);
    return result;
}

void rte_free(void *address)
{
    void (*next_free)(void *) = dlsym(RTLD_NEXT, "rte_free");
    if (!next_free) abort();
    void *expected = address;
    int rx_rollback = address && atomic_compare_exchange_strong(&allocated_rx_queues,
        &expected, NULL);
    next_free(address);
    if (rx_rollback) fputs("ker-test: rx queue allocation released\n", stderr);
}

int clock_gettime(clockid_t clock, struct timespec *value)
{
    int saved = errno;
    const char *mode = getenv("KER_TEST_STARTUP_FAILURE");
    /* Only the application preload has this startup channel. The separate
     * DPDK worker and every monotonic sample keep using the real host clock. */
    if (clock == CLOCK_REALTIME && mode && !strcmp(mode, "realtime") &&
        getenv("KER_STARTUP_FD") && getenv("KER_PACKET_FD")) {
        errno = EIO;
        return -1;
    }
    int (*next_clock)(clockid_t, struct timespec *) = dlsym(RTLD_NEXT, "clock_gettime");
    if (!next_clock) { errno = ENOSYS; return -1; }
    errno = saved;
    return next_clock(clock, value);
}

int rte_eal_cleanup(void)
{
    int (*next_cleanup)(void) = dlsym(RTLD_NEXT, "rte_eal_cleanup");
    if (!next_cleanup) return -1;
    const char *mode = getenv("KER_TEST_PORT_QUEUE_ALLOCATION");
    if (mode && !strcmp(mode, "tx"))
        fprintf(stderr, "ker-test: rx queue allocation %s before EAL cleanup\n",
                atomic_load(&allocated_rx_queues) ? "still owned" : "released");
    int result = next_cleanup();
    const char *path = getenv("KER_TEST_STARTUP_CLEANUP");
    if (path) {
        FILE *file = fopen(path, "w");
        if (file) { fprintf(file, "%d\n", result); fclose(file); }
    }
    return result;
}
