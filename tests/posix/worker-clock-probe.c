#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Fail only after the parent observes READY and creates its private marker.
 * Inject once on the main worker thread; EAL background threads, cleanup,
 * startup and realtime/other clock reads still use the host clock. */
int clock_gettime(clockid_t clock, struct timespec *value)
{
    int saved = errno;
    static int injected;
    const char *marker = getenv("KER_TEST_WORKER_CLOCK_FAIL");
    if (clock == CLOCK_MONOTONIC && syscall(SYS_gettid) == getpid() &&
        !injected && marker && access(marker, F_OK) == 0) {
        injected = 1;
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
    static int (*next_cleanup)(void);
    if (!next_cleanup) next_cleanup = dlsym(RTLD_NEXT, "rte_eal_cleanup");
    if (!next_cleanup) return -1;
    int result = next_cleanup();
    const char *path = getenv("KER_TEST_WORKER_CLEANUP");
    if (path) {
        FILE *file = fopen(path, "w");
        if (file) { fprintf(file, "%d\n", result); fclose(file); }
    }
    return result;
}
