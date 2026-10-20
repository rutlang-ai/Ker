#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    int result = next_cleanup();
    const char *path = getenv("KER_TEST_STARTUP_CLEANUP");
    if (path) {
        FILE *file = fopen(path, "w");
        if (file) { fprintf(file, "%d\n", result); fclose(file); }
    }
    return result;
}
