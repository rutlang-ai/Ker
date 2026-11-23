/* Fault the actual host realtime read in native startup, not a fake kernel. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
int clock_gettime(clockid_t clock, struct timespec *value)
{
    if (clock == CLOCK_REALTIME && getenv("KER_TEST_STARTUP_REALTIME_FAILURE")) {
        static const char marker[] = "TEST_REALTIME_CLOCK_EIO\n";
        (void)syscall(SYS_write, STDERR_FILENO, marker, sizeof(marker)-1);
        errno = EIO;
        return -1;
    }
    return (int)syscall(SYS_clock_gettime, clock, value);
}
static void (*native_stop)(void);
static int stop(void *unused) { (void)unused; native_stop(); return 0; }
int main(int argc, char **argv)
{
    CHECK(argc == 2 && !strcmp(argv[1], "clock"));
    puts("TEST_APPLICATION_REACHED");
    CHECK(!fflush(stdout)); /* Entry evidence must survive a later fatal exit. */
    uint64_t (*capabilities)(void) = dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    int (*current_time)(int64_t *, long *) = dlsym(RTLD_DEFAULT, "ker_posix_get_current_time");
    int (*native_run)(ker_posix_loop_func, void *) = dlsym(RTLD_DEFAULT, "ker_posix_run");
    native_stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    CHECK(capabilities && (capabilities() & KER_CAP_LINUX_STACK));
    CHECK(current_time && native_run && native_stop);
    struct timespec before, after;
    int64_t seconds = -1; long nanoseconds = -1;
    CHECK(!clock_gettime(CLOCK_REALTIME, &before));
    CHECK(!current_time(&seconds, &nanoseconds));
    CHECK(!clock_gettime(CLOCK_REALTIME, &after));
    CHECK(seconds >= before.tv_sec-1 && seconds <= after.tv_sec+1);
    CHECK(nanoseconds >= 0 && nanoseconds < 1000000000L);
    CHECK(!native_run(stop, NULL) && !capabilities());
    puts("HOST_SOURCE_CASE test_ff_update_current_ts_assert_fail_on_clock_error");
    return 0;
}
