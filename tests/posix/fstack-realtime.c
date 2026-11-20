#define _GNU_SOURCE
#include <ker/posix.h>
#include "fd-table.h"
#include "realtime-clock.h"
#include "host-clock.h"
#include "host-memory.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <lkl.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static atomic_int fault;
static atomic_uint realtime_reads;
static bool active;
static _Thread_local unsigned native_realtime_reads;
static _Thread_local bool fail_native_read;
enum { VALID, HOST_ERROR, INVALID_NSEC };
int __real_clock_gettime(clockid_t clock, struct timespec *value);
long __real_lkl_syscall(long number, long *parameters);

/* This fixture boots original Linux and controls the adapter's lifetime at
 * the same boundary that the launcher owns during normal startup. */
bool ker_native_ready(void)
{
    return active;
}

long __wrap_lkl_syscall(long number, long *parameters)
{
    if (number == __lkl__NR_clock_gettime && parameters[0] == LKL_CLOCK_REALTIME) {
        native_realtime_reads++;
        if (fail_native_read) {
            fail_native_read = false;
            struct __lkl__kernel_timespec *value = (void *)parameters[1];
            *value = (struct __lkl__kernel_timespec){.tv_sec = 7, .tv_nsec = 8};
            return -EIO;
        }
    }
    return __real_lkl_syscall(number, parameters);
}
int __wrap_clock_gettime(clockid_t clock, struct timespec *value)
{
    if (clock != CLOCK_REALTIME) return __real_clock_gettime(clock, value);
    atomic_fetch_add(&realtime_reads, 1);
    if (atomic_load(&fault) == HOST_ERROR) { errno = EIO; return -1; }
    int result = __real_clock_gettime(clock, value);
    if (!result && atomic_load(&fault) == INVALID_NSEC) value->tv_nsec = 1000000000L;
    return result;
}
static int64_t host_ns(clockid_t clock)
{
    struct timespec value;
    CHECK(__real_clock_gettime(clock, &value) == 0);
    CHECK(value.tv_nsec >= 0 && value.tv_nsec < 1000000000L);
    return (int64_t)value.tv_sec * 1000000000LL + value.tv_nsec;
}
static struct __lkl__kernel_timespec native_clock(int clock)
{
    struct __lkl__kernel_timespec value = {.tv_sec = -1, .tv_nsec = -1};
    CHECK(lkl_sys_clock_gettime(clock, &value) == 0);
    CHECK(value.tv_nsec >= 0 && value.tv_nsec < 1000000000L);
    return value;
}
static int64_t native_ns(int clock)
{
    struct __lkl__kernel_timespec value = native_clock(clock);
    return value.tv_sec * 1000000000LL + value.tv_nsec;
}
static void obsolete_epoch(void)
{
    struct __lkl__kernel_timespec old = {.tv_sec = 946684800, .tv_nsec = 0};
    CHECK(lkl_sys_clock_settime(LKL_CLOCK_REALTIME, &old) == 0);
}
static void failed_sync(int kind, int expected)
{
    obsolete_epoch();
    int64_t host_before = host_ns(CLOCK_MONOTONIC);
    int64_t before = native_ns(LKL_CLOCK_REALTIME);
    int64_t mono_before = native_ns(LKL_CLOCK_MONOTONIC);
    atomic_store(&realtime_reads, 0);
    atomic_store(&fault, kind);
    CHECK(ker_native_sync_realtime() == -expected);
    atomic_store(&fault, VALID);
    CHECK(atomic_load(&realtime_reads) == 1);
    int64_t mono_after = native_ns(LKL_CLOCK_MONOTONIC);
    int64_t after = native_ns(LKL_CLOCK_REALTIME);
    /* A rejected synchronization must leave realtime advancing at the old
     * epoch, rather than writing stale/uninitialized host timestamp data. */
    CHECK(after >= before && mono_after >= mono_before);
    int64_t elapsed = host_ns(CLOCK_MONOTONIC) - host_before;
    CHECK(after - before <= elapsed + 1000000LL);
    CHECK(mono_after - mono_before <= elapsed + 1000000LL);
}
static void successful_sync(void)
{
    obsolete_epoch();
    int64_t host_mono_before = host_ns(CLOCK_MONOTONIC);
    int64_t mono_before = native_ns(LKL_CLOCK_MONOTONIC);
    int64_t host_before = host_ns(CLOCK_REALTIME);
    atomic_store(&realtime_reads, 0);
    CHECK(ker_native_sync_realtime() == 0);
    CHECK(atomic_load(&realtime_reads) == 1);
    int64_t actual = native_ns(LKL_CLOCK_REALTIME);
    int64_t host_after = host_ns(CLOCK_REALTIME);
    CHECK(actual / 1000000000LL > 1577836800LL);
    CHECK(actual >= host_before - 1000000LL && actual <= host_after + 1000000LL);
    struct timespec delay = {.tv_nsec = 2000000};
    while (nanosleep(&delay, &delay) != 0) CHECK(errno == EINTR);
    CHECK(native_ns(LKL_CLOCK_REALTIME) > actual);
    int64_t mono_after = native_ns(LKL_CLOCK_MONOTONIC);
    int64_t host_mono_after = host_ns(CLOCK_MONOTONIC);
    CHECK(mono_after > mono_before);
    /* Host observations bracket native observations, so scheduler pauses
     * between samples cannot be mistaken for a private monotonic jump. */
    CHECK(mono_after - mono_before <= host_mono_after - host_mono_before + 1000000LL);
    puts("PASS: original Linux realtime matches host epoch/advances; monotonic timer clock unchanged");
}
static void native_wait_advance(const char *stage)
{
    unsigned int reads = atomic_load(&realtime_reads);
    int64_t host_before = host_ns(CLOCK_MONOTONIC);
    struct __lkl__kernel_timespec before = native_clock(LKL_CLOCK_REALTIME);
    int64_t mono_before = native_ns(LKL_CLOCK_MONOTONIC);
    /* Use original Linux's timed wait rather than a host sleep to advance
     * the observations. No descriptors or host socket fallback are involved. */
    CHECK(lkl_sys_poll(NULL, 0, 25) == 0);
    int64_t mono_after = native_ns(LKL_CLOCK_MONOTONIC);
    struct __lkl__kernel_timespec after = native_clock(LKL_CLOCK_REALTIME);
    int64_t host_after = host_ns(CLOCK_MONOTONIC);
    CHECK(before.tv_sec > 0 && after.tv_sec > 0);
    CHECK(after.tv_sec > before.tv_sec ||
          (after.tv_sec == before.tv_sec && after.tv_nsec > before.tv_nsec));
    int64_t elapsed = (after.tv_sec - before.tv_sec) * 1000000000LL +
        after.tv_nsec - before.tv_nsec;
    CHECK(mono_after - mono_before >= 25000000LL);
    CHECK(elapsed >= 25000000LL);
    CHECK(mono_after - mono_before <= host_after - host_before + 1000000LL);
    CHECK(elapsed <= host_after - host_before + 1000000LL);
    /* The advancing samples came from the original Linux clock, not another
     * invocation of the wrapped host realtime read. */
    CHECK(atomic_load(&realtime_reads) == reads);
    printf("PASS: %s, normalized native realtime advances across original Linux timed poll\n", stage);
}
static void current_time_updates(void)
{
    obsolete_epoch(); native_wait_advance("old epoch");
    successful_sync(); native_wait_advance("first synchronization");
    failed_sync(HOST_ERROR, EIO); native_wait_advance("host EIO retains advancing old epoch");
    failed_sync(INVALID_NSEC, EINVAL); native_wait_advance("native EINVAL retains advancing old epoch");
    successful_sync(); native_wait_advance("recovered synchronization");
}
static void inactive_realtime(void)
{
    long nanoseconds = -1;
    unsigned reads = native_realtime_reads;
    CHECK(ker_posix_get_current_time(NULL, &nanoseconds) == -1 && errno == ENETDOWN);
    CHECK(nanoseconds == -1 && native_realtime_reads == reads);
}
static void optional_seconds(void)
{
    obsolete_epoch();
    struct __lkl__kernel_timespec before = native_clock(LKL_CLOCK_REALTIME);
    unsigned reads = native_realtime_reads;
    long nanoseconds = -1;
    CHECK(ker_posix_get_current_time(NULL, &nanoseconds) == 0);
    CHECK(native_realtime_reads == reads + 1);
    struct __lkl__kernel_timespec after = native_clock(LKL_CLOCK_REALTIME);
    CHECK(nanoseconds >= 0 && nanoseconds < 1000000000L);
    if (before.tv_sec == after.tv_sec)
        CHECK(nanoseconds >= before.tv_nsec && nanoseconds <= after.tv_nsec);
    else if (after.tv_sec == before.tv_sec + 1)
        CHECK(nanoseconds >= before.tv_nsec || nanoseconds <= after.tv_nsec);

    reads = native_realtime_reads;
    nanoseconds = -1;
    fail_native_read = true;
    CHECK(ker_posix_get_current_time(NULL, &nanoseconds) == -1 && errno == EIO);
    CHECK(!fail_native_read && nanoseconds == -1 && native_realtime_reads == reads + 1);
    CHECK(ker_posix_get_current_time(NULL, &nanoseconds) == 0);
    CHECK(nanoseconds >= 0 && nanoseconds < 1000000000L);
    puts("PASS: original Linux realtime nanoseconds with seconds omitted");
}
int main(int argc, char **argv)
{
    bool updates = argc == 2 && !strcmp(argv[1], "--updates");
    bool null_seconds = argc == 2 && !strcmp(argv[1], "--null-seconds");
    CHECK(argc == 1 || updates || null_seconds);
    if (null_seconds) inactive_realtime();
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    active = true;
    if (updates) current_time_updates();
    else if (null_seconds) optional_seconds();
    else {
        failed_sync(HOST_ERROR, EIO);
        /* Host read succeeds, but original Linux must reject invalid nanoseconds. */
        failed_sync(INVALID_NSEC, EINVAL);
        successful_sync(); successful_sync();
    }
    active = false;
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    if (null_seconds) inactive_realtime();
    else puts("PASS: host EIO/native EINVAL propagate without epoch mutation; recovery and repeat sync succeed");
    return 0;
}
