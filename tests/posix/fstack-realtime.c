#define _GNU_SOURCE
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
enum { VALID, HOST_ERROR, INVALID_NSEC };
int __real_clock_gettime(clockid_t clock, struct timespec *value);
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
static int64_t native_ns(int clock)
{
    struct __lkl__kernel_timespec value = {.tv_sec = -1, .tv_nsec = -1};
    CHECK(lkl_sys_clock_gettime(clock, &value) == 0);
    CHECK(value.tv_nsec >= 0 && value.tv_nsec < 1000000000L);
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
/* The source current-time case refreshes twice and compares the resulting
 * realtime samples. Ker refreshes the private original Linux clock, rather
 * than introducing a second cached timestamp/getter implementation. */
static int64_t refreshed_time(void)
{
    int64_t before = host_ns(CLOCK_REALTIME);
    atomic_store(&realtime_reads, 0);
    CHECK(ker_native_sync_realtime() == 0);
    CHECK(atomic_load(&realtime_reads) == 1);
    int64_t actual = native_ns(LKL_CLOCK_REALTIME);
    int64_t after = host_ns(CLOCK_REALTIME);
    CHECK(actual / 1000000000LL > 1577836800LL);
    CHECK(actual >= before - 1000000LL && actual <= after + 1000000LL);
    return actual;
}
static void refresh_profile(int kind)
{
    obsolete_epoch();
    int64_t first = refreshed_time();
    int64_t host_before = host_ns(CLOCK_MONOTONIC);
    int64_t mono_before = native_ns(LKL_CLOCK_MONOTONIC);
    struct timespec delay = {.tv_nsec = 2000000};
    while (nanosleep(&delay, &delay) != 0) CHECK(errno == EINTR);
    if (kind != VALID) {
        int64_t host_failure_before = host_ns(CLOCK_MONOTONIC);
        int64_t before = native_ns(LKL_CLOCK_REALTIME);
        atomic_store(&realtime_reads, 0);
        atomic_store(&fault, kind);
        CHECK(ker_native_sync_realtime() == -(kind == HOST_ERROR ? EIO : EINVAL));
        atomic_store(&fault, VALID);
        CHECK(atomic_load(&realtime_reads) == 1);
        int64_t after = native_ns(LKL_CLOCK_REALTIME);
        int64_t elapsed = host_ns(CLOCK_MONOTONIC) - host_failure_before;
        CHECK(after >= before && after - before <= elapsed + 1000000LL);
    }
    int64_t second = refreshed_time();
    CHECK(second > first);
    int64_t mono_after = native_ns(LKL_CLOCK_MONOTONIC);
    int64_t host_after = host_ns(CLOCK_MONOTONIC);
    CHECK(mono_after > mono_before);
    CHECK(mono_after - mono_before <= host_after - host_before + 1000000LL);
    printf("PASS: realtime refresh profile=%s advances across two updates; "
        "original Linux epoch/monotonic and recovery checked\n",
        kind == VALID ? "advance" : kind == HOST_ERROR ? "host-error" : "invalid-nsec");
}
int main(int argc, char **argv)
{
    CHECK(argc == 1 || (argc == 2 && (!strcmp(argv[1], "advance") ||
        !strcmp(argv[1], "host-error") || !strcmp(argv[1], "invalid-nsec"))));
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    if (argc == 2) {
        refresh_profile(!strcmp(argv[1], "advance") ? VALID :
            !strcmp(argv[1], "host-error") ? HOST_ERROR : INVALID_NSEC);
    } else {
        failed_sync(HOST_ERROR, EIO);
        /* Host read succeeds, but original Linux rejects invalid nanoseconds. */
        failed_sync(INVALID_NSEC, EINVAL);
        successful_sync(); successful_sync();
    }
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    if (argc == 1)
        puts("PASS: host EIO/native EINVAL propagate without epoch mutation; recovery and repeat sync succeed");
    return 0;
}
