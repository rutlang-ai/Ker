/* Optional current-time outputs through the production adapter and real Linux. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include "host-memory.h"
#include "host-clock.h"
#include "realtime-clock.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lkl.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static bool active;
static _Thread_local unsigned reads;
static _Thread_local bool fail_read;
bool ker_native_ready(void) { return active; }
long __real_lkl_syscall(long number, long *params);
long __wrap_lkl_syscall(long number, long *params)
{
    if (number == __lkl__NR_clock_gettime) {
        reads++;
        CHECK(params[0] == LKL_CLOCK_REALTIME);
        if (fail_read) {
            fail_read = false;
            struct __lkl__kernel_timespec *value = (void *)params[1];
            *value = (struct __lkl__kernel_timespec){.tv_sec=7, .tv_nsec=8};
            return -EIO;
        }
    }
    return __real_lkl_syscall(number, params);
}
static struct __lkl__kernel_timespec native_time(void)
{
    struct __lkl__kernel_timespec value;
    CHECK(!lkl_sys_clock_gettime(LKL_CLOCK_REALTIME, &value));
    return value;
}
static int compare(struct __lkl__kernel_timespec a, struct __lkl__kernel_timespec b)
{
    if (a.tv_sec != b.tv_sec) return a.tv_sec < b.tv_sec ? -1 : 1;
    return a.tv_nsec < b.tv_nsec ? -1 : a.tv_nsec > b.tv_nsec;
}
static void optional(void)
{
    /* Distinguish the private kernel clock from any host clock fallback. */
    struct __lkl__kernel_timespec old = {.tv_sec=946684800, .tv_nsec=123456789};
    CHECK(!lkl_sys_clock_settime(LKL_CLOCK_REALTIME, &old));
    struct __lkl__kernel_timespec before = native_time();
    int64_t seconds = -1; long nanoseconds = -1;
    unsigned prior = reads;
    CHECK(!ker_posix_get_current_time(&seconds, &nanoseconds) && reads == prior+1);
    struct __lkl__kernel_timespec after = native_time();
    struct __lkl__kernel_timespec actual = {.tv_sec=seconds, .tv_nsec=nanoseconds};
    CHECK(compare(before, actual) <= 0 && compare(actual, after) <= 0 && seconds < 1577836800);
    CHECK(!ker_native_sync_realtime());
    nanoseconds = -1; prior = reads;
    CHECK(!ker_posix_get_current_time(NULL, &nanoseconds) && reads == prior+1);
    CHECK(nanoseconds >= 0 && nanoseconds < 1000000000L);
    puts("TIME_SOURCE_CASE test_ff_get_current_time_null_sec");
    seconds = -1; prior = reads;
    CHECK(!ker_posix_get_current_time(&seconds, NULL) && reads == prior+1);
    CHECK(seconds > 1577836800);
    puts("TIME_SOURCE_CASE test_ff_get_current_time_null_nsec");
    prior = reads;
    CHECK(!ker_posix_get_current_time(NULL, NULL) && reads == prior+1);
}
static void errors(void)
{
    for (unsigned outputs = 0; outputs < 4; outputs++) {
        int64_t seconds = 91; long nanoseconds = 92;
        unsigned prior = reads;
        fail_read = true;
        CHECK(ker_posix_get_current_time(outputs & 1 ? &seconds : NULL,
              outputs & 2 ? &nanoseconds : NULL) == -1 && errno == EIO && !fail_read);
        CHECK(reads == prior+1 && seconds == 91 && nanoseconds == 92);
        CHECK(!ker_posix_get_current_time(&seconds, &nanoseconds));
        CHECK(seconds > 1577836800 && nanoseconds >= 0 && nanoseconds < 1000000000L);
    }
}
static void inactive(void)
{
    int64_t seconds = 91; long nanoseconds = 92; unsigned prior = reads;
    CHECK(ker_posix_get_current_time(&seconds, &nanoseconds) == -1 && errno == ENETDOWN);
    CHECK(seconds == 91 && nanoseconds == 92 && reads == prior);
    CHECK(ker_posix_get_current_time(NULL, NULL) == -1 && errno == ENETDOWN && reads == prior);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2); inactive();
    ker_native_host_memory_init(&lkl_host_ops); ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL; CHECK(!lkl_init(&lkl_host_ops)); CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); CHECK(!ker_native_sync_realtime()); active = true;
    if (!strcmp(argv[1], "optional")) optional();
    else { CHECK(!strcmp(argv[1], "errors")); errors(); }
    active = false; inactive();
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    puts("PASS: original Linux realtime optional outputs, lifetime and error preservation");
    return 0;
}
