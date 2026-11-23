/* Optional current-time outputs through the production adapter and real Linux. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include "host-memory.h"
#include "host-clock.h"
#include "realtime-clock.h"
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
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
/* No clock adjustment or native shutdown occurs until all readers join. */
#define READERS 4U
#define ROUNDS 32U
static pthread_barrier_t reader_barrier;
struct reader { unsigned id; unsigned failures; unsigned samples; };
static void synchronize(void)
{
    int result = pthread_barrier_wait(&reader_barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *read_parallel(void *opaque)
{
    struct reader *reader = opaque;
    CHECK(reads == 0 && !fail_read);
    synchronize();
    for (unsigned round = 0; round < ROUNDS; round++) {
        for (unsigned outputs = 0; outputs < 4; outputs++) {
            int64_t seconds = 91; long nanoseconds = 92;
            unsigned prior = reads;
            bool injected = (reader->id + round) % 2 == 0;
            fail_read = injected;
            /* Half the readers fail while the other half perform real reads.
             * A process-global injection flag would be consumed by a peer. */
            synchronize();
            int result = ker_posix_get_current_time(outputs & 1 ? &seconds : NULL,
                                                   outputs & 2 ? &nanoseconds : NULL);
            CHECK(reads == prior+1 && !fail_read);
            if (injected) {
                CHECK(result == -1 && errno == EIO && seconds == 91 && nanoseconds == 92);
                reader->failures++;
            } else {
                CHECK(result == 0);
                CHECK(outputs & 1 ? seconds >= 946684800 && seconds < 1577836800 : seconds == 91);
                CHECK(outputs & 2 ? nanoseconds >= 0 && nanoseconds < 1000000000L : nanoseconds == 92);
            }
            struct __lkl__kernel_timespec before = native_time();
            CHECK(!ker_posix_get_current_time(&seconds, &nanoseconds));
            struct __lkl__kernel_timespec after = native_time();
            struct __lkl__kernel_timespec actual = {.tv_sec=seconds, .tv_nsec=nanoseconds};
            CHECK(compare(before, actual) <= 0 && compare(actual, after) <= 0);
            CHECK(seconds >= 946684800 && seconds < 1577836800);
            CHECK(nanoseconds >= 0 && nanoseconds < 1000000000L && reads == prior+4);
            reader->samples++;
            int expected = reader->id & 1 ? E2BIG : ERANGE;
            errno = expected;
            synchronize();
            CHECK(errno == expected);
        }
    }
    CHECK(reads == ROUNDS*4*4 && reader->failures == ROUNDS*2 && reader->samples == ROUNDS*4);
    return reader;
}
static void parallel(void)
{
    struct __lkl__kernel_timespec old = {.tv_sec=946684800, .tv_nsec=123456789};
    CHECK(!lkl_sys_clock_settime(LKL_CLOCK_REALTIME, &old));
    struct reader readers[READERS]; pthread_t threads[READERS];
    unsigned prior = reads;
    CHECK(!pthread_barrier_init(&reader_barrier, NULL, READERS));
    for (unsigned i = 0; i < READERS; i++) {
        readers[i] = (struct reader){.id=i};
        CHECK(!pthread_create(&threads[i], NULL, read_parallel, &readers[i]));
    }
    for (unsigned i = 0; i < READERS; i++) {
        void *result;
        CHECK(!pthread_join(threads[i], &result) && result == &readers[i]);
    }
    CHECK(reads == prior && !fail_read);
    CHECK(!pthread_barrier_destroy(&reader_barrier));
    CHECK(!ker_native_sync_realtime());
    printf("TIME_PARALLEL readers=%u samples=%u failures=%u\n",
           READERS, READERS*ROUNDS*4, READERS*ROUNDS*2);
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
    else if (!strcmp(argv[1], "parallel")) parallel();
    else { CHECK(!strcmp(argv[1], "errors")); errors(); }
    active = false; inactive();
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    puts("PASS: original Linux realtime optional outputs, lifetime and error preservation");
    return 0;
}
