#define _POSIX_C_SOURCE 200809L
#include "worker-clock.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static enum { REAL, FAIL, SAMPLE } mode;
static struct timespec sample;
int __real_clock_gettime(clockid_t, struct timespec *);
int __wrap_clock_gettime(clockid_t clock, struct timespec *value)
{
    CHECK(clock == CLOCK_MONOTONIC);
    if (mode == FAIL) { errno = EIO; return -1; }
    if (mode == SAMPLE) { *value = sample; return 0; }
    return __real_clock_gettime(clock, value);
}
static void rejected(struct timespec value, int error)
{
    sample = value;
    int64_t output = 123;
    errno = 0;
    CHECK(ker_worker_now_ns(&output) == -1 && errno == error && output == 123);
}
int main(void)
{
    int64_t before, after;
    CHECK(ker_worker_now_ns(&before) == 0 && before > 0);
    struct timespec delay = {.tv_nsec = 2000000};
    while (nanosleep(&delay, &delay)) CHECK(errno == EINTR);
    CHECK(ker_worker_now_ns(&after) == 0 && after > before);
    mode = FAIL;
    int64_t output = 123;
    CHECK(ker_worker_now_ns(&output) == -1 && errno == EIO && output == 123);
    mode = SAMPLE;
    sample = (struct timespec){.tv_sec = 12, .tv_nsec = 345};
    CHECK(ker_worker_now_ns(&output) == 0 && output == INT64_C(12000000345));
    rejected((struct timespec){.tv_sec = -1}, EINVAL);
    rejected((struct timespec){.tv_nsec = -1}, EINVAL);
    rejected((struct timespec){.tv_nsec = 1000000000}, EINVAL);
    sample = (struct timespec){.tv_sec = INT64_MAX / INT64_C(1000000000),
        .tv_nsec = INT64_MAX % INT64_C(1000000000)};
    CHECK(ker_worker_now_ns(&output) == 0 && output == INT64_MAX);
    sample.tv_nsec++;
    rejected(sample, EOVERFLOW);
    mode = REAL;
    CHECK(ker_worker_now_ns(&output) == 0 && output >= after);
    puts("PASS: real worker monotonic nanoseconds advance; failures preserve output; exact conversion and overflow bounds");
    return 0;
}
