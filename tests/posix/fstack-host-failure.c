/* F-Stack host clock failure/panic scenarios against Ker's real callbacks.
 * Only the failing clock call is injected; normal calls reach the host. */
#define _GNU_SOURCE
#include "host-clock.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static int fail_clock;
int __real_clock_gettime(clockid_t clock, struct timespec *value);
int __wrap_clock_gettime(clockid_t clock, struct timespec *value)
{
    if (fail_clock && clock == CLOCK_MONOTONIC) {
        errno = EIO;
        return -1;
    }
    return __real_clock_gettime(clock, value);
}
static unsigned long long nanoseconds(struct timespec t)
{
    return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void fatal_callback(struct lkl_host_operations *ops, int clock_error)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        struct rlimit limit = {0, 0};
        if (setrlimit(RLIMIT_CORE, &limit)) _exit(2);
        if (clock_error) {
            fail_clock = 1;
            (void)ops->time();
        } else {
            ops->panic();
        }
        _exit(3); /* Returning from either fatal callback is a failure. */
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
}
int main(void)
{
    struct lkl_host_operations ops = {0};
    ker_native_host_clock_init(&ops);
    CHECK(ops.time && ops.panic);
    struct timespec before, after;
    CHECK(__real_clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    unsigned long long start = ops.time(), last = start;
    CHECK(__real_clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK(nanoseconds(before) <= start && start <= nanoseconds(after));
    for (int i = 0; i < 1000; ++i) {
        unsigned long long next = ops.time(); CHECK(next >= last); last = next;
    }
    struct timespec delay = {.tv_nsec = 2000000};
    while (nanosleep(&delay, &delay)) CHECK(errno == EINTR);
    CHECK(ops.time() > last);
    fatal_callback(&ops, 1);
    fatal_callback(&ops, 0);
    /* Child fault injection must not poison the parent callback. */
    CHECK(ops.time() >= start);
    puts("PASS: real monotonic clock, clock failure and unconditional panic abort");
    return 0;
}
