#define _GNU_SOURCE
#include "host-timer.h"
#include "host-memory.h"
#include "host-clock.h"
#include "host-thread.h"
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)

/* Fail only the calling test thread. Successful calls always reach POSIX;
 * original Linux runs with fault injection and allocation tracking disabled. */
static _Thread_local int fail_allocation, fail_create, fail_set, fail_delete, track;
static _Thread_local long balance;
static timer_t observed_timer;
static struct itimerspec observed_value;
void *__real_malloc(size_t size);
void __real_free(void *pointer);
int __real_timer_create(clockid_t clock, struct sigevent *event, timer_t *timer);
int __real_timer_settime(timer_t timer, int flags, const struct itimerspec *value,
                         struct itimerspec *old);
int __real_timer_delete(timer_t timer);
void *__wrap_malloc(size_t size)
{
    if (fail_allocation) { fail_allocation = 0; errno = ENOMEM; return NULL; }
    void *value = __real_malloc(size);
    if (track && value) ++balance;
    return value;
}
void __wrap_free(void *value)
{
    if (track && value) --balance;
    __real_free(value);
}
int __wrap_timer_create(clockid_t clock, struct sigevent *event, timer_t *timer)
{
    if (fail_create) { errno = fail_create; fail_create = 0; return -1; }
    if (track) CHECK(clock == CLOCK_REALTIME && event->sigev_notify == SIGEV_THREAD);
    int result = __real_timer_create(clock, event, timer);
    if (!result && track) observed_timer = *timer;
    return result;
}
int __wrap_timer_settime(timer_t timer, int flags, const struct itimerspec *value,
                         struct itimerspec *old)
{
    if (fail_set) { errno = fail_set; fail_set = 0; return -1; }
    if (track) { CHECK(flags == 0); observed_value = *value; }
    return __real_timer_settime(timer, flags, value, old);
}
int __wrap_timer_delete(timer_t timer)
{
    if (fail_delete) { errno = fail_delete; fail_delete = 0; return -1; }
    return __real_timer_delete(timer);
}
static struct lkl_host_operations ops;
/* Static lifetime: deletion is not claimed to join in-flight SIGEV_THREAD
 * callbacks. The callback never dereferences the timer's opaque storage. */
static sem_t fired;
static atomic_uint callbacks;
static void notify(void)
{
    atomic_fetch_add(&callbacks, 1);
    CHECK(sem_post(&fired) == 0);
}
static void ignore_expiration(void) { }
static void delete_failure(void)
{
    /* Fork before the parent has called timer_create or started any threads. */
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        struct rlimit limit = {0, 0}; CHECK(setrlimit(RLIMIT_CORE, &limit) == 0);
        void *timer = ops.timer_alloc(notify); CHECK(timer);
        fail_delete = EINVAL;
        ops.timer_free(timer);
        _exit(3);
    }
    int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    puts("PASS: failed timer deletion aborts rather than silently freeing a live handle");
}
static void timer_lifecycle(void)
{
    track = 1;
    fail_allocation = 1; errno = EINVAL;
    CHECK(ops.timer_alloc(notify) == NULL && !fail_allocation && errno == ENOMEM && balance == 0);
    const int errors[] = {EAGAIN, ENOMEM};
    for (unsigned int i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fail_create = errors[i]; errno = EINVAL;
        CHECK(ops.timer_alloc(notify) == NULL);
        CHECK(!fail_create && errno == errors[i] && balance == 0);
        void *timer = ops.timer_alloc(notify); CHECK(timer && balance == 1);
        ops.timer_free(timer); CHECK(balance == 0);
    }
    /* Conversion checks may expire if the host deschedules the test. Use a
     * separate callback so that cannot contaminate the one-shot fire oracle. */
    void *timer = ops.timer_alloc(ignore_expiration); CHECK(timer && balance == 1);
    CHECK(ops.timer_set_oneshot(timer, 1000000001UL) == 0);
    CHECK(observed_value.it_value.tv_sec == 1 && observed_value.it_value.tv_nsec == 1);
    CHECK(observed_value.it_interval.tv_sec == 0 && observed_value.it_interval.tv_nsec == 0);
    /* Failure must return errno; then the same real timer must remain usable. */
    fail_set = EINVAL; errno = EIO;
    CHECK(ops.timer_set_oneshot(timer, 0) == -1 && !fail_set && errno == EINVAL);
    CHECK(ops.timer_set_oneshot(timer, 0) == 0);
    struct itimerspec value;
    CHECK(timer_gettime(observed_timer, &value) == 0);
    CHECK(value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
    CHECK(value.it_interval.tv_sec == 0 && value.it_interval.tv_nsec == 0);
    ops.timer_free(timer); CHECK(balance == 0);
    timer = ops.timer_alloc(notify); CHECK(timer && balance == 1);
    /* Longer than this CTest's entire timeout: the observed callback must
     * come from replacing this deadline, not from the first arm expiring. */
    CHECK(ops.timer_set_oneshot(timer, 100000000001UL) == 0);
    CHECK(observed_value.it_value.tv_sec == 100 && observed_value.it_value.tv_nsec == 1);
    CHECK(ops.timer_set_oneshot(timer, 1) == 0);
    CHECK(observed_value.it_value.tv_sec == 0 && observed_value.it_value.tv_nsec == 1);
    struct timespec deadline; CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 5;
    while (sem_timedwait(&fired, &deadline)) CHECK(errno == EINTR);
    CHECK(atomic_load(&callbacks) == 1);
    CHECK(timer_gettime(observed_timer, &value) == 0);
    CHECK(value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
    CHECK(value.it_interval.tv_sec == 0 && value.it_interval.tv_nsec == 0);
    ops.timer_free(timer); CHECK(balance == 0);
    track = 0;
    puts("PASS: timer allocation/create failures preserve errno, release storage and recover");
    puts("PASS: nanosecond conversion, zero disarm, set failure recovery, rearm and real one-shot callback");
}
static atomic_uint kernel_allocations, kernel_arms, kernel_frees, kernel_fires;
static _Atomic(void (*)(void)) kernel_routine;
static void kernel_notify(void)
{
    atomic_fetch_add(&kernel_fires, 1);
    atomic_load(&kernel_routine)();
}
static void *count_alloc(void (*routine)(void))
{
    atomic_store(&kernel_routine, routine);
    void *timer = ops.timer_alloc(kernel_notify);
    if (timer) atomic_fetch_add(&kernel_allocations, 1);
    return timer;
}
static int count_arm(void *timer, unsigned long ns)
{
    int result = ops.timer_set_oneshot(timer, ns);
    if (!result && ns) atomic_fetch_add(&kernel_arms, 1);
    return result;
}
static void count_free(void *timer)
{
    ops.timer_free(timer);
    atomic_fetch_add(&kernel_frees, 1);
}
int main(void)
{
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    ker_native_host_thread_init(&lkl_host_ops);
    ker_native_host_timer_init(&lkl_host_ops);
    ops = lkl_host_ops;
    CHECK(sem_init(&fired, 0, 0) == 0);
    delete_failure();
    timer_lifecycle();
    lkl_host_ops.print = NULL;
    lkl_host_ops.timer_alloc = count_alloc;
    lkl_host_ops.timer_set_oneshot = count_arm;
    lkl_host_ops.timer_free = count_free;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    CHECK(lkl_sys_poll(NULL, 0, 20) == 0); /* Original Linux hrtimer wakeup. */
    CHECK(atomic_load(&kernel_allocations) > 0 && atomic_load(&kernel_arms) > 0);
    CHECK(atomic_load(&kernel_fires) > 0);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    CHECK(atomic_load(&kernel_allocations) == atomic_load(&kernel_frees));
    puts("PASS: original Linux allocates/arms/fires/frees adapted timers and wakes timed poll");
    return 0;
}
