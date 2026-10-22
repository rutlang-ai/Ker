#define _GNU_SOURCE
#include "host-thread.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <limits.h>
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
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static struct lkl_host_operations ops;
static _Thread_local int fail_alloc, fail_init, fail_wait, fail_destroy, track_alloc, watch_wait;
static _Thread_local long allocations;
static atomic_uint attempts, interrupted, returned, kernel_semaphores;
void *__real_malloc(size_t size);
void __real_free(void *value);
int __real_sem_init(sem_t *sem, int shared, unsigned int count);
int __real_sem_wait(sem_t *sem);
int __real_sem_destroy(sem_t *sem);
void *__wrap_malloc(size_t size)
{
    if (fail_alloc) { fail_alloc = 0; errno = ENOMEM; return NULL; }
    void *value = __real_malloc(size);
    if (value && track_alloc) ++allocations;
    return value;
}
void __wrap_free(void *value)
{
    if (value && track_alloc) --allocations;
    __real_free(value);
}
int __wrap_sem_init(sem_t *sem, int shared, unsigned int count)
{
    if (fail_init) { errno = fail_init; fail_init = 0; return -1; }
    return __real_sem_init(sem, shared, count);
}
int __wrap_sem_wait(sem_t *sem)
{
    if (fail_wait) { errno = fail_wait; fail_wait = 0; return -1; }
    if (watch_wait) atomic_fetch_add(&attempts, 1);
    int result = __real_sem_wait(sem);
    if (watch_wait && result && errno == EINTR) atomic_fetch_add(&interrupted, 1);
    return result;
}
int __wrap_sem_destroy(sem_t *sem)
{
    if (fail_destroy) { errno = fail_destroy; fail_destroy = 0; return -1; }
    return __real_sem_destroy(sem);
}
static void allocation_failures(void)
{
    track_alloc = fail_alloc = 1;
    CHECK(ops.sem_alloc(0) == NULL && errno == ENOMEM && !fail_alloc && allocations == 0);
    CHECK(ops.sem_alloc(-1) == NULL && errno == EINVAL && allocations == 0);
    const int errors[] = {ENOSPC, ENOMEM};
    for (unsigned int i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fail_init = errors[i]; errno = EINVAL;
        CHECK(ops.sem_alloc(0) == NULL && errno == errors[i] && !fail_init && allocations == 0);
        struct lkl_sem *sem = ops.sem_alloc(1); CHECK(sem && allocations == 1);
        ops.sem_down(sem); ops.sem_up(sem); ops.sem_down(sem); ops.sem_free(sem);
        CHECK(allocations == 0);
    }
    track_alloc = 0;
    puts("PASS: semaphore allocation/init errors preserve errno and release storage; real semaphore recovery succeeds");
}
static void fatal_errors(void)
{
    long maximum = sysconf(_SC_SEM_VALUE_MAX); CHECK(maximum > 0 && maximum <= INT_MAX);
    for (int mode = 0; mode < 3; ++mode) {
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) {
            struct rlimit no_core = {0, 0}; CHECK(setrlimit(RLIMIT_CORE, &no_core) == 0);
            struct lkl_sem *sem = ops.sem_alloc(mode == 0 ? (int)maximum : 0); CHECK(sem);
            if (!mode) ops.sem_up(sem); /* Actual host EOVERFLOW. */
            else if (mode == 1) { fail_wait = EINVAL; ops.sem_down(sem); }
            else { fail_destroy = EINVAL; ops.sem_free(sem); }
            _exit(3);
        }
        int status; CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
    puts("PASS: actual post overflow and injected wait/destroy errors abort instead of continuing without synchronization");
}
struct waiter_argument { struct lkl_sem *sem; unsigned int value; };
static void waiter(void *opaque)
{
    struct waiter_argument *argument = opaque; CHECK(argument->value == 0x1234);
    watch_wait = 1;
    ops.sem_down(argument->sem);
    watch_wait = 0;
    argument->value = 0xabcd;
    atomic_store(&returned, 1);
}
static void signal_handler(int number) { (void)number; }
static void tick(void)
{
    struct timespec delay = {.tv_nsec = 1000000};
    while (nanosleep(&delay, &delay)) CHECK(errno == EINTR);
}
static void interrupted_wait(void)
{
    struct sigaction action = {.sa_handler = signal_handler}, old_action;
    sigemptyset(&action.sa_mask); CHECK(sigaction(SIGUSR1, &action, &old_action) == 0);
    sigset_t signal, old_mask; sigemptyset(&signal); sigaddset(&signal, SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &signal, &old_mask) == 0);
    struct waiter_argument argument = {.sem = ops.sem_alloc(0), .value = 0x1234}; CHECK(argument.sem);
    lkl_thread_t thread = ops.thread_create(waiter, &argument); CHECK(thread);
    for (int i = 0; i < 2000 && !atomic_load(&attempts); ++i) tick();
    CHECK(atomic_load(&attempts) > 0);
    /* An entered wrapper is not proof that sem_wait has blocked. Repeat real
     * thread-directed signals until an actual EINTR return is observed. */
    for (int i = 0; i < 2000 && !atomic_load(&interrupted); ++i) {
        CHECK(!atomic_load(&returned));
        CHECK(pthread_kill((pthread_t)thread, SIGUSR1) == 0);
        tick();
    }
    CHECK(atomic_load(&interrupted) > 0 && !atomic_load(&returned));
    ops.sem_up(argument.sem);
    CHECK(ops.thread_join(thread) == 0);
    CHECK(atomic_load(&returned) == 1 && atomic_load(&attempts) >= 2 && argument.value == 0xabcd);
    ops.sem_free(argument.sem);
    CHECK(pthread_sigmask(SIG_SETMASK, &old_mask, NULL) == 0);
    CHECK(sigaction(SIGUSR1, &old_action, NULL) == 0);
    puts("PASS: real blocked sem_wait returns EINTR, retries and remains blocked until a real post");
}
static struct lkl_sem *count_semaphore(int count)
{
    struct lkl_sem *sem = ops.sem_alloc(count);
    if (sem) atomic_fetch_add(&kernel_semaphores, 1);
    return sem;
}
int main(void)
{
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    ker_native_host_thread_init(&lkl_host_ops);
    ops = lkl_host_ops;
    allocation_failures(); fatal_errors(); interrupted_wait();
    lkl_host_ops.print = NULL; lkl_host_ops.sem_alloc = count_semaphore;
    CHECK(lkl_init(&lkl_host_ops) == 0 && lkl_start_kernel("%s", "mem=64M") == 0);
    CHECK(lkl_sys_getpid() > 0 && atomic_load(&kernel_semaphores) > 0);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    puts("PASS: original Linux boots and halts using measured real host semaphores");
    return 0;
}
