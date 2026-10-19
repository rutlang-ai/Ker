#define _GNU_SOURCE
#include "host-thread.h"
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <lkl.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

/* Inject only host allocation failure, as in the pinned upstream case.
 * All thread, TLS, semaphore and mutex operations use real callbacks. */
void *__real_malloc(size_t size);
static _Thread_local int fail_next_allocation, count_allocations;
static _Thread_local long allocation_balance;
void __real_free(void *pointer);
void __wrap_free(void *pointer)
{
    if (count_allocations && pointer) --allocation_balance;
    __real_free(pointer);
}
void *__wrap_malloc(size_t size)
{
    if (fail_next_allocation) {
        fail_next_allocation = 0;
        errno = ENOMEM;
        return NULL;
    }
    void *pointer = __real_malloc(size);
    if (count_allocations && pointer) ++allocation_balance;
    return pointer;
}
static struct lkl_host_operations ops;
static struct lkl_tls_key *key;
static struct lkl_sem *ready, *release_workers;
static struct lkl_mutex *mutex;
static unsigned int total;
static atomic_uint destructors, unexpected_runs, kernel_threads;
static lkl_thread_t parent;
struct argument { unsigned int id; lkl_thread_t self; };

static void tls_destructor(void *value)
{
    struct argument *arg = value;
    CHECK(arg && arg->id >= 1 && arg->id <= 4);
    atomic_fetch_add(&destructors, 1);
}
static void must_not_run(void *arg)
{
    (void)arg;
    atomic_fetch_add(&unexpected_runs, 1);
}
static void worker(void *value)
{
    struct argument *arg = value;
    CHECK(arg && arg->id >= 1 && arg->id <= 4);
    arg->self = ops.thread_self();
    CHECK(!ops.thread_equal(arg->self, parent));
    CHECK(ops.tls_get(key) == NULL); /* pthread TLS is not inherited. */
    CHECK(ops.tls_set(key, arg) == 0);
    ops.sem_up(ready);
    ops.sem_down(release_workers);
    for (unsigned int i = 0; i < 1000; ++i) {
        ops.mutex_lock(mutex);
        ++total;
        ops.mutex_unlock(mutex);
        CHECK(ops.tls_get(key) == arg);
    }
}
static lkl_thread_t count_create(void (*routine)(void *), void *arg)
{
    lkl_thread_t thread = ops.thread_create(routine, arg);
    if (thread) atomic_fetch_add(&kernel_threads, 1);
    return thread;
}
int main(void)
{
    ker_native_host_thread_init(&lkl_host_ops);
    ops = lkl_host_ops;
    CHECK(ops.thread_create && ops.thread_join && ops.thread_self && ops.thread_equal);
    CHECK(ops.tls_alloc && ops.tls_free && ops.tls_set && ops.tls_get);
    CHECK(ops.sem_alloc && ops.sem_free && ops.sem_up && ops.sem_down);
    CHECK(ops.mutex_alloc && ops.mutex_free && ops.mutex_lock && ops.mutex_unlock);
    /* No host thread exists yet: failure injection cannot affect another one. */
    fail_next_allocation = 1;
    errno = 0;
    CHECK(ops.thread_create(must_not_run, NULL) == 0);
    CHECK(!fail_next_allocation && errno == ENOMEM);
    CHECK(atomic_load(&unexpected_runs) == 0);
    puts("PASS: thread allocation failure returns zero without running the callback");

    fail_next_allocation = 1;
    errno = 0;
    CHECK(ops.tls_alloc(tls_destructor) == NULL);
    CHECK(!fail_next_allocation && errno == ENOMEM);
    puts("PASS: TLS key allocation failure returns NULL without dereferencing it");

    long limit = sysconf(_SC_THREAD_KEYS_MAX);
    CHECK(limit > 0 && limit <= 1048576);
    struct lkl_tls_key **keys = calloc((size_t)limit + 1, sizeof(*keys)); CHECK(keys);
    count_allocations = 1;
    long used;
    for (used = 0; used <= limit; ++used) {
        keys[used] = ops.tls_alloc(NULL);
        if (!keys[used]) break;
    }
    CHECK(used <= limit && errno == EAGAIN);
    for (long i = 0; i < used; ++i) ops.tls_free(keys[i]);
    CHECK(allocation_balance == 0);
    count_allocations = 0;
    free(keys);
    puts("PASS: real pthread key exhaustion fails cleanly and releases all key allocations");

    key = ops.tls_alloc(tls_destructor); CHECK(key);
    int parent_value = 42;
    CHECK(ops.tls_set(key, &parent_value) == 0);
    parent = ops.thread_self();
    ready = ops.sem_alloc(0); release_workers = ops.sem_alloc(0);
    mutex = ops.mutex_alloc(0); CHECK(ready && release_workers && mutex);
    struct argument args[4]; lkl_thread_t threads[4];
    for (unsigned int i = 0; i < 4; ++i) {
        args[i] = (struct argument){.id = i + 1};
        threads[i] = ops.thread_create(worker, &args[i]); CHECK(threads[i]);
    }
    for (unsigned int i = 0; i < 4; ++i) ops.sem_down(ready);
    CHECK(total == 0);
    CHECK(ops.tls_get(key) == &parent_value);
    /* Compare IDs while all workers are alive behind the semaphore gate. */
    for (unsigned int i = 0; i < 4; ++i)
        CHECK(ops.thread_equal(threads[i], args[i].self));
    for (unsigned int i = 0; i < 4; ++i) ops.sem_up(release_workers);
    for (unsigned int i = 0; i < 4; ++i) {
        CHECK(ops.thread_join(threads[i]) == 0);
    }
    CHECK(total == 4000 && atomic_load(&destructors) == 4);
    CHECK(ops.tls_get(key) == &parent_value);
    CHECK(ops.tls_set(key, NULL) == 0);
    ops.tls_free(key);
    ops.sem_free(ready); ops.sem_free(release_workers); ops.mutex_free(mutex);
    /* Reuse verifies that freeing a key does not leave the old parent value. */
    key = ops.tls_alloc(NULL); CHECK(key && ops.tls_get(key) == NULL); ops.tls_free(key);
    puts("PASS: arguments, join completion, thread identity, isolated TLS and destructors");
    puts("PASS: semaphore gating and mutex-protected counter across four real threads");

    lkl_host_ops.print = NULL;
    lkl_host_ops.thread_create = count_create;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    CHECK(lkl_sys_getpid() > 0 && atomic_load(&kernel_threads) > 0);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    puts("PASS: original Linux creates actual host threads, boots and shuts down");
    return 0;
}
