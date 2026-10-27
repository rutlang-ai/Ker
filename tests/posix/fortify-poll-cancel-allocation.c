#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <lkl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

extern int __poll_chk(struct pollfd *, nfds_t, int, size_t);
extern int __ppoll_chk(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *, size_t);

/* Compile the actual production dispatcher while recording ownership and
 * poll routing. */
enum { TEST_NATIVE_FD = 1000000 };
static struct ker_fd fake_native_entry;
static atomic_int ownership_lookups, host_poll_calls, host_ppoll_calls, native_poll_calls;
struct ker_fd *ker_fd_get(int fd)
{
    atomic_fetch_add_explicit(&ownership_lookups, 1, memory_order_relaxed);
    return fd == TEST_NATIVE_FD ? &fake_native_entry : NULL;
}
long ker_fd_put(struct ker_fd *entry) { (void)entry; return 0; }

enum snapshot_mode { SNAPSHOT_REAL, SNAPSHOT_ENOSYS, SNAPSHOT_EPERM,
    SNAPSHOT_ZERO, SNAPSHOT_SHORT, SNAPSHOT_EINTR_ONCE };
static atomic_int snapshot_mode, snapshot_calls;

long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...)
{
    if (number != SYS_process_vm_readv) { errno = ENOSYS; return -1; }
    int call = atomic_fetch_add_explicit(&snapshot_calls, 1, memory_order_relaxed) + 1;
    va_list args;
    va_start(args, number);
    pid_t pid = va_arg(args, pid_t);
    struct iovec *local = va_arg(args, struct iovec *);
    int local_count = va_arg(args, int);
    struct iovec *remote = va_arg(args, struct iovec *);
    int remote_count = va_arg(args, int);
    int flags = va_arg(args, int);
    va_end(args);
    switch (atomic_load_explicit(&snapshot_mode, memory_order_relaxed)) {
    case SNAPSHOT_ENOSYS: errno = ENOSYS; return -1;
    case SNAPSHOT_EPERM: errno = EPERM; return -1;
    case SNAPSHOT_ZERO: return 0;
    case SNAPSHOT_SHORT: return local[0].iov_len ? (long)local[0].iov_len - 1 : 0;
    case SNAPSHOT_EINTR_ONCE:
        if (call == 1) { errno = EINTR; return -1; }
        break;
    case SNAPSHOT_REAL: break;
    }
    return __real_syscall(number, pid, local, local_count, remote, remote_count, flags);
}

void ker_test_host_poll_call(void) { atomic_fetch_add(&host_poll_calls, 1); }
void ker_test_host_ppoll_call(void) { atomic_fetch_add(&host_ppoll_calls, 1); }
void ker_test_native_poll_call(void) { atomic_fetch_add(&native_poll_calls, 1); }

void *__real_calloc(size_t count, size_t size);
void __real_free(void *pointer);
static atomic_int tracking;
static void *tracked[8];
static atomic_size_t allocation_count;
static size_t free_count, live_count;

static void reset_allocation_tracking(void)
{
    atomic_store_explicit(&tracking, 0, memory_order_relaxed);
    atomic_store_explicit(&allocation_count, 0, memory_order_relaxed);
    free_count = live_count = 0;
    for (size_t i = 0; i < sizeof(tracked) / sizeof(tracked[0]); ++i) tracked[i] = NULL;
}

void *__wrap_calloc(size_t count, size_t size)
{
    void *pointer = __real_calloc(count, size);
    if (pointer && atomic_load_explicit(&tracking, memory_order_relaxed)) {
        size_t slot = atomic_fetch_add_explicit(&allocation_count, 1, memory_order_relaxed);
        if (slot == sizeof(tracked) / sizeof(tracked[0])) abort();
        tracked[slot] = pointer;
        ++live_count;
    }
    return pointer;
}

void __wrap_free(void *pointer)
{
    if (pointer && atomic_load_explicit(&tracking, memory_order_relaxed)) {
        for (size_t i = 0; i < allocation_count; ++i) {
            if (tracked[i] == pointer) {
                tracked[i] = NULL;
                ++free_count;
                --live_count;
                break;
            }
        }
    }
    __real_free(pointer);
}

struct blocked_poll {
    struct pollfd event;
    atomic_int entered, start;
    int use_ppoll;
};

static void *block_in_checked_poll(void *opaque)
{
    struct blocked_poll *call = opaque;
    const struct timespec infinite = { .tv_sec = 3600, .tv_nsec = 0 };
    atomic_store_explicit(&call->entered, 1, memory_order_release);
    while (!atomic_load_explicit(&call->start, memory_order_acquire)) sched_yield();
    if (call->use_ppoll)
        (void)__ppoll_chk(&call->event, 1, &infinite, NULL, sizeof(call->event));
    else
        (void)__poll_chk(&call->event, 1, -1, sizeof(call->event));
    return NULL;
}

static int one_cancelled_wait(int pipefd[2], int use_ppoll)
{
    struct blocked_poll call = { .event = { .fd = pipefd[0], .events = POLLIN },
        .use_ppoll = use_ppoll };
    atomic_init(&call.entered, 0);
    atomic_init(&call.start, 0);
    reset_allocation_tracking();
    atomic_store_explicit(&snapshot_mode, SNAPSHOT_REAL, memory_order_relaxed);

    pthread_t thread;
    if (pthread_create(&thread, NULL, block_in_checked_poll, &call)) return 1;
    while (!atomic_load_explicit(&call.entered, memory_order_acquire)) sched_yield();
    atomic_store_explicit(&tracking, 1, memory_order_release);
    atomic_store_explicit(&call.start, 1, memory_order_release);
    /* Wait for both production allocations and allow libc to enter its wait. */
    for (unsigned i = 0; i < 1000000 &&
        atomic_load_explicit(&allocation_count, memory_order_relaxed) < 2; ++i) sched_yield();
    if (atomic_load_explicit(&allocation_count, memory_order_relaxed) != 2) return 2;
    usleep(10000);
    if (pthread_cancel(thread)) return 3;
    void *result = NULL;
    if (pthread_join(thread, &result)) return 4;
    atomic_store_explicit(&tracking, 0, memory_order_release);
    if (result != PTHREAD_CANCELED) return 5;
    size_t allocated = atomic_load_explicit(&allocation_count, memory_order_relaxed);
    if (allocated != 2 || free_count != 2 || live_count != 0) {
        fprintf(stderr, "%s allocation balance: allocated=%zu freed=%zu live=%zu\n",
            use_ppoll ? "ppoll" : "poll", allocated, free_count, live_count);
        return 6;
    }
    return 0;
}

static int checked_snapshot_error(int pipe_read, int is_ppoll, enum snapshot_mode mode,
    struct pollfd *events, nfds_t count, int expected_errno, int expected_syscalls)
{
    reset_allocation_tracking();
    atomic_store_explicit(&snapshot_mode, mode, memory_order_relaxed);
    atomic_store_explicit(&snapshot_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&ownership_lookups, 0, memory_order_relaxed);
    atomic_store_explicit(&host_poll_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&host_ppoll_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&native_poll_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&tracking, 1, memory_order_release);
    const struct timespec zero = {0, 0};
    errno = 0;
    int result = is_ppoll ? __ppoll_chk(events, count, &zero, NULL, count * sizeof(*events)) :
        __poll_chk(events, count, 0, count * sizeof(*events));
    int actual_errno = errno;
    atomic_store_explicit(&tracking, 0, memory_order_release);
    size_t allocated = atomic_load_explicit(&allocation_count, memory_order_relaxed);
    if (result != -1 || actual_errno != expected_errno ||
        atomic_load_explicit(&snapshot_calls, memory_order_relaxed) != expected_syscalls ||
        atomic_load_explicit(&ownership_lookups, memory_order_relaxed) != 0 ||
        atomic_load_explicit(&host_poll_calls, memory_order_relaxed) != 0 ||
        atomic_load_explicit(&host_ppoll_calls, memory_order_relaxed) != 0 ||
        atomic_load_explicit(&native_poll_calls, memory_order_relaxed) != 0 ||
        allocated != 2 || free_count != 2 || live_count != 0) {
        fprintf(stderr, "snapshot failure routing (%s, mode=%d): result=%d errno=%d calls=%d owner=%d host=%d/%d native=%d alloc=%zu free=%zu live=%zu\n",
            is_ppoll ? "ppoll" : "poll", mode, result, actual_errno,
            atomic_load_explicit(&snapshot_calls, memory_order_relaxed),
            atomic_load_explicit(&ownership_lookups, memory_order_relaxed),
            atomic_load_explicit(&host_poll_calls, memory_order_relaxed),
            atomic_load_explicit(&host_ppoll_calls, memory_order_relaxed),
            atomic_load_explicit(&native_poll_calls, memory_order_relaxed), allocated, free_count, live_count);
        return 1;
    }
    (void)pipe_read;
    return 0;
}

static int checked_snapshot_eintr_retry(int is_ppoll, int pipe_read)
{
    struct pollfd event = { .fd = pipe_read, .events = POLLIN };
    reset_allocation_tracking();
    atomic_store_explicit(&snapshot_mode, SNAPSHOT_EINTR_ONCE, memory_order_relaxed);
    atomic_store_explicit(&snapshot_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&ownership_lookups, 0, memory_order_relaxed);
    atomic_store_explicit(&host_poll_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&host_ppoll_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&native_poll_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&tracking, 1, memory_order_release);
    const struct timespec zero = {0, 0};
    int result = is_ppoll ? __ppoll_chk(&event, 1, &zero, NULL, sizeof(event)) :
        __poll_chk(&event, 1, 0, sizeof(event));
    atomic_store_explicit(&tracking, 0, memory_order_release);
    size_t allocated = atomic_load_explicit(&allocation_count, memory_order_relaxed);
    int host_calls = is_ppoll ? atomic_load_explicit(&host_ppoll_calls, memory_order_relaxed) :
        atomic_load_explicit(&host_poll_calls, memory_order_relaxed);
    if (result != 1 || !(event.revents & POLLIN) ||
        atomic_load_explicit(&snapshot_calls, memory_order_relaxed) != 2 ||
        atomic_load_explicit(&ownership_lookups, memory_order_relaxed) != 1 || host_calls != 1 ||
        atomic_load_explicit(&native_poll_calls, memory_order_relaxed) != 0 ||
        allocated != 2 || free_count != 2 || live_count != 0) {
        fprintf(stderr, "EINTR snapshot retry (%s): result=%d revents=%x syscalls=%d owner=%d host=%d native=%d alloc=%zu free=%zu live=%zu\n",
            is_ppoll ? "ppoll" : "poll", result, event.revents,
            atomic_load_explicit(&snapshot_calls, memory_order_relaxed),
            atomic_load_explicit(&ownership_lookups, memory_order_relaxed), host_calls,
            atomic_load_explicit(&native_poll_calls, memory_order_relaxed), allocated, free_count, live_count);
        return 1;
    }
    return 0;
}

static int snapshot_failure_contracts(int pipe_read)
{
    struct pollfd events[2] = {
        { .fd = pipe_read, .events = POLLIN },
        { .fd = TEST_NATIVE_FD, .events = POLLIN }
    };
    struct { enum snapshot_mode mode; int error; } failures[] = {
        {SNAPSHOT_ENOSYS, ENOSYS}, {SNAPSHOT_EPERM, EPERM},
        {SNAPSHOT_ZERO, EFAULT}, {SNAPSHOT_SHORT, EFAULT}
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        for (int is_ppoll = 0; is_ppoll <= 1; ++is_ppoll) {
            if (checked_snapshot_error(pipe_read, is_ppoll, failures[i].mode,
                    events, 2, failures[i].error, 1)) return 1;
        }
    }
    struct pollfd *invalid = (struct pollfd *)(uintptr_t)1;
    for (int is_ppoll = 0; is_ppoll <= 1; ++is_ppoll) {
        if (checked_snapshot_error(pipe_read, is_ppoll, SNAPSHOT_REAL,
                invalid, 1, EFAULT, 1)) return 2;
    }
    for (int is_ppoll = 0; is_ppoll <= 1; ++is_ppoll) {
        if (checked_snapshot_eintr_retry(is_ppoll, pipe_read)) return 3;
    }
    return 0;
}

int main(void)
{
    int pipefd[2];
    if (pipe(pipefd)) return 1;
    for (unsigned i = 0; i < 8; ++i) {
        int result = one_cancelled_wait(pipefd, 0);
        if (result) return 10 + result;
        result = one_cancelled_wait(pipefd, 1);
        if (result) return 20 + result;
    }
    close(pipefd[0]);
    close(pipefd[1]);
    int ready_pipe[2];
    if (pipe(ready_pipe) || write(ready_pipe[1], "s", 1) != 1) return 31;
    if (snapshot_failure_contracts(ready_pipe[0])) return 32;
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    puts("PASS: 16 canceled waits freed both buffers; poll/ppoll snapshot failures preserved errno, freed buffers, and did not route unknown ownership");
    return 0;
}
