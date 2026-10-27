#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <lkl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int __poll_chk(struct pollfd *, nfds_t, int, size_t);
extern int __ppoll_chk(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *, size_t);

/* This standalone harness compiles the production fortified wrapper with all
 * descriptors classified as host-owned. */
struct ker_fd *ker_fd_get(int fd) { (void)fd; return NULL; }
long ker_fd_put(struct ker_fd *entry) { (void)entry; return 0; }

void *__real_calloc(size_t count, size_t size);
void __real_free(void *pointer);
static atomic_int tracking;
static void *tracked[8];
static atomic_size_t allocation_count;
static size_t free_count, live_count;

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
    atomic_store_explicit(&allocation_count, 0, memory_order_relaxed);
    free_count = live_count = 0;
    for (size_t i = 0; i < sizeof(tracked) / sizeof(tracked[0]); ++i) tracked[i] = NULL;

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

int main(void)
{
    int pipefd[2];
    if (pipe(pipefd)) return 1;
    for (unsigned i = 0; i < 8; ++i) {
        int result = one_cancelled_wait(pipefd, 0);
        if (result) return result;
        result = one_cancelled_wait(pipefd, 1);
        if (result) return result;
    }
    close(pipefd[0]);
    close(pipefd[1]);
    puts("PASS: 16 cancelled host poll/ppoll waits freed both production dispatch buffers");
    return 0;
}
