/* Independent segmented owners and explicit join-based ownership transfer. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include "native-buffer.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lkl.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
#define CAPACITY 8195U
#define SEGMENT 4096U
#define TURNS 8U
static bool active;
bool ker_native_ready(void) { return active; }
static pthread_barrier_t barrier;
struct work { unsigned id; struct ker_posix_buffer_writer *owner; unsigned char bytes[CAPACITY]; };
static void sync_workers(void)
{
    int result = pthread_barrier_wait(&barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void pattern(struct work *work)
{
    for (size_t i = 0; i < CAPACITY; i++) work->bytes[i] = (unsigned char)(work->id * 47 + i);
}
static void verify(struct work *work, size_t total)
{
    const void *nodes[3];
    for (size_t i = 0; i < 3; i++) {
        size_t used = SIZE_MAX, capacity = SIZE_MAX, length = SIZE_MAX;
        size_t expected_size = i == 2 ? 3 : SEGMENT;
        size_t offset = i * SEGMENT;
        size_t expected_used = total > offset ? total - offset : 0;
        if (expected_used > expected_size) expected_used = expected_size;
        nodes[i] = ker_posix_buffer_writer_segment(work->owner, i, &used, &capacity, &length);
        CHECK(nodes[i] && used == expected_used && capacity == expected_size && length == total);
        CHECK(!memcmp(nodes[i], work->bytes + offset, used));
        if (i) CHECK(nodes[i] != nodes[i-1]);
    }
    CHECK(nodes[0] != nodes[2]);
}
static void invalid(struct ker_posix_buffer_writer *owner)
{
    size_t a = 31, b = 32, c = 33;
    CHECK(!ker_posix_buffer_writer_segment(owner, 0, &a, &b, &c) && errno == EINVAL);
    CHECK(a == 31 && b == 32 && c == 33);
    CHECK(ker_posix_buffer_writer_append(owner, "x", 1) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_writer_destroy(owner) == -1 && errno == EINVAL);
}
static void *parallel_worker(void *opaque)
{
    struct work *work = opaque;
    struct ker_posix_buffer_writer *previous = NULL;
    pattern(work);
    sync_workers();
    for (unsigned turn = 0; turn < TURNS; turn++) {
        work->owner = ker_posix_buffer_writer_create_segmented(CAPACITY, SEGMENT); CHECK(work->owner);
        if (previous) invalid(previous); /* Replacement already exists. */
        CHECK(ker_posix_buffer_writer_append(work->owner, work->bytes, 17) == 17);
        verify(work, 17);
        CHECK(ker_posix_buffer_writer_append(work->owner, work->bytes+17, 4095) == 4095);
        verify(work, 4112);
        CHECK(ker_posix_buffer_writer_append(work->owner, NULL, 1) == -1 && errno == EINVAL);
        CHECK(ker_posix_buffer_writer_append(work->owner, work->bytes, SIZE_MAX) == -1 && errno == EINVAL);
        verify(work, 4112);
        CHECK(ker_posix_buffer_writer_append(work->owner, work->bytes+4112, CAPACITY-4112) == CAPACITY-4112);
        verify(work, CAPACITY);
        CHECK(!ker_posix_buffer_writer_destroy(work->owner));
        previous = work->owner;
    }
    int expected = work->id & 1 ? E2BIG : EINVAL;
    errno = expected;
    sync_workers();
    CHECK(errno == expected);
    return NULL;
}
static void parallel(void)
{
    struct work work[4]; pthread_t threads[4];
    CHECK(!pthread_barrier_init(&barrier, NULL, 5));
    for (unsigned i = 0; i < 4; i++) {
        work[i].id = i;
        CHECK(!pthread_create(&threads[i], NULL, parallel_worker, &work[i]));
    }
    sync_workers();
    errno = ERANGE; sync_workers(); CHECK(errno == ERANGE);
    for (unsigned i = 0; i < 4; i++) { CHECK(!pthread_join(threads[i], NULL)); invalid(work[i].owner); }
    CHECK(!pthread_barrier_destroy(&barrier));
}
static void *producer(void *opaque)
{
    struct work *work = opaque;
    CHECK(ker_posix_buffer_writer_append(work->owner, work->bytes, 4100) == 4100);
    verify(work, 4100);
    return work->owner;
}
static void *consumer(void *opaque)
{
    struct work *work = opaque;
    verify(work, 4100);
    size_t used;
    const void *data = ker_posix_buffer_writer_segment(work->owner, 1, &used, NULL, NULL);
    CHECK(data && used == 4);
    CHECK(ker_posix_buffer_free((void *)data) == -1 && errno == EBUSY);
    CHECK(!ker_posix_buffer_realloc((void *)data, 1) && errno == EBUSY);
    CHECK(ker_posix_buffer_writer_append(work->owner, work->bytes+4100, CAPACITY-4100) == CAPACITY-4100);
    verify(work, CAPACITY);
    return work->owner;
}
static void *releaser(void *opaque)
{
    struct work *work = opaque; verify(work, CAPACITY);
    CHECK(!ker_posix_buffer_writer_destroy(work->owner));
    return NULL;
}
static void handoff(void)
{
    struct work work = {.id = 7}; pattern(&work);
    work.owner = ker_posix_buffer_writer_create_segmented(CAPACITY, SEGMENT); CHECK(work.owner);
    pthread_t thread; void *result;
    CHECK(!pthread_create(&thread, NULL, producer, &work));
    CHECK(!pthread_join(thread, &result) && result == work.owner);
    CHECK(!pthread_create(&thread, NULL, consumer, &work));
    CHECK(!pthread_join(thread, &result) && result == work.owner);
    CHECK(!pthread_create(&thread, NULL, releaser, &work));
    CHECK(!pthread_join(thread, &result) && result == NULL);
    struct ker_posix_buffer_writer *stale = work.owner;
    work.owner = ker_posix_buffer_writer_create_segmented(CAPACITY, SEGMENT); CHECK(work.owner);
    invalid(stale); verify(&work, 0); CHECK(!ker_posix_buffer_writer_destroy(work.owner));
}
int main(int argc, char **argv)
{
    CHECK(argc == 2 && (!strcmp(argv[1], "parallel") || !strcmp(argv[1], "handoff")));
    ker_native_host_memory_init(&lkl_host_ops); ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL; CHECK(!lkl_init(&lkl_host_ops)); CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    if (!strcmp(argv[1], "parallel")) parallel(); else handoff();
    struct ker_posix_buffer_writer *residual = ker_posix_buffer_writer_create_segmented(CAPACITY, SEGMENT); CHECK(residual);
    active = false;
    CHECK(!ker_posix_buffer_writer_segment(residual, 2, NULL, NULL, NULL) && errno == ENETDOWN);
    struct ker_native_buffer_counters final;
    CHECK(!ker_native_buffers_close_all(&final));
    CHECK(final.allocations == (!strcmp(argv[1], "parallel") ? 4*TURNS*3+3 : 9) &&
          final.allocations == final.releases && final.shutdown_releases == 3 &&
          !final.live && !final.bytes && !final.option_guards_live);
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    printf("PASS: segmented owner %s, exact cross-thread bytes/lengths and complete VMA reclamation\n", argv[1]);
    return 0;
}
