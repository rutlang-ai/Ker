/* Real Linux VMA writes across distinct threads and synchronized ownership transfer. */
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
static bool active;
bool ker_native_ready(void) { return active; }
static pthread_barrier_t barrier;
static void sync_workers(void)
{
    int result = pthread_barrier_wait(&barrier);
    CHECK(!result || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
struct work { unsigned id; unsigned char *base; };
static void *parallel_worker(void *opaque)
{
    struct work *work = opaque;
    unsigned char source[8193];
    for (unsigned i = 0; i < sizeof(source); ++i) source[i] = (unsigned char)(work->id * 31 + i);
    sync_workers();
    for (unsigned turn = 0; turn < 32; ++turn) {
        CHECK(ker_posix_buffer_write(work->base, 0, source, sizeof(source)) == (int)sizeof(source));
        CHECK(!memcmp(work->base, source, sizeof(source)));
        CHECK(ker_posix_buffer_write(work->base, sizeof(source)-1, source, 2) == -1 && errno == EINVAL);
        CHECK(!memcmp(work->base, source, sizeof(source)));
        CHECK(ker_posix_buffer_write(work->base, 0, NULL, 1) == -1 && errno == EINVAL);
        CHECK(!memcmp(work->base, source, sizeof(source)));
        CHECK(ker_posix_buffer_write(work->base, sizeof(source), source, 0) == 0);
    }
    /* Other callers change their own error state while the main thread keeps
     * an independent sentinel. Synchronization never exposes one buffer to two owners. */
    int expected = work->id & 1 ? E2BIG : EINVAL;
    if (work->id & 1) errno = expected;
    else CHECK(ker_posix_buffer_write(work->base, SIZE_MAX, source, 1) == -1 && errno == EINVAL);
    sync_workers();
    CHECK(errno == expected);
    CHECK(!memcmp(work->base, source, sizeof(source)));
    CHECK(!ker_posix_buffer_free(work->base));
    return NULL;
}
static void parallel(void)
{
    pthread_t threads[4]; struct work work[4];
    CHECK(!pthread_barrier_init(&barrier, NULL, 5));
    for (unsigned i = 0; i < 4; ++i) {
        work[i] = (struct work){.id=i, .base=ker_posix_buffer_alloc(8193)};
        CHECK(work[i].base && !pthread_create(&threads[i], NULL, parallel_worker, &work[i]));
    }
    sync_workers();
    errno = ERANGE;
    sync_workers();
    CHECK(errno == ERANGE);
    for (unsigned i = 0; i < 4; ++i) CHECK(!pthread_join(threads[i], NULL));
    CHECK(!pthread_barrier_destroy(&barrier));
}
static void *producer(void *opaque)
{
    unsigned char *p = opaque;
    CHECK(ker_posix_buffer_write(p, 0, "native-owned-data", 17) == 17);
    return p;
}
static void *consumer(void *opaque)
{
    unsigned char *old = opaque;
    CHECK(!memcmp(old, "native-owned-data", 17));
    unsigned char *p = ker_posix_buffer_realloc(old, 8193);
    CHECK(p && p != old && !memcmp(p, "native-owned-data", 17));
    for (unsigned i = 17; i < 8193; ++i) CHECK(!p[i]);
    CHECK(ker_posix_buffer_write(old, 0, "x", 1) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_write(p, 8190, "overflow", 8) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_write(p, 0, NULL, 1) == -1 && errno == EINVAL);
    CHECK(!memcmp(p, "native-owned-data", 17));
    for (unsigned i = 17; i < 8193; ++i) CHECK(!p[i]);
    unsigned char source[8193]; memset(source, 0x44, sizeof(source));
    CHECK(ker_posix_buffer_write(p, 0, source, 4096) == 4096);
    CHECK(ker_posix_buffer_write(p, 4096, source+4096, 4097) == 4097);
    CHECK(!memcmp(p, source, sizeof(source)));
    CHECK(!ker_posix_buffer_free(p));
    return NULL;
}
static void handoff(void)
{
    unsigned char *p = ker_posix_buffer_alloc(17); CHECK(p);
    pthread_t thread; void *result = NULL;
    CHECK(!pthread_create(&thread, NULL, producer, p));
    CHECK(!pthread_join(thread, &result) && result == p);
    CHECK(!pthread_create(&thread, NULL, consumer, result));
    CHECK(!pthread_join(thread, &result) && result == NULL);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2 && (!strcmp(argv[1], "parallel") || !strcmp(argv[1], "handoff")));
    ker_native_host_memory_init(&lkl_host_ops); ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(!lkl_init(&lkl_host_ops)); CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    if (!strcmp(argv[1], "parallel")) parallel(); else handoff();
    unsigned char *residual = ker_posix_buffer_alloc(7); CHECK(residual);
    active = false;
    CHECK(ker_posix_buffer_write(residual, 0, "x", 1) == -1 && errno == ENETDOWN);
    struct ker_native_buffer_counters final;
    CHECK(!ker_native_buffers_close_all(&final));
    CHECK(final.allocations == (!strcmp(argv[1], "parallel") ? 5U : 3U) &&
          final.releases == final.allocations && final.shutdown_releases == 1 &&
          !final.live && !final.bytes && !final.option_guards_live);
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    printf("PASS: native bounded write %s, exact bytes/errno and complete VMA reclamation\n", argv[1]);
    return 0;
}
