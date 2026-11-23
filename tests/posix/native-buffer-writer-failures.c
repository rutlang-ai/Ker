/* Only targeted failure calls are injected; successful VMAs/syscalls are original Linux. */
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
static _Thread_local unsigned maps, unmaps, watched_allocations, watched_releases;
static _Thread_local bool fail_malloc, fail_map, fail_unmap, watch_malloc;
static _Thread_local void *watched;
void *__real_malloc(size_t size);
void __real_free(void *pointer);
void *__wrap_malloc(size_t size)
{
    if (fail_malloc) { fail_malloc = false; errno = ENOMEM; return NULL; }
    void *result = __real_malloc(size);
    if (watch_malloc) { watch_malloc = false; CHECK(result && !watched); watched = result; watched_allocations++; }
    return result;
}
void __wrap_free(void *pointer)
{
    if (pointer && pointer == watched) { watched_releases++; watched = NULL; }
    __real_free(pointer);
}
long __real_lkl_syscall(long number, long *params);
long __wrap_lkl_syscall(long number, long *params)
{
    if (number == __lkl__NR_mmap) {
        maps++;
        if (fail_map) { fail_map = false; return -ENOMEM; }
    }
    if (number == __lkl__NR_munmap) {
        unmaps++;
        if (fail_unmap) { fail_unmap = false; return -EIO; }
    }
    return __real_lkl_syscall(number, params);
}
static const unsigned char *view(struct ker_posix_buffer_writer *w, size_t expected, size_t capacity)
{
    size_t used = SIZE_MAX, size = SIZE_MAX;
    const unsigned char *data = ker_posix_buffer_writer_view(w, &used, &size);
    CHECK(data && used == expected && size == capacity);
    return data;
}
static void constructor(void)
{
    struct ker_posix_buffer_writer *live = ker_posix_buffer_writer_create(16); CHECK(live);
    CHECK(ker_posix_buffer_writer_append(live, "live", 4) == 4);
    const unsigned char *data = view(live, 4, 16);
    unsigned before_maps = maps, before_unmaps = unmaps;
    fail_malloc = true;
    CHECK(!ker_posix_buffer_writer_create(0) && errno == ENOMEM && !fail_malloc);
    CHECK(maps == before_maps && unmaps == before_unmaps);
    CHECK(view(live, 4, 16) == data && !memcmp(data, "live", 4));
    fail_map = true; watch_malloc = true;
    CHECK(!ker_posix_buffer_writer_create(0) && errno == ENOMEM && !fail_map && !watch_malloc);
    CHECK(maps == before_maps+1 && unmaps == before_unmaps &&
          watched_allocations == 1 && watched_releases == 1 && !watched);
    CHECK(view(live, 4, 16) == data && !memcmp(data, "live", 4));
    struct ker_posix_buffer_writer *empty = ker_posix_buffer_writer_create(0); CHECK(empty);
    CHECK(view(empty, 0, 0) && ker_posix_buffer_writer_append(empty, "x", 0) == 0);
    CHECK(ker_posix_buffer_writer_append(live, "ok", 2) == 2 && !memcmp(view(live, 6, 16), "liveok", 6));
    CHECK(!ker_posix_buffer_writer_destroy(empty) && !ker_posix_buffer_writer_destroy(live));
}
static void *producer(void *opaque)
{
    struct ker_posix_buffer_writer *w = opaque;
    CHECK(ker_posix_buffer_writer_append(w, "AB", 2) == 2);
    CHECK(!memcmp(view(w, 6, 16), "liveAB", 6));
    return w;
}
static void *consumer(void *opaque)
{
    struct ker_posix_buffer_writer *w = opaque;
    CHECK(!memcmp(view(w, 6, 16), "liveAB", 6));
    CHECK(ker_posix_buffer_writer_append(w, "x", 0) == 0);
    CHECK(ker_posix_buffer_writer_append(w, NULL, 0) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_writer_append(w, "CD", 2) == 2);
    CHECK(!memcmp(view(w, 8, 16), "liveABCD", 8));
    return w;
}
static void retry(void)
{
    struct ker_posix_buffer_writer *w = ker_posix_buffer_writer_create(16);
    struct ker_posix_buffer_writer *other = ker_posix_buffer_writer_create(8); CHECK(w && other);
    CHECK(ker_posix_buffer_writer_append(w, "live", 4) == 4);
    CHECK(ker_posix_buffer_writer_append(other, "peer", 4) == 4);
    const unsigned char *data = view(w, 4, 16), *peer = view(other, 4, 8);
    pthread_t thread; void *result = NULL;
    CHECK(!pthread_create(&thread, NULL, producer, w));
    CHECK(!pthread_join(thread, &result) && result == w);
    unsigned before_unmaps = unmaps;
    fail_unmap = true;
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EIO && !fail_unmap);
    CHECK(unmaps == before_unmaps+1);
    CHECK(view(w, 6, 16) == data && !memcmp(data, "liveAB", 6));
    CHECK(view(other, 4, 8) == peer && !memcmp(peer, "peer", 4));
    CHECK(ker_posix_buffer_free((void *)data) == -1 && errno == EBUSY);
    CHECK(!pthread_create(&thread, NULL, consumer, w));
    CHECK(!pthread_join(thread, &result) && result == w);
    CHECK(view(w, 8, 16) == data && !memcmp(data, "liveABCD", 8));
    CHECK(!ker_posix_buffer_writer_destroy(w) && unmaps == before_unmaps+2);
    size_t length = 91, capacity = 92;
    CHECK(!ker_posix_buffer_writer_view(w, &length, &capacity) && errno == EINVAL && length == 91 && capacity == 92);
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EINVAL && unmaps == before_unmaps+2);
    CHECK(view(other, 4, 8) == peer && !memcmp(peer, "peer", 4));
    CHECK(!ker_posix_buffer_writer_destroy(other));
}
int main(int argc, char **argv)
{
    CHECK(argc == 2 && (!strcmp(argv[1], "constructor") || !strcmp(argv[1], "retry")));
    ker_native_host_memory_init(&lkl_host_ops); ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL; CHECK(!lkl_init(&lkl_host_ops)); CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    if (!strcmp(argv[1], "constructor")) constructor(); else retry();
    struct ker_posix_buffer_writer *residual = ker_posix_buffer_writer_create(0); CHECK(residual);
    CHECK(view(residual, 0, 0) && ker_posix_buffer_writer_append(residual, "x", 0) == 0);
    active = false;
    CHECK(ker_posix_buffer_writer_destroy(residual) == -1 && errno == ENETDOWN);
    struct ker_native_buffer_counters final; CHECK(!ker_native_buffers_close_all(&final));
    CHECK(final.allocations == 3 && final.releases == 3 && final.shutdown_releases == 1 &&
          !final.live && !final.bytes && !final.option_guards_live);
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    printf("PASS: native writer %s failures preserve owners and permit exact real cleanup\n", argv[1]);
    return 0;
}
