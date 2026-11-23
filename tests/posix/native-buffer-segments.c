/* Production segmented owners and actual original Linux VMAs. Only explicit
 * failure probes replace one syscall/allocation; successful calls remain real. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include "native-buffer.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lkl.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static bool active;
static _Thread_local bool fail_alloc;
static _Thread_local unsigned fail_map, fail_unmap, successful_maps, successful_unmaps;
bool ker_native_ready(void) { return active; }
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size)
{
    if (fail_alloc) { fail_alloc = false; errno = ENOMEM; return NULL; }
    return __real_malloc(size);
}
long __real_lkl_syscall(long number, long *params);
long __wrap_lkl_syscall(long number, long *params)
{
    if (number == __lkl__NR_mmap && fail_map && !--fail_map) return -ENOMEM;
    if (number == __lkl__NR_munmap && fail_unmap && !--fail_unmap) return -EIO;
    long result = __real_lkl_syscall(number, params);
    if (number == __lkl__NR_mmap && (uintptr_t)result < (uintptr_t)-4095) successful_maps++;
    if (number == __lkl__NR_munmap && !result) successful_unmaps++;
    return result;
}
static const unsigned char *segment(struct ker_posix_buffer_writer *w, size_t index,
    size_t used, size_t size, size_t total)
{
    size_t a = SIZE_MAX, b = SIZE_MAX, c = SIZE_MAX;
    const unsigned char *data = ker_posix_buffer_writer_segment(w, index, &a, &b, &c);
    CHECK(data && a == used && b == size && c == total);
    return data;
}
static void invalid(struct ker_posix_buffer_writer *w, size_t index, int error)
{
    size_t a = 41, b = 42, c = 43;
    CHECK(!ker_posix_buffer_writer_segment(w, index, &a, &b, &c) && errno == error);
    CHECK(a == 41 && b == 42 && c == 43);
}
static void layout(void)
{
    unsigned char bytes[178];
    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (unsigned char)(i & 0x7f);
    struct ker_posix_buffer_writer *w = ker_posix_buffer_writer_create_segmented(178, 128); CHECK(w);
    const unsigned char *first = segment(w, 0, 0, 128, 0);
    const unsigned char *second = segment(w, 1, 0, 50, 0); CHECK(first != second);
    CHECK(ker_posix_buffer_writer_append(w, bytes, sizeof(bytes)) == 178);
    CHECK(segment(w, 0, 128, 128, 178) == first && !memcmp(first, bytes, 128));
    CHECK(segment(w, 1, 50, 50, 178) == second && !memcmp(second, bytes+128, 50));
    CHECK(ker_posix_buffer_writer_append(w, bytes, 1) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_writer_append(w, NULL, 0) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_writer_append(w, bytes, 0) == 0);
    invalid(w, 2, EINVAL); invalid(w, SIZE_MAX, EINVAL);
    size_t a = 41, b = 42;
    CHECK(!ker_posix_buffer_writer_view(w, &a, &b) && errno == EOPNOTSUPP && a == 41 && b == 42);
    CHECK(ker_posix_buffer_free((void *)second) == -1 && errno == EBUSY);
    CHECK(ker_posix_buffer_write((void *)first, 0, "x", 1) == -1 && errno == EBUSY);
    CHECK(!ker_posix_buffer_realloc((void *)second, 51) && errno == EBUSY);
    CHECK(!memcmp(first, bytes, 128) && !memcmp(second, bytes+128, 50));
    CHECK(!ker_posix_buffer_writer_destroy(w));
    struct ker_posix_buffer_writer *replacement = ker_posix_buffer_writer_create_segmented(178, 128); CHECK(replacement);
    invalid(w, 0, EINVAL);
    CHECK(ker_posix_buffer_writer_append(w, bytes, 1) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EINVAL);
    segment(replacement, 0, 0, 128, 0); CHECK(!ker_posix_buffer_writer_destroy(replacement));
    /* Repeated appends crossing boundaries, including overlapping borrowed input. */
    w = ker_posix_buffer_writer_create_segmented(24, 8); CHECK(w);
    CHECK(ker_posix_buffer_writer_append(w, "abcdef", 6) == 6);
    first = segment(w, 0, 6, 8, 6);
    CHECK(ker_posix_buffer_writer_append(w, first, 6) == 6);
    CHECK(!memcmp(segment(w, 0, 8, 8, 12), "abcdefab", 8));
    CHECK(!memcmp(segment(w, 1, 4, 8, 12), "cdef", 4));
    segment(w, 2, 0, 8, 12);
    CHECK(ker_posix_buffer_writer_append(w, bytes, SIZE_MAX) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_writer_append(w, "ghijklmnopqr", 12) == 12);
    CHECK(!memcmp(segment(w, 1, 8, 8, 24), "cdefghij", 8));
    CHECK(!memcmp(segment(w, 2, 8, 8, 24), "klmnopqr", 8));
    CHECK(!ker_posix_buffer_writer_destroy(w));
    puts("BUFFER_SOURCE_CASE test_ff_zc_mbuf_write_multi_segment");
}
static void failures(void)
{
    CHECK(!ker_posix_buffer_writer_create_segmented(0, 128) && errno == EINVAL);
    CHECK(!ker_posix_buffer_writer_create_segmented(178, 0) && errno == EINVAL);
    CHECK(!ker_posix_buffer_writer_create_segmented((size_t)INT_MAX+1, 128) && errno == EINVAL);
    CHECK(!ker_posix_buffer_writer_create_segmented(IOV_MAX+1, 1) && errno == EINVAL);
    fail_map = 2;
    CHECK(!ker_posix_buffer_writer_create_segmented(178, 128) && errno == ENOMEM && !fail_map);
    /* Failed constructor rollback stays registered for shutdown reclamation. */
    fail_map = 2; fail_unmap = 1;
    CHECK(!ker_posix_buffer_writer_create_segmented(178, 128) && errno == ENOMEM && !fail_unmap);
    struct ker_posix_buffer_writer *w = ker_posix_buffer_writer_create_segmented(24, 8); CHECK(w);
    CHECK(ker_posix_buffer_writer_append(w, "abcdef", 6) == 6);
    fail_alloc = true;
    CHECK(ker_posix_buffer_writer_append(w, "ghijklmnopqr", 12) == -1 && errno == ENOMEM && !fail_alloc);
    CHECK(!memcmp(segment(w, 0, 6, 8, 6), "abcdef", 6));
    segment(w, 1, 0, 8, 6); segment(w, 2, 0, 8, 6);
    fail_unmap = 1;
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EIO && !fail_unmap);
    CHECK(ker_posix_buffer_writer_append(w, "gh", 2) == 2); /* No segment lost yet. */
    fail_unmap = 2;
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EIO && !fail_unmap);
    invalid(w, 0, EBUSY);
    CHECK(ker_posix_buffer_writer_append(w, "i", 1) == -1 && errno == EBUSY);
    CHECK(!ker_posix_buffer_writer_view(w, NULL, NULL) && errno == EBUSY);
    CHECK(!ker_posix_buffer_writer_destroy(w));
    invalid(w, 0, EINVAL);
    /* Retire children, fail root unmap, then retry root only. */
    w = ker_posix_buffer_writer_create_segmented(16, 8); CHECK(w);
    fail_unmap = 2;
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EIO);
    invalid(w, 0, EBUSY); CHECK(!ker_posix_buffer_writer_destroy(w));
}
static struct ker_posix_buffer_writer *sentinel(void)
{
    struct ker_posix_buffer_writer *w = ker_posix_buffer_writer_create_segmented(32, 16); CHECK(w);
    CHECK(ker_posix_buffer_writer_append(w, "abcdefghijklmnopqrstuvwx", 24) == 24);
    return w;
}
static void sentinel_unchanged(struct ker_posix_buffer_writer *w)
{
    CHECK(!memcmp(segment(w, 0, 16, 16, 24), "abcdefghijklmnop", 16));
    CHECK(!memcmp(segment(w, 1, 8, 16, 24), "qrstuvwx", 8));
}
static void constructor_matrix(void)
{
    struct ker_posix_buffer_writer *live = sentinel();
    unsigned maps = successful_maps, unmaps = successful_unmaps;
    fail_alloc = true;
    CHECK(!ker_posix_buffer_writer_create_segmented(50, 16) && errno == ENOMEM && !fail_alloc);
    CHECK(successful_maps == maps && successful_unmaps == unmaps);
    sentinel_unchanged(live);
    /* Fail every possible mapping, including the short last node. */
    for (unsigned position = 1; position <= 4; position++) {
        maps = successful_maps; unmaps = successful_unmaps;
        fail_map = position;
        CHECK(!ker_posix_buffer_writer_create_segmented(50, 16) && errno == ENOMEM && !fail_map);
        CHECK(successful_maps - maps == position-1 && successful_unmaps - unmaps == position-1);
        sentinel_unchanged(live);
    }
    /* Fail each rollback unmap after a later constructor failure. Exactly one
     * node per attempt must remain for real shutdown cleanup, not be forgotten. */
    for (unsigned position = 1; position <= 3; position++) {
        maps = successful_maps; unmaps = successful_unmaps;
        fail_map = 4; fail_unmap = position;
        CHECK(!ker_posix_buffer_writer_create_segmented(50, 16) && errno == ENOMEM && !fail_map && !fail_unmap);
        CHECK(successful_maps - maps == 3 && successful_unmaps - unmaps == 2);
        sentinel_unchanged(live);
    }
    CHECK(!ker_posix_buffer_writer_destroy(live));
}
static void destroy_matrix(void)
{
    struct ker_posix_buffer_writer *live = sentinel();
    unsigned char bytes[50];
    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (unsigned char)(i ^ 0x5a);
    /* Includes first-child failure, intermediate nodes and root-last failure. */
    for (unsigned position = 1; position <= 4; position++) {
        struct ker_posix_buffer_writer *w = ker_posix_buffer_writer_create_segmented(50, 16); CHECK(w);
        CHECK(ker_posix_buffer_writer_append(w, bytes, 30) == 30);
        unsigned unmaps = successful_unmaps;
        fail_unmap = position;
        CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EIO && !fail_unmap);
        CHECK(successful_unmaps - unmaps == position-1);
        if (position == 1) {
            CHECK(!memcmp(segment(w, 0, 16, 16, 30), bytes, 16));
            CHECK(!memcmp(segment(w, 1, 14, 16, 30), bytes+16, 14));
            segment(w, 2, 0, 16, 30); segment(w, 3, 0, 2, 30);
            CHECK(ker_posix_buffer_writer_append(w, bytes+30, 1) == 1);
            CHECK(!memcmp(segment(w, 1, 15, 16, 31), bytes+16, 15));
        } else {
            invalid(w, 0, EBUSY);
            CHECK(ker_posix_buffer_writer_append(w, bytes, 1) == -1 && errno == EBUSY);
        }
        sentinel_unchanged(live);
        fail_unmap = 1;
        CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EIO && !fail_unmap);
        CHECK(successful_unmaps - unmaps == position-1);
        if (position > 1) invalid(w, 0, EBUSY);
        CHECK(!ker_posix_buffer_writer_destroy(w) && successful_unmaps - unmaps == 4);
        struct ker_posix_buffer_writer *replacement = ker_posix_buffer_writer_create_segmented(50, 16); CHECK(replacement);
        invalid(w, 0, EINVAL);
        CHECK(ker_posix_buffer_writer_append(w, bytes, 1) == -1 && errno == EINVAL);
        CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EINVAL);
        CHECK(successful_unmaps - unmaps == 4);
        segment(replacement, 0, 0, 16, 0); segment(replacement, 3, 0, 2, 0);
        CHECK(!ker_posix_buffer_writer_destroy(replacement));
        CHECK(successful_unmaps - unmaps == 8);
        sentinel_unchanged(live);
    }
    CHECK(!ker_posix_buffer_writer_destroy(live));
}
static void ranges(void)
{
    struct ker_posix_buffer_writer *live = sentinel();
    struct ker_posix_buffer_writer *w = ker_posix_buffer_writer_create_segmented(178, 128); CHECK(w);
    unsigned char bytes[178];
    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (unsigned char)(i ^ 0x6b);
    CHECK(ker_posix_buffer_writer_append(w, bytes, sizeof(bytes)) == 178);
    const unsigned char *first = segment(w, 0, 128, 128, 178);
    const unsigned char *second = segment(w, 1, 50, 50, 178);
    struct iovec single, *vectors = (void *)(uintptr_t)1;
    size_t count = 99;
    fail_alloc = true;
    CHECK(ker_native_writer_range(w, 100, 70, &single, &vectors, &count) == -ENOMEM);
    CHECK(!fail_alloc && vectors == (void *)(uintptr_t)1 && count == 99);
    CHECK(segment(w, 0, 128, 128, 178) == first && !memcmp(first, bytes, 128));
    CHECK(segment(w, 1, 50, 50, 178) == second && !memcmp(second, bytes+128, 50));
    sentinel_unchanged(live);
    CHECK(ker_native_writer_range(w, 100, 70, &single, &vectors, &count) == 0 && count == 2);
    CHECK(vectors != &single && vectors[0].iov_base == first+100 && vectors[0].iov_len == 28 &&
          vectors[1].iov_base == second && vectors[1].iov_len == 42);
    free(vectors);
    fail_alloc = true;
    CHECK(!ker_native_writer_range(w, 128, 50, &single, &vectors, &count));
    CHECK(fail_alloc && vectors == &single && count == 1 && single.iov_base == second && single.iov_len == 50);
    fail_alloc = false;
    vectors = (void *)(uintptr_t)1; count = 99;
    CHECK(ker_native_writer_range(w, 170, 9, &single, &vectors, &count) == -EINVAL);
    CHECK(vectors == (void *)(uintptr_t)1 && count == 99);
    CHECK(!ker_posix_buffer_writer_destroy(w) && !ker_posix_buffer_writer_destroy(live));
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    CHECK(!ker_posix_buffer_writer_create_segmented(178, 128) && errno == ENETDOWN);
    ker_native_host_memory_init(&lkl_host_ops); ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL; CHECK(!lkl_init(&lkl_host_ops)); CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    if (!strcmp(argv[1], "layout")) layout();
    else if (!strcmp(argv[1], "failures")) failures();
    else if (!strcmp(argv[1], "constructor-matrix")) constructor_matrix();
    else if (!strcmp(argv[1], "ranges")) ranges();
    else { CHECK(!strcmp(argv[1], "destroy-matrix")); destroy_matrix(); }
    struct ker_posix_buffer_writer *residual = ker_posix_buffer_writer_create_segmented(178, 128); CHECK(residual);
    active = false; invalid(residual, 0, ENETDOWN);
    CHECK(ker_posix_buffer_writer_append(residual, "x", 1) == -1 && errno == ENETDOWN);
    CHECK(ker_posix_buffer_writer_destroy(residual) == -1 && errno == ENETDOWN);
    struct ker_native_buffer_counters final; CHECK(!ker_native_buffers_close_all(&final));
    CHECK(final.allocations == final.releases && !final.live && !final.bytes && !final.option_guards_live);
    unsigned expected = !strcmp(argv[1], "ranges") ? 6 :
        !strcmp(argv[1], "constructor-matrix") ? 19 :
        !strcmp(argv[1], "destroy-matrix") ? 36 : 9;
    unsigned residuals = !strcmp(argv[1], "constructor-matrix") ? 5 :
        !strcmp(argv[1], "failures") ? 3 : 2;
    CHECK(final.allocations == expected && final.shutdown_releases == residuals);
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    printf("PASS: segmented owner %s, exact VMA reclamation\n", argv[1]);
    return 0;
}
