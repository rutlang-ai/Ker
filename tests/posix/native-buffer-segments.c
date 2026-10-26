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
static bool active, fail_alloc;
static unsigned fail_map, fail_unmap;
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
    return __real_lkl_syscall(number, params);
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
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    CHECK(!ker_posix_buffer_writer_create_segmented(178, 128) && errno == ENETDOWN);
    ker_native_host_memory_init(&lkl_host_ops); ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL; CHECK(!lkl_init(&lkl_host_ops)); CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    if (!strcmp(argv[1], "layout")) layout();
    else { CHECK(!strcmp(argv[1], "failures")); failures(); }
    struct ker_posix_buffer_writer *residual = ker_posix_buffer_writer_create_segmented(178, 128); CHECK(residual);
    active = false; invalid(residual, 0, ENETDOWN);
    CHECK(ker_posix_buffer_writer_append(residual, "x", 1) == -1 && errno == ENETDOWN);
    CHECK(ker_posix_buffer_writer_destroy(residual) == -1 && errno == ENETDOWN);
    struct ker_native_buffer_counters final; CHECK(!ker_native_buffers_close_all(&final));
    CHECK(final.allocations == final.releases && !final.live && !final.bytes && !final.option_guards_live);
    CHECK(final.allocations == 9);
    CHECK(final.shutdown_releases == (!strcmp(argv[1], "layout") ? 2 : 3));
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    printf("PASS: segmented owner %s, exact VMA reclamation\n", argv[1]);
    return 0;
}
