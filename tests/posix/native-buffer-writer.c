/* Owned append cursor over actual original-Linux VMAs, not an mbuf mirror. */
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
bool ker_native_ready(void) { return active; }
static const unsigned char *view(struct ker_posix_buffer_writer *w, size_t expected_length, size_t expected_capacity)
{
    size_t length = SIZE_MAX, capacity = SIZE_MAX;
    const unsigned char *data = ker_posix_buffer_writer_view(w, &length, &capacity);
    CHECK(data && length == expected_length && capacity == expected_capacity);
    CHECK(ker_posix_buffer_writer_view(w, NULL, NULL) == data);
    return data;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2 && (!strcmp(argv[1], "empty") || !strcmp(argv[1], "append") || !strcmp(argv[1], "zero")));
    CHECK(!ker_posix_buffer_writer_create((size_t)INT_MAX+1) && errno == EINVAL);
    CHECK(!ker_posix_buffer_writer_create(0) && errno == ENETDOWN);
    ker_native_host_memory_init(&lkl_host_ops); ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL; CHECK(!lkl_init(&lkl_host_ops)); CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    CHECK(!ker_posix_buffer_alloc(0) && errno == EINVAL); /* Existing raw API remains distinct. */
    size_t capacity = !strcmp(argv[1], "empty") ? 0 : 64;
    struct ker_posix_buffer_writer *w = ker_posix_buffer_writer_create(capacity); CHECK(w);
    const unsigned char *p = view(w, 0, capacity);
    CHECK(ker_posix_buffer_free((void *)p) == -1 && errno == EBUSY);
    CHECK(!ker_posix_buffer_realloc((void *)p, 128) && errno == EBUSY);
    CHECK(ker_posix_buffer_write((void *)p, 0, "x", 1) == -1 && errno == EBUSY);
    CHECK(view(w, 0, capacity) == p);
    if (!strcmp(argv[1], "empty")) {
        CHECK(ker_posix_buffer_writer_append(w, "x", 0) == 0 && view(w, 0, 0) == p);
        CHECK(ker_posix_buffer_writer_append(w, "x", 1) == -1 && errno == EINVAL);
        CHECK(view(w, 0, 0) == p);
        puts("BUFFER_SOURCE_CASE test_ff_zc_mbuf_get_zero_len_returns_minimal_chain");
    } else if (!strcmp(argv[1], "append")) {
        CHECK(ker_posix_buffer_writer_append(w, "ab", 2) == 2 && !memcmp(view(w, 2, 64), "ab", 2));
        CHECK(ker_posix_buffer_writer_append(w, "cd", 2) == 2 && !memcmp(view(w, 4, 64), "abcd", 4));
        CHECK(ker_posix_buffer_writer_append(w, "x", SIZE_MAX) == -1 && errno == EINVAL);
        CHECK(ker_posix_buffer_writer_append(w, NULL, 4) == -1 && errno == EINVAL);
        CHECK(!memcmp(view(w, 4, 64), "abcd", 4));
        CHECK(ker_posix_buffer_writer_append(w, p, 4) == 4 && !memcmp(view(w, 8, 64), "abcdabcd", 8));
        puts("BUFFER_SOURCE_CASE test_ff_zc_mbuf_write_accumulates_pkthdr_len");
    } else {
        CHECK(ker_posix_buffer_writer_append(w, "x", 0) == 0 && view(w, 0, 64) == p);
        CHECK(ker_posix_buffer_writer_append(w, "abc", 3) == 3);
        CHECK(ker_posix_buffer_writer_append(w, "x", 0) == 0 && !memcmp(view(w, 3, 64), "abc", 3));
        CHECK(ker_posix_buffer_writer_append(w, NULL, 0) == -1 && errno == EINVAL);
        CHECK(!memcmp(view(w, 3, 64), "abc", 3));
        puts("BUFFER_SOURCE_CASE test_ff_zc_mbuf_write_zero_len_noop");
    }
    CHECK(!ker_posix_buffer_writer_destroy(w));
    size_t length = 91, size = 92;
    CHECK(!ker_posix_buffer_writer_view(w, &length, &size) && errno == EINVAL && length == 91 && size == 92);
    CHECK(ker_posix_buffer_writer_append(w, "x", 1) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == EINVAL);
    void *raw = ker_posix_buffer_alloc(4); CHECK(raw);
    CHECK(ker_posix_buffer_writer_destroy(raw) == -1 && errno == EINVAL);
    CHECK(!ker_posix_buffer_free(raw));
    w = ker_posix_buffer_writer_create(0); CHECK(w); active = false;
    CHECK(!ker_posix_buffer_writer_view(w, &length, &size) && errno == ENETDOWN && length == 91 && size == 92);
    CHECK(ker_posix_buffer_writer_append(w, "x", 0) == -1 && errno == ENETDOWN);
    CHECK(ker_posix_buffer_writer_destroy(w) == -1 && errno == ENETDOWN);
    struct ker_native_buffer_counters final; CHECK(!ker_native_buffers_close_all(&final));
    CHECK(final.allocations == 3 && final.releases == 3 && final.shutdown_releases == 1 &&
          !final.live && !final.bytes && !final.option_guards_live);
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    printf("PASS: owned VMA writer %s, exact length/ownership and full shutdown reclamation\n", argv[1]);
    return 0;
}
