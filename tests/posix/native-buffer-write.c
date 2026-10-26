/* Actual original-Linux VMAs and production bounded writes; no algorithm mirror. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include "native-buffer.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lkl.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)

/* Standalone kernel bootstrap supplies the same active/inactive lifetime gate. */
static bool active;
bool ker_native_ready(void) { return active; }
static void all_bytes(const unsigned char *p, size_t length, unsigned char value)
{
    for (size_t i = 0; i < length; ++i) CHECK(p[i] == value);
}
static void overflow(unsigned char *p)
{
    memset(p, 0x5a, 4);
    CHECK(ker_posix_buffer_write(p, 0, "abcdefg", 8) == -1 && errno == EINVAL);
    all_bytes(p, 4, 0x5a);
    const size_t offsets[] = {1, 4, 5, SIZE_MAX};
    const size_t lengths[] = {4, 1, 0, 1};
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(ker_posix_buffer_write(p, offsets[i], "data", lengths[i]) == -1 && errno == EINVAL);
        all_bytes(p, 4, 0x5a);
    }
    CHECK(ker_posix_buffer_write(p, 0, "x", SIZE_MAX) == -1 && errno == EINVAL);
    all_bytes(p, 4, 0x5a);
    CHECK(ker_posix_buffer_write(p, 0, "abcd", 4) == 4 && !memcmp(p, "abcd", 4));
    puts("BUFFER_SOURCE_CASE test_ff_zc_mbuf_write_overflow_returns_error");
}
static void null_data(unsigned char *p)
{
    memset(p, 0x6d, 64);
    CHECK(ker_posix_buffer_write(p, 0, NULL, 4) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_write(p, 0, NULL, 0) == -1 && errno == EINVAL);
    all_bytes(p, 64, 0x6d);
    CHECK(ker_posix_buffer_write(p, 32, "end", 3) == 3);
    all_bytes(p, 32, 0x6d); CHECK(!memcmp(p+32, "end", 3)); all_bytes(p+35, 29, 0x6d);
    puts("BUFFER_SOURCE_CASE test_ff_zc_mbuf_write_null_data_returns_error");
}
static void copied(unsigned char *p)
{
    unsigned char source[8193];
    for (unsigned i = 0; i < sizeof(source); ++i) source[i] = (unsigned char)(i ^ (i >> 8));
    CHECK(ker_posix_buffer_write(p, 0, source, sizeof(source)) == (int)sizeof(source));
    CHECK(!memcmp(p, source, sizeof(source)));
    CHECK(ker_posix_buffer_write(p, 1, p, sizeof(source)-1) == (int)sizeof(source)-1);
    CHECK(p[0] == source[0] && !memcmp(p+1, source, sizeof(source)-1));
    errno = 23;
    CHECK(ker_posix_buffer_write(p, sizeof(source), source, 0) == 0 && errno == 23);
    CHECK(p[0] == source[0] && !memcmp(p+1, source, sizeof(source)-1));
    CHECK(ker_posix_buffer_write(p+1, 0, source, 1) == -1 && errno == EINVAL);
    int foreign = 0xCAFE;
    CHECK(ker_posix_buffer_write(&foreign, 0, source, 1) == -1 && errno == EINVAL && foreign == 0xCAFE);
    CHECK(p[0] == source[0] && !memcmp(p+1, source, sizeof(source)-1));
    puts("PASS: real multi-page copy, overlap, zero write and exact-base ownership");
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    CHECK(!strcmp(argv[1], "overflow") || !strcmp(argv[1], "null") || !strcmp(argv[1], "copy"));
    char sentinel = 's';
    CHECK(ker_posix_buffer_write(NULL, 0, &sentinel, 1) == -1 && errno == EINVAL);
    CHECK(ker_posix_buffer_write(&sentinel, 0, &sentinel, 1) == -1 && errno == ENETDOWN && sentinel == 's');
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(!lkl_init(&lkl_host_ops));
    CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    size_t length = !strcmp(argv[1], "overflow") ? 4 : !strcmp(argv[1], "null") ? 64 : 8193;
    unsigned char *p = ker_posix_buffer_alloc(length); CHECK(p); all_bytes(p, length, 0);
    if (!strcmp(argv[1], "overflow")) overflow(p);
    else if (!strcmp(argv[1], "null")) null_data(p);
    else copied(p);
    CHECK(!ker_posix_buffer_free(p));
    CHECK(ker_posix_buffer_write(p, 0, &sentinel, 1) == -1 && errno == EINVAL);
    p = ker_posix_buffer_alloc(7); CHECK(p);
    active = false;
    CHECK(ker_posix_buffer_write(p, 0, &sentinel, 1) == -1 && errno == ENETDOWN);
    all_bytes(p, 7, 0);
    struct ker_native_buffer_counters final;
    CHECK(!ker_native_buffers_close_all(&final));
    CHECK(final.allocations == 2 && final.releases == 2 && final.shutdown_releases == 1 &&
          !final.live && !final.bytes && !final.option_guards_live);
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    CHECK(ker_posix_buffer_write(p, 0, &sentinel, 1) == -1 && errno == ENETDOWN);
    printf("PASS: native bounded write profile=%s and exact VMA/shutdown accounting\n", argv[1]);
    return 0;
}
