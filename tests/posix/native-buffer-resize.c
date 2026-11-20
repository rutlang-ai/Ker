/* Native-memory-domain realloc: actual original Linux VMAs, not libc realloc. */
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

/* Only the targeted failing syscall is injected. Every success, including
 * the rollback release, uses the original Linux implementation. */
static _Thread_local int fail_map, fail_unmap;
static _Thread_local unsigned maps, unmaps;
static bool active;
bool ker_native_ready(void) { return active; }
long __real_lkl_syscall(long number, long *params);
long __wrap_lkl_syscall(long number, long *params)
{
    if (number == __lkl__NR_mmap) {
        maps++;
        if (fail_map) { fail_map = 0; return -ENOMEM; }
    }
    if (number == __lkl__NR_munmap) {
        unmaps++;
        if (fail_unmap) { fail_unmap--; return -EIO; }
    }
    return __real_lkl_syscall(number, params);
}
static void pattern(unsigned char *p, size_t size)
{
    for (size_t i = 0; i < size; i++) p[i] = (unsigned char)((i * 17) ^ (i >> 8));
}
static void preserved(const unsigned char *p, size_t size)
{
    for (size_t i = 0; i < size; i++) CHECK(p[i] == (unsigned char)((i * 17) ^ (i >> 8)));
}
static struct ker_native_buffer_counters counters(void)
{
    /* close_all is intentionally used only at the end; inspect lifetime via
     * final exact allocation/release identity rather than synthetic mappings. */
    struct ker_native_buffer_counters value;
    CHECK(!ker_native_buffers_close_all(&value));
    return value;
}
int main(void)
{
    int sentinel = 0xCAFE;
    errno = 23;
    CHECK(ker_posix_buffer_realloc(&sentinel, 0) == &sentinel && sentinel == 0xCAFE && errno == 23);
    CHECK(!ker_posix_buffer_realloc(NULL, 0) && errno == 23 && !maps && !unmaps);
    CHECK(!ker_posix_buffer_realloc(NULL, 64) && errno == ENETDOWN);
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(!lkl_init(&lkl_host_ops));
    CHECK(!lkl_start_kernel("%s", "mem=64M"));
    CHECK(lkl_sys_getpid() > 0); active = true;
    unsigned char *p = ker_posix_buffer_alloc(16 * 4); CHECK(p);
    for (unsigned i = 0; i < 64; i++) CHECK(!p[i]);
    CHECK(!ker_posix_buffer_free(p));
    puts("PASS: source calloc 16x4 zero bytes through original Linux mapping");
    p = ker_posix_buffer_realloc(NULL, 8); CHECK(p); pattern(p, 8);
    unsigned char *q = ker_posix_buffer_realloc(p, 32); CHECK(q && q != p);
    preserved(q, 8);
    for (unsigned i = 8; i < 32; i++) CHECK(!q[i]);
    CHECK(ker_posix_buffer_free(p) == -1 && errno == EINVAL);
    p = q;
    CHECK(ker_posix_buffer_realloc(p, 32) == p);
    unsigned map_count = maps, unmap_count = unmaps;
    errno = 17;
    CHECK(ker_posix_buffer_realloc(p, 0) == p && errno == 17);
    CHECK(ker_posix_buffer_realloc(&sentinel, 0) == &sentinel && sentinel == 0xCAFE);
    CHECK(maps == map_count && unmaps == unmap_count);
    CHECK(!ker_posix_buffer_realloc(&sentinel, 64) && errno == EINVAL);
    CHECK(!ker_posix_buffer_realloc(p + 1, 64) && errno == EINVAL);
    CHECK(!ker_posix_buffer_realloc(p, (size_t)INT_MAX + 1) && errno == EINVAL);
    CHECK(maps == map_count && unmaps == unmap_count); preserved(p, 8);
    pattern(p, 32);
    fail_map = 1;
    CHECK(!ker_posix_buffer_realloc(p, 8193) && errno == ENOMEM && !fail_map);
    CHECK(unmaps == unmap_count); preserved(p, 32);
    /* Failure releasing the old VMA must roll back only the new one. */
    fail_unmap = 1;
    CHECK(!ker_posix_buffer_realloc(p, 8193) && errno == EIO && !fail_unmap);
    CHECK(unmaps == unmap_count + 2); preserved(p, 32);
    q = ker_posix_buffer_realloc(p, 8193); CHECK(q && q != p);
    preserved(q, 32);
    for (unsigned i = 32; i < 8193; i++) CHECK(!q[i]);
    CHECK(ker_posix_buffer_free(p) == -1 && errno == EINVAL); p = q;
    pattern(p, 8193);
    q = ker_posix_buffer_realloc(p, 4097); CHECK(q && q != p); preserved(q, 4097);
    CHECK(ker_posix_buffer_free(p) == -1 && errno == EINVAL); p = q;
    CHECK(!ker_posix_buffer_free(p));
    CHECK(!ker_posix_buffer_realloc(p, 64) && errno == EINVAL);
    puts("PASS: grow/shrink preserve prefix, zero extension, stale-base rejection and zero-size identity");
    puts("PASS: injected ENOMEM and old-unmap EIO preserve old VMA; recovery succeeds");
    /* Both unmaps fail: the hidden rollback VMA stays tracked for shutdown,
     * and the caller still owns the original mapping. */
    p = ker_posix_buffer_alloc(33); CHECK(p); pattern(p, 33);
    fail_unmap = 2;
    CHECK(!ker_posix_buffer_realloc(p, 8193) && errno == EIO && !fail_unmap); preserved(p, 33);
    active = false;
    CHECK(!ker_posix_buffer_realloc(p, 64) && errno == ENETDOWN);
    struct ker_native_buffer_counters final = counters();
    CHECK(final.allocations == final.releases && final.shutdown_releases == 2 &&
          !final.live && !final.bytes && !final.option_guards_live);
    CHECK(!lkl_sys_halt()); lkl_cleanup();
    CHECK(ker_posix_buffer_realloc(&sentinel, 0) == &sentinel && sentinel == 0xCAFE);
    puts("PASS: double-unmap failure remains tracked; real shutdown reclaims both VMAs");
    return 0;
}
