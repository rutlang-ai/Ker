#define _GNU_SOURCE
#include "host-entropy.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static enum { NORMAL, FAIL, ZERO, SHORT_RETRY, SHORT_FAIL } mode;
static unsigned calls, shim_calls;
long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...)
{
    /* This isolated executable should see only the host entropy syscall.
     * Fail closed on any other caller rather than forwarding a guessed arity. */
    CHECK(number == SYS_getrandom);
    va_list ap;
    va_start(ap, number);
    void *buffer = va_arg(ap, void *);
    size_t length = va_arg(ap, size_t);
    int flags = va_arg(ap, int);
    va_end(ap);
    CHECK(flags == 0);
    calls++;
    if (mode == FAIL) { errno = EIO; return -1; }
    if (mode == ZERO) return 0;
    if (mode == SHORT_FAIL && calls > 1) { errno = EIO; return -1; }
    if (mode == SHORT_FAIL && length > 7) length = 7;
    if (mode == SHORT_RETRY) {
        if (calls == 1) { errno = EINTR; return -1; }
        if (length > 7) length = 7;
    }
    return __real_syscall(number, buffer, length, flags);
}
/* Stand in for an application's/preload getrandom shim. The production seed
 * adapter must never dispatch through this symbol. */
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags)
{
    (void)flags;
    shim_calls++;
    memset(buffer, 0, length);
    return (ssize_t)length;
}
static void no_node(void)
{
    CHECK(lkl_sys_open("/ker-native-entropy", LKL_O_RDONLY, 0) == -LKL_ENOENT);
}
static void random_outputs(void)
{
    unsigned char bytes[64] = {0};
    CHECK(lkl_sys_getrandom((char *)bytes, sizeof(bytes), GRND_NONBLOCK) == sizeof(bytes));
    unsigned nonzero = 0;
    for (unsigned i = 0; i < sizeof(bytes); ++i) nonzero += bytes[i] != 0;
    CHECK(nonzero >= 50); /* Same sanity threshold as the pinned source case. */
    uint32_t previous = 0;
    unsigned changed = 0;
    for (unsigned i = 0; i < 16; ++i) {
        uint32_t value;
        CHECK(lkl_sys_getrandom((char *)&value, sizeof(value), GRND_NONBLOCK) == sizeof(value));
        changed += value != previous;
        previous = value;
    }
    CHECK(changed >= 12);
    puts("PASS: original Linux nonblocking random fills64 bytes and varies across16 words");
}
int main(void)
{
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    mode = FAIL; calls = 0;
    CHECK(ker_native_seed_entropy() == -EIO && calls == 1); no_node();
    mode = ZERO; calls = 0;
    CHECK(ker_native_seed_entropy() == -EIO && calls == 1); no_node();
    mode = SHORT_FAIL; calls = 0;
    CHECK(ker_native_seed_entropy() == -EIO && calls == 2); no_node();
    mode = SHORT_RETRY; calls = 0;
    CHECK(ker_native_seed_entropy() == 0 && calls >= 6 && shim_calls == 0); no_node();
    random_outputs();
    mode = NORMAL; calls = 0;
    CHECK(ker_native_seed_entropy() == 0 && calls >= 1 && shim_calls == 0); no_node();
    random_outputs();
    /* A native setup error must propagate and must not remove an existing
     * object at the temporary device path, even after host entropy was read. */
    long existing = lkl_sys_open("/ker-native-entropy", LKL_O_CREAT | LKL_O_EXCL | LKL_O_RDWR, 0600);
    CHECK(existing >= 0);
    CHECK(lkl_sys_write((unsigned int)existing, "marker", 6) == 6);
    CHECK(ker_native_seed_entropy() == -LKL_EEXIST);
    char marker[6] = {0};
    CHECK(lkl_sys_lseek((unsigned int)existing, 0, 0) == 0);
    CHECK(lkl_sys_read((unsigned int)existing, marker, sizeof(marker)) == sizeof(marker));
    CHECK(memcmp(marker, "marker", 6) == 0);
    CHECK(lkl_sys_close((unsigned int)existing) == 0);
    CHECK(lkl_sys_unlinkat(LKL_AT_FDCWD, "/ker-native-entropy", 0) == 0); no_node();
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    puts("PASS: syscall entropy bypasses getrandom shim; host failure/zero read, short reads/EINTR, reseed and private-node cleanup");
    return 0;
}
