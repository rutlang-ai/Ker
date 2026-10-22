/* F-Stack host mapping scenarios extended across Ker/LKL page boundaries. */
#define _GNU_SOURCE
#include "host-memory.h"
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)

/* Faults are local to the calling test thread. All successful mappings and
 * releases use real mmap/munmap; no injected address is synthetic. */
static _Thread_local int fail_map, ignore_exact, fail_release;
static _Thread_local void *fallback;
static _Thread_local unsigned int releases;
void *__real_mmap(void *address, size_t size, int prot, int flags, int fd, off_t offset);
int __real_munmap(void *address, size_t size);
void *__wrap_mmap(void *address, size_t size, int prot, int flags, int fd, off_t offset)
{
    if (fail_map) { errno = fail_map; fail_map = 0; return MAP_FAILED; }
    if (ignore_exact) {
        CHECK(flags & MAP_FIXED_NOREPLACE);
        ignore_exact = 0;
        fallback = __real_mmap(NULL, size, prot, flags & ~MAP_FIXED_NOREPLACE, fd, offset);
        CHECK(fallback != MAP_FAILED && fallback != address);
        return fallback;
    }
    return __real_mmap(address, size, prot, flags, fd, offset);
}
int __wrap_munmap(void *address, size_t size)
{
    if (fail_release) { errno = fail_release; fail_release = 0; return -1; }
    if (fallback && address == fallback) ++releases;
    return __real_munmap(address, size);
}
static void unmapped(void *address, size_t size)
{
    unsigned char resident[2];
    errno = 0;
    CHECK(mincore(address, size, resident) == -1 && errno == ENOMEM);
}
static void fatal_release(struct lkl_host_operations *ops, size_t size, int exact)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        struct rlimit limit = {0, 0}; CHECK(setrlimit(RLIMIT_CORE, &limit) == 0);
        void *address = ops->page_alloc(size); CHECK(address);
        fail_release = EINVAL;
        if (exact) {
            ignore_exact = 1;
            (void)ops->mmap(address, size, LKL_PROT_READ | LKL_PROT_WRITE);
        } else ops->page_free(address, size);
        _exit(3);
    }
    int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
}
int main(void)
{
    struct lkl_host_operations ops = {0};
    ker_native_host_memory_init(&ops);
    CHECK(ops.page_alloc && ops.page_free && ops.mmap);
    long page = sysconf(_SC_PAGESIZE); CHECK(page > 0);
    size_t size = (size_t)page * 2;
    const int errors[] = {ENOMEM, EAGAIN};
    for (unsigned int i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fail_map = errors[i]; errno = 0;
        CHECK(ops.page_alloc(size) == NULL && errno == errors[i] && !fail_map);
        unsigned char *bytes = ops.page_alloc(size); CHECK(bytes);
        CHECK((uintptr_t)bytes % (size_t)page == 0);
        for (size_t j = 0; j < size; ++j) CHECK(bytes[j] == 0);
        memset(bytes, 0x39, size);
        for (size_t j = 0; j < size; ++j) CHECK(bytes[j] == 0x39);
        ops.page_free(bytes, size); unmapped(bytes, size);
    }
    errno = 0; CHECK(ops.page_alloc(0) == NULL && errno == EINVAL);
    unsigned char *occupied = ops.page_alloc(size); CHECK(occupied);
    memset(occupied, 0xab, size);
    fail_map = ENOMEM; errno = 0;
    CHECK(ops.mmap(occupied, size, LKL_PROT_READ | LKL_PROT_WRITE) == NULL);
    CHECK(errno == ENOMEM && !fail_map);
    ignore_exact = 1; errno = 0;
    CHECK(ops.mmap(occupied, size, LKL_PROT_READ | LKL_PROT_WRITE) == NULL);
    CHECK(errno == EEXIST && releases == 1 && !ignore_exact);
    unmapped(fallback, size); fallback = NULL;
    for (size_t j = 0; j < size; ++j) CHECK(occupied[j] == 0xab);
    /* Also exercise real MAP_FIXED_NOREPLACE collision handling. */
    errno = 0;
    CHECK(ops.mmap(occupied, size, LKL_PROT_READ | LKL_PROT_WRITE) == NULL);
    CHECK(errno == EEXIST);
    for (size_t j = 0; j < size; ++j) CHECK(occupied[j] == 0xab);
    ops.page_free(occupied, size); unmapped(occupied, size);
    fatal_release(&ops, size, 0);
    fatal_release(&ops, size, 1);
    puts("PASS: page allocation failures recover to real zeroed aligned writable pages and real release");
    puts("PASS: exact-address fallback releases only the returned mapping and preserves occupied bytes");
    puts("PASS: failed page release and fallback cleanup abort in DEBUG and NDEBUG");
    return 0;
}
