#define _GNU_SOURCE
#include "host-memory.h"
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static struct lkl_host_operations original;
static atomic_ulong allocations, mappings_used, pages_used, clock_reads;

static void *count_alloc(unsigned long size)
{
    atomic_fetch_add(&allocations, 1);
    return original.mem_alloc(size);
}
static void *count_pages(unsigned long size)
{
    atomic_fetch_add(&pages_used, 1);
    return original.page_alloc(size);
}
static void *count_map(void *address, unsigned long size, enum lkl_prot protection)
{
    atomic_fetch_add(&mappings_used, 1);
    return original.mmap(address, size, protection);
}
static unsigned long long count_time(void)
{
    atomic_fetch_add(&clock_reads, 1);
    return original.time();
}
static void unmapped(void *address, size_t size)
{
    unsigned char resident;
    errno = 0;
    CHECK(mincore(address, size, &resident) == -1 && errno == ENOMEM);
}
/* LKL's mmap callback reserves an exact address, unlike ff_mmap(NULL,...).
 * Choose an unused address before any LKL threads exist; do not use MAP_FIXED
 * to overwrite an existing mapping. MAP_FIXED_NOREPLACE rejects collisions. */
static void *map_at_unused(size_t size, enum lkl_prot protection)
{
    void *address = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(address != MAP_FAILED);
    CHECK(munmap(address, size) == 0);
    CHECK(original.mmap(address, size, protection) == address);
    return address;
}
static void mappings(void)
{
    size_t size = (size_t)sysconf(_SC_PAGESIZE);
    CHECK(size >= 4096);
    unsigned char *bytes = map_at_unused(size, LKL_PROT_READ | LKL_PROT_WRITE);
    for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == 0);
    memset(bytes, 0xab, size);
    for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == 0xab);
    /* An occupied address must fail without clobbering the original bytes. */
    CHECK(original.mmap(bytes, size, LKL_PROT_READ | LKL_PROT_WRITE) == NULL);
    for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == 0xab);
    CHECK(original.munmap(bytes, size) == 0); unmapped(bytes, size);
    puts("PASS: fixed-address anonymous read/write mapping, collision and unmap");

    bytes = map_at_unused(size, LKL_PROT_WRITE);
    /* A write-only mapping may also be readable on some architectures. */
    memset(bytes, 0x6d, size);
    CHECK(original.munmap(bytes, size) == 0); unmapped(bytes, size);
    puts("PASS: write-only mapping accepts writes and unmaps");

    bytes = map_at_unused(size, LKL_PROT_READ);
    for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core) != 0) _exit(2);
        *(volatile unsigned char *)bytes = 1;
        _exit(3);
    }
    int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
    CHECK(bytes[0] == 0);
    CHECK(original.munmap(bytes, size) == 0); unmapped(bytes, size);
    puts("PASS: read-only mapping is zero-filled and rejects writes");

    bytes = original.page_alloc(size); CHECK(bytes != NULL);
    CHECK((uintptr_t)bytes % size == 0);
    memset(bytes, 0x39, size);
    for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == 0x39);
    original.page_free(bytes, size); unmapped(bytes, size);
    puts("PASS: page allocator alignment, writable extent and release");
}
static void memory_and_time(void)
{
    unsigned char *bytes = original.mem_alloc(64); CHECK(bytes != NULL);
    memset(bytes, 0xab, 64);
    for (int i = 0; i < 64; ++i) CHECK(bytes[i] == 0xab);
    original.mem_free(bytes); original.mem_free(NULL);
    puts("PASS: host allocation is writable and freeing NULL is harmless");
    unsigned long long start = original.time(), last = start;
    CHECK(start > 0);
    for (int i = 0; i < 1000; ++i) {
        unsigned long long next = original.time(); CHECK(next >= last); last = next;
    }
    struct timespec delay = {.tv_nsec = 2000000};
    while (nanosleep(&delay, &delay) != 0) CHECK(errno == EINTR);
    CHECK(original.time() > start);
    puts("PASS: monotonic host nanoseconds do not regress and advance after delay");
}
int main(void)
{
    ker_native_host_memory_init(&lkl_host_ops);
    original = lkl_host_ops;
    CHECK(original.mem_alloc && original.mem_free && original.time);
    CHECK(original.mmap && original.munmap && original.page_alloc && original.page_free);
    /* Fork for protection checks before the kernel creates host threads. */
    memory_and_time(); mappings();
    lkl_host_ops.print = NULL;
    lkl_host_ops.mem_alloc = count_alloc;
    lkl_host_ops.page_alloc = count_pages;
    lkl_host_ops.time = count_time;
    lkl_host_ops.mmap = count_map;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    CHECK(lkl_sys_getpid() > 0);
    CHECK(atomic_load(&allocations) + atomic_load(&mappings_used) + atomic_load(&pages_used) > 0);
    CHECK(atomic_load(&clock_reads) > 0);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    puts("PASS: original Linux boots, calls the measured host callbacks and shuts down");
    return 0;
}
