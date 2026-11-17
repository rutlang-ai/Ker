/* Critical host mapping failure against the actual original-Linux boot path. */
#define _GNU_SOURCE
#include "host-memory.h"
#include "host-thread.h"
#include "host-clock.h"
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
#define BOOT_BYTES (64UL * 1024 * 1024)
static struct lkl_host_operations original;
static atomic_int fail_mapping;
static atomic_uint allocations, releases;
static _Atomic(void *) mapping;
static int trace_fd = -1;
struct failure_record { unsigned long size; int error; unsigned int allocations; };

void *__real_mmap64(void *address, size_t size, int prot, int flags, int fd, off64_t offset);
void *__wrap_mmap64(void *address, size_t size, int prot, int flags, int fd, off64_t offset)
{
    if (size == BOOT_BYTES && atomic_exchange(&fail_mapping, 0)) {
        CHECK(address == NULL && prot == (PROT_READ | PROT_WRITE));
        CHECK(flags == (MAP_PRIVATE | MAP_ANONYMOUS) && fd == -1 && offset == 0);
        struct failure_record record = {
            .size = size, .error = ENOMEM, .allocations = atomic_load(&allocations),
        };
        CHECK(write(trace_fd, &record, sizeof(record)) == (ssize_t)sizeof(record));
        errno = ENOMEM;
        return MAP_FAILED;
    }
    return __real_mmap64(address, size, prot, flags, fd, offset);
}
static void *count_alloc(unsigned long size)
{
    CHECK(size == BOOT_BYTES);
    atomic_fetch_add(&allocations, 1);
    void *result = original.page_alloc(size);
    atomic_store(&mapping, result);
    return result;
}
static void count_free(void *address, unsigned long size)
{
    CHECK(size == BOOT_BYTES && address == atomic_load(&mapping));
    original.page_free(address, size);
    atomic_fetch_add(&releases, 1);
}
static void fatal_boot(void)
{
    int channel[2]; CHECK(pipe(channel) == 0);
    /* No parent kernel or host threads have been started before this fork. */
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        struct rlimit limit = {0, 0}; CHECK(setrlimit(RLIMIT_CORE, &limit) == 0);
        CHECK(close(channel[0]) == 0);
        trace_fd = channel[1];
        atomic_store(&fail_mapping, 1);
        CHECK(lkl_init(&lkl_host_ops) == 0);
        /* The real page_alloc must return NULL to Linux bootmem_init. Its
         * BUG_ON must reach the installed fatal panic callback, not return. */
        (void)lkl_start_kernel("%s", "mem=64M");
        _exit(3);
    }
    CHECK(close(channel[1]) == 0);
    int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    struct failure_record record;
    CHECK(read(channel[0], &record, sizeof(record)) == (ssize_t)sizeof(record));
    CHECK(record.size == BOOT_BYTES && record.error == ENOMEM && record.allocations == 1);
    char extra; CHECK(read(channel[0], &extra, 1) == 0);
    CHECK(close(channel[0]) == 0);
    CHECK(!atomic_load(&fail_mapping) && !atomic_load(&allocations) && !atomic_load(&mapping));
    puts("PASS: actual Linux boot page mapping ENOMEM reaches fatal panic before startup returns");
}
static void healthy_boot(void)
{
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    CHECK(atomic_load(&allocations) == 1 && atomic_load(&mapping));
    CHECK(lkl_sys_poll(NULL, 0, 10) == 0);
    long fd = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_DGRAM, 0);
    CHECK(fd >= 0 && lkl_sys_close(fd) == 0);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    CHECK(atomic_load(&releases) == 1);
    long page = sysconf(_SC_PAGESIZE); CHECK(page > 0);
    uintptr_t address = (uintptr_t)atomic_load(&mapping);
    unsigned char resident;
    errno = 0;
    CHECK(mincore((void *)address, (size_t)page, &resident) == -1 && errno == ENOMEM);
    errno = 0;
    CHECK(mincore((void *)(address + BOOT_BYTES - (unsigned long)page), (size_t)page,
        &resident) == -1 && errno == ENOMEM);
    puts("PASS: fault-free parent boots original Linux, waits, creates a socket and releases real boot pages");
}
int main(void)
{
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_thread_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    original = lkl_host_ops;
    CHECK(original.page_alloc && original.page_free);
    lkl_host_ops.page_alloc = count_alloc;
    lkl_host_ops.page_free = count_free;
    fatal_boot();
    healthy_boot();
    return 0;
}
