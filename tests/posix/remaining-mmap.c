#define _GNU_SOURCE
#include <ker/posix.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include "check.h"
#include "host-mapping.h"

#define ff_mmap example_host_mmap
#define expect_assert_failure(expression) do { \
    puts("HOST_MMAP_FATAL_ARMED"); fflush(stdout); \
    (void)(expression); \
    exit(3); \
} while (0)
#include "fstack-host-mmap-source.inc"

int main(void)
{
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    CHECK(release && release());
    CHECK(mmap(NULL, 4096, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == EINVAL);
    test_ff_mmap_failure_exits(NULL);
    return 4;
}
