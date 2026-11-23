#define _GNU_SOURCE
#include <sys/mman.h>
#include "host-mapping.h"
#include "host-readiness-native.h"
#define ff_mmap example_host_mmap
/* The outer native test process observes the actual exit, without mocking exit. */
#define expect_assert_failure(expression) do { \
    puts("HOST_MMAP_FATAL_ARMED"); fflush(stdout); \
    (void)(expression); \
    puts("HOST_MMAP_FATAL_RETURNED"); fflush(stdout); \
    exit(3); \
} while (0)
#include "fstack-host-mmap-source.inc"
int main(void)
{
    example_require_native();
    uint64_t (*capabilities)(void) = dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    Dl_info runtime, operation;
    REQUIRE(dladdr((void *)capabilities, &runtime));
    REQUIRE(dladdr(dlsym(RTLD_DEFAULT, "mmap"), &operation));
    REQUIRE(runtime.dli_fbase == operation.dli_fbase);
    /* Ker's ordinary mmap still reports an error instead of terminating. */
    errno = 0;
    REQUIRE(mmap(NULL, 4096, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == EINVAL);
    puts("NATIVE_MMAP_ERROR_RETURNED"); fflush(stdout);
    test_ff_mmap_failure_exits(NULL);
    exit(4);
}
