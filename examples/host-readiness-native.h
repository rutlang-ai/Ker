#ifndef EXAMPLE_HOST_READINESS_NATIVE_H
#define EXAMPLE_HOST_READINESS_NATIVE_H
#include <ker/posix.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static void (*example_native_stop)(void);
static int example_stop(void *unused)
{
    (void)unused;
    example_native_stop();
    return 0;
}
static void example_require_native(void)
{
    uint64_t (*capabilities)(void) = dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    REQUIRE(capabilities && release && (capabilities() & KER_CAP_LINUX_STACK) && release());
    Dl_info runtime, operation;
    REQUIRE(dladdr((void *)capabilities, &runtime));
    const char *names[] = {"epoll_create1", "epoll_ctl", "epoll_wait"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        REQUIRE(dladdr(dlsym(RTLD_DEFAULT, names[i]), &operation));
        REQUIRE(operation.dli_fbase == runtime.dli_fbase);
    }
    REQUIRE(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM);
}
static void example_finish_native(void)
{
    int (*run)(ker_posix_loop_func, void *) = dlsym(RTLD_DEFAULT, "ker_posix_run");
    example_native_stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    REQUIRE(run && example_native_stop && run(example_stop, NULL) == 0);
    uint64_t (*capabilities)(void) = dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    REQUIRE(capabilities && capabilities() == 0);
}
#endif
