#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Test-only observer. AF_UNIX always traverses the production preload.
 * msg_oob compares UNIX behavior against TCP on the same host kernel; keep
 * that oracle on the host without changing the upstream test or Ker routing. */
static int audit_fd = -1;
static int (*next_socket)(int, int, int);
static int (*next_socketpair)(int, int, int, int[2]);

static void record(const char *text)
{
    size_t length = strlen(text);
    if (audit_fd < 0 || syscall(SYS_write, audit_fd, text, length) != (ssize_t)length)
        _exit(126);
}

__attribute__((constructor)) static void initialize(void)
{
    const char *path = getenv("KER_UNIX_TEST_AUDIT");
    const char *library = getenv("KER_UNIX_TEST_LIBRARY");
    char expected[PATH_MAX], actual[PATH_MAX];
    Dl_info info = {0};
    next_socket = dlsym(RTLD_NEXT, "socket");
    next_socketpair = dlsym(RTLD_NEXT, "socketpair");
    int (*runtime_ready)(void) = dlsym(RTLD_NEXT, "ker_sb_preload_runtime_ready");
    void *ker_socket = dlsym(RTLD_NEXT, "ker_sb_posix_socket");
    if (!path || !library || !next_socket || !next_socketpair ||
        !runtime_ready || !runtime_ready() || ker_socket != (void *)next_socket ||
        !dladdr((void *)next_socket, &info) || !info.dli_fname ||
        !realpath(library, expected) || !realpath(info.dli_fname, actual) ||
        strcmp(actual, expected)) _exit(126);
    audit_fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    record("KER_UNIX_ADAPTER_LOADED\n");
}

int socket(int domain, int type, int protocol)
{
    if (domain == AF_UNIX) {
        record("KER_UNIX_SOCKET\n");
        if (getenv("KER_UNIX_TEST_REJECT")) { errno = EACCES; return -1; }
    }
    if ((domain == AF_INET || domain == AF_INET6) &&
        getenv("KER_UNIX_TEST_HOST_TCP_REFERENCE")) {
        record("HOST_TCP_REFERENCE_SOCKET\n");
        return (int)syscall(SYS_socket, domain, type, protocol);
    }
    return next_socket(domain, type, protocol);
}

int socketpair(int domain, int type, int protocol, int pair[2])
{
    if (domain == AF_UNIX) {
        record("KER_UNIX_SOCKETPAIR\n");
        if (getenv("KER_UNIX_TEST_REJECT")) { errno = EACCES; return -1; }
    }
    return next_socketpair(domain, type, protocol, pair);
}
