#define _GNU_SOURCE
#include "fd-table.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static int native_socket(int type)
{
    long fd = lkl_sys_socket(LKL_AF_INET, type, 0);
    CHECK(fd >= 0);
    return (int)fd;
}
static void socket_type(int native, int expected)
{
    int type = -1, length = sizeof(type);
    CHECK(lkl_sys_getsockopt(native, LKL_SOL_SOCKET, LKL_SO_TYPE, (char *)&type, &length) == 0);
    CHECK(type == expected && length == sizeof(type));
}
static void closed(int native)
{
    CHECK(lkl_sys_fcntl(native, LKL_F_GETFD, 0) == -LKL_EBADF);
}
static void invalid_indices(void)
{
    const int invalid[] = {-1, KER_FD_LIMIT, 1 << 30};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(ker_fd_get(invalid[i]) == NULL);
        errno = 0;
        CHECK(ker_fd_close(invalid[i]) == -1 && errno == EBADF);
    }
    int native = native_socket(LKL_SOCK_DGRAM);
    errno = 0;
    CHECK(ker_fd_export(native, KER_FD_SOCKET, -1, 0, 0, KER_FD_LIMIT) == -1);
    CHECK(errno == EMFILE);
    closed(native); /* Export owns its input even on failure. */
    CHECK(ker_fd_put(NULL) == 0);
}
int main(void)
{
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    invalid_indices();
    int empty = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
    CHECK(empty >= 0 && ker_fd_get(empty) == NULL);
    CHECK(syscall(SYS_close, empty) == 0);
    int first = native_socket(LKL_SOCK_DGRAM);
    int app = ker_fd_export(first, KER_FD_SOCKET, -1, O_CLOEXEC, 0, -1);
    CHECK(app >= 0);
    CHECK(syscall(SYS_fcntl, app, F_GETFD) == FD_CLOEXEC);
    struct ker_fd *old = ker_fd_get(app);
    CHECK(old && old->native == first && old->kind == KER_FD_SOCKET);
    socket_type(old->native, LKL_SOCK_DGRAM);

    int second = native_socket(LKL_SOCK_STREAM);
    CHECK(ker_fd_export(second, KER_FD_SOCKET, -1, 0, 0, app) == app);
    CHECK(syscall(SYS_fcntl, app, F_GETFD) == 0);
    struct ker_fd *current = ker_fd_get(app);
    CHECK(current && current != old && current->native == second);
    socket_type(current->native, LKL_SOCK_STREAM);
    socket_type(old->native, LKL_SOCK_DGRAM);
    CHECK(ker_fd_put(old) == 0); closed(first);
    CHECK(ker_fd_put(current) == 0);
    puts("PASS: real socket mapping replacement preserves referenced old object");

    int duplicate = (int)lkl_sys_dup(second); CHECK(duplicate >= 0);
    int alias = ker_fd_export(duplicate, KER_FD_SOCKET, -1, 0, 0, -1);
    CHECK(alias >= 0 && alias != app);
    CHECK(ker_fd_close(app) == 0);
    CHECK(ker_fd_get(app) == NULL); closed(second);
    errno = 0;
    CHECK(syscall(SYS_fcntl, app, F_GETFD) == -1 && errno == EBADF);
    socket_type(duplicate, LKL_SOCK_STREAM);
    CHECK(ker_fd_close(alias) == 0);
    CHECK(ker_fd_get(alias) == NULL); closed(duplicate);
    puts("PASS: clearing a mapping releases host reservation and native fd independently of aliases");

    /* A host replacement must also remove the native association. */
    int third = native_socket(LKL_SOCK_DGRAM);
    app = ker_fd_export(third, KER_FD_SOCKET, -1, 0, 0, -1);
    CHECK(app >= 0);
    int host = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
    CHECK(host >= 0 && host != app);
    CHECK(ker_fd_dup_host(host, app, O_CLOEXEC) == app);
    CHECK(ker_fd_get(app) == NULL); closed(third);
    char byte;
    CHECK(syscall(SYS_read, app, &byte, 1) == 0);
    CHECK(ker_fd_close(app) == 0);
    CHECK(syscall(SYS_close, host) == 0);
    invalid_indices();
    int survivor = native_socket(LKL_SOCK_DGRAM);
    app = ker_fd_export(survivor, KER_FD_SOCKET, -1, 0, 0, -1);
    CHECK(app >= 0);
    current = ker_fd_get(app); CHECK(current != NULL);
    invalid_indices(); /* Rejected operations must not mutate a valid mapping. */
    struct ker_fd *again = ker_fd_get(app); CHECK(again == current);
    CHECK(ker_fd_put(again) == 0);
    ker_fd_close_all();
    CHECK(ker_fd_get(app) == NULL);
    errno = 0;
    CHECK(syscall(SYS_fcntl, app, F_GETFD) == -1 && errno == EBADF);
    socket_type(survivor, LKL_SOCK_DGRAM);
    CHECK(ker_fd_put(current) == 0); closed(survivor);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    puts("PASS: host replacement, invalid indices and failed export ownership; original Linux halted");
    return 0;
}
