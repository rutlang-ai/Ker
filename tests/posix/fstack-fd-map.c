#define _GNU_SOURCE
#include "fd-table.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)

/* This standalone fd-table test starts LKL directly rather than through the
 * POSIX lifecycle; fd-table's own mappings identify its native descriptors. */
bool ker_native_ready(void) { return false; }

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
static void host_datagram(int host)
{
    int type = -1; socklen_t length = sizeof(type);
    CHECK(syscall(SYS_getsockopt, host, SOL_SOCKET, SO_TYPE, &type, &length) == 0);
    CHECK(type == SOCK_DGRAM && length == sizeof(type));
    struct sockaddr_in address = {0}; length = sizeof(address);
    CHECK(syscall(SYS_getsockname, host, &address, &length) == 0);
    CHECK(length == sizeof(address) && address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    static const char expected[] = "host socket remains independent";
    CHECK(syscall(SYS_sendto, host, expected, sizeof(expected), 0,
                  &address, sizeof(address)) == (long)sizeof(expected));
    char actual[sizeof(expected)];
    CHECK(syscall(SYS_recvfrom, host, actual, sizeof(actual), 0, NULL, NULL) == (long)sizeof(actual));
    CHECK(!memcmp(actual, expected, sizeof(actual)));
}
static void coexistence(void)
{
    for (int host_first = 0; host_first < 2; ++host_first) {
        int original = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        CHECK(original >= 0);
        /* Reserve a host fd outside bootstrap descriptors; the private Linux
         * table can hold the identical number without sharing the object. */
        int host = (int)syscall(SYS_fcntl, original, F_DUPFD_CLOEXEC, 256);
        CHECK(host >= 256 && host < KER_FD_LIMIT);
        CHECK(syscall(SYS_close, original) == 0);
        struct timeval timeout = {.tv_sec = 2};
        CHECK(syscall(SYS_setsockopt, host, SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0);
        struct sockaddr_in address = {.sin_family = AF_INET,
                                     .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        CHECK(syscall(SYS_bind, host, &address, sizeof(address)) == 0);
        int first = native_socket(LKL_SOCK_STREAM);
        int native = (int)lkl_sys_fcntl(first, LKL_F_DUPFD_CLOEXEC, host);
        CHECK(native == host);
        CHECK(lkl_sys_close(first) == 0);
        CHECK(ker_fd_get(host) == NULL);
        int app = ker_fd_export(native, KER_FD_SOCKET, -1, O_CLOEXEC, 0, -1);
        CHECK(app >= 0 && app != host);
        CHECK(ker_fd_get(host) == NULL);
        struct ker_fd *entry = ker_fd_get(app);
        CHECK(entry && entry->native == host && entry->kind == KER_FD_SOCKET);
        socket_type(entry->native, LKL_SOCK_STREAM);
        CHECK(ker_fd_put(entry) == 0);
        CHECK(syscall(SYS_fcntl, app, F_GETFD) == FD_CLOEXEC);
        CHECK((syscall(SYS_fcntl, app, F_GETFL) & O_PATH) == O_PATH);
        host_datagram(host);
        if (host_first) {
            CHECK(syscall(SYS_close, host) == 0);
            errno = 0;
            CHECK(syscall(SYS_fcntl, host, F_GETFD) == -1 && errno == EBADF);
            entry = ker_fd_get(app); CHECK(entry && entry->native == native);
            socket_type(entry->native, LKL_SOCK_STREAM);
            CHECK(ker_fd_put(entry) == 0);
        }
        CHECK(ker_fd_close(app) == 0);
        CHECK(ker_fd_get(app) == NULL); closed(native);
        errno = 0;
        CHECK(syscall(SYS_fcntl, app, F_GETFD) == -1 && errno == EBADF);
        if (!host_first) {
            host_datagram(host);
            CHECK(syscall(SYS_close, host) == 0);
        }
    }
    puts("PASS: same-number host UDP/native TCP descriptors round-trip through real exports with independent close lifetimes");
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
    coexistence();
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
