#define _GNU_SOURCE
#include "syscall-result.h"
#include "host-memory.h"
#include "host-clock.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <lkl.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static void mapping(void)
{
    /* Exact symbolic error list from the pinned F-Stack mapping case. Input
     * values come from original Linux UAPI, expected values from host libc. */
    static const struct { int native, host; const char *name; } cases[] = {
        {LKL_EPERM, EPERM, "EPERM"},
        {LKL_ENOENT, ENOENT, "ENOENT"},
        {LKL_ESRCH, ESRCH, "ESRCH"},
        {LKL_EINTR, EINTR, "EINTR"},
        {LKL_EIO, EIO, "EIO"},
        {LKL_ENXIO, ENXIO, "ENXIO"},
        {LKL_E2BIG, E2BIG, "E2BIG"},
        {LKL_ENOEXEC, ENOEXEC, "ENOEXEC"},
        {LKL_EBADF, EBADF, "EBADF"},
        {LKL_ECHILD, ECHILD, "ECHILD"},
        {LKL_EDEADLK, EDEADLK, "EDEADLK"},
        {LKL_ENOMEM, ENOMEM, "ENOMEM"},
        {LKL_EACCES, EACCES, "EACCES"},
        {LKL_EFAULT, EFAULT, "EFAULT"},
        {LKL_ENOTBLK, ENOTBLK, "ENOTBLK"},
        {LKL_EBUSY, EBUSY, "EBUSY"},
        {LKL_EEXIST, EEXIST, "EEXIST"},
        {LKL_EXDEV, EXDEV, "EXDEV"},
        {LKL_ENODEV, ENODEV, "ENODEV"},
        {LKL_ENOTDIR, ENOTDIR, "ENOTDIR"},
        {LKL_EISDIR, EISDIR, "EISDIR"},
        {LKL_EINVAL, EINVAL, "EINVAL"},
        {LKL_ENFILE, ENFILE, "ENFILE"},
        {LKL_EMFILE, EMFILE, "EMFILE"},
        {LKL_ENOTTY, ENOTTY, "ENOTTY"},
        {LKL_ETXTBSY, ETXTBSY, "ETXTBSY"},
        {LKL_EFBIG, EFBIG, "EFBIG"},
        {LKL_ENOSPC, ENOSPC, "ENOSPC"},
        {LKL_ESPIPE, ESPIPE, "ESPIPE"},
        {LKL_EROFS, EROFS, "EROFS"},
        {LKL_EMLINK, EMLINK, "EMLINK"},
        {LKL_EPIPE, EPIPE, "EPIPE"},
        {LKL_EDOM, EDOM, "EDOM"},
        {LKL_ERANGE, ERANGE, "ERANGE"},
        {LKL_EWOULDBLOCK, EWOULDBLOCK, "EWOULDBLOCK"},
        {LKL_EINPROGRESS, EINPROGRESS, "EINPROGRESS"},
        {LKL_EALREADY, EALREADY, "EALREADY"},
        {LKL_ENOTSOCK, ENOTSOCK, "ENOTSOCK"},
        {LKL_EDESTADDRREQ, EDESTADDRREQ, "EDESTADDRREQ"},
        {LKL_EMSGSIZE, EMSGSIZE, "EMSGSIZE"},
        {LKL_EPROTOTYPE, EPROTOTYPE, "EPROTOTYPE"},
        {LKL_ENOPROTOOPT, ENOPROTOOPT, "ENOPROTOOPT"},
        {LKL_EPROTONOSUPPORT, EPROTONOSUPPORT, "EPROTONOSUPPORT"},
        {LKL_ESOCKTNOSUPPORT, ESOCKTNOSUPPORT, "ESOCKTNOSUPPORT"},
        {LKL_EOPNOTSUPP, ENOTSUP, "ENOTSUP (Linux EOPNOTSUPP alias)"},
        {LKL_EPFNOSUPPORT, EPFNOSUPPORT, "EPFNOSUPPORT"},
        {LKL_EAFNOSUPPORT, EAFNOSUPPORT, "EAFNOSUPPORT"},
        {LKL_EADDRINUSE, EADDRINUSE, "EADDRINUSE"},
        {LKL_EADDRNOTAVAIL, EADDRNOTAVAIL, "EADDRNOTAVAIL"},
        {LKL_ENETDOWN, ENETDOWN, "ENETDOWN"},
        {LKL_ENETUNREACH, ENETUNREACH, "ENETUNREACH"},
        {LKL_ENETRESET, ENETRESET, "ENETRESET"},
        {LKL_ECONNABORTED, ECONNABORTED, "ECONNABORTED"},
        {LKL_ECONNRESET, ECONNRESET, "ECONNRESET"},
        {LKL_ENOBUFS, ENOBUFS, "ENOBUFS"},
        {LKL_EISCONN, EISCONN, "EISCONN"},
        {LKL_ENOTCONN, ENOTCONN, "ENOTCONN"},
        {LKL_ESHUTDOWN, ESHUTDOWN, "ESHUTDOWN"},
        {LKL_ETOOMANYREFS, ETOOMANYREFS, "ETOOMANYREFS"},
        {LKL_ETIMEDOUT, ETIMEDOUT, "ETIMEDOUT"},
        {LKL_ECONNREFUSED, ECONNREFUSED, "ECONNREFUSED"},
        {LKL_ELOOP, ELOOP, "ELOOP"},
        {LKL_ENAMETOOLONG, ENAMETOOLONG, "ENAMETOOLONG"},
        {LKL_EHOSTDOWN, EHOSTDOWN, "EHOSTDOWN"},
        {LKL_EHOSTUNREACH, EHOSTUNREACH, "EHOSTUNREACH"},
        {LKL_ENOTEMPTY, ENOTEMPTY, "ENOTEMPTY"},
        {LKL_EUSERS, EUSERS, "EUSERS"},
        {LKL_EDQUOT, EDQUOT, "EDQUOT"},
        {LKL_ESTALE, ESTALE, "ESTALE"},
        {LKL_EREMOTE, EREMOTE, "EREMOTE"},
        {LKL_ENOLCK, ENOLCK, "ENOLCK"},
        {LKL_ENOSYS, ENOSYS, "ENOSYS"},
        {LKL_EIDRM, EIDRM, "EIDRM"},
        {LKL_ENOMSG, ENOMSG, "ENOMSG"},
        {LKL_EOVERFLOW, EOVERFLOW, "EOVERFLOW"},
        {LKL_ECANCELED, ECANCELED, "ECANCELED"},
        {LKL_EILSEQ, EILSEQ, "EILSEQ"},
        {LKL_EBADMSG, EBADMSG, "EBADMSG"},
        {LKL_EMULTIHOP, EMULTIHOP, "EMULTIHOP"},
        {LKL_ENOLINK, ENOLINK, "ENOLINK"},
        {LKL_EPROTO, EPROTO, "EPROTO"},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        errno = 0;
        long result = ker_native_result(-cases[i].native);
        if (result != -1 || errno != cases[i].host) {
            fprintf(stderr, "%s: result=%ld errno=%d expected=%d\n",
                cases[i].name, result, errno, cases[i].host);
            exit(1);
        }
    }
    errno = 0;
    CHECK(ker_native_result(-99999) == -1 && errno == 99999);
    const long success[] = {0, 1, 65536, LONG_MAX};
    for (unsigned i = 0; i < sizeof(success) / sizeof(success[0]); ++i) {
        errno = EBUSY;
        CHECK(ker_native_result(success[i]) == success[i] && errno == EBUSY);
    }
    printf("PASS: %zu symbolic errno mappings, unknown error and full-width success preservation\n",
        sizeof(cases) / sizeof(cases[0]));
}
static void failure(long value, int expected)
{
    CHECK(value == -expected);
    errno = 0;
    CHECK(ker_native_result(value) == -1 && errno == expected);
}
int main(void)
{
    mapping();
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    failure(lkl_sys_close(-1), EBADF);
    failure(lkl_sys_socket(LKL_AF_INET, -1, 0), EINVAL);
    failure(lkl_sys_socket(-1, LKL_SOCK_STREAM, 0), EAFNOSUPPORT);
    int fd = (int)ker_native_result(lkl_sys_socket(LKL_AF_INET, LKL_SOCK_STREAM, 0));
    CHECK(fd >= 0);
    struct lkl_sockaddr address;
    int length = sizeof(address);
    failure(lkl_sys_getpeername(fd, &address, &length), ENOTCONN);
    failure(lkl_sys_shutdown(fd, 99), EINVAL);
    CHECK(ker_native_result(lkl_sys_close(fd)) == 0);
    errno = EBUSY;
    CHECK(ker_native_result(lkl_sys_getpid()) > 0 && errno == EBUSY);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    puts("PASS: original Linux errors and successful syscalls use the production conversion helper");
    return 0;
}
