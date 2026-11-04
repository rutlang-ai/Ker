#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Link-time observation only: preserve the original listen result and make
 * the harness wait for the actual listener rather than a guessed delay. */
int __real_listen(int, int);
int __real_open(const char *, int, ...);
int __wrap_listen(int fd, int backlog)
{
    int result = __real_listen(fd, backlog);
    int error = errno;
    const char *path = getenv("KER_MPTCP_TEST_LISTENER_READY");
    if (!result && path) {
        int marker = (int)syscall(SYS_openat, AT_FDCWD, path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (marker < 0 || syscall(SYS_close, marker)) _exit(126);
    }
    errno = error;
    return result;
}

/* Stage the immutable sendfile input in the same kernel as the socket.
 * This is fixture preparation, not host-to-native sendfile emulation. */
int __wrap_open(const char *path, int flags, ...)
{
    int mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    int host = __real_open(path, flags, mode);
    int open_error = errno;
    const char *input = getenv("KER_MPTCP_TEST_NATIVE_INPUT");
    if (host < 0 || !input || strcmp(input, path)) { errno = open_error; return host; }
    int (*prepare)(int) = dlsym(RTLD_DEFAULT, "ker_linux_selftest_input");
    int native = -1;
    if (prepare) native = prepare(host);
    else errno = ENOSYS;
    int error = errno;
    (void)syscall(SYS_close, host);
    errno = error;
    return native;
}
