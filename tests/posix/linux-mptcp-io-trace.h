#ifndef KER_LINUX_MPTCP_IO_TRACE_H
#define KER_LINUX_MPTCP_IO_TRACE_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Diagnostic-only tracing for unchanged saveWithPeek selftests. The trace
 * records call metadata and timing only; never socket payload. */
static inline int ker_mptcp_trace_peek_scope(pid_t target, unsigned *port)
{
    int entry_errno = errno;
    static pid_t cached_pid = -1;
    static int cached_scope;
    static unsigned cached_port;
    if (target == 0) target = (pid_t)syscall(SYS_getpid);
    if (target == cached_pid) {
        if (port) *port = cached_port;
        errno = entry_errno;
        return cached_scope;
    }
    cached_pid = target; cached_scope = 0; cached_port = 0;
    if (!getenv("KER_MPTCP_IO_TRACE")) goto done;
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)target);
    if (length < 0 || (size_t)length >= sizeof(path)) goto done;
    int cmdfd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (cmdfd < 0) goto done;
    char arguments[8192];
    ssize_t count = syscall(SYS_read, cmdfd, arguments, sizeof(arguments));
    syscall(SYS_close, cmdfd);
    if (count <= 0) goto done;
    for (ssize_t offset = 0; offset < count;) {
        size_t remaining = (size_t)(count - offset);
        size_t item = strnlen(arguments + offset, remaining);
        const char *value = arguments + offset;
        if (item == sizeof("saveWithPeek") - 1 && !memcmp(value, "saveWithPeek", item))
            cached_scope = 1;
        if (item == 2 && value[0] == '-' && value[1] == 'p' && offset + (ssize_t)item < count) {
            ssize_t next = offset + (ssize_t)item + 1;
            size_t digits = strnlen(arguments + next, (size_t)(count - next));
            for (size_t i = 0; i < digits && arguments[next + (ssize_t)i] >= '0' &&
                 arguments[next + (ssize_t)i] <= '9'; i++)
                cached_port = cached_port * 10 + (unsigned)(arguments[next + (ssize_t)i] - '0');
        }
        offset += (ssize_t)item + 1;
    }
done:
    if (port) *port = cached_port;
    errno = entry_errno;
    return cached_scope;
}

static inline void ker_mptcp_io_trace(const char *role, const char *operation,
    const char *phase, pid_t peer, unsigned port, int fd, int flags,
    size_t requested, long result, int error)
{
    int entry_errno = errno;
    const char *path = getenv("KER_MPTCP_IO_TRACE");
    if (!path || !*path) { errno = entry_errno; return; }
    static pid_t owner;
    static int tracefd = -1;
    static int reported_failure;
    pid_t self = (pid_t)syscall(SYS_getpid);
    if (owner != self) {
        owner = self; tracefd = -1; reported_failure = 0;
        tracefd = (int)syscall(SYS_openat, AT_FDCWD, path,
            O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    }
    if (tracefd < 0) {
        if (!reported_failure) {
            static const char message[] = "KER_MPTCP_IO_TRACE_ERROR open\n";
            syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
            reported_failure = 1;
        }
        errno = entry_errno;
        return;
    }
    struct timespec now = {0};
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now)) {
        now.tv_sec = 0; now.tv_nsec = 0;
    }
    char line[320];
    int length = snprintf(line, sizeof(line),
        "%lld.%09ld role=%s op=%s phase=%s pid=%ld tid=%ld peer=%ld port=%u fd=%d flags=0x%x requested=%zu result=%ld errno=%d\n",
        (long long)now.tv_sec, now.tv_nsec, role, operation, phase,
        (long)self, (long)syscall(SYS_gettid), (long)peer, port, fd, flags,
        requested, result, error);
    if (length < 0 || (size_t)length >= sizeof(line) ||
        syscall(SYS_write, tracefd, line, (size_t)length) != length) {
        if (!reported_failure) {
            static const char message[] = "KER_MPTCP_IO_TRACE_ERROR write\n";
            syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
            reported_failure = 1;
        }
    }
    errno = entry_errno;
}

#endif
