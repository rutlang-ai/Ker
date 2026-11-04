#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

/* Private, tests-ON export. Prepare an immutable regular-file fixture so the
 * original kernel sendfile operates on two fds from its own file table. */
int ker_linux_selftest_input(int host)
{
    if (!ker_native_ready()) { errno = ENETDOWN; return -1; }
    struct stat info;
    if (syscall(SYS_fstat, host, &info)) return -1;
    if (!S_ISREG(info.st_mode) || info.st_size < 0 || info.st_size > 1024 * 1024) {
        errno = EINVAL;
        return -1;
    }
    char path[96];
    snprintf(path, sizeof(path), "/ker-selftest-input-%ld-%d", (long)getpid(), host);
    long writer = lkl_sys_open(path, LKL_O_WRONLY | LKL_O_CREAT | LKL_O_EXCL, 0600);
    if (writer < 0) { errno = (int)-writer; return -1; }
    long error = 0;
    for (off_t offset = 0; offset < info.st_size;) {
        char bytes[16384];
        size_t request = (size_t)(info.st_size - offset);
        if (request > sizeof(bytes)) request = sizeof(bytes);
        ssize_t got = syscall(SYS_pread64, host, bytes, request, offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { error = got < 0 ? -errno : -EIO; break; }
        long written = lkl_sys_write(writer, bytes, (size_t)got);
        if (written != got) { error = written < 0 ? written : -EIO; break; }
        offset += got;
    }
    lkl_sys_close(writer);
    long reader = error ? error : lkl_sys_open(path, LKL_O_RDONLY, 0);
    lkl_sys_unlink(path);
    if (reader < 0) { errno = (int)-reader; return -1; }
    return ker_fd_export((int)reader, KER_FD_FILE, -1, O_CLOEXEC, 0, -1);
}
