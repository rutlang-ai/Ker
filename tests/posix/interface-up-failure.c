/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

int __real_lkl_if_up(int index);

/* Linked only into the test variant; the production preload has no hook. */
int __wrap_lkl_if_up(int index)
{
    const char *stage = index == 1 ? "loopback" : "interface";
    const char *mode = getenv("KER_TEST_IF_UP_FAILURE");
    int injected = mode && !strcmp(mode, stage);
    int result = injected ? -LKL_EIO : __real_lkl_if_up(index);
    const char *path = getenv("KER_TEST_IF_UP_TRACE");
    if (path) {
        char text[96];
        int length = snprintf(text, sizeof(text), "%s %s %d\n", stage,
            injected ? "injected" : "real", result);
        /* Use host syscalls, not the socket preload's descriptor routing. */
        int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
            O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) return -LKL_EIO;
        long count = syscall(SYS_write, fd, text, (size_t)length);
        long closed = syscall(SYS_close, fd);
        if (count != length || closed) return -LKL_EIO;
    }
    return result;
}
