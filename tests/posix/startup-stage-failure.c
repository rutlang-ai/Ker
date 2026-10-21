/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>

int __real_lkl_init(struct lkl_host_operations *ops);
int __real_lkl_netdev_add(struct lkl_netdev *device, struct lkl_netdev_args *args);
int __real_lkl_start_kernel(const char *format, ...);
int __real_lkl_if_up(int index);

static int inject(const char *stage)
{
    const char *mode = getenv("KER_TEST_NATIVE_STAGE_FAILURE");
    return mode && !strcmp(mode, stage);
}

static int record(const char *stage, int injected, int result)
{
    const char *path = getenv("KER_TEST_NATIVE_STAGE_TRACE");
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

/* Linked only into the non-installed test variant. Controls forward to LKL. */
int __wrap_lkl_init(struct lkl_host_operations *ops)
{
    int failed = inject("init");
    return record("init", failed, failed ? -LKL_EIO : __real_lkl_init(ops));
}

int __wrap_lkl_netdev_add(struct lkl_netdev *device, struct lkl_netdev_args *args)
{
    int failed = inject("register");
    return record("register", failed, failed ? -LKL_EIO : __real_lkl_netdev_add(device, args));
}

int __wrap_lkl_start_kernel(const char *format, ...)
{
    int failed = inject("boot");
    if (failed) return record("boot", 1, -LKL_EIO);
    va_list arguments;
    va_start(arguments, format);
    char *command = NULL;
    int length = vasprintf(&command, format, arguments);
    va_end(arguments);
    if (length < 0) return record("boot", 0, -LKL_ENOMEM);
    int result = __real_lkl_start_kernel("%s", command);
    free(command);
    return record("boot", 0, result);
}

int __wrap_lkl_if_up(int index)
{
    const char *stage = index == 1 ? "loopback" : "interface";
    int failed = inject(stage);
    return record(stage, failed, failed ? -LKL_EIO : __real_lkl_if_up(index));
}
