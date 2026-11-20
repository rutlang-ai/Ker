/* Observe original LKL registration and teardown in the production adapter. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static struct lkl_netdev *registered;
static int registered_id = -1;
static int packet_fd = -1;

int __real_lkl_netdev_add(struct lkl_netdev *device, struct lkl_netdev_args *arguments);
void __real_lkl_netdev_remove(int id);
void __real_lkl_netdev_free(struct lkl_netdev *device);

static void note(const char *operation, int id)
{
    const char *path = getenv("KER_TEST_NETDEV_TRACE");
    if (!path) abort();
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) abort();
    char line[64];
    int length = snprintf(line, sizeof(line), "%s %d\n", operation, id);
    if (length < 0 || length >= (int)sizeof(line) ||
        syscall(SYS_write, fd, line, (size_t)length) != length || syscall(SYS_close, fd))
        abort();
}

int __wrap_lkl_netdev_add(struct lkl_netdev *device, struct lkl_netdev_args *arguments)
{
    const char *text = getenv("KER_PACKET_FD");
    if (!text || registered) abort();
    char *end;
    long fd = strtol(text, &end, 10);
    if (end == text || *end || fd < 0 || fd > INT_MAX) abort();
    packet_fd = (int)fd;
    if (syscall(SYS_fcntl, packet_fd, F_GETFD) < 0) abort();
    int id = __real_lkl_netdev_add(device, arguments);
    if (id < 0) return id;
    registered = device;
    registered_id = id;
    note("add", id);
    return id;
}

void __wrap_lkl_netdev_remove(int id)
{
    if (!registered || id != registered_id) abort();
    __real_lkl_netdev_remove(id);
    note("remove", id);
}

void __wrap_lkl_netdev_free(struct lkl_netdev *device)
{
    if (!registered || device != registered) abort();
    registered = NULL;
    __real_lkl_netdev_free(device);
    errno = 0;
    if (syscall(SYS_fcntl, packet_fd, F_GETFD) != -1 || errno != EBADF) abort();
    note("free", registered_id);
}
