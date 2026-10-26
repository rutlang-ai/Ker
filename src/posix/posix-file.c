#define _GNU_SOURCE
#include "fd-table.h"
#include "syscall-result.h"
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <lkl.h>

/* The application descriptor reserves a host slot; operations must use its
 * imported-kernel owner, not the O_PATH placeholder. */
off_t lseek(int fd, off_t offset, int whence)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_lseek, fd, offset, whence);
    long value = lkl_sys_lseek(entry->native, offset, whence);
    ker_fd_put(entry);
    return ker_native_result(value);
}
#define POSITIONED(name, native_name, qualifier) \
ssize_t name(int fd, qualifier void *bytes, size_t length, off_t offset) \
{ \
    struct ker_fd *entry = ker_fd_get(fd); \
    if (!entry) return syscall(SYS_##native_name, fd, bytes, length, offset); \
    long value = lkl_sys_##native_name(entry->native, bytes, length, offset); \
    ker_fd_put(entry); \
    return ker_native_result(value); \
}
POSITIONED(pread, pread64, )
POSITIONED(pwrite, pwrite64, const)
#define VECTOR(name, flags_decl, flags_arg, stream_signal) \
ssize_t name(int fd, const struct iovec *vectors, int count, off_t offset flags_decl) \
{ \
    struct ker_fd *entry = ker_fd_get(fd); \
    unsigned long low = (uint64_t)offset, high = (uint64_t)offset >> 32; \
    if (!entry) return syscall(SYS_##name, fd, vectors, count, low, high flags_arg); \
    long value = lkl_sys_##name(entry->native, (const struct lkl_iovec *)vectors, count, low, high flags_arg); \
    ker_fd_put(entry); \
    if (stream_signal && offset == -1) return ker_native_write_result(value, 0); \
    return ker_native_result(value); \
}
#define COMMA ,
VECTOR(preadv, , , 0)
VECTOR(pwritev, , , 0)
VECTOR(preadv2, COMMA int flags, COMMA flags, 0)
VECTOR(pwritev2, COMMA int flags, COMMA flags, 1)
_Static_assert(sizeof(off_t) == sizeof(off64_t), "Linux host offset ABI");
extern __typeof(lseek64) lseek64 __attribute__((alias("lseek")));
extern __typeof(pread64) pread64 __attribute__((alias("pread")));
extern __typeof(pwrite64) pwrite64 __attribute__((alias("pwrite")));
extern __typeof(preadv64) preadv64 __attribute__((alias("preadv")));
extern __typeof(pwritev64) pwritev64 __attribute__((alias("pwritev")));
extern __typeof(preadv64v2) preadv64v2 __attribute__((alias("preadv2")));
extern __typeof(pwritev64v2) pwritev64v2 __attribute__((alias("pwritev2")));

int ftruncate(int fd, off_t length)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_ftruncate, fd, length);
    long value = lkl_sys_ftruncate(entry->native, length);
    ker_fd_put(entry);
    return ker_native_result(value);
}
extern __typeof(ftruncate64) ftruncate64 __attribute__((alias("ftruncate")));
#define SYNC(name) \
int name(int fd) \
{ \
    struct ker_fd *entry = ker_fd_get(fd); \
    if (!entry) return syscall(SYS_##name, fd); \
    long value = lkl_sys_##name(entry->native); \
    ker_fd_put(entry); \
    return ker_native_result(value); \
}
SYNC(fsync)
SYNC(fdatasync)
int fchmod(int fd, mode_t mode)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fchmod, fd, mode);
    long value = lkl_sys_fchmod(entry->native, mode);
    ker_fd_put(entry);
    return ker_native_result(value);
}
int fchown(int fd, uid_t owner, gid_t group)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fchown, fd, owner, group);
    long value = lkl_sys_fchown(entry->native, owner, group);
    ker_fd_put(entry);
    return ker_native_result(value);
}
int futimens(int fd, const struct timespec times[2])
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_utimensat, fd, NULL, times, 0);
    struct __lkl__kernel_timespec native[2];
    if (times) for (int i = 0; i < 2; ++i) {
        native[i].tv_sec = times[i].tv_sec;
        native[i].tv_nsec = times[i].tv_nsec;
    }
    long value = lkl_sys_utimensat(entry->native, NULL,
                                   times ? (void *)native : NULL, 0);
    ker_fd_put(entry);
    return ker_native_result(value);
}
int futimes(int fd, const struct timeval times[2])
{
    if (!times) return futimens(fd, NULL);
    struct timespec converted[2];
    for (int i = 0; i < 2; ++i) {
        if (times[i].tv_usec < 0 || times[i].tv_usec >= 1000000) { errno = EINVAL; return -1; }
        converted[i].tv_sec = times[i].tv_sec;
        converted[i].tv_nsec = times[i].tv_usec * 1000;
    }
    return futimens(fd, converted);
}

int fallocate(int fd, int mode, off_t offset, off_t length)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fallocate, fd, mode, offset, length);
    long value = lkl_sys_fallocate(entry->native, mode, offset, length);
    ker_fd_put(entry);
    return ker_native_result(value);
}
extern __typeof(fallocate64) fallocate64 __attribute__((alias("fallocate")));

int posix_fallocate(int fd, off_t offset, off_t length)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) {
        int (*host_posix_fallocate)(int, off_t, off_t) = dlsym(RTLD_NEXT, "posix_fallocate");
        return host_posix_fallocate ? host_posix_fallocate(fd, offset, length) : ENOSYS;
    }
    long value = lkl_sys_fallocate(entry->native, 0, offset, length);
    ker_fd_put(entry);
    return value < 0 ? (int)-value : 0;
}
extern __typeof(posix_fallocate64) posix_fallocate64 __attribute__((alias("posix_fallocate")));
