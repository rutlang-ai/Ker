#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static void translate_stat(struct stat *output, const struct lkl_stat *native)
{
    memset(output, 0, sizeof(*output));
    output->st_dev = native->st_dev;
    output->st_ino = native->st_ino;
    output->st_mode = native->st_mode;
    output->st_nlink = native->st_nlink;
    output->st_uid = native->st_uid;
    output->st_gid = native->st_gid;
    output->st_rdev = native->st_rdev;
    output->st_size = native->st_size;
    output->st_blksize = native->st_blksize;
    output->st_blocks = native->st_blocks;
    output->st_atim.tv_sec = native->lkl_st_atime;
    output->st_atim.tv_nsec = native->st_atime_nsec;
    output->st_mtim.tv_sec = native->lkl_st_mtime;
    output->st_mtim.tv_nsec = native->st_mtime_nsec;
    output->st_ctim.tv_sec = native->lkl_st_ctime;
    output->st_ctim.tv_nsec = native->st_ctime_nsec;
}
/* Keep the implementation separate from libc's nonnull declaration so the
 * explicit EFAULT boundary also survives optimized builds. */
static int descriptor_stat(int fd, struct stat *output)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fstat, fd, output);
    struct lkl_stat native;
    long result = lkl_sys_fstat(entry->native, &native);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
    if (!output) { errno = EFAULT; return -1; }
    translate_stat(output, &native);
    return 0;
}
int fstat(int fd, struct stat *output) __attribute__((alias("descriptor_stat")));
_Static_assert(sizeof(struct stat) == sizeof(struct stat64), "x86_64 stat64 ABI");
int fstat64(int fd, struct stat64 *output) { return fstat(fd, (void *)output); }
int __fxstat(int version, int fd, struct stat *output) { (void)version; return fstat(fd, output); }
int __fxstat64(int version, int fd, struct stat64 *output) { (void)version; return fstat(fd, (void *)output); }

static int descriptor_statfs(int fd, struct statfs *output)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fstatfs, fd, output);
    struct lkl_statfs native;
    long result = lkl_sys_fstatfs(entry->native, &native);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
    if (!output) { errno = EFAULT; return -1; }
    memset(output, 0, sizeof(*output));
    output->f_type = native.f_type;
    output->f_bsize = native.f_bsize;
    output->f_blocks = native.f_blocks;
    output->f_bfree = native.f_bfree;
    output->f_bavail = native.f_bavail;
    output->f_files = native.f_files;
    output->f_ffree = native.f_ffree;
    _Static_assert(sizeof(output->f_fsid) == sizeof(native.f_fsid), "Linux fsid ABI");
    memcpy(&output->f_fsid, &native.f_fsid, sizeof(output->f_fsid));
    output->f_namelen = native.f_namelen;
    output->f_frsize = native.f_frsize;
    output->f_flags = native.f_flags;
    return 0;
}
int fstatfs(int fd, struct statfs *output) __attribute__((alias("descriptor_statfs")));
_Static_assert(sizeof(struct statfs) == sizeof(struct statfs64), "Linux statfs64 ABI");
int fstatfs64(int fd, struct statfs64 *output) __attribute__((alias("descriptor_statfs")));
/* Copy a native-owned path without asking LKL to dereference a host pointer.
 * Read in bounded chunks, stopping at NUL even when the next page is invalid. */
static int copy_native_path(const char *path, char local_path[PATH_MAX])
{
    uintptr_t base = (uintptr_t)path;
    if (!path) { errno = EFAULT; return -1; }
    size_t copied = 0;
    while (copied < PATH_MAX) {
        size_t amount = PATH_MAX - copied;
        if (amount > 128) amount = 128;
        if (base > UINTPTR_MAX - copied) { errno = EFAULT; return -1; }
        uintptr_t remote_address = base + copied;
        if (remote_address > UINTPTR_MAX - (amount - 1)) {
            size_t available = (size_t)(UINTPTR_MAX - remote_address + 1);
            if (available < amount) amount = available;
        }
        if (!amount) { errno = EFAULT; return -1; }
        struct iovec local = {.iov_base = local_path + copied, .iov_len = amount};
        struct iovec remote = {.iov_base = (void *)remote_address, .iov_len = amount};
        ssize_t length;
        do {
            length = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
        } while (length < 0 && errno == EINTR);
        if (length <= 0) { errno = EFAULT; return -1; }
        if (memchr(local_path + copied, '\0', (size_t)length)) return 0;
        copied += (size_t)length;
        if ((size_t)length != amount) { errno = EFAULT; return -1; }
    }
    errno = ENAMETOOLONG;
    return -1;
}

/* Absolute paths still select the host filesystem; relative paths and the
 * empty-path descriptor operation must respect imported fd ownership. */
static int descriptor_statat(int fd, const char *path, struct stat *output, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_newfstatat, fd, path, output, flags);
    char local_path[PATH_MAX];
    if (path) {
        if (copy_native_path(path, local_path) < 0) {
            int error = errno;
            ker_fd_put(entry);
            errno = error;
            return -1;
        }
        path = local_path;
        if (path[0] == '/') {
            ker_fd_put(entry);
            return syscall(SYS_newfstatat, fd, path, output, flags);
        }
    }
    if (!path && flags != AT_EMPTY_PATH) {
        ker_fd_put(entry); errno = EFAULT; return -1;
    }
    struct lkl_stat native;
    long result = lkl_sys_fstatat(entry->native, path, &native, flags);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
    if (!output) { errno = EFAULT; return -1; }
    translate_stat(output, &native);
    return 0;
}
int fstatat(int fd, const char *path, struct stat *output, int flags)
    __attribute__((alias("descriptor_statat")));
int fstatat64(int fd, const char *path, struct stat64 *output, int flags)
{ return descriptor_statat(fd, path, (void *)output, flags); }
int __fxstatat(int version, int fd, const char *path, struct stat *output, int flags)
{ (void)version; return descriptor_statat(fd, path, output, flags); }
int __fxstatat64(int version, int fd, const char *path, struct stat64 *output, int flags)
{ (void)version; return descriptor_statat(fd, path, (void *)output, flags); }
