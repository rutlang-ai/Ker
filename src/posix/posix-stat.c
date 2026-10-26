#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

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
    memset(output, 0, sizeof(*output));
    output->st_dev = native.st_dev;
    output->st_ino = native.st_ino;
    output->st_mode = native.st_mode;
    output->st_nlink = native.st_nlink;
    output->st_uid = native.st_uid;
    output->st_gid = native.st_gid;
    output->st_rdev = native.st_rdev;
    output->st_size = native.st_size;
    output->st_blksize = native.st_blksize;
    output->st_blocks = native.st_blocks;
    output->st_atim.tv_sec = native.lkl_st_atime;
    output->st_atim.tv_nsec = native.st_atime_nsec;
    output->st_mtim.tv_sec = native.lkl_st_mtime;
    output->st_mtim.tv_nsec = native.st_mtime_nsec;
    output->st_ctim.tv_sec = native.lkl_st_ctime;
    output->st_ctim.tv_nsec = native.st_ctime_nsec;
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
