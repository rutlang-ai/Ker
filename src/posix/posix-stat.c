#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

int fstat(int fd, struct stat *output)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fstat, fd, output);
    struct lkl_stat native;
    long result = lkl_sys_fstat(entry->native, &native);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
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
_Static_assert(sizeof(struct stat) == sizeof(struct stat64), "x86_64 stat64 ABI");
int fstat64(int fd, struct stat64 *output) { return fstat(fd, (void *)output); }
int __fxstat(int version, int fd, struct stat *output) { (void)version; return fstat(fd, output); }
int __fxstat64(int version, int fd, struct stat64 *output) { (void)version; return fstat(fd, (void *)output); }
