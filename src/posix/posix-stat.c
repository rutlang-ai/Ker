#define _GNU_SOURCE
#include "fd-table.h"
#include "posix-usercopy.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
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
    struct stat translated;
    translate_stat(&translated, &native);
    long copied = ker_copy_to_user(output, &translated, sizeof(translated));
    if (copied < 0) { errno = (int)-copied; return -1; }
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
    struct statfs translated;
    memset(&translated, 0, sizeof(translated));
    translated.f_type = native.f_type;
    translated.f_bsize = native.f_bsize;
    translated.f_blocks = native.f_blocks;
    translated.f_bfree = native.f_bfree;
    translated.f_bavail = native.f_bavail;
    translated.f_files = native.f_files;
    translated.f_ffree = native.f_ffree;
    _Static_assert(sizeof(translated.f_fsid) == sizeof(native.f_fsid), "Linux fsid ABI");
    memcpy(&translated.f_fsid, &native.f_fsid, sizeof(translated.f_fsid));
    translated.f_namelen = native.f_namelen;
    translated.f_frsize = native.f_frsize;
    translated.f_flags = native.f_flags;
    long copied = ker_copy_to_user(output, &translated, sizeof(translated));
    if (copied < 0) { errno = (int)-copied; return -1; }
    return 0;
}
int fstatfs(int fd, struct statfs *output) __attribute__((alias("descriptor_statfs")));
_Static_assert(sizeof(struct statfs) == sizeof(struct statfs64), "Linux statfs64 ABI");
int fstatfs64(int fd, struct statfs64 *output) __attribute__((alias("descriptor_statfs")));
/* Copy a native-owned path before inspecting or passing it into LKL. */
static int copy_native_path(const char *path, char local_path[PATH_MAX])
{
    long result = ker_copy_user_cstring(path, local_path, PATH_MAX);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
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
    struct stat translated;
    translate_stat(&translated, &native);
    long copied = ker_copy_to_user(output, &translated, sizeof(translated));
    if (copied < 0) { errno = (int)-copied; return -1; }
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

/* statx is a fixed Linux UAPI wire layout, including its reserved extension
 * area. Both kernels use the same host byte order and 64-bit ABI. */
_Static_assert(sizeof(struct statx) == sizeof(struct lkl_statx), "statx UAPI size");
#define STATX_OFFSET(field) _Static_assert(offsetof(struct statx, field) == offsetof(struct lkl_statx, field), "statx " #field)
STATX_OFFSET(stx_mask); STATX_OFFSET(stx_ino); STATX_OFFSET(stx_atime);
STATX_OFFSET(stx_mtime); STATX_OFFSET(stx_dev_major); STATX_OFFSET(stx_mnt_id);
static int descriptor_statx(int fd, const char *path, int flags, unsigned mask, struct statx *output)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_statx, fd, path, flags, mask, output);
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
            return syscall(SYS_statx, fd, path, flags, mask, output);
        }
    }
    int lookup = flags & ~(AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE);
    if (!path && lookup != AT_EMPTY_PATH) {
        ker_fd_put(entry); errno = EFAULT; return -1;
    }
    struct lkl_statx native;
    long result = lkl_sys_statx(entry->native, path, flags, mask, &native);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
    long copied = ker_copy_to_user(output, &native, sizeof(native));
    if (copied < 0) { errno = (int)-copied; return -1; }
    return 0;
}
int statx(int fd, const char *path, int flags, unsigned mask, struct statx *output)
    __attribute__((alias("descriptor_statx")));

/* faccessat's flags belong to the access check; use faccessat2 rather than
 * silently discarding AT_EACCESS/AT_EMPTY_PATH as the old raw syscall would. */
static int descriptor_accessat(int fd, const char *path, int mode, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_faccessat2, fd, path, mode, flags);
    /* Match do_faccessat's mode-then-flags validation before pathname access. */
    if (mode & ~(R_OK | W_OK | X_OK)) {
        ker_fd_put(entry); errno = EINVAL; return -1;
    }
    if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) {
        ker_fd_put(entry); errno = EINVAL; return -1;
    }
    char native_path[PATH_MAX];
    long copied = ker_copy_user_cstring(path, native_path, sizeof(native_path));
    if (copied < 0) {
        int error = (int)-copied;
        ker_fd_put(entry);
        errno = error; return -1;
    }
    if (native_path[0] == '/') {
        ker_fd_put(entry);
        return syscall(SYS_faccessat2, fd, native_path, mode, flags);
    }
    long result = lkl_sys_faccessat2(entry->native, native_path, mode, flags);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
int faccessat(int fd, const char *path, int mode, int flags)
    __attribute__((alias("descriptor_accessat")));

/* Linux added fchmodat2 for flag support. On hosts that predate it, retain
 * the old fchmodat syscall only when no flags need to be represented. */
static int host_fchmodat(int fd, const char *path, mode_t mode, int flags)
{
    int result = (int)syscall(SYS_fchmodat2, fd, path, mode, flags);
    if (result < 0 && errno == ENOSYS && flags == 0)
        return (int)syscall(SYS_fchmodat, fd, path, mode);
    return result;
}

static int descriptor_chmodat(int fd, const char *path, mode_t mode, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return host_fchmodat(fd, path, mode, flags);
    if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) {
        ker_fd_put(entry); errno = EINVAL; return -1;
    }
    char native_path[PATH_MAX];
    if (copy_native_path(path, native_path) < 0) {
        int error = errno;
        ker_fd_put(entry);
        errno = error; return -1;
    }
    if (native_path[0] == '/') {
        ker_fd_put(entry);
        return host_fchmodat(fd, native_path, mode, flags);
    }
    long result = lkl_sys_fchmodat2(entry->native, native_path, mode, flags);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
int fchmodat(int fd, const char *path, mode_t mode, int flags)
    __attribute__((alias("descriptor_chmodat")));
static int descriptor_chownat(int fd, const char *path, uid_t owner, gid_t group, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fchownat, fd, path, owner, group, flags);
    if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) {
        ker_fd_put(entry); errno = EINVAL; return -1;
    }
    char native_path[PATH_MAX];
    if (copy_native_path(path, native_path) < 0) {
        int error = errno;
        ker_fd_put(entry);
        errno = error; return -1;
    }
    if (native_path[0] == '/') {
        ker_fd_put(entry);
        return syscall(SYS_fchownat, fd, native_path, owner, group, flags);
    }
    long result = lkl_sys_fchownat(entry->native, native_path, owner, group, flags);
    ker_fd_put(entry);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
int fchownat(int fd, const char *path, uid_t owner, gid_t group, int flags)
    __attribute__((alias("descriptor_chownat")));
