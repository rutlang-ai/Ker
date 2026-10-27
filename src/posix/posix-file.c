#define _GNU_SOURCE
#include "fd-table.h"
#include "posix-usercopy.h"
#include "syscall-result.h"
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/xattr.h>
#include <stdlib.h>
#include <sys/xattr.h>
#include <sys/mman.h>
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
ssize_t readahead(int fd, off64_t offset, size_t count)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_readahead, fd, offset, count);
    long value = lkl_sys_readahead(entry->native, offset, count);
    ker_fd_put(entry);
    return ker_native_result(value);
}
int sync_file_range(int fd, off64_t offset, off64_t count, unsigned flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_sync_file_range, fd, offset, count, flags);
    long value = lkl_sys_sync_file_range(entry->native, offset, count, flags);
    ker_fd_put(entry);
    return ker_native_result(value);
}
int posix_fadvise(int fd, off_t offset, off_t length, int advice)
{
    int saved = errno;
    struct ker_fd *entry = ker_fd_get(fd);
    long value;
    if (!entry) {
        value = syscall(SYS_fadvise64, fd, offset, length, advice);
        if (value < 0) value = -errno;
    } else {
        /* The pinned build omits CONFIG_ADVISE_SYSCALLS and its generated
         * wrapper. Ask the real syscall table, preserving its ENOSYS boundary. */
        _Static_assert(sizeof(long) == sizeof(off_t), "Linux 64-bit syscall arguments");
        long arguments[6] = {entry->native, offset, length, advice, 0, 0};
        value = lkl_syscall(__lkl__NR_fadvise64, arguments);
        ker_fd_put(entry);
    }
    errno = saved;
    return value < 0 ? (int)-value : (int)value;
}
extern __typeof(posix_fadvise64) posix_fadvise64 __attribute__((alias("posix_fadvise")));
/* Copy names into host memory before an LKL syscall. Its strncpy_from_user
 * routines must not dereference a caller address in the host address space. */
static long ker_copy_xattr_name(const char *name, char local_name[XATTR_NAME_MAX + 1])
{
    long length = ker_copy_user_cstring(name, local_name, XATTR_NAME_MAX + 1);
    if (length == -ENAMETOOLONG) return -ERANGE;
    if (length <= 0) return length ? length : -ERANGE;
    return length;
}

/* Never pass a caller-owned value/list buffer into LKL: its usercopy helpers
 * interpret pointers in the imported kernel's address space. Stage through
 * host memory and preserve partial-copy EFAULT behavior without invoking the
 * native operation after an incomplete input copy. */
static long ker_copy_xattr_buffer(void *local_buffer, void *user_buffer,
                                  size_t length, int to_user)
{
    if (!length) return 0;
    if (!local_buffer || !user_buffer ||
        (uintptr_t)user_buffer > UINTPTR_MAX - (length - 1))
        return -EFAULT;
    struct iovec local = {.iov_base = local_buffer, .iov_len = length};
    struct iovec remote = {.iov_base = user_buffer, .iov_len = length};
    long copied;
    do {
        copied = syscall(to_user ? SYS_process_vm_writev : SYS_process_vm_readv,
                         getpid(), &local, 1, &remote, 1, 0);
    } while (copied < 0 && errno == EINTR);
    return copied == (long)length ? 0 : -EFAULT;
}

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fgetxattr, fd, name, value, size);
    char local_name[XATTR_NAME_MAX + 1];
    long name_error = ker_copy_xattr_name(name, local_name);
    if (name_error < 0) { ker_fd_put(entry); return ker_native_result(name_error); }
    if (!value && size) { ker_fd_put(entry); errno = EFAULT; return -1; }
    size_t capacity = size < XATTR_SIZE_MAX ? size : XATTR_SIZE_MAX;
    void *local_value = capacity ? malloc(capacity) : NULL;
    if (capacity && !local_value) { ker_fd_put(entry); errno = ENOMEM; return -1; }
    long result = lkl_sys_fgetxattr(entry->native, local_name, local_value, capacity);
    if (result > 0 && capacity && (size_t)result > capacity) result = -EIO;
    if (result > 0 && capacity) {
        long copy_error = ker_copy_xattr_buffer(local_value, value, (size_t)result, 1);
        if (copy_error < 0) result = copy_error;
    }
    free(local_value);
    ker_fd_put(entry);
    return ker_native_result(result);
}

int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fsetxattr, fd, name, value, size, flags);
    if (flags & ~(XATTR_CREATE | XATTR_REPLACE)) {
        ker_fd_put(entry);
        return ker_native_result(-EINVAL);
    }
    char local_name[XATTR_NAME_MAX + 1];
    long name_error = ker_copy_xattr_name(name, local_name);
    if (name_error < 0) { ker_fd_put(entry); return ker_native_result(name_error); }
    if (size > XATTR_SIZE_MAX) { ker_fd_put(entry); return ker_native_result(-E2BIG); }
    if (!value && size) { ker_fd_put(entry); return ker_native_result(-EFAULT); }
    void *local_value = size ? malloc(size) : NULL;
    if (size && !local_value) { ker_fd_put(entry); errno = ENOMEM; return -1; }
    long copy_error = ker_copy_xattr_buffer(local_value, (void *)value, size, 0);
    if (copy_error < 0) {
        free(local_value);
        ker_fd_put(entry);
        return ker_native_result(copy_error);
    }
    long result = lkl_sys_fsetxattr(entry->native, local_name, local_value, size, flags);
    free(local_value);
    ker_fd_put(entry);
    return ker_native_result(result);
}

ssize_t flistxattr(int fd, char *list, size_t size)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_flistxattr, fd, list, size);
    if (!list && size) { ker_fd_put(entry); errno = EFAULT; return -1; }
    size_t capacity = size < XATTR_LIST_MAX ? size : XATTR_LIST_MAX;
    char *local_list = capacity ? malloc(capacity) : NULL;
    if (capacity && !local_list) { ker_fd_put(entry); errno = ENOMEM; return -1; }
    long result = lkl_sys_flistxattr(entry->native, local_list, capacity);
    if (result > 0 && capacity && (size_t)result > capacity) result = -EIO;
    if (result > 0 && capacity) {
        long copy_error = ker_copy_xattr_buffer(local_list, list, (size_t)result, 1);
        if (copy_error < 0) result = copy_error;
    }
    free(local_list);
    ker_fd_put(entry);
    return ker_native_result(result);
}

int fremovexattr(int fd, const char *name)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_fremovexattr, fd, name);
    char local_name[XATTR_NAME_MAX + 1];
    long name_error = ker_copy_xattr_name(name, local_name);
    if (name_error < 0) { ker_fd_put(entry); return ker_native_result(name_error); }
    long result = lkl_sys_fremovexattr(entry->native, local_name);
    ker_fd_put(entry);
    return ker_native_result(result);
}

void *mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
    /* Anonymous mappings ignore fd, including a native reservation value. */
    if (flags & MAP_ANONYMOUS) return (void *)syscall(SYS_mmap, address, length, protection, flags, fd, offset);
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return (void *)syscall(SYS_mmap, address, length, protection, flags, fd, offset);
    if ((uint64_t)offset & 4095) {
        ker_fd_put(entry); errno = EINVAL; return MAP_FAILED;
    }
    void *value = lkl_sys_mmap(address, length, protection, flags, entry->native, offset);
    ker_fd_put(entry);
    if ((uintptr_t)value >= (uintptr_t)-4095) {
        errno = -(long)value; return MAP_FAILED;
    }
    return value;
}
extern __typeof(mmap64) mmap64 __attribute__((alias("mmap")));
