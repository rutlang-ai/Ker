#define _GNU_SOURCE
#include "fd-table.h"
#include "syscall-result.h"
#include <stdint.h>
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
#define VECTOR(name, flags_decl, flags_arg) \
ssize_t name(int fd, const struct iovec *vectors, int count, off_t offset flags_decl) \
{ \
    struct ker_fd *entry = ker_fd_get(fd); \
    unsigned long low = (uint64_t)offset, high = (uint64_t)offset >> 32; \
    if (!entry) return syscall(SYS_##name, fd, vectors, count, low, high flags_arg); \
    long value = lkl_sys_##name(entry->native, (const struct lkl_iovec *)vectors, count, low, high flags_arg); \
    ker_fd_put(entry); \
    return ker_native_result(value); \
}
#define COMMA ,
VECTOR(preadv, , )
VECTOR(pwritev, , )
VECTOR(preadv2, COMMA int flags, COMMA flags)
VECTOR(pwritev2, COMMA int flags, COMMA flags)
_Static_assert(sizeof(off_t) == sizeof(off64_t), "Linux host offset ABI");
extern __typeof(lseek64) lseek64 __attribute__((alias("lseek")));
extern __typeof(pread64) pread64 __attribute__((alias("pread")));
extern __typeof(pwrite64) pwrite64 __attribute__((alias("pwrite")));
extern __typeof(preadv64) preadv64 __attribute__((alias("preadv")));
extern __typeof(pwritev64) pwritev64 __attribute__((alias("pwritev")));
extern __typeof(preadv64v2) preadv64v2 __attribute__((alias("preadv2")));
extern __typeof(pwritev64v2) pwritev64v2 __attribute__((alias("pwritev2")));
