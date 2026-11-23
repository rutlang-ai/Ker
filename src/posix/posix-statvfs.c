#define _GNU_SOURCE
#include "fd-table.h"
#include "syscall-result.h"
#include "lkl-overlay/arch/lkl/include/asm/ker-host-usercopy.h"
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

/* Linux statvfs is a libc translation of statfs, not a separate syscall.
 * Keep the queried filesystem in the descriptor's owning kernel. */
static int descriptor_statvfs(int fd, struct statvfs *output)
{
    struct statfs queried;
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) {
        if (syscall(SYS_fstatfs, fd, &queried) < 0) return -1;
    } else {
        struct lkl_statfs original;
        long result = lkl_sys_fstatfs(entry->native, &original);
        ker_fd_put(entry);
        if (result < 0) return ker_native_result(result);
        memset(&queried, 0, sizeof(queried));
        queried.f_type = original.f_type;
        queried.f_bsize = original.f_bsize;
        queried.f_frsize = original.f_frsize;
        queried.f_blocks = original.f_blocks;
        queried.f_bfree = original.f_bfree;
        queried.f_bavail = original.f_bavail;
        queried.f_files = original.f_files;
        queried.f_ffree = original.f_ffree;
        queried.f_namelen = original.f_namelen;
        queried.f_flags = original.f_flags;
        _Static_assert(sizeof(queried.f_fsid) == sizeof(original.f_fsid), "Linux filesystem identity ABI");
        memcpy(&queried.f_fsid, &original.f_fsid, sizeof(queried.f_fsid));
    }
    struct statvfs value = {0};
    value.f_bsize = queried.f_bsize;
    value.f_frsize = queried.f_frsize ? queried.f_frsize : queried.f_bsize;
    value.f_blocks = queried.f_blocks;
    value.f_bfree = queried.f_bfree;
    value.f_bavail = queried.f_bavail;
    value.f_files = queried.f_files;
    value.f_ffree = queried.f_ffree;
    value.f_favail = queried.f_ffree;
    _Static_assert(sizeof(value.f_fsid) == 8 && sizeof(queried.f_fsid.__val[0]) == 4, "Linux x86_64 fsid width");
    value.f_fsid = (uint32_t)queried.f_fsid.__val[0] | ((uint64_t)(uint32_t)queried.f_fsid.__val[1] << 32);
    value.f_namemax = queried.f_namelen;
    /* Linux sets ST_VALID internally; it is not a public statvfs flag. */
    value.f_flag = (unsigned long)queried.f_flags ^ 0x20UL;
#ifdef KER_STATVFS_HAS_TYPE
    value.f_type = queried.f_type;
#endif
    if (ker_host_usercopy(output, &value, sizeof(value), 1)) { errno = EFAULT; return -1; }
    return 0;
}
int fstatvfs(int fd, struct statvfs *output) { return descriptor_statvfs(fd, output); }
_Static_assert(sizeof(struct statvfs) == sizeof(struct statvfs64), "Linux x86_64 statvfs64 layout");
_Static_assert(offsetof(struct statvfs, f_namemax) == offsetof(struct statvfs64, f_namemax), "statvfs64 final field");
int fstatvfs64(int fd, struct statvfs64 *output) { return descriptor_statvfs(fd, (void *)output); }
