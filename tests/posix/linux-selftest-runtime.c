#define _GNU_SOURCE
#include "linux-selftest-runtime.h"
#include "fd-table.h"
#include "lifecycle.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static atomic_ulong operations[KER_TEST_OPERATION_COUNT];
static void report_operations(void);

static long export_file(long native, enum ker_fd_kind kind, int flags)
{
    if (native < 0) return native;
    int fd = ker_fd_export((int)native, kind, -1, flags & O_CLOEXEC, 0, -1);
    return fd < 0 ? -errno : fd;
}

long ker_linux_selftest_call(unsigned operation, const unsigned long a[6])
{
    if (operation == KER_TEST_FINALIZE) {
        report_operations();
        return ker_native_finalize();
    }
    if (!ker_native_ready()) return -ENETDOWN;
    if (operation >= KER_TEST_OPERATION_COUNT) return -EINVAL;
    atomic_fetch_add_explicit(&operations[operation], 1, memory_order_relaxed);
    struct ker_fd *entry;
    long result;
    switch (operation) {
    case KER_TEST_IF_UP: return lkl_if_up((int)a[0]);
    case KER_TEST_UNSHARE: return lkl_sys_unshare(a[0]);
    case KER_TEST_SETNS:
    case KER_TEST_FD_NUMBER:
        entry = ker_fd_get((int)a[0]);
        if (!entry) return -EBADF;
        result = operation == KER_TEST_SETNS ? lkl_sys_setns(entry->native, (int)a[1]) : entry->native;
        ker_fd_put(entry);
        return result;
    case KER_TEST_OPEN:
        return export_file(lkl_sys_open((const char *)a[0], (int)a[1], (int)a[2]), KER_FD_FILE, (int)a[1]);
    case KER_TEST_ACCESS: return lkl_sys_access((const char *)a[0], (int)a[1]);
    case KER_TEST_MKDIR: return lkl_sys_mkdir((const char *)a[0], (int)a[1]);
    case KER_TEST_RMDIR: return lkl_sys_rmdir((const char *)a[0]);
    case KER_TEST_MOUNT:
        return lkl_sys_mount((char *)a[0], (char *)a[1], (char *)a[2], a[3], (void *)a[4]);
    case KER_TEST_UMOUNT: return lkl_sys_umount((char *)a[0], 0);
    case KER_TEST_NETLINK:
        /* Administrative setup belongs only to this uninstalled test fixture.
         * Ordinary exported netlink sockets retain their capability guards. */
        return export_file(lkl_sys_socket(LKL_AF_NETLINK, (int)a[0], (int)a[1]),
                           KER_FD_NETLINK_SELFTEST_ADMIN, (a[0] & O_CLOEXEC) ? O_CLOEXEC : 0);
    default: return -EINVAL;
    }
}

__attribute__((destructor)) static void report_operations(void)
{
    static atomic_bool reported;
    if (!atomic_load_explicit(&operations[KER_TEST_UNSHARE], memory_order_relaxed) ||
        atomic_exchange_explicit(&reported, true, memory_order_relaxed)) return;
    char line[512];
    int length = snprintf(line, sizeof(line),
        "KER_LINUX_SELFTEST_OPS {\"unshare\":%lu,\"setns\":%lu,\"open\":%lu,\"netlink\":%lu,\"mount\":%lu}\n",
        atomic_load(&operations[KER_TEST_UNSHARE]), atomic_load(&operations[KER_TEST_SETNS]),
        atomic_load(&operations[KER_TEST_OPEN]), atomic_load(&operations[KER_TEST_NETLINK]),
        atomic_load(&operations[KER_TEST_MOUNT]));
    if (length > 0 && (size_t)length < sizeof(line))
        (void)syscall(SYS_write, STDERR_FILENO, line, (size_t)length);
}
