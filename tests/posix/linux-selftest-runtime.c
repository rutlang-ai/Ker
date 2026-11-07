#define _GNU_SOURCE
#include "linux-selftest-runtime.h"
#include "fd-table.h"
#include "lifecycle.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl/linux/in6.h>

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
    case KER_TEST_OPEN_MACVTAP: {
        /* macvtap's /dev/tap<ifindex> name is not its allocated minor. Read
         * the real driver's sysfs dev_t in native Linux before making a node
         * in its private filesystem; never borrow a host macvtap device. */
        if (!a[0] || a[0] > 0x7fffffffUL) return -EINVAL;
        if (lkl_sys_access("/sys/class/macvtap", F_OK)) {
            result = lkl_sys_mkdir("/sys", 0555);
            if (result < 0 && result != -EEXIST) return result;
            result = lkl_sys_mount("sysfs", "/sys", "sysfs", 0, NULL);
            if (result < 0) return result;
        }
        char info[96], node[48], text[64];
        snprintf(info, sizeof(info), "/sys/class/macvtap/tap%lu/dev", a[0]);
        long fd = lkl_sys_open(info, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) return fd;
        long size = lkl_sys_read(fd, text, sizeof(text) - 1);
        long closed = lkl_sys_close(fd);
        if (size < 0) return size;
        if (closed < 0) return closed;
        if (!size || size == (long)sizeof(text) - 1) return -EIO;
        text[size] = 0;
        unsigned major, minor; char trailing;
        if (sscanf(text, "%u:%u %c", &major, &minor, &trailing) != 2 ||
            major > 0xfff || minor > 0xfffff) return -EINVAL;
        unsigned device = (major << 8) | (minor & 0xff) | ((minor & 0xfff00) << 12);
        result = lkl_sys_mkdir("/dev", 0700);
        if (result < 0 && result != -EEXIST) return result;
        snprintf(node, sizeof(node), "/dev/tap%lu", a[0]);
        result = lkl_sys_unlink(node);
        if (result < 0 && result != -ENOENT) return result;
        result = lkl_sys_mknodat(LKL_AT_FDCWD, node, S_IFCHR | 0600, device);
        if (result < 0) return result;
        return export_file(lkl_sys_open(node, O_RDWR | O_NONBLOCK | O_CLOEXEC, 0), KER_FD_FILE, O_CLOEXEC);
    }
    case KER_TEST_SOCKET:
        /* Invalid address families must reach Linux too. The public facade
         * deliberately leaves non-network families on the host; this private
         * selftest operation avoids testing that host fallback by accident. */
        return export_file(lkl_sys_socket((int)a[0], (int)a[1], (int)a[2]), KER_FD_SOCKET,
                           (a[1] & O_CLOEXEC) ? O_CLOEXEC : 0);
    case KER_TEST_OPEN_TUN:
        /* Private test device setup; the real tun driver handles every ioctl
         * and packet. No host /dev/net/tun descriptor enters native Linux. */
        result = lkl_sys_mkdir("/dev", 0700);
        if (result < 0 && result != -EEXIST) return result;
        result = lkl_sys_mkdir("/dev/net", 0700);
        if (result < 0 && result != -EEXIST) return result;
        result = lkl_sys_mknodat(LKL_AT_FDCWD, "/dev/net/tun", S_IFCHR | 0600, (10U << 8) | 200U);
        if (result < 0 && result != -EEXIST) return result;
        return export_file(lkl_sys_open("/dev/net/tun", O_RDWR | O_CLOEXEC, 0), KER_FD_FILE, O_CLOEXEC);
    case KER_TEST_IF_UP: return lkl_if_up((int)a[0]);
    case KER_TEST_UNSHARE: return lkl_sys_unshare(a[0]);
    case KER_TEST_SETNS:
    case KER_TEST_FD_NUMBER:
    case KER_TEST_GETDENTS:
        entry = ker_fd_get((int)a[0]);
        if (!entry) return -EBADF;
        if (operation == KER_TEST_SETNS) result = lkl_sys_setns(entry->native, (int)a[1]);
        else if (operation == KER_TEST_GETDENTS) result = lkl_sys_getdents64(entry->native, (struct lkl_linux_dirent64 *)a[1], a[2]);
        else result = entry->native;
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
    case KER_TEST_RAW_SOCKET:
        /* Uninstalled upstream tools need native ICMP and device ioctls too.
         * Keep this administrative boundary out of the public socket API. */
        if ((a[0] != LKL_AF_INET && a[0] != LKL_AF_INET6) ||
            !(((a[1] & ~O_CLOEXEC) == LKL_SOCK_RAW &&
               (a[2] == LKL_IPPROTO_RAW || (a[0] == LKL_AF_INET && a[2] == LKL_IPPROTO_ICMP) ||
                (a[0] == LKL_AF_INET6 && a[2] == IPPROTO_ICMPV6))) ||
              ((a[1] & ~O_CLOEXEC) == LKL_SOCK_DGRAM &&
               (a[2] == 0 || (a[0] == LKL_AF_INET && a[2] == LKL_IPPROTO_ICMP) ||
                (a[0] == LKL_AF_INET6 && a[2] == IPPROTO_ICMPV6))))) return -EOPNOTSUPP;
        return export_file(lkl_sys_socket((int)a[0], (int)a[1], (int)a[2]), KER_FD_SOCKET,
                           (a[1] & O_CLOEXEC) ? O_CLOEXEC : 0);
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
