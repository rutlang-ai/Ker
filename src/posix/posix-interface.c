#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <limits.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static long interface_query(unsigned long operation, struct ifreq *request)
{
    bool native = ker_native_ready();
    long fd = native ? lkl_sys_socket(AF_INET, SOCK_DGRAM, 0) :
        syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return native ? fd : -errno;
    long result = native ? lkl_sys_ioctl(fd, operation, (unsigned long)request) :
        syscall(SYS_ioctl, fd, operation, request);
    if (!native && result < 0) result = -errno;
    if (native) lkl_sys_close(fd); else syscall(SYS_close, fd);
    return result;
}
unsigned if_nametoindex(const char *name)
{
    size_t length = strnlen(name, IFNAMSIZ);
    if (length == IFNAMSIZ) { errno = ENODEV; return 0; }
    struct ifreq request = {0};
    memcpy(request.ifr_name, name, length + 1);
    long result = interface_query(SIOCGIFINDEX, &request);
    if (result < 0) { errno = -result; return 0; }
    return request.ifr_ifindex;
}
char *if_indextoname(unsigned index, char name[IF_NAMESIZE])
{
    if (index > INT_MAX) { errno = ENXIO; return NULL; }
    struct ifreq request = {.ifr_ifindex = (int)index};
    long result = interface_query(SIOCGIFNAME, &request);
    if (result < 0) { errno = result == -ENODEV ? ENXIO : (int)-result; return NULL; }
    memcpy(name, request.ifr_name, IF_NAMESIZE);
    return name;
}
