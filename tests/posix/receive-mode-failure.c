/* Reject one host flag readback after a real successful TAP flag change. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
static bool changed, fired;
int ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    int (*original)(int, unsigned long, ...) = dlsym(RTLD_NEXT, "ioctl");
    if (!original) { errno = ENOSYS; return -1; }
    bool flags = request == SIOCGIFFLAGS || request == SIOCSIFFLAGS;
    struct ifreq *interface = argument;
    bool target = flags && interface && getenv("KER_TEST_RECEIVE_MODE_FAILURE") &&
        !strcmp(interface->ifr_name, "offpeer");
    if (target && request == SIOCGIFFLAGS && changed && !fired) {
        fired = true; errno = EIO;
        fputs("INJECT: kernel TAP flag readback EIO after successful set\n", stderr);
        return -1;
    }
    int result = original(fd, request, argument);
    if (target && request == SIOCSIFFLAGS && !result && (interface->ifr_flags & IFF_ALLMULTI)) changed = true;
    return result;
}
