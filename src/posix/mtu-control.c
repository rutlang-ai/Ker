#define _GNU_SOURCE
#include "mtu-control.h"
#include "packet-channel.h"
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <lkl.h>

struct device_control { int fd, index, maximum; };
static struct device_control devices[8];
static unsigned device_count;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
void ker_mtu_control_init(int fd, int index, int maximum)
{
    if (device_count == 8) abort();
    devices[device_count++] = (struct device_control){fd, index, maximum};
}
/* A failed/ambiguous transaction cannot be reported as a coherent interface.
 * The launcher detects the failed application and stops the worker as well. */
static void inconsistent(void)
{
    static const char message[] = "ker: Linux/PMD MTU transaction lost consistency\n";
    (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
    abort();
}
static struct ker_mtu_message exchange(const struct device_control *device, unsigned operation, int mtu, int previous)
{
    struct ker_mtu_message message = {KER_MTU_MAGIC, operation, mtu, previous, 0};
    long result;
    do result = syscall(SYS_sendto, device->fd, &message, sizeof(message), MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
    while (result < 0 && errno == EINTR);
    if (result != sizeof(message)) inconsistent();
    struct pollfd pollfd = {device->fd, POLLIN, 0};
    struct timespec timeout = {5, 0};
    do result = syscall(SYS_ppoll, &pollfd, 1, &timeout, NULL, 0); while (result < 0 && errno == EINTR);
    if (result != 1 || !(pollfd.revents & POLLIN)) inconsistent();
    do result = syscall(SYS_recvfrom, device->fd, &message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC, NULL, NULL);
    while (result < 0 && errno == EINTR);
    if (result != sizeof(message) || message.magic != KER_MTU_MAGIC || message.operation != operation ||
        message.status > 0 || message.status < -4095 || message.mtu < KER_NATIVE_MIN_MTU || message.mtu > device->maximum) inconsistent();
    return message;
}
long ker_mtu_ioctl(int fd, unsigned long request, unsigned long argument)
{
    if (request != SIOCSIFMTU && request != SIOCGIFMTU)
        return lkl_sys_ioctl(fd, request, argument);
    /* Let Linux validate the interface name and resolve its real ifindex. */
    if (!argument) return -EFAULT;
    struct ifreq original = *(struct ifreq *)argument;
    struct ifreq lookup = original;
    long result = lkl_sys_ioctl(fd, SIOCGIFINDEX, (unsigned long)&lookup);
    if (result < 0) return result;
    const struct device_control *device = NULL;
    for (unsigned i = 0; i < device_count; i++)
        if (devices[i].index == lookup.ifr_ifindex) device = &devices[i];
    if (!device) return lkl_sys_ioctl(fd, request, argument);
    if (device->fd < 0) return -EOPNOTSUPP;
    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    pthread_mutex_lock(&lock);
    struct ifreq previous = original;
    result = lkl_sys_ioctl(fd, SIOCGIFMTU, (unsigned long)&previous);
    if (result < 0) goto done;
    struct ker_mtu_message response = exchange(device, KER_MTU_GET, 0, 0);
    if (response.status || response.mtu != previous.ifr_mtu) inconsistent();
    if (request == SIOCGIFMTU) {
        *(struct ifreq *)argument = previous;
        goto done;
    }
    if (original.ifr_mtu < KER_NATIVE_MIN_MTU || original.ifr_mtu > device->maximum) {
        result = -EINVAL; goto done;
    }
    result = lkl_sys_ioctl(fd, request, (unsigned long)&original);
    if (result < 0) goto done;
    response = exchange(device, KER_MTU_SET, original.ifr_mtu, previous.ifr_mtu);
    if (response.status) {
        if (response.mtu != previous.ifr_mtu ||
            lkl_sys_ioctl(fd, SIOCSIFMTU, (unsigned long)&previous) < 0) inconsistent();
        struct ifreq verify = previous;
        if (lkl_sys_ioctl(fd, SIOCGIFMTU, (unsigned long)&verify) < 0 ||
            verify.ifr_mtu != previous.ifr_mtu) inconsistent();
        result = response.status;
    } else if (response.mtu != original.ifr_mtu) inconsistent();
done:
    pthread_mutex_unlock(&lock);
    pthread_setcancelstate(cancellation, NULL);
    return result;
}
