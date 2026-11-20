#define _GNU_SOURCE
#include "mtu-control.h"
#include "packet-channel.h"
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <lkl.h>

static int control_fd = -1, device_index, maximum_mtu;
static pthread_mutex_t control_lock = PTHREAD_MUTEX_INITIALIZER;

void ker_mtu_control_init(int fd, int index, int ceiling)
{
    control_fd = fd;
    device_index = index;
    maximum_mtu = ceiling;
}

void ker_mtu_control_close(void)
{
    if (control_fd >= 0)
        (void)syscall(SYS_close, control_fd);
}

static _Noreturn void inconsistent_mtu(void)
{
    static const char message[] = "ker: cannot establish a consistent Linux and DPDK MTU\n";
    (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
    _Exit(125);
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        inconsistent_mtu();
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int set_worker_mtu(int old_mtu, int new_mtu)
{
    struct ker_mtu_message message = {
        .magic = KER_MTU_MAGIC, .previous = old_mtu, .mtu = new_mtu,
    };
    long result;
    do {
        result = syscall(SYS_sendto, control_fd, &message, sizeof(message),
            MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
    } while (result < 0 && errno == EINTR);
    if (result != sizeof(message))
        inconsistent_mtu();

    int64_t deadline = monotonic_ms() + 5000;
    struct pollfd wait = {.fd = control_fd, .events = POLLIN};
    do {
        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0)
            inconsistent_mtu();
        struct timespec timeout = {
            .tv_sec = remaining / 1000, .tv_nsec = (remaining % 1000) * 1000000,
        };
        result = syscall(SYS_ppoll, &wait, 1, &timeout, NULL, 0);
    } while (result < 0 && errno == EINTR);
    if (result != 1 || !(wait.revents & POLLIN))
        inconsistent_mtu();

    do {
        result = syscall(SYS_recvfrom, control_fd, &message, sizeof(message),
            MSG_DONTWAIT | MSG_TRUNC, NULL, NULL);
    } while (result < 0 && errno == EINTR);
    if (result != sizeof(message) || message.magic != KER_MTU_MAGIC ||
        message.previous != old_mtu || message.status > 0 || message.status < -4095 ||
        message.mtu != (message.status ? old_mtu : new_mtu))
        inconsistent_mtu();
    return message.status;
}

static long change_mtu(int fd, struct ifreq requested)
{
    struct ifreq previous = requested;
    long result = lkl_sys_ioctl(fd, SIOCGIFMTU, (unsigned long)&previous);
    if (result < 0)
        return result;
    if (requested.ifr_mtu < KER_NATIVE_MIN_MTU || requested.ifr_mtu > maximum_mtu)
        return -EINVAL;

    result = lkl_sys_ioctl(fd, SIOCSIFMTU, (unsigned long)&requested);
    if (result < 0)
        return result;

    struct ifreq actual = requested;
    if (lkl_sys_ioctl(fd, SIOCGIFMTU, (unsigned long)&actual) < 0 ||
        actual.ifr_mtu != requested.ifr_mtu)
        inconsistent_mtu();

    int status = set_worker_mtu(previous.ifr_mtu, requested.ifr_mtu);
    if (status && (lkl_sys_ioctl(fd, SIOCSIFMTU, (unsigned long)&previous) < 0 ||
        lkl_sys_ioctl(fd, SIOCGIFMTU, (unsigned long)&actual) < 0 ||
        actual.ifr_mtu != previous.ifr_mtu))
        inconsistent_mtu();
    return status;
}

long ker_mtu_ioctl(int fd, unsigned long request, unsigned long argument)
{
    if (control_fd < 0 || (request != SIOCSIFMTU && request != SIOCGIFMTU))
        return lkl_sys_ioctl(fd, request, argument);
    if (!argument)
        return -EFAULT;

    const struct ifreq requested = *(const struct ifreq *)argument;
    struct ifreq interface = requested;
    long result = lkl_sys_ioctl(fd, SIOCGIFINDEX, (unsigned long)&interface);
    if (result < 0)
        return result;
    if (interface.ifr_ifindex != device_index)
        return lkl_sys_ioctl(fd, request, argument);

    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    pthread_mutex_lock(&control_lock);
    result = request == SIOCSIFMTU ? change_mtu(fd, requested) :
        lkl_sys_ioctl(fd, request, argument);
    pthread_mutex_unlock(&control_lock);
    pthread_setcancelstate(cancellation, NULL);
    return result;
}
