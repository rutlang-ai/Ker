#define _GNU_SOURCE
#include "packet-device.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl_host.h>

struct packet_device {
    struct lkl_netdev native;
    int fd, wake;
    atomic_int wanted;
    atomic_bool stopped;
};

static void notify(struct packet_device *device)
{
    uint64_t one = 1;
    ssize_t result;
    do result = syscall(SYS_write, device->wake, &one, sizeof(one));
    while (result < 0 && errno == EINTR);
}
static int transfer(struct lkl_netdev *native, struct iovec *iov, int count, bool tx)
{
    struct packet_device *device = (struct packet_device *)native;
    if (atomic_load_explicit(&device->stopped, memory_order_acquire)) {
        errno = ESHUTDOWN;
        return -1;
    }
    if (count <= 0 || count > IOV_MAX) { errno = EINVAL; return -1; }
    struct msghdr message = {.msg_iov = iov, .msg_iovlen = (size_t)count};
    ssize_t result;
    do result = tx ? syscall(SYS_sendmsg, device->fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL) :
        syscall(SYS_recvmsg, device->fd, &message, MSG_DONTWAIT | MSG_TRUNC);
    while (result < 0 && errno == EINTR);
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        atomic_fetch_or_explicit(&device->wanted, tx ? POLLOUT : POLLIN, memory_order_release);
        notify(device);
    }
    if (!tx && result >= 0 && (message.msg_flags & MSG_TRUNC)) { errno = EMSGSIZE; return -1; }
    if (result > INT_MAX) { errno = EOVERFLOW; return -1; }
    return (int)result;
}
static int transmit(struct lkl_netdev *native, struct iovec *iov, int count)
{
    return transfer(native, iov, count, true);
}
static int receive(struct lkl_netdev *native, struct iovec *iov, int count)
{
    return transfer(native, iov, count, false);
}
static int poll_device(struct lkl_netdev *native)
{
    struct packet_device *device = (struct packet_device *)native;
    for (;;) {
        if (atomic_load_explicit(&device->stopped, memory_order_acquire)) return LKL_DEV_NET_POLL_HUP;
        struct pollfd fds[] = {
            {device->fd, (short)atomic_load_explicit(&device->wanted, memory_order_acquire), 0},
            {device->wake, POLLIN, 0},
        };
        int result;
        do result = syscall(SYS_ppoll, fds, 2, NULL, NULL, 0); while (result < 0 && errno == EINTR);
        if (result < 0) return -errno;
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP | POLLNVAL))
            return LKL_DEV_NET_POLL_HUP;
        if (fds[1].revents & POLLIN) {
            uint64_t value;
            (void)syscall(SYS_read, device->wake, &value, sizeof(value));
        }
        int ready = fds[0].revents & (POLLIN | POLLOUT);
        if (ready) {
            atomic_fetch_and_explicit(&device->wanted, ~ready, memory_order_acq_rel);
            return ((ready & POLLIN) ? LKL_DEV_NET_POLL_RX : 0) |
                ((ready & POLLOUT) ? LKL_DEV_NET_POLL_TX : 0);
        }
    }
}
static void stop_device(struct lkl_netdev *native)
{
    struct packet_device *device = (struct packet_device *)native;
    atomic_store_explicit(&device->stopped, true, memory_order_release);
    notify(device);
}
static void free_device(struct lkl_netdev *native)
{
    struct packet_device *device = (struct packet_device *)native;
    syscall(SYS_close, device->fd);
    syscall(SYS_close, device->wake);
    free(device);
}
static struct lkl_dev_net_ops operations = {
    .tx = transmit, .rx = receive, .poll = poll_device,
    .poll_hup = stop_device, .free = free_device,
};
struct lkl_netdev *ker_packet_device_create(int fd)
{
    struct packet_device *device = calloc(1, sizeof(*device));
    if (!device) return NULL;
    int wake = syscall(SYS_eventfd2, 0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake < 0) { free(device); return NULL; }
    device->fd = fd;
    device->wake = wake;
    atomic_init(&device->wanted, 0);
    atomic_init(&device->stopped, false);
    device->native.ops = &operations;
    device->native.has_vnet_hdr = 1;
    return &device->native;
}
