#define _GNU_SOURCE
#include "extra-interfaces.h"
#include "packet-channel.h"
#include "packet-device.h"
#include "mtu-control.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl_host.h>
#include <lkl/linux/virtio_net.h>

struct interface {
    struct lkl_netdev *device;
    int control, mtu, maximum;
    char *address, *address6, *vips, *vips6;
};
static struct interface interfaces[7];
static unsigned count;
static char *storage;
static int number(const char *text, long maximum)
{
    char *end; errno = 0;
    long value = strtol(text, &end, 10);
    return errno || !*text || *end || value < 0 || value > maximum ? -1 : (int)value;
}
static int channel(int fd, int type)
{
    int actual = 0; socklen_t size = sizeof(actual);
    return syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &actual, &size) || actual != type ||
        syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC) < 0 ? -EINVAL : 0;
}
int ker_extra_interfaces_register(const char *settings)
{
    if (!settings || !*settings) return 0;
    storage = strdup(settings);
    if (!storage) return -ENOMEM;
    char *rest = storage, *text;
    while ((text = strsep(&rest, ";"))) {
        if (count == 7) return -E2BIG;
        char *fields[9], *part = text;
        for (unsigned i = 0; i < 9; i++) {
            fields[i] = strsep(&part, "|");
            if (!fields[i] || !*fields[i]) return -EINVAL;
        }
        if (part) return -EINVAL;
        int fd = number(fields[0], INT_MAX), control = number(fields[1], INT_MAX);
        int maximum = number(fields[2], KER_NATIVE_MAX_MTU), mtu = number(fields[3], KER_NATIVE_MAX_MTU);
        if (mtu < KER_NATIVE_MIN_MTU || maximum < mtu || channel(fd, SOCK_DGRAM) ||
            channel(control, SOCK_SEQPACKET)) return -EINVAL;
        unsigned values[6]; char extra;
        if (sscanf(fields[4], "%x:%x:%x:%x:%x:%x%c", &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5], &extra) != 6) return -EINVAL;
        unsigned char mac[6];
        for (unsigned i = 0; i < 6; i++) {
            if (values[i] > 255) return -EINVAL;
            mac[i] = (unsigned char)values[i];
        }
        struct lkl_netdev *device = ker_packet_device_create(fd);
        if (!device) return -ENOMEM;
        struct lkl_netdev_args args = {.mac = mac, .offload = maximum > 1500 ?
            (1U << LKL_VIRTIO_NET_F_MRG_RXBUF) : 0};
        int result = lkl_netdev_add(device, &args);
        if (result < 0) { lkl_netdev_free(device); return result; }
        device->id = result;
        interfaces[count++] = (struct interface){device, control, mtu, maximum,
            fields[5], fields[6], fields[7], fields[8]};
    }
    return 0;
}
static int address4(int index, const char *configuration)
{
    char text[INET_ADDRSTRLEN + 4];
    if (strlen(configuration) >= sizeof(text)) return -EINVAL;
    strcpy(text, configuration);
    char *slash = strchr(text, '/');
    if (!slash) return -EINVAL;
    *slash++ = 0;
    int prefix = number(slash, 32); struct in_addr address;
    if (prefix < 0 || inet_pton(AF_INET, text, &address) != 1) return -EINVAL;
    return lkl_if_set_ipv4(index, address.s_addr, prefix);
}
static int address6(int index, const char *configuration, struct in6_addr *address)
{
    char text[INET6_ADDRSTRLEN + 5];
    if (strlen(configuration) >= sizeof(text)) return -EINVAL;
    strcpy(text, configuration);
    char *slash = strchr(text, '/');
    if (!slash) return -EINVAL;
    *slash++ = 0;
    int prefix = number(slash, 128);
    if (prefix < 0 || inet_pton(AF_INET6, text, address) != 1) return -EINVAL;
    return lkl_if_add_ip(index, LKL_AF_INET6, address, prefix);
}
int ker_extra_interfaces_configure(void)
{
    for (unsigned i = 0; i < count; i++) {
        struct interface *item = &interfaces[i];
        int index = lkl_netdev_get_ifindex(item->device->id);
        if (index <= 0) return index ? index : -ENODEV;
        int result = address4(index, item->address);
        if (result) return result;
        char *rest = strcmp(item->vips, "-") ? item->vips : NULL, *vip;
        unsigned vips = 0;
        while ((vip = strsep(&rest, ","))) {
            if (++vips > 32 || (result = address4(index, vip))) return result ? result : -E2BIG;
        }
        if ((result = lkl_if_set_mtu(index, item->mtu))) return result;
        ker_mtu_control_init(item->control, index, item->maximum);
        if ((result = lkl_if_up(index))) return result;
        struct in6_addr dad[33]; unsigned entries = 0;
        if (strcmp(item->address6, "-")) {
            if ((result = address6(index, item->address6, &dad[entries++]))) return result;
        }
        rest = strcmp(item->vips6, "-") ? item->vips6 : NULL;
        vips = 0;
        while ((vip = strsep(&rest, ","))) {
            if (++vips > 32 || entries == 33) return -E2BIG;
            if ((result = address6(index, vip, &dad[entries++]))) return result;
        }
        for (unsigned j = 0; j < entries; j++)
            if ((result = lkl_if_wait_ipv6_dad(index, &dad[j]))) return result;
    }
    return 0;
}
void ker_extra_interfaces_remove(void)
{
    while (count) {
        struct lkl_netdev *device = interfaces[--count].device;
        lkl_netdev_remove(device->id); lkl_netdev_free(device);
    }
    free(storage); storage = NULL;
}
