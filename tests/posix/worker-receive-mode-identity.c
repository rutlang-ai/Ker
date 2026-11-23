/* Exercise receive-mode cleanup when Linux invalidates its pinned ifindex. */
#define _GNU_SOURCE
#include "worker-receive-mode.h"
#include <errno.h>
#include <linux/if_packet.h>
#include <rte_dev.h>
#include <rte_devargs.h>
#include <rte_ethdev.h>
#include <rte_kvargs.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); return 1; \
} } while (0)

static struct rte_devargs device_args = {.args = "path=/mock/vhost,iface=mock0"};
static unsigned ioctl_get_flags, ioctl_set_flags, closed_fds;
static unsigned char closed[64];
static int reported_ifindex = 77;
static bool fail_initial_flags_read;
static struct rte_kvargs fake_kvargs;
static char fake_device;

int rte_eth_allmulticast_enable(uint16_t port)
{
    (void)port;
    return -ENOTSUP;
}

int rte_eth_allmulticast_get(uint16_t port)
{
    (void)port;
    return 0;
}

int rte_eth_dev_info_get(uint16_t port, struct rte_eth_dev_info *info)
{
    (void)port;
    memset(info, 0, sizeof(*info));
    info->driver_name = "net_virtio_user";
    info->device = (struct rte_device *)&fake_device;
    return 0;
}

const struct rte_devargs *rte_dev_devargs(const struct rte_device *device)
{
    (void)device;
    return &device_args;
}

struct rte_kvargs *rte_kvargs_parse(const char *args, const char *const valid_keys[])
{
    (void)args;
    (void)valid_keys;
    return &fake_kvargs;
}

unsigned int rte_kvargs_count(const struct rte_kvargs *kvlist, const char *key)
{
    (void)kvlist;
    return !strcmp(key, "path") || !strcmp(key, "iface");
}

const char *rte_kvargs_get(const struct rte_kvargs *kvlist, const char *key)
{
    (void)kvlist;
    if (!strcmp(key, "path")) return "/mock/vhost";
    if (!strcmp(key, "iface")) return "mock0";
    return NULL;
}

void rte_kvargs_free(struct rte_kvargs *kvlist)
{
    (void)kvlist;
}

int __wrap_stat(const char *path, struct stat *status)
{
    (void)path;
    memset(status, 0, sizeof(*status));
    status->st_mode = S_IFCHR;
    status->st_rdev = 42;
    return 0;
}

unsigned int __wrap_if_nametoindex(const char *name)
{
    return !strcmp(name, "mock0") || !strcmp(name, "mock-moved") ? 77 : 0;
}

char *__wrap_if_indextoname(unsigned int index, char *name)
{
    if (index != 77) return NULL;
    strcpy(name, "mock-moved");
    return name;
}

int __wrap_socket(int domain, int type, int protocol)
{
    static int next_fd = 41;
    (void)domain;
    (void)type;
    (void)protocol;
    return next_fd++;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

int __wrap_getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    (void)length;
    ((struct sockaddr_ll *)address)->sll_ifindex = reported_ifindex;
    return 0;
}

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    va_start(arguments, request);
    struct ifreq *interface = va_arg(arguments, struct ifreq *);
    va_end(arguments);
    (void)fd;
    if (request == SIOCGIFFLAGS) {
        ioctl_get_flags++;
        if (fail_initial_flags_read) { errno = EIO; return -1; }
        interface->ifr_flags = IFF_ALLMULTI;
    } else if (request == SIOCSIFFLAGS) {
        ioctl_set_flags++;
    }
    return 0;
}

int __wrap_close(int fd)
{
    if (fd >= 0 && (size_t)fd < sizeof(closed)) closed[fd] = 1;
    closed_fds++;
    return 0;
}

static void reset_observations(void)
{
    memset(closed, 0, sizeof(closed));
    closed_fds = ioctl_get_flags = ioctl_set_flags = 0;
}

int main(void)
{
    struct ker_worker_receive_mode state = {.socket_fd = -1, .identity_fd = -1};
    fail_initial_flags_read = true;
    CHECK(ker_worker_allmulticast_enable(0, &state) == -EIO);
    CHECK(state.identity_fd == 41 && state.socket_fd == 42);
    CHECK(ker_worker_receive_mode_restore(&state) == 0);
    CHECK(closed[41] && closed[42] && closed_fds == 2);
    CHECK(ioctl_set_flags == 0);

    reset_observations();
    fail_initial_flags_read = false;
    reported_ifindex = -1; /* packet_notifier() after NETDEV_UNREGISTER */
    state = (struct ker_worker_receive_mode){.socket_fd = 42, .identity_fd = 41,
        .ifindex = 77, .restore_allmulti = true};
    CHECK(ker_worker_receive_mode_restore(&state) == -ENODEV);
    CHECK(ioctl_get_flags == 0 && ioctl_set_flags == 0);
    CHECK(closed[41] && closed[42] && closed_fds == 2);
    CHECK(state.socket_fd == -1 && state.identity_fd == -1);

    reported_ifindex = 78; /* a different interface must also fail closed */
    reset_observations();
    state = (struct ker_worker_receive_mode){.socket_fd = 42, .identity_fd = 41,
        .ifindex = 77, .restore_allmulti = true};
    CHECK(ker_worker_receive_mode_restore(&state) == -ENODEV);
    CHECK(ioctl_set_flags == 0 && closed[41] && closed[42]);
    puts("PASS: stale TAP identity skips flag ioctls and closes both descriptors");
    return 0;
}
