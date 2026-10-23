/* Adapt explicit kernel TAP receive mode when virtio has no CTRL_RX facility. */
#define _GNU_SOURCE
#include "worker-receive-mode.h"
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <rte_dev.h>
#include <rte_devargs.h>
#include <rte_ethdev.h>
#include <rte_kvargs.h>

int ker_worker_allmulticast_enable(uint16_t port, struct ker_worker_receive_mode *state)
{
    int result = rte_eth_allmulticast_enable(port);
    if (!result) {
        if (rte_eth_allmulticast_get(port) != 1) return -EIO;
        state->method = "pmd";
        return 0;
    }
    if (result != -ENOTSUP && result != -EOPNOTSUPP) return result;
    struct rte_eth_dev_info info;
    if (rte_eth_dev_info_get(port, &info) || !info.driver_name ||
        strcmp(info.driver_name, "net_virtio_user") || !info.device) return result;
    const struct rte_devargs *args = rte_dev_devargs(info.device);
    if (!args || !args->args) return result;
    struct rte_kvargs *values = rte_kvargs_parse(args->args, NULL);
    if (!values) return -EINVAL;
    const char *path = rte_kvargs_get(values, "path"), *name = rte_kvargs_get(values, "iface");
    struct stat backend, canonical;
    /* The original PMD successfully opened the named TAP with TUNSETIFF.
     * Do not apply host-interface settings to a socket/vDPA backend, an
     * automatically generated name, or an unrelated character device. */
    bool qualified = rte_kvargs_count(values, "path") == 1 &&
        rte_kvargs_count(values, "iface") == 1 && path && name && *name &&
        strlen(name) < IFNAMSIZ && !strchr(name, '%') &&
        !stat(path, &backend) && !stat("/dev/vhost-net", &canonical) &&
        S_ISCHR(backend.st_mode) && S_ISCHR(canonical.st_mode) &&
        backend.st_rdev == canonical.st_rdev;
    if (qualified) {
        memcpy(state->interface, name, strlen(name) + 1);
        state->ifindex = if_nametoindex(name);
        qualified = state->ifindex != 0;
    }
    rte_kvargs_free(values);
    if (!qualified) return result;
    /* Keep a protocol-zero AF_PACKET binding as an identity handle. Linux
     * clears its ifindex on NETDEV_UNREGISTER, so a reused index cannot pass
     * cleanup; protocol zero registers no packet receive hook. This fallback
     * therefore needs CAP_NET_RAW in addition to the flag ioctl permission. */
    state->identity_fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (state->identity_fd < 0) return -errno;
    struct sockaddr_ll identity = {.sll_family = AF_PACKET, .sll_ifindex = (int)state->ifindex};
    if (bind(state->identity_fd, (struct sockaddr *)&identity, sizeof(identity))) return -errno;
    socklen_t identity_length = sizeof(identity);
    if (getsockname(state->identity_fd, (struct sockaddr *)&identity, &identity_length)) return -errno;
    if (identity.sll_ifindex != (int)state->ifindex) return -ENODEV;
    state->socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (state->socket_fd < 0) return -errno;
    struct ifreq request = {0};
    memcpy(request.ifr_name, state->interface, IFNAMSIZ);
    if (ioctl(state->socket_fd, SIOCGIFFLAGS, &request)) return -errno;
    state->restore_allmulti = !(request.ifr_flags & IFF_ALLMULTI);
    request.ifr_flags |= IFF_ALLMULTI;
    if (ioctl(state->socket_fd, SIOCSIFFLAGS, &request) ||
        ioctl(state->socket_fd, SIOCGIFFLAGS, &request)) return -errno;
    if (!(request.ifr_flags & IFF_ALLMULTI)) return -EIO;
    state->method = "host_tap";
    return 0;
}

int ker_worker_receive_mode_restore(struct ker_worker_receive_mode *state)
{
    int result = 0;
    if (state->socket_fd >= 0 && state->restore_allmulti) {
        struct ifreq request = {0};
        struct sockaddr_ll identity = {0};
        socklen_t identity_length = sizeof(identity);
        char current[IFNAMSIZ];
        if (state->identity_fd < 0 ||
            getsockname(state->identity_fd, (struct sockaddr *)&identity, &identity_length) ||
            identity.sll_ifindex != (int)state->ifindex || !if_indextoname(state->ifindex, current) ||
            if_nametoindex(current) != state->ifindex) result = -ENODEV;
        else memcpy(request.ifr_name, current, strlen(current) + 1);
        if (!result && ioctl(state->socket_fd, SIOCGIFFLAGS, &request)) result = -errno;
        else if (!result) {
            request.ifr_flags &= ~IFF_ALLMULTI;
            if (ioctl(state->socket_fd, SIOCSIFFLAGS, &request) ||
                ioctl(state->socket_fd, SIOCGIFFLAGS, &request)) result = -errno;
            else if (request.ifr_flags & IFF_ALLMULTI) result = -EIO;
        }
    }
    if (state->identity_fd >= 0 && close(state->identity_fd) && !result) result = -errno;
    state->identity_fd = -1;
    if (state->socket_fd >= 0 && close(state->socket_fd) && !result) result = -errno;
    state->socket_fd = -1;
    return result;
}
