/* One imported Linux instance owns both interfaces and every socket below. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static struct sockaddr_storage address(int family, const char *ip, int port)
{
    struct sockaddr_storage result = {0};
    if (family == AF_INET) {
        struct sockaddr_in *p = (void *)&result;
        p->sin_family = family; p->sin_port = htons(port);
        CHECK(inet_pton(family, ip, &p->sin_addr) == 1);
    } else {
        struct sockaddr_in6 *p = (void *)&result;
        p->sin6_family = family; p->sin6_port = htons(port);
        CHECK(inet_pton(family, ip, &p->sin6_addr) == 1);
    }
    return result;
}
static void exchange(int family, const char *local, const char *remote, int datagram, unsigned seed)
{
    int fd = socket(family, datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {5, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_storage src = address(family, local, 0), dst = address(family, remote, 29600);
    socklen_t size = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    CHECK(bind(fd, (void *)&src, size) == 0);
    CHECK(connect(fd, (void *)&dst, size) == 0);
    unsigned char bytes[16], reply[16];
    for (unsigned i = 0; i < sizeof(bytes); i++) bytes[i] = seed + i;
    CHECK(send(fd, bytes, sizeof(bytes), MSG_NOSIGNAL) == sizeof(bytes));
    CHECK(recv(fd, reply, sizeof(reply), datagram ? 0 : MSG_WAITALL) == sizeof(reply));
    CHECK(memcmp(bytes, reply, sizeof(bytes)) == 0);
    if (!datagram) {
        CHECK(shutdown(fd, SHUT_WR) == 0);
        CHECK(recv(fd, reply, sizeof(reply), 0) == 0);
    }
    CHECK(close(fd) == 0);
}
static void mtu_controls(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0); CHECK(fd >= 0);
    struct ifreq aux = {0}, primary = {0};
    for (int index = 2; index < 10; index++) {
        struct ifreq query = {.ifr_ifindex = index};
        if (ioctl(fd, SIOCGIFNAME, &query)) continue;
        struct ifreq location = query;
        if (ioctl(fd, SIOCGIFADDR, &location)) continue;
        struct sockaddr_in *ip = (void *)&location.ifr_addr;
        if (ip->sin_addr.s_addr == inet_addr("198.18.0.2")) primary = query;
        if (ip->sin_addr.s_addr == inet_addr("198.19.0.2")) aux = query;
    }
    CHECK(primary.ifr_name[0] && aux.ifr_name[0] && strcmp(primary.ifr_name, aux.ifr_name));
    CHECK(ioctl(fd, SIOCGIFMTU, &primary) == 0 && primary.ifr_mtu == 1500);
    aux.ifr_mtu = 1600; CHECK(ioctl(fd, SIOCSIFMTU, &aux) == 0);
    CHECK(ioctl(fd, SIOCGIFMTU, &aux) == 0 && aux.ifr_mtu == 1600);
    CHECK(ioctl(fd, SIOCGIFMTU, &primary) == 0 && primary.ifr_mtu == 1500);
    aux.ifr_mtu = 9000; errno = 0;
    CHECK(ioctl(fd, SIOCSIFMTU, &aux) == -1 && errno == EINVAL);
    CHECK(ioctl(fd, SIOCGIFMTU, &aux) == 0 && aux.ifr_mtu == 1600);
    aux.ifr_mtu = 1500; CHECK(ioctl(fd, SIOCSIFMTU, &aux) == 0);
    close(fd);
}
int main(void)
{
    mtu_controls();
    unsigned seed = 0;
    for (int side = 0; side < 2; side++) {
        char local[80], remote[80];
        snprintf(remote, sizeof(remote), "198.%d.0.1", 18 + side);
        for (int vip = 2; vip <= 5; vip++) {
            snprintf(local, sizeof(local), "198.%d.0.%d", 18 + side, vip);
            exchange(AF_INET, local, remote, 0, seed++);
        }
        snprintf(remote, sizeof(remote), "2001:db8:%d::1", 1 + side);
        for (int vip = 2; vip <= 4; vip++) {
            snprintf(local, sizeof(local), "2001:db8:%d::%d", 1 + side, vip);
            exchange(AF_INET6, local, remote, 0, seed++);
        }
    }
    /* Egress auxiliary, ingress primary: both interfaces must belong to the
     * same kernel namespace/socket table. Separate native stacks cannot pass. */
    exchange(AF_INET, "198.18.0.2", "198.19.0.1", 1, 71);
    exchange(AF_INET6, "2001:db8:1::2", "2001:db8:2::1", 1, 72);
    puts("PASS: two native interfaces, every VIP, cross-interface sockets and independent MTU controls");
    return 0;
}
