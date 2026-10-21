/* IPv6 UDP Ethernet interoperability: original Linux, independent host peers. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);                           \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
static struct in6_addr local_address, peer_address;
static unsigned int interface;
static int port;
static void set(int fd, int level, int name, int value) {
    CHECK(setsockopt(fd, level, name, &value, sizeof(value)) == 0);
}
static int open_udp(int listen_port, int wildcard) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 8};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    set(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    set(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    struct sockaddr_in6 a = {.sin6_family = AF_INET6,
                             .sin6_port = htons(listen_port),
                             .sin6_addr = wildcard ? in6addr_any : local_address};
    CHECK(bind(fd, (void *)&a, sizeof(a)) == 0);
    return fd;
}
static struct sockaddr_in6 remote(int destination_port) {
    return (struct sockaddr_in6){
        .sin6_family = AF_INET6, .sin6_port = htons(destination_port), .sin6_addr = peer_address};
}
static void empty(int fd) {
    char c;
    errno = 0;
    CHECK(recv(fd, &c, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
}
static void fill(unsigned char *data, size_t length, unsigned int record) {
    for (size_t i = 0; i < length; i++)
        data[i] = (unsigned char)(i * 71 + record * 29);
}
static void receive(int fd, struct sockaddr_in6 *peer, size_t size, unsigned int record) {
    unsigned char data[65528], expected[65528];
    fill(expected, size, record);
    socklen_t length = sizeof(*peer);
    CHECK(recvfrom(fd, data, sizeof(data), 0, (void *)peer, &length) == (ssize_t)size);
    CHECK(length == sizeof(*peer) && peer->sin6_family == AF_INET6 &&
          !memcmp(&peer->sin6_addr, &peer_address, 16));
    CHECK(!memcmp(data, expected, size));
}
static void transmit(int fd, struct sockaddr_in6 peer, size_t size, unsigned int record) {
    unsigned char data[65528];
    fill(data, size, record);
    struct iovec vector = {data, size};
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } control = {0};
    struct msghdr message = {.msg_name = &peer,
                             .msg_namelen = sizeof(peer),
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = &control,
                             .msg_controllen = sizeof(control)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_IPV6;
    header->cmsg_type = IPV6_PKTINFO;
    header->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo info = {.ipi6_addr = local_address, .ipi6_ifindex = interface};
    memcpy(CMSG_DATA(header), &info, sizeof(info));
    CHECK(sendmsg(fd, &message, 0) == (ssize_t)size);
}
static unsigned int find_interface(int fd, const char *ipv4) {
    struct ifreq entries[32];
    struct ifconf list = {.ifc_len = sizeof(entries), .ifc_req = entries};
    CHECK(ioctl(fd, SIOCGIFCONF, &list) == 0);
    struct in_addr wanted;
    CHECK(inet_pton(AF_INET, ipv4, &wanted) == 1);
    for (int i = 0; i < list.ifc_len / (int)sizeof(entries[0]); i++)
        if (((struct sockaddr_in *)&entries[i].ifr_addr)->sin_addr.s_addr == wanted.s_addr) {
            struct ifreq request = entries[i];
            CHECK(ioctl(fd, SIOCGIFINDEX, &request) == 0);
            CHECK(request.ifr_ifindex > 0);
            return (unsigned)request.ifr_ifindex;
        }
    CHECK(0);
    return 0;
}
static void ancillary(int server) {
    int fd = open_udp(server ? port : 0, server);
    set(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1);
    set(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1);
    set(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, 1);
    set(fd, SOL_SOCKET, SO_TIMESTAMPNS, 1);
    set(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 37);
    set(fd, IPPROTO_IPV6, IPV6_TCLASS, 44);
    struct sockaddr_in6 peer = remote(server ? 0 : port);
    if (server) {
        puts("READY");
        fflush(stdout);
    }
    for (unsigned int n = 0; n < 3; n++) {
        for (int phase = 0; phase < 2; phase++)
            if ((phase == 0) != server) {
                unsigned char data[37];
                fill(data, sizeof(data), n);
                struct iovec v = {data, sizeof(data)};
                union {
                    struct cmsghdr align;
                    char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
                } control = {0};
                struct msghdr m = {.msg_name = &peer,
                                   .msg_namelen = sizeof(peer),
                                   .msg_iov = &v,
                                   .msg_iovlen = 1,
                                   .msg_control = &control,
                                   .msg_controllen = sizeof(control)};
                struct cmsghdr *c = CMSG_FIRSTHDR(&m);
                c->cmsg_level = IPPROTO_IPV6;
                c->cmsg_type = IPV6_PKTINFO;
                c->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                struct in6_pktinfo info = {.ipi6_addr = local_address, .ipi6_ifindex = interface};
                memcpy(CMSG_DATA(c), &info, sizeof(info));
                CHECK(sendmsg(fd, &m, 0) == sizeof(data));
            } else {
                unsigned char data[37], expected[37];
                fill(expected, sizeof(expected), n);
                struct iovec v = {data, sizeof(data)};
                union {
                    struct cmsghdr align;
                    char bytes[512];
                } control;
                struct msghdr m = {.msg_name = &peer,
                                   .msg_namelen = sizeof(peer),
                                   .msg_iov = &v,
                                   .msg_iovlen = 1,
                                   .msg_control = &control,
                                   .msg_controllen = n == 1 ? 1 : sizeof(control)};
                CHECK(recvmsg(fd, &m, 0) == sizeof(data) && !memcmp(data, expected, sizeof(data)) &&
                      !memcmp(&peer.sin6_addr, &peer_address, 16));
                CHECK(!!(m.msg_flags & MSG_CTRUNC) == (n == 1));
                if (n == 1)
                    continue;
                int packet = 0, hops = 0, traffic = 0, timestamp = 0;
                for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
                    if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
                        struct in6_pktinfo info;
                        CHECK(c->cmsg_len == CMSG_LEN(sizeof(info)));
                        memcpy(&info, CMSG_DATA(c), sizeof(info));
                        CHECK(info.ipi6_ifindex == interface && !memcmp(&info.ipi6_addr, &local_address, 16));
                        packet++;
                    }
                    if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT) {
                        int value;
                        memcpy(&value, CMSG_DATA(c), sizeof(value));
                        CHECK(value == 37);
                        hops++;
                    }
                    if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_TCLASS) {
                        int value;
                        memcpy(&value, CMSG_DATA(c), sizeof(value));
                        CHECK(value == 44);
                        traffic++;
                    }
                    if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
                        struct timespec value, now;
                        CHECK(c->cmsg_len == CMSG_LEN(sizeof(value)));
                        memcpy(&value, CMSG_DATA(c), sizeof(value));
                        CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0 && value.tv_sec >= now.tv_sec - 2 &&
                              value.tv_sec <= now.tv_sec + 1 && value.tv_nsec >= 0 &&
                              value.tv_nsec < 1000000000);
                        timestamp++;
                    }
                }
                CHECK(packet == 1 && hops == 1 && traffic == 1 && timestamp == 1);
            }
    }
    empty(fd);
    CHECK(close(fd) == 0);
}
static void errors(int server) {
    if (server) {
        int fd = open_udp(port, 0);
        puts("READY");
        fflush(stdout);
        for (unsigned n = 0; n < 3; n++) {
            struct sockaddr_in6 peer;
            receive(fd, &peer, 37, n);
            transmit(fd, peer, 37, n);
        }
        CHECK(close(fd) == 0);
        return;
    }
    for (unsigned n = 0; n < 3; n++) {
        int fd = open_udp(0, 0);
        set(fd, IPPROTO_IPV6, IPV6_RECVERR, 1);
        struct sockaddr_in6 bad = remote(port + 100), good = remote(port);
        if (n)
            CHECK(connect(fd, (void *)&bad, sizeof(bad)) == 0);
        transmit(fd, bad, 37, n);
        struct pollfd wait = {.fd = fd, .events = POLLIN};
        CHECK(poll(&wait, 1, 5000) == 1 && (wait.revents & POLLERR));
        int error = 0;
        socklen_t size = sizeof(error);
        CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == ECONNREFUSED);
        unsigned char data[128], expected[37];
        fill(expected, sizeof(expected), n);
        union {
            struct cmsghdr align;
            char bytes[512];
        } control;
        struct sockaddr_in6 destination;
        struct iovec v = {data, sizeof(data)};
        struct msghdr m = {.msg_name = &destination,
                           .msg_namelen = sizeof(destination),
                           .msg_iov = &v,
                           .msg_iovlen = 1,
                           .msg_control = &control,
                           .msg_controllen = n == 2 ? 1 : sizeof(control)};
        CHECK(recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT) == 37 && !memcmp(data, expected, 37));
        CHECK(m.msg_flags & MSG_ERRQUEUE);
        CHECK(destination.sin6_port == bad.sin6_port && !memcmp(&destination.sin6_addr, &bad.sin6_addr, 16));
        if (n == 2)
            CHECK(m.msg_flags & MSG_CTRUNC);
        else {
            int found = 0;
            CHECK(!(m.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
                if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_RECVERR) {
                    CHECK(c->cmsg_len >=
                          CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in6)));
                    struct sock_extended_err *e = (void *)CMSG_DATA(c);
                    CHECK(e->ee_errno == ECONNREFUSED && e->ee_origin == SO_EE_ORIGIN_ICMP6 &&
                          e->ee_type == ICMP6_DST_UNREACH && e->ee_code == ICMP6_DST_UNREACH_NOPORT);
                    struct sockaddr_in6 *offender = (void *)SO_EE_OFFENDER(e);
                    CHECK(offender->sin6_family == AF_INET6 &&
                          !memcmp(&offender->sin6_addr, &peer_address, 16));
                    found++;
                }
            CHECK(found == 1);
        }
        m.msg_controllen = sizeof(control);
        errno = 0;
        CHECK(recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT) == -1 && errno == EAGAIN);
        CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0);
        if (n)
            CHECK(connect(fd, (void *)&good, sizeof(good)) == 0);
        transmit(fd, good, 37, n);
        struct sockaddr_in6 source;
        receive(fd, &source, 37, n);
        empty(fd);
        CHECK(close(fd) == 0);
    }
}
static void fragments(int server) {
    int fd = open_udp(server ? port : 0, 0);
    set(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DONT);
    set(fd, IPPROTO_IPV6, IPV6_DONTFRAG, 0);
    struct sockaddr_in6 peer = remote(server ? 0 : port);
    size_t sizes[] = {1452, 1453, 4096, 65527};
    if (server) {
        puts("READY");
        fflush(stdout);
    }
    for (unsigned n = 0; n < 4; n++) {
        if (!server)
            transmit(fd, peer, sizes[n], n);
        receive(fd, &peer, sizes[n], n);
        if (server)
            transmit(fd, peer, sizes[n], n);
    }
    unsigned char too_large[65528] = {0};
    errno = 0;
    CHECK(sendto(fd, too_large, sizeof(too_large), 0, (void *)&peer, sizeof(peer)) == -1 &&
          errno == EMSGSIZE);
    if (!server)
        transmit(fd, peer, 37, 9);
    receive(fd, &peer, 37, 9);
    if (server)
        transmit(fd, peer, 37, 9);
    empty(fd);
    CHECK(close(fd) == 0);
}
static void segmented_send(int fd, struct sockaddr_in6 peer, unsigned int start) {
    unsigned char data[111];
    for (unsigned int i = 0; i < 3; i++)
        fill(data + i * 37, 37, start + i);
    struct iovec v = {data, sizeof(data)};
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(unsigned short))];
    } control = {0};
    struct msghdr message = {.msg_name = &peer,
                             .msg_namelen = sizeof(peer),
                             .msg_iov = &v,
                             .msg_iovlen = 1,
                             .msg_control = &control,
                             .msg_controllen = sizeof(control)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = IPPROTO_UDP;
    c->cmsg_type = UDP_SEGMENT;
    c->cmsg_len = CMSG_LEN(sizeof(unsigned short));
    unsigned short segment = 37;
    memcpy(CMSG_DATA(c), &segment, sizeof(segment));
    CHECK(sendmsg(fd, &message, 0) == sizeof(data));
}
static void segmentation(int server) {
    int fd = open_udp(server ? port : 0, 0);
    struct sockaddr_in6 peer = remote(server ? 0 : port);
    if (server) {
        puts("READY");
        fflush(stdout);
    } else
        segmented_send(fd, peer, 0);
    for (unsigned int i = 0; i < 3; i++)
        receive(fd, &peer, 37, (server ? 0 : 3) + i);
    if (server)
        segmented_send(fd, peer, 3);
    empty(fd);
    CHECK(close(fd) == 0);
}
static void membership(int fd, struct in6_addr group, int ssm, int join) {
    if (ssm) {
        struct group_source_req req = {.gsr_interface = interface};
        struct sockaddr_in6 g = {.sin6_family = AF_INET6, .sin6_addr = group}, s = remote(0);
        memcpy(&req.gsr_group, &g, sizeof(g));
        memcpy(&req.gsr_source, &s, sizeof(s));
        CHECK(setsockopt(fd, IPPROTO_IPV6, join ? MCAST_JOIN_SOURCE_GROUP : MCAST_LEAVE_SOURCE_GROUP, &req,
                         sizeof(req)) == 0);
    } else {
        struct ipv6_mreq req = {.ipv6mr_multiaddr = group, .ipv6mr_interface = interface};
        CHECK(setsockopt(fd, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &req, sizeof(req)) ==
              0);
    }
}
static void multicast(int server, int ssm) {
    struct in6_addr group;
    CHECK(inet_pton(AF_INET6, ssm ? "ff3e::114" : "ff02::114", &group) == 1);
    if (server) {
        int a = open_udp(port, 1), b = open_udp(port, 1);
        int fds[] = {a, b};
        for (int i = 0; i < 2; i++) {
            set(fds[i], IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0);
            membership(fds[i], group, ssm, 1);
        }
        puts("READY");
        fflush(stdout);
        struct sockaddr_in6 peer;
        receive(a, &peer, 33, 0);
        receive(b, &peer, 33, 0);
        membership(a, group, ssm, 0);
        CHECK(close(a) == 0);
        membership(b, group, ssm, 0);
        membership(b, group, ssm, 1);
        transmit(b, peer, 33, 0);
        receive(b, &peer, 257, 1);
        transmit(b, peer, 257, 1);
        empty(b);
        membership(b, group, ssm, 0);
        CHECK(close(b) == 0);
    } else {
        int fd = open_udp(0, 0);
        set(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (int)interface);
        set(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 7);
        set(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1);
        struct sockaddr_in6 destination = {.sin6_family = AF_INET6,
                                           .sin6_addr = group,
                                           .sin6_port = htons(port),
                                           .sin6_scope_id = interface},
                            peer;
        for (unsigned n = 0; n < 2; n++) {
            transmit(fd, destination, n ? 257 : 33, n);
            receive(fd, &peer, n ? 257 : 33, n);
        }
        empty(fd);
        CHECK(close(fd) == 0);
    }
}
int main(int argc, char **argv) {
    CHECK(argc == 7);
    int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    CHECK(inet_pton(AF_INET6, argv[2], &local_address) == 1 &&
          inet_pton(AF_INET6, argv[3], &peer_address) == 1);
    port = atoi(argv[4]);
    CHECK(port > 0 && port < 65400);
    int query = open_udp(0, 0);
    interface = find_interface(query, argv[6]);
    CHECK(close(query) == 0);
    if (!strcmp(argv[5], "ancillary"))
        ancillary(server);
    else if (!strcmp(argv[5], "errors"))
        errors(server);
    else if (!strcmp(argv[5], "fragments"))
        fragments(server);
    else if (!strcmp(argv[5], "segmentation"))
        segmentation(server);
    else if (!strcmp(argv[5], "multicast"))
        multicast(server, 0);
    else if (!strcmp(argv[5], "ssm"))
        multicast(server, 1);
    else
        CHECK(0);
    printf("PASS: IPv6 UDP %s %s\n", argv[1], argv[5]);
    return 0;
}
