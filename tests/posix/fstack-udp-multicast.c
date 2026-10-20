/* Linux-specific multicast extension of the pinned F-Stack UDP example. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static const size_t lengths[] = {33, 257};
static void fill(unsigned char *bytes, int record)
{
    for (size_t i = 0; i < lengths[record]; ++i) bytes[i] = (unsigned char)(i * 71 + record * 29);
}
static void option(int fd, int name, int value)
{
    CHECK(setsockopt(fd, IPPROTO_IP, name, &value, sizeof(value)) == 0);
    int actual = -1; socklen_t length = sizeof(actual);
    CHECK(getsockopt(fd, IPPROTO_IP, name, &actual, &length) == 0);
    CHECK(length == sizeof(actual) && actual == value);
}
static int create(int ep, struct in_addr local, unsigned short port, int receiver)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    int enabled = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port),
        .sin_addr = receiver ? (struct in_addr){0} : local};
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
    struct epoll_event event = {.events = EPOLLIN, .data.fd = fd};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    return fd;
}
static void ready(int ep, int fd)
{
    /* Fanout sockets may wake in either order. Wait for this descriptor
     * before collecting the level-triggered epoll set (at most two fds). */
    struct pollfd target = {.fd = fd, .events = POLLIN};
    int count;
    do { count = poll(&target, 1, 5000); } while (count < 0 && errno == EINTR);
    CHECK(count == 1 && (target.revents & POLLIN));
    struct epoll_event events[2];
    do { count = epoll_wait(ep, events, 2, 5000); } while (count < 0 && errno == EINTR);
    CHECK(count > 0);
    for (int i = 0; i < count; ++i)
        if (events[i].data.fd == fd) { CHECK(events[i].events & EPOLLIN); return; }
    CHECK(0);
}
static void receive(int fd, int ep, struct sockaddr_in *peer, struct in_addr local,
    struct in_addr group, int record, int multicast)
{
    ready(ep, fd);
    unsigned char bytes[257], expected[257]; fill(expected, record);
    struct sockaddr_in source = {0};
    struct iovec vector = {bytes, sizeof(bytes)};
    union { struct cmsghdr align; unsigned char bytes[256]; } control;
    struct msghdr message = {.msg_name = &source, .msg_namelen = sizeof(source),
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)};
    CHECK(recvmsg(fd, &message, 0) == (ssize_t)lengths[record]);
    CHECK(!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) && !memcmp(bytes, expected, lengths[record]));
    CHECK(message.msg_namelen == sizeof(source) && source.sin_family == AF_INET);
    CHECK(source.sin_addr.s_addr == peer->sin_addr.s_addr && source.sin_port != 0);
    if (peer->sin_port) CHECK(source.sin_port == peer->sin_port);
    *peer = source;
    if (!multicast) return;
    int found_info = 0, found_ttl = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            CHECK(c->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)));
            struct in_pktinfo info; memcpy(&info, CMSG_DATA(c), sizeof(info));
            CHECK(info.ipi_ifindex > 0 && info.ipi_addr.s_addr == group.s_addr);
            CHECK(info.ipi_spec_dst.s_addr == local.s_addr); ++found_info;
        } else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL) {
            CHECK(c->cmsg_len == CMSG_LEN(sizeof(int)));
            int ttl; memcpy(&ttl, CMSG_DATA(c), sizeof(ttl));
            CHECK(ttl == 7); ++found_ttl;
        } else CHECK(0);
    }
    CHECK(found_info == 1 && found_ttl == 1);
}
static void transmit(int fd, struct sockaddr_in peer, int record)
{
    unsigned char bytes[257]; fill(bytes, record);
    ssize_t count;
    do { count = sendto(fd, bytes, lengths[record], 0, (void *)&peer, sizeof(peer)); }
    while (count < 0 && errno == EINTR);
    CHECK(count == (ssize_t)lengths[record]);
}
static void member(int fd, struct ip_mreq membership, struct in_addr source, int ssm, int join)
{
    if (ssm) {
        struct ip_mreq_source request = {.imr_multiaddr = membership.imr_multiaddr,
            .imr_interface = membership.imr_interface, .imr_sourceaddr = source};
        CHECK(setsockopt(fd, IPPROTO_IP, join ? IP_ADD_SOURCE_MEMBERSHIP : IP_DROP_SOURCE_MEMBERSHIP,
            &request, sizeof(request)) == 0);
    } else CHECK(setsockopt(fd, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP,
        &membership, sizeof(membership)) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5 || (argc == 6 && !strcmp(argv[5], "ssm")));
    int ssm = argc == 6;
    int receiver = !strcmp(argv[1], "server");
    CHECK(receiver || !strcmp(argv[1], "client"));
    struct in_addr local, group;
    struct sockaddr_in peer = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &local) == 1);
    CHECK(inet_pton(AF_INET, argv[3], &peer.sin_addr) == 1);
    CHECK(inet_pton(AF_INET, "239.255.42.17", &group) == 1);
    char *end; long port = strtol(argv[4], &end, 10);
    CHECK(!*end && port > 0 && port <= 65535);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    if (receiver) {
        int fds[2];
        struct ip_mreq membership = {.imr_multiaddr = group, .imr_interface = local};
        for (int i = 0; i < 2; ++i) {
            fds[i] = create(ep, local, port, 1);
            option(fds[i], IP_MULTICAST_ALL, 0);
            option(fds[i], IP_PKTINFO, 1);
            option(fds[i], IP_RECVTTL, 1);
            member(fds[i], membership, peer.sin_addr, ssm, 1);
            errno = 0;
            if (!ssm) CHECK(setsockopt(fds[i], IPPROTO_IP, IP_ADD_MEMBERSHIP, &membership, sizeof(membership)) == -1 && errno == EADDRINUSE);
        }
        printf("READY %ld\n", port); fflush(stdout);
        receive(fds[0], ep, &peer, local, group, 0, 1);
        receive(fds[1], ep, &peer, local, group, 0, 1);
        member(fds[0], membership, peer.sin_addr, ssm, 0);
        CHECK(close(fds[0]) == 0);
        member(fds[1], membership, peer.sin_addr, ssm, 0);
        errno = 0;
        if (!ssm) CHECK(setsockopt(fds[1], IPPROTO_IP, IP_DROP_MEMBERSHIP, &membership, sizeof(membership)) == -1 && errno == EADDRNOTAVAIL);
        member(fds[1], membership, peer.sin_addr, ssm, 1);
        /* Ack only after rejoin: the sender cannot race the next packet. */
        transmit(fds[1], peer, 0);
        receive(fds[1], ep, &peer, local, group, 1, 1);
        transmit(fds[1], peer, 1);
        member(fds[1], membership, peer.sin_addr, ssm, 0);
        CHECK(close(fds[1]) == 0);
    } else {
        int fd = create(ep, local, 0, 0);
        CHECK(setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &local, sizeof(local)) == 0);
        struct in_addr actual = {0}; socklen_t length = sizeof(actual);
        CHECK(getsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &actual, &length) == 0);
        CHECK(length == sizeof(actual) && actual.s_addr == local.s_addr);
        option(fd, IP_MULTICAST_TTL, 7);
        option(fd, IP_MULTICAST_LOOP, 1);
        peer.sin_port = htons(port);
        struct sockaddr_in destination = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = group};
        for (int record = 0; record < 2; ++record) {
            transmit(fd, destination, record);
            receive(fd, ep, &peer, local, group, record, 0);
        }
        unsigned char byte; errno = 0;
        CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
        CHECK(close(fd) == 0);
    }
    CHECK(close(ep) == 0);
    printf("PASS: UDP multicast %s membership, fanout, interface, TTL and rejoin\n", argv[1]);
    return 0;
}
