/* Ker-specific IPv4 broadcast extension of the pinned F-Stack UDP example. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define SIZE 37
#define TAG UINT64_C(0xfedcba9876543210)
static void fill(unsigned char *bytes, int record, int reply)
{
    for (int i = 0; i < SIZE; ++i) bytes[i] = (unsigned char)(i * 71 + record * 29 + reply * 93);
}
static void broadcast_option(int fd, int enabled)
{
    CHECK(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(enabled)) == 0);
    int actual = -1; socklen_t length = sizeof(actual);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_BROADCAST, &actual, &length) == 0);
    CHECK(length == sizeof(actual) && actual == enabled);
}
static ssize_t transmit(int fd, struct sockaddr_in destination, int record, int reply, int api)
{
    unsigned char bytes[SIZE]; fill(bytes, record, reply);
    struct iovec vector = {bytes, sizeof(bytes)};
    struct msghdr message = {.msg_name = &destination, .msg_namelen = sizeof(destination),
        .msg_iov = &vector, .msg_iovlen = 1};
    if (api == 0) return sendto(fd, bytes, sizeof(bytes), 0, (void *)&destination, sizeof(destination));
    if (api == 1) return sendmsg(fd, &message, 0);
    struct mmsghdr batch = {.msg_hdr = message};
    int count = sendmmsg(fd, &batch, 1, 0);
    if (count < 0) return count;
    CHECK(count == 1); return batch.msg_len;
}
static struct sockaddr_in receive(int fd, int ep, struct sockaddr_in expected_peer,
    struct in_addr destination, struct in_addr local, int *interface, int record, int reply)
{
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN) && event.data.u64 == TAG);
    unsigned char bytes[SIZE], expected[SIZE]; fill(expected, record, reply);
    struct sockaddr_in source = {0}; struct iovec vector = {bytes, sizeof(bytes)};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))]; } control;
    struct msghdr message = {.msg_name = &source, .msg_namelen = sizeof(source),
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)};
    CHECK(recvmsg(fd, &message, 0) == SIZE && !memcmp(bytes, expected, SIZE));
    CHECK(!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    CHECK(message.msg_namelen == sizeof(source) && source.sin_family == AF_INET);
    CHECK(source.sin_addr.s_addr == expected_peer.sin_addr.s_addr && source.sin_port != 0);
    if (expected_peer.sin_port) CHECK(source.sin_port == expected_peer.sin_port);
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    CHECK(c && c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO &&
          c->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)) && !CMSG_NXTHDR(&message, c));
    struct in_pktinfo info; memcpy(&info, CMSG_DATA(c), sizeof(info));
    CHECK(info.ipi_addr.s_addr == destination.s_addr && info.ipi_spec_dst.s_addr == local.s_addr);
    CHECK(info.ipi_ifindex > 0);
    if (*interface) CHECK(info.ipi_ifindex == *interface);
    *interface = info.ipi_ifindex; return source;
}
int main(int argc, char **argv)
{
    CHECK(argc == 5 || (argc == 6 && !strcmp(argv[5], "limited")));
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr local, broadcast;
    CHECK(inet_pton(AF_INET, argv[2], &local) == 1);
    CHECK(inet_pton(AF_INET, argc == 6 ? "255.255.255.255" : "198.18.0.255", &broadcast) == 1);
    struct sockaddr_in peer = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[3], &peer.sin_addr) == 1);
    char *end; long port = strtol(argv[4], &end, 10); CHECK(!*end && port > 0 && port <= 65535);
    if (!server) peer.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    int enabled = 1;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof(enabled)) == 0);
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_BROADCAST, &value, &length) == 0 &&
          length == sizeof(value) && value == 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = server ? htons(port) : 0,
        .sin_addr = server ? (struct in_addr){0} : local};
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
    if (!server) {
        length = sizeof(address); CHECK(getsockname(fd, (void *)&address, &length) == 0);
        CHECK(length == sizeof(address) && address.sin_addr.s_addr == local.s_addr && address.sin_port != 0);
    }
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    if (server) { printf("READY %ld\n", port); fflush(stdout); }
    /* Same-kernel host unicast can use loopback while broadcast uses the link. */
    int interfaces[2] = {0};
    for (int record = 0; record < 4; ++record) {
        if (!server) {
            struct sockaddr_in destination = peer;
            if (record < 3) {
                destination.sin_addr = broadcast; errno = 0;
                CHECK(transmit(fd, destination, record, 0, record) == -1 && errno == EACCES);
                broadcast_option(fd, 1);
            } else {
                struct sockaddr_in rejected = peer; rejected.sin_addr = broadcast; errno = 0;
                CHECK(transmit(fd, rejected, record, 0, 0) == -1 && errno == EACCES);
            }
            CHECK(transmit(fd, destination, record, 0, record < 3 ? record : 0) == SIZE);
        }
        struct in_addr destination = server && record < 3 ? broadcast : local;
        peer = receive(fd, ep, peer, destination, local, &interfaces[server && record < 3], record, !server);
        if (server) CHECK(transmit(fd, peer, record, 1, 0) == SIZE);
        else if (record < 3) broadcast_option(fd, 0);
    }
    length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_BROADCAST, &value, &length) == 0 &&
          length == sizeof(value) && value == 0);
    unsigned char byte; errno = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(close(ep) == 0 && close(fd) == 0);
    printf("PASS: UDP %s broadcast permission, three send APIs, packet info and unicast recovery\n", argv[1]);
    return 0;
}
