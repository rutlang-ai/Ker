/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TAG UINT64_C(0xfedcba9876543210)
static void transfer(int fd, void *data, size_t length, int sending)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = sending ? send(fd, (char *)data + done, length - done, MSG_NOSIGNAL) :
                                 recv(fd, (char *)data + done, length - done, 0);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0); done += (size_t)count;
    }
}
static void marker(int fd, char expected, int sending)
{
    char byte = expected; transfer(fd, &byte, 1, sending); CHECK(byte == expected);
}
static void eof(int fd)
{
    char byte; CHECK(recv(fd, &byte, 1, 0) == 0);
}
static void timeout(int fd)
{
    struct timeval value = {.tv_sec = 5};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value)) == 0);
}
static int listen_at(struct sockaddr_in address, int nonblock)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), 0);
    int value = 1; CHECK(fd >= 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == 0);
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 4) == 0);
    timeout(fd); return fd;
}
static int connect_to(struct sockaddr_in address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0); timeout(fd);
    CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    struct sockaddr_in peer = {0}; socklen_t length = sizeof(peer);
    CHECK(getpeername(fd, (void *)&peer, &length) == 0 && length == sizeof(peer));
    CHECK(peer.sin_family == AF_INET && peer.sin_addr.s_addr == address.sin_addr.s_addr &&
          peer.sin_port == address.sin_port);
    int error = -1; length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
    return fd;
}
static int cork(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_UDP, UDP_CORK, &value, &length) == 0 && length == sizeof(value)); return value;
}
static int udp_at(struct sockaddr_in local, struct sockaddr_in peer)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    CHECK(bind(fd, (void *)&local, sizeof(local)) == 0 && connect(fd, (void *)&peer, sizeof(peer)) == 0);
    struct sockaddr_in actual = {0}; socklen_t length = sizeof(actual);
    CHECK(getsockname(fd, (void *)&actual, &length) == 0 && length == sizeof(actual));
    CHECK(actual.sin_addr.s_addr == local.sin_addr.s_addr && actual.sin_port == local.sin_port);
    CHECK(cork(fd) == 0); return fd;
}
static int watch(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0); return ep;
}
static void empty(int fd, int ep)
{
    unsigned char byte; errno = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    int available = -1; CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == 0);
    struct epoll_event event; CHECK(epoll_wait(ep, &event, 1, 0) == 0);
}
static void receive_packet(int fd, int ep, struct sockaddr_in peer, const unsigned char *expected, size_t length)
{
    struct pollfd target = {.fd = fd, .events = POLLIN};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN) && event.data.u64 == TAG);
    int available = -1; CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == (int)length);
    unsigned char bytes[95]; struct sockaddr_in source = {0}; socklen_t size = sizeof(source);
    CHECK(recvfrom(fd, bytes, sizeof(bytes), MSG_TRUNC, (void *)&source, &size) == (ssize_t)length);
    CHECK(size == sizeof(source) && source.sin_family == AF_INET && source.sin_addr.s_addr == peer.sin_addr.s_addr &&
          source.sin_port == peer.sin_port && !memcmp(bytes, expected, length));
    empty(fd, ep);
}
static void payload(unsigned char bytes[95], int mode, int server)
{
    for (size_t i = 0; i < 95; ++i) bytes[i] = (unsigned char)(mode * 79 + server * 103 + i * 37);
}
static void send_corked(int fd, int alias, int control, int mode, int server)
{
    unsigned char bytes[95]; payload(bytes, mode, server); marker(control, 'R', 0);
    struct iovec vector = {bytes, 17}; struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    if (!mode) {
        CHECK(sendmsg(fd, &message, MSG_MORE) == 17);
        CHECK(sendto(alias, bytes + 17, 31, MSG_MORE, NULL, 0) == 31);
        CHECK(cork(fd) == 0 && cork(alias) == 0); /* MSG_MORE is per-call, not UDP_CORK. */
    } else {
        int enabled = 1; CHECK(setsockopt(alias, IPPROTO_UDP, UDP_CORK, &enabled, sizeof(enabled)) == 0);
        CHECK(cork(fd) == 1 && cork(alias) == 1);
        CHECK(send(fd, bytes, 17, 0) == 17);
        struct iovec parts[2] = {{bytes + 17, 11}, {bytes + 28, 20}};
        CHECK(writev(alias, parts, 2) == 31);
        vector = (struct iovec){bytes + 48, 47};
        CHECK(sendmsg(fd, &message, 0) == 47);
    }
    marker(control, 'P', 1); marker(control, 'C', 0);
    if (!mode) CHECK(send(alias, bytes + 48, 47, 0) == 47);
    else {
        int enabled = 0; CHECK(setsockopt(alias, IPPROTO_UDP, UDP_CORK, &enabled, sizeof(enabled)) == 0);
    }
    CHECK(cork(fd) == 0 && cork(alias) == 0); marker(control, 'A', 0);
    /* A later ordinary send must be a separate datagram after the flush. */
    CHECK(send(fd, bytes, 5, 0) == 5); marker(control, 'B', 0);
}
static void receive_corked(int fd, int ep, int control, struct sockaddr_in peer, int mode, int peer_server)
{
    unsigned char bytes[95]; payload(bytes, mode, peer_server);
    empty(fd, ep); marker(control, 'R', 1); marker(control, 'P', 0);
    empty(fd, ep); marker(control, 'C', 1);
    receive_packet(fd, ep, peer, bytes, sizeof(bytes)); marker(control, 'A', 1);
    receive_packet(fd, ep, peer, bytes, 5); marker(control, 'B', 1);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr local, remote;
    CHECK(inet_pton(AF_INET, argv[2], &local) == 1 && inet_pton(AF_INET, argv[3], &remote) == 1);
    char *end; long port = strtol(argv[4], &end, 10); CHECK(!*end && port > 0 && port < 65534);
    struct sockaddr_in control_address = {.sin_family = AF_INET, .sin_addr = server ? local : remote,
        .sin_port = htons(port)};
    int listener = server ? listen_at(control_address, 0) : -1;
    int control = server ? -1 : connect_to(control_address);
    struct sockaddr_in own = {.sin_family = AF_INET, .sin_addr = local, .sin_port = htons(port + (server ? 1 : 2))};
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port + (server ? 2 : 1))};
    int fd = udp_at(own, peer), alias = dup(fd), ep = watch(fd); CHECK(alias >= 0);
    if (server) {
        printf("READY %ld\n", port); fflush(stdout);
        control = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0); timeout(control);
        CHECK(close(listener) == 0);
    }
    for (int mode = 0; mode < 2; ++mode) {
        if (server) {
            receive_corked(fd, ep, control, peer, mode, 0); send_corked(fd, alias, control, mode, 1);
        } else {
            send_corked(fd, alias, control, mode, 0); receive_corked(fd, ep, control, peer, mode, 1);
        }
    }
    CHECK(cork(fd) == 0); empty(fd, ep);
    CHECK(close(alias) == 0 && close(fd) == 0 && close(ep) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
    printf("PASS: UDP %s bidirectional MSG_MORE/UDP_CORK coalescing, alias uncork and plain recovery\n", argv[1]);
    return 0;
}
