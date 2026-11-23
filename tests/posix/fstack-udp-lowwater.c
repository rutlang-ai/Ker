/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
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
#include <sys/select.h>
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

static void empty(int fd, int ep)
{
    unsigned char byte; errno = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    struct epoll_event event; CHECK(epoll_wait(ep, &event, 1, 0) == 0);
}
static int lowwater(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void exchange(int fd, int alias, int ep, int control, struct sockaddr_in peer, int sending, int mode)
{
    const size_t lengths[] = {0, 17, 33};
    for (size_t round = 0; round < 3; ++round) {
        unsigned char expected[33];
        for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(mode * 97 + round * 71 + i * 29);
        if (sending) {
            marker(control, 'R', 0);
            CHECK(send(fd, expected, lengths[round], 0) == (ssize_t)lengths[round]);
            /* Do not supply another datagram to satisfy a broken WAITALL implementation. */
            marker(control, 'A', 0);
        } else {
            empty(fd, ep); marker(control, 'R', 1);
            struct pollfd target = {.fd = alias, .events = POLLIN};
            CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
            struct epoll_event event;
            CHECK(epoll_wait(ep, &event, 1, 0) == 1 && (event.events & EPOLLIN) && event.data.u64 == TAG);
            CHECK(alias < FD_SETSIZE); fd_set readers; FD_ZERO(&readers); FD_SET(alias, &readers);
            struct timeval zero = {0}; CHECK(select(alias + 1, &readers, NULL, NULL, &zero) == 1 && FD_ISSET(alias, &readers));
            int available = -1;
            CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == (int)lengths[round]);
            unsigned char bytes[64]; memset(bytes, 0xa5, sizeof(bytes));
            struct iovec vectors[2] = {{bytes, 5}, {bytes + 5, sizeof(bytes) - 5}};
            struct sockaddr_in source = {0};
            struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2,
                .msg_name = &source, .msg_namelen = sizeof(source)};
            struct timespec start, finish; CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
            CHECK(recvmsg(alias, &message, MSG_WAITALL) == (ssize_t)lengths[round]);
            CHECK(clock_gettime(CLOCK_MONOTONIC, &finish) == 0);
            double elapsed = finish.tv_sec - start.tv_sec + (finish.tv_nsec - start.tv_nsec) / 1e9;
            CHECK(elapsed < 4.0); /* Below the five-second SO_RCVTIMEO. */
            CHECK(message.msg_flags == 0 && message.msg_namelen == sizeof(source));
            CHECK(source.sin_family == AF_INET && source.sin_addr.s_addr == peer.sin_addr.s_addr && source.sin_port == peer.sin_port);
            CHECK(!memcmp(bytes, expected, lengths[round]));
            for (size_t i = lengths[round]; i < sizeof(bytes); ++i) CHECK(bytes[i] == 0xa5);
            CHECK(lowwater(fd) == (mode ? 4096 : 1) && lowwater(alias) == lowwater(fd));
            CHECK(!(fcntl(alias, F_GETFL) & O_NONBLOCK)); empty(fd, ep);
            marker(control, 'A', 1);
        }
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 5); int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr local, remote;
    CHECK(inet_pton(AF_INET, argv[2], &local) == 1 && inet_pton(AF_INET, argv[3], &remote) == 1);
    char *end; long port = strtol(argv[4], &end, 10); CHECK(!*end && port > 0 && port < 65534);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = server ? local : remote, .sin_port = htons(port)};
    int listener = server ? listen_at(address, 0) : -1;
    int control = server ? -1 : connect_to(address);
    struct sockaddr_in own = {.sin_family = AF_INET, .sin_addr = local, .sin_port = htons(port + (server ? 1 : 2))};
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port + (server ? 2 : 1))};
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0); timeout(fd);
    CHECK(bind(fd, (void *)&own, sizeof(own)) == 0 && connect(fd, (void *)&peer, sizeof(peer)) == 0);
    struct sockaddr_in actual; socklen_t length = sizeof(actual);
    CHECK(getsockname(fd, (void *)&actual, &length) == 0 && length == sizeof(actual));
    CHECK(actual.sin_addr.s_addr == own.sin_addr.s_addr && actual.sin_port == own.sin_port);
    if (server) {
        printf("READY %ld\n", port); fflush(stdout);
        control = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0); timeout(control); CHECK(close(listener) == 0);
    }
    int alias = dup(fd), ep = epoll_create1(EPOLL_CLOEXEC); CHECK(alias >= 0 && ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, alias, &event) == 0);
    CHECK(lowwater(fd) == 1 && lowwater(alias) == 1);
    for (int mode = 0; mode < 2; ++mode) {
        int value = mode ? 4096 : 1;
        CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVLOWAT, &value, sizeof(value)) == 0);
        CHECK(lowwater(fd) == value && lowwater(alias) == value);
        exchange(fd, alias, ep, control, peer, !server, mode);
        exchange(fd, alias, ep, control, peer, server, mode);
    }
    int value = 1; CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &value, sizeof(value)) == 0);
    CHECK(lowwater(alias) == 1); empty(fd, ep);
    CHECK(close(alias) == 0 && close(fd) == 0 && close(ep) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
    printf("PASS: UDP %s SO_RCVLOWAT readiness, empty datagram and MSG_WAITALL boundaries\n", argv[1]);
    return 0;
}
