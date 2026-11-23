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

static int lowwater(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static int64_t milliseconds(void)
{
    struct timespec value; CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static void queued(int fd, int wanted)
{
    int64_t deadline = milliseconds() + 5000;
    for (;;) {
        int count = -1; CHECK(ioctl(fd, FIONREAD, &count) == 0);
        if (count == wanted) return;
        CHECK(count >= 0 && count < wanted && milliseconds() < deadline);
        CHECK(poll(NULL, 0, 1) == 0);
    }
}
static void suppressed(int fd, int ep)
{
    struct pollfd target = {.fd = fd, .events = POLLIN | POLLRDHUP};
    CHECK(poll(&target, 1, 0) == 0);
    struct epoll_event event; CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    CHECK(fd < FD_SETSIZE); fd_set readers; FD_ZERO(&readers); FD_SET(fd, &readers);
    struct timeval zero = {0}; CHECK(select(fd + 1, &readers, NULL, NULL, &zero) == 0);
}
static void readable(int fd, int ep, int fin)
{
    struct pollfd target = {.fd = fd, .events = POLLIN | POLLRDHUP};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN) && event.data.u64 == TAG);
    if (fin) CHECK((target.revents & POLLRDHUP) && (event.events & EPOLLRDHUP));
    fd_set readers; FD_ZERO(&readers); FD_SET(fd, &readers); struct timeval zero = {0};
    CHECK(select(fd + 1, &readers, NULL, NULL, &zero) == 1 && FD_ISSET(fd, &readers));
}
static void exchange(int fd, int alias, int ep, int control, int sending, int direction)
{
    for (int phase = 0; phase < 4; ++phase) {
        unsigned char expected[64];
        size_t payload = phase == 2 ? sizeof(expected) : 17;
        for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(direction * 109 + phase * 71 + i * 31);
        if (sending) {
            marker(control, 'R', 0); transfer(fd, expected, 17, 1);
            marker(control, 'S', 1);
            if (phase == 2) {
                marker(control, 'T', 0); transfer(fd, expected + 17, payload - 17, 1);
                marker(control, 'Q', 1);
            }
            if (phase == 3) {
                marker(control, 'F', 0); CHECK(shutdown(alias, SHUT_WR) == 0); marker(control, 'C', 1);
            }
            marker(control, 'A', 0);
        } else {
            int value = 64; CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVLOWAT, &value, sizeof(value)) == 0);
            CHECK(lowwater(fd) == 64 && lowwater(alias) == 64);
            marker(control, 'R', 1); marker(control, 'S', 0);
            queued(fd, 17); suppressed(alias, ep);
            unsigned char actual[96]; memset(actual, 0xa5, sizeof(actual));
            if (!phase) {
                /* O_NONBLOCK stays clear; the per-call flag bypasses the low-water wait. */
                CHECK(recv(alias, actual, sizeof(actual), MSG_PEEK | MSG_DONTWAIT) == (ssize_t)payload);
                CHECK(!memcmp(actual, expected, payload));
                queued(fd, 17); suppressed(alias, ep);
                CHECK(recv(alias, actual, sizeof(actual), MSG_DONTWAIT) == (ssize_t)payload);
                CHECK(lowwater(fd) == 64);
            } else if (phase == 1) {
                value = 1; CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVLOWAT, &value, sizeof(value)) == 0);
                CHECK(lowwater(fd) == 1); readable(alias, ep, 0);
                value = 64; CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &value, sizeof(value)) == 0);
                CHECK(lowwater(alias) == 64); suppressed(alias, ep);
                value = 1; CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVLOWAT, &value, sizeof(value)) == 0);
                CHECK(lowwater(fd) == 1); readable(alias, ep, 0);
                CHECK(recv(fd, actual, sizeof(actual), 0) == (ssize_t)payload);
            } else if (phase == 2) {
                marker(control, 'T', 1); marker(control, 'Q', 0);
                queued(fd, 64); CHECK(lowwater(alias) == 64); readable(alias, ep, 0);
                CHECK(recv(alias, actual, payload, MSG_WAITALL) == (ssize_t)payload);
            } else {
                marker(control, 'F', 1); marker(control, 'C', 0); readable(alias, ep, 1);
                CHECK(recv(alias, actual, sizeof(actual), MSG_WAITALL) == (ssize_t)payload);
                CHECK(lowwater(fd) == 64); eof(fd); eof(alias);
            }
            CHECK(!memcmp(actual, expected, payload));
            for (size_t i = payload; i < sizeof(actual); ++i) CHECK(actual[i] == 0xa5);
            int count = -1; CHECK(ioctl(fd, FIONREAD, &count) == 0 && count == 0);
            CHECK(!(fcntl(fd, F_GETFL) & O_NONBLOCK) && !(fcntl(alias, F_GETFL) & O_NONBLOCK));
            if (phase != 3) suppressed(alias, ep);
            marker(control, 'A', 1);
        }
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 4); int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr address_value; CHECK(inet_pton(AF_INET, argv[2], &address_value) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = address_value, .sin_port = htons(port)};
    int listener = server ? listen_at(address, 0) : -1;
    struct sockaddr_in data_address = address; data_address.sin_port = htons(port + 1);
    int data_listener = server ? listen_at(data_address, 0) : -1;
    if (server) { printf("READY %ld\n", port); fflush(stdout); }
    int control = server ? accept4(listener, NULL, NULL, SOCK_CLOEXEC) : connect_to(address);
    CHECK(control >= 0); timeout(control);
    int fd = server ? accept4(data_listener, NULL, NULL, SOCK_CLOEXEC) : connect_to(data_address);
    CHECK(fd >= 0); timeout(fd);
    if (server) CHECK(close(listener) == 0 && close(data_listener) == 0);
    int alias = dup(fd), ep = epoll_create1(EPOLL_CLOEXEC); CHECK(alias >= 0 && alias < FD_SETSIZE && ep >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, alias, &event) == 0);
    CHECK(lowwater(fd) == 1 && lowwater(alias) == 1);
    exchange(fd, alias, ep, control, !server, 0); exchange(fd, alias, ep, control, server, 1);
    int value = 1; CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &value, sizeof(value)) == 0);
    CHECK(lowwater(alias) == 1);
    CHECK(close(fd) == 0 && close(alias) == 0 && close(ep) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
    printf("PASS: TCP %s low-water readiness, DONTWAIT/PEEK, threshold arrival, alias raising/lowering and FIN tail\n", argv[1]);
    return 0;
}
