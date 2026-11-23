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

static struct linger linger_value(int fd)
{
    struct linger value = {-1, -1}; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_LINGER, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static int socket_error(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void scenario(int fd, int control, int closer, int mode, int direction)
{
    int alias = dup(fd); CHECK(alias >= 0);
    unsigned char expected[17];
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(mode * 71 + direction * 109 + i * 31);
    if (closer) {
        CHECK(linger_value(fd).l_onoff == 0);
        struct linger value = {1, 0};
        CHECK(setsockopt(fd, SOL_SOCKET, SO_LINGER, &value, sizeof(value)) == 0);
        CHECK(linger_value(alias).l_onoff == 1 && linger_value(alias).l_linger == 0);
        if (!mode) {
            value.l_onoff = 0;
            CHECK(setsockopt(alias, SOL_SOCKET, SO_LINGER, &value, sizeof(value)) == 0);
            CHECK(linger_value(fd).l_onoff == 0);
        }
        marker(fd, 'H', 1); CHECK(close(fd) == 0);
        marker(control, 'C', 1); marker(control, 'A', 0);
        transfer(alias, expected, sizeof(expected), 1); marker(control, 'B', 0);
        CHECK(close(alias) == 0); marker(control, 'F', 1); marker(control, 'D', 0);
    } else {
        int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
        struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.u64 = TAG};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
        marker(fd, 'H', 0); marker(control, 'C', 0);
        /* Closing the original descriptor must not close a still-referenced socket. */
        struct pollfd target = {.fd = fd, .events = POLLIN | POLLRDHUP};
        CHECK(poll(&target, 1, 100) == 0 && epoll_wait(ep, &event, 1, 0) == 0);
        unsigned char byte; errno = 0;
        CHECK(recv(alias, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
        CHECK(socket_error(fd) == 0); marker(control, 'A', 1);
        unsigned char actual[17]; transfer(fd, actual, sizeof(actual), 0);
        CHECK(!memcmp(actual, expected, sizeof(actual))); marker(control, 'B', 1);
        marker(control, 'F', 0);
        CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN) && (target.revents & POLLRDHUP));
        CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && event.data.u64 == TAG &&
              (event.events & EPOLLIN) && (event.events & EPOLLRDHUP));
        if (mode) CHECK((target.revents & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP) &&
                        (event.events & (EPOLLERR | EPOLLHUP)) == (EPOLLERR | EPOLLHUP));
        if (mode == 1) {
            errno = 0; CHECK(recv(alias, &byte, 1, 0) == -1 && errno == ECONNRESET);
        } else if (mode == 2) CHECK(socket_error(alias) == ECONNRESET);
        else CHECK(socket_error(fd) == 0);
        CHECK(socket_error(fd) == 0 && socket_error(alias) == 0);
        eof(fd); eof(alias);
        CHECK(close(fd) == 0 && close(alias) == 0 && close(ep) == 0); marker(control, 'D', 1);
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 4); int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr remote; CHECK(inet_pton(AF_INET, argv[2], &remote) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port)};
    int listener = server ? listen_at(address, 0) : -1;
    struct sockaddr_in data_address = address; data_address.sin_port = htons(port + 1);
    int data_listener = server ? listen_at(data_address, 0) : -1;
    if (server) { printf("READY %ld\n", port); fflush(stdout); }
    int control = server ? accept4(listener, NULL, NULL, SOCK_CLOEXEC) : connect_to(address);
    CHECK(control >= 0); timeout(control); if (server) CHECK(close(listener) == 0);
    for (int mode = 0; mode < 3; ++mode) for (int direction = 0; direction < 2; ++direction) {
        int fd = server ? accept4(data_listener, NULL, NULL, SOCK_CLOEXEC) : connect_to(data_address);
        CHECK(fd >= 0); timeout(fd);
        scenario(fd, control, server == direction, mode, direction);
    }
    if (server) CHECK(close(data_listener) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
    printf("PASS: TCP %s shared SO_LINGER, last-alias close, graceful EOF and reset error consumers\n", argv[1]);
    return 0;
}
