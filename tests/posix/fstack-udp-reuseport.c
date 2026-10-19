/* Ker-specific UDP reuseport extension of the pinned F-Stack UDP example. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TAG UINT64_C(0xfedcba9876543210)
static void same(struct sockaddr_in actual, struct sockaddr_in expected)
{
    CHECK(actual.sin_family == AF_INET && actual.sin_addr.s_addr == expected.sin_addr.s_addr &&
          actual.sin_port == expected.sin_port);
}
static int option(int fd, int name)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, name, &value, &length) == 0 && length == sizeof(value)); return value;
}
static int open_at(struct sockaddr_in address, int reuse)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    CHECK(option(fd, SO_REUSEADDR) == 0 && option(fd, SO_REUSEPORT) == 0);
    if (reuse) CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) == 0);
    CHECK(option(fd, SO_REUSEPORT) == reuse);
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
    struct sockaddr_in actual = {0}; socklen_t length = sizeof(actual);
    CHECK(getsockname(fd, (void *)&actual, &length) == 0 && length == sizeof(actual)); same(actual, address);
    return fd;
}
static void unconnected(int fd)
{
    struct sockaddr_in address; socklen_t length = sizeof(address); errno = 0;
    CHECK(getpeername(fd, (void *)&address, &length) == -1 && errno == ENOTCONN);
}
static void add(int ep, int fd, uint64_t tag)
{
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = tag};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
}
static void transmit(int fd, const struct sockaddr_in *destination, uint32_t token)
{
    token = htonl(token);
    CHECK(sendto(fd, &token, sizeof(token), 0, (const void *)destination,
        destination ? sizeof(*destination) : 0) == sizeof(token));
}
static void receive(int fd, int ep, uint64_t tag, struct sockaddr_in peer, uint32_t token)
{
    struct pollfd target = {.fd = fd, .events = POLLIN};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN) && event.data.u64 == tag);
    struct sockaddr_in source = {0}; socklen_t length = sizeof(source); uint32_t actual;
    CHECK(recvfrom(fd, &actual, sizeof(actual), MSG_TRUNC, (void *)&source, &length) == sizeof(actual));
    CHECK(length == sizeof(source) && ntohl(actual) == token); same(source, peer);
}
static void empty(int fd)
{
    uint32_t token; errno = 0;
    CHECK(recv(fd, &token, sizeof(token), MSG_DONTWAIT) == -1 && errno == EAGAIN);
}
static void serve(struct in_addr local, struct in_addr remote, unsigned short port)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = local, .sin_port = htons(port)};
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port + 1)};
    struct sockaddr_in b = a; b.sin_port = htons(port + 2);
    int connected = open_at(address, 1), fallback = open_at(address, 1);
    int outsider = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(outsider >= 0);
    CHECK(option(outsider, SO_REUSEADDR) == 0 && option(outsider, SO_REUSEPORT) == 0);
    errno = 0; CHECK(bind(outsider, (void *)&address, sizeof(address)) == -1 && errno == EADDRINUSE);
    CHECK(close(outsider) == 0);
    CHECK(connect(connected, (void *)&a, sizeof(a)) == 0);
    struct sockaddr_in actual = {0}; socklen_t length = sizeof(actual);
    CHECK(getpeername(connected, (void *)&actual, &length) == 0 && length == sizeof(actual)); same(actual, a);
    unconnected(fallback);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    add(ep, connected, TAG); add(ep, fallback, TAG + 1);
    printf("READY %u\n", port); fflush(stdout);
    receive(connected, ep, TAG, a, 1); empty(fallback); transmit(connected, NULL, 11);
    receive(fallback, ep, TAG + 1, b, 2); empty(connected);
    /* The reply is the barrier: A cannot send its next request before retirement. */
    CHECK(close(connected) == 0);
    struct epoll_event event; CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    transmit(fallback, &b, 12);
    receive(fallback, ep, TAG + 1, a, 3); transmit(fallback, &a, 13);
    receive(fallback, ep, TAG + 1, b, 4); transmit(fallback, &b, 14);
    unconnected(fallback); empty(fallback);
    CHECK(option(fallback, SO_REUSEPORT) == 1 && option(fallback, SO_REUSEADDR) == 0);
    CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    CHECK(close(fallback) == 0 && close(ep) == 0);
}
static void exchange(int fd, int ep, uint64_t tag, struct sockaddr_in peer, uint32_t token)
{
    transmit(fd, &peer, token); receive(fd, ep, tag, peer, token + 10); empty(fd);
}
static void connect_sources(struct in_addr local, struct in_addr remote, unsigned short port)
{
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port)};
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = local, .sin_port = htons(port + 1)};
    struct sockaddr_in b = a; b.sin_port = htons(port + 2);
    int first = open_at(a, 0), second = open_at(b, 0);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    add(ep, first, TAG); add(ep, second, TAG + 1);
    exchange(first, ep, TAG, peer, 1); exchange(second, ep, TAG + 1, peer, 2);
    exchange(first, ep, TAG, peer, 3); exchange(second, ep, TAG + 1, peer, 4);
    unconnected(first); unconnected(second);
    CHECK(close(first) == 0 && close(second) == 0 && close(ep) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr local, remote;
    CHECK(inet_pton(AF_INET, argv[2], &local) == 1 && inet_pton(AF_INET, argv[3], &remote) == 1);
    char *end; long port = strtol(argv[4], &end, 10); CHECK(!*end && port > 0 && port < 65534);
    if (server) serve(local, remote, port); else connect_sources(local, remote, port);
    printf("PASS: UDP %s reuseport bind, connected source selection and member retirement\n", argv[1]);
    return 0;
}
