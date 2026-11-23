/* Linux connect/reconnect extension of pinned F-Stack fd/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
static int socket_error(int fd)
{
    int error = -1; socklen_t length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    CHECK(length == sizeof(error)); return error;
}
static void peer_matches(int fd, struct sockaddr_in expected)
{
    struct sockaddr_in actual = {0}; socklen_t length = sizeof(actual);
    CHECK(getpeername(fd, (void *)&actual, &length) == 0 && length == sizeof(actual));
    CHECK(actual.sin_family == AF_INET && actual.sin_port == expected.sin_port);
    CHECK(actual.sin_addr.s_addr == expected.sin_addr.s_addr);
}
static void disconnected(int fd)
{
    struct sockaddr_in address; socklen_t length = sizeof(address); errno = 0;
    CHECK(getpeername(fd, (void *)&address, &length) == -1 && errno == ENOTCONN);
}
static void reset_connection(int fd)
{
    struct sockaddr address = {.sa_family = AF_UNSPEC};
    CHECK(connect(fd, &address, sizeof(address)) == 0);
    disconnected(fd);
    int flags = fcntl(fd, F_GETFL); CHECK(flags >= 0 && (flags & O_NONBLOCK));
}
static void ready(int fd, int ep, unsigned int wanted)
{
    struct pollfd target = {.fd = fd, .events = wanted == EPOLLIN ? POLLIN : POLLOUT};
    int count;
    do { count = poll(&target, 1, 5000); } while (count < 0 && errno == EINTR);
    CHECK(count == 1 && (target.revents & target.events));
    struct epoll_event event;
    do { count = epoll_wait(ep, &event, 1, 5000); } while (count < 0 && errno == EINTR);
    CHECK(count == 1 && event.data.u64 == TAG && (event.events & wanted));
}
static void connect_to(int fd, int ep, struct sockaddr_in peer)
{
    int result = connect(fd, (void *)&peer, sizeof(peer));
    CHECK(result == 0 || (result == -1 && errno == EINPROGRESS));
    ready(fd, ep, EPOLLOUT);
    CHECK(socket_error(fd) == 0); peer_matches(fd, peer);
}
static void exchange(int fd, int ep, const char *token)
{
    size_t sent = 0, received = 0; char bytes[4];
    while (sent < 4) {
        ready(fd, ep, EPOLLOUT);
        ssize_t count = send(fd, token + sent, 4 - sent, MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        CHECK(count > 0); sent += (size_t)count;
    }
    while (received < 4) {
        ready(fd, ep, EPOLLIN);
        ssize_t count = recv(fd, bytes + received, 4 - received, 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        CHECK(count > 0); received += (size_t)count;
    }
    CHECK(!memcmp(bytes, token, 4));
}
static int listen_at(struct sockaddr_in address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), enabled = 1;
    CHECK(fd >= 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0);
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 4) == 0);
    return fd;
}
static void serve(struct sockaddr_in address, unsigned short port)
{
    int listeners[2];
    for (int i = 0; i < 2; ++i) {
        address.sin_port = htons(port + i); listeners[i] = listen_at(address);
    }
    printf("READY %u\n", port); fflush(stdout);
    for (int i = 0; i < 2; ++i) {
        int fd = accept4(listeners[i], NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0);
        CHECK(close(listeners[i]) == 0);
        struct timeval timeout = {.tv_sec = 5};
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        const char *token = i ? "two2" : "one1"; char bytes[4];
        CHECK(recv(fd, bytes, sizeof(bytes), MSG_WAITALL) == 4 && !memcmp(bytes, token, 4));
        CHECK(send(fd, bytes, sizeof(bytes), MSG_NOSIGNAL) == 4);
        char byte;
        if (!i) {
            errno = 0; CHECK(recv(fd, &byte, 1, 0) == -1 && errno == ECONNRESET);
        } else {
            CHECK(shutdown(fd, SHUT_WR) == 0);
            CHECK(recv(fd, &byte, 1, 0) == 0);
        }
        CHECK(close(fd) == 0);
    }
}
static void connect_lifecycle(struct sockaddr_in address, unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    int alias = dup(fd), ep = epoll_create1(EPOLL_CLOEXEC); CHECK(alias >= 0 && ep >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    address.sin_port = htons(port + 2); errno = 0;
    CHECK(connect(fd, (void *)&address, sizeof(address)) == -1 && errno == EINPROGRESS);
    struct pollfd target = {.fd = alias, .events = POLLOUT};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLERR));
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLERR) && event.data.u64 == TAG);
    CHECK(socket_error(alias) == ECONNREFUSED && socket_error(fd) == 0);
    disconnected(fd);
    int count = epoll_wait(ep, &event, 1, 0);
    CHECK(count == 0 || (count == 1 && !(event.events & EPOLLERR) && event.data.u64 == TAG));
    reset_connection(alias); disconnected(fd);
    address.sin_port = htons(port);
    connect_to(alias, ep, address); peer_matches(fd, address);
    exchange(fd, ep, "one1");
    reset_connection(alias); disconnected(fd);
    int error = socket_error(fd); CHECK(error == 0 || error == ECONNRESET);
    CHECK(socket_error(alias) == 0);
    address.sin_port = htons(port + 1);
    connect_to(alias, ep, address); peer_matches(fd, address);
    /* The registration remains on the original file while its alias is alive. */
    CHECK(close(fd) == 0);
    exchange(alias, ep, "two2");
    ready(alias, ep, EPOLLIN);
    char byte; CHECK(recv(alias, &byte, 1, 0) == 0);
    CHECK(shutdown(alias, SHUT_WR) == 0);
    CHECK(close(alias) == 0 && close(ep) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10);
    CHECK(!*end && port > 0 && port < 65534);
    if (server) serve(address, (unsigned short)port); else connect_lifecycle(address, (unsigned short)port);
    printf("PASS: TCP %s refused error, AF_UNSPEC reconnect, alias lifetime and epoll\n", argv[1]);
    return 0;
}
