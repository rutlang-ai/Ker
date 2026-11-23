/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
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
    value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, &length) == 0 && value == 0);
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
static int option(int fd, int name)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, name, &value, &length) == 0 && length == sizeof(value)); return value;
}
static void bind_conflict(struct sockaddr_in address, int reuse)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
    CHECK(option(fd, SO_REUSEADDR) == reuse && option(fd, SO_REUSEPORT) == 0);
    errno = 0; CHECK(bind(fd, (void *)&address, sizeof(address)) == -1 && errno == EADDRINUSE);
    CHECK(close(fd) == 0);
}
static int accept_ready(int fd, int ep, uint64_t tag)
{
    struct pollfd target = {.fd = fd, .events = POLLIN};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN) && event.data.u64 == tag);
    int child = accept4(fd, NULL, NULL, SOCK_CLOEXEC); CHECK(child >= 0); timeout(child); return child;
}
static void send_token(int fd, uint32_t token)
{
    token = htonl(token); transfer(fd, &token, sizeof(token), 1);
}
static void receive_token(int fd, uint32_t token)
{
    uint32_t actual; transfer(fd, &actual, sizeof(actual), 0); CHECK(ntohl(actual) == token);
}
static void echo(int fd, uint32_t token)
{
    receive_token(fd, token); send_token(fd, token);
}
static void exchange(int fd, uint32_t token)
{
    send_token(fd, token); receive_token(fd, token);
}
static void serve(struct sockaddr_in address, unsigned short port)
{
    int control_listener = listen_at(address, 0);
    address.sin_port = htons(port + 1);
    int listener = listen_at(address, 1), alias = dup(listener); CHECK(alias >= 0);
    CHECK(option(listener, SO_REUSEADDR) == 1 && option(alias, SO_ACCEPTCONN) == 1);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, listener, &event) == 0);
    printf("READY %u\n", port); fflush(stdout);
    int control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
    timeout(control); CHECK(close(control_listener) == 0);
    int old = accept_ready(alias, ep, TAG); echo(old, 1);
    /* REUSEADDR cannot overlap live TCP listeners without REUSEPORT. */
    bind_conflict(address, 1);
    CHECK(close(listener) == 0 && option(alias, SO_ACCEPTCONN) == 1);
    bind_conflict(address, 1);
    CHECK(close(alias) == 0);
    /* Accepted connection is still ESTABLISHED and holds this local port. */
    bind_conflict(address, 0);
    listener = listen_at(address, 1);
    CHECK(option(listener, SO_REUSEADDR) == 1 && option(listener, SO_ACCEPTCONN) == 1);
    event = (struct epoll_event){.events = EPOLLIN, .data.u64 = TAG + 1};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, listener, &event) == 0);
    marker(control, 'N', 1);
    echo(old, 2);
    int current = accept_ready(listener, ep, TAG + 1);
    receive_token(current, 3);
    CHECK(close(listener) == 0); send_token(current, 3);
    CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    echo(old, 4); eof(old); CHECK(shutdown(old, SHUT_WR) == 0 && close(old) == 0);
    receive_token(current, 5); eof(current); send_token(current, 5);
    CHECK(shutdown(current, SHUT_WR) == 0 && close(current) == 0);
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0);
    CHECK(close(control) == 0 && close(ep) == 0);
}
static void connect_restart(struct sockaddr_in address, unsigned short port)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    int old = connect_to(address); exchange(old, 1); marker(control, 'N', 0);
    exchange(old, 2);
    int current = connect_to(address); exchange(current, 3);
    exchange(old, 4); CHECK(shutdown(old, SHUT_WR) == 0); eof(old); CHECK(close(old) == 0);
    send_token(current, 5); CHECK(shutdown(current, SHUT_WR) == 0);
    receive_token(current, 5); eof(current); CHECK(close(current) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    address.sin_port = htons(port);
    if (server) serve(address, port); else connect_restart(address, port);
    printf("PASS: TCP %s listener alias lifetime, REUSEADDR restart, old/new streams and EOF\n", argv[1]);
    return 0;
}
