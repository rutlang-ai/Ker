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
static int listen_at(struct sockaddr_in address, int reuseport)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    int value = 1; CHECK(fd >= 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == 0);
    if (reuseport) {
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == 0);
        value = 0; socklen_t length = sizeof(value);
        CHECK(getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, &length) == 0);
        CHECK(length == sizeof(value) && value == 1);
    }
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 16) == 0);
    return fd;
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
static uint32_t receive_token(int fd)
{
    uint32_t token; transfer(fd, &token, sizeof(token), 0); return ntohl(token);
}
static void send_token(int fd, uint32_t token)
{
    token = htonl(token); transfer(fd, &token, sizeof(token), 1);
}
static int accept_ready(int *listeners, int ep, int *owner)
{
    struct pollfd targets[2] = {{.fd = listeners[0], .events = POLLIN},
                               {.fd = listeners[1], .events = POLLIN}};
    CHECK(poll(targets, 2, 5000) > 0);
    CHECK((targets[0].revents | targets[1].revents) & POLLIN);
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN));
    CHECK(event.data.u64 == TAG || event.data.u64 == TAG + 1);
    *owner = (int)(event.data.u64 - TAG); CHECK(listeners[*owner] >= 0);
    int fd = accept4(listeners[*owner], NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0);
    timeout(fd); return fd;
}
static void serve(struct sockaddr_in address, unsigned short port)
{
    int control_listener = listen_at(address, 0);
    address.sin_port = htons(port + 1);
    int listeners[2] = {listen_at(address, 1), listen_at(address, 1)};
    /* SO_REUSEADDR alone cannot join this live TCP reuseport group. */
    int outsider = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), enabled = 1;
    CHECK(outsider >= 0);
    CHECK(setsockopt(outsider, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0);
    errno = 0; CHECK(bind(outsider, (void *)&address, sizeof(address)) == -1 && errno == EADDRINUSE);
    CHECK(close(outsider) == 0);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    for (int i = 0; i < 2; ++i) {
        struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG + i};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, listeners[i], &event) == 0);
    }
    printf("READY %u\n", port); fflush(stdout);
    struct pollfd control_ready = {.fd = control_listener, .events = POLLIN};
    CHECK(poll(&control_ready, 1, 5000) == 1 && (control_ready.revents & POLLIN));
    int control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
    timeout(control); CHECK(close(control_listener) == 0);
    marker(control, 'C', 0);
    unsigned int seen = 0; int retained = -1, retired_owner = -1;
    for (int i = 0; i < 8; ++i) {
        int owner, fd = accept_ready(listeners, ep, &owner);
        uint32_t token = receive_token(fd);
        CHECK(token >= 1 && token <= 8 && !(seen & (1U << (token - 1))));
        seen |= 1U << (token - 1); send_token(fd, token);
        if (token == 1) { retained = fd; retired_owner = owner; }
        else { eof(fd); CHECK(shutdown(fd, SHUT_WR) == 0 && close(fd) == 0); }
    }
    CHECK(seen == 255 && retained >= 0 && retired_owner >= 0);
    /* Close precisely the listener that accepted the retained connection. */
    CHECK(close(listeners[retired_owner]) == 0); listeners[retired_owner] = -1;
    marker(control, 'A', 1);
    CHECK(receive_token(retained) == 999); eof(retained); send_token(retained, 999);
    CHECK(shutdown(retained, SHUT_WR) == 0 && close(retained) == 0);
    marker(control, 'C', 0);
    seen = 0;
    for (int i = 0; i < 4; ++i) {
        int owner, fd = accept_ready(listeners, ep, &owner); CHECK(owner != retired_owner);
        uint32_t token = receive_token(fd);
        CHECK(token >= 101 && token <= 104 && !(seen & (1U << (token - 101))));
        seen |= 1U << (token - 101); eof(fd); send_token(fd, token);
        CHECK(shutdown(fd, SHUT_WR) == 0 && close(fd) == 0);
    }
    CHECK(seen == 15);
    struct epoll_event event; CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0);
    CHECK(close(control) == 0 && close(listeners[1 - retired_owner]) == 0 && close(ep) == 0);
}
static void connect_batches(struct sockaddr_in address, unsigned short port)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    int sockets[8];
    for (int i = 0; i < 8; ++i) {
        sockets[i] = connect_to(address); send_token(sockets[i], i + 1);
        if (i) CHECK(shutdown(sockets[i], SHUT_WR) == 0);
    }
    marker(control, 'C', 1); marker(control, 'A', 0);
    for (int i = 0; i < 8; ++i) {
        CHECK(receive_token(sockets[i]) == (uint32_t)i + 1);
        if (i) { eof(sockets[i]); CHECK(close(sockets[i]) == 0); }
    }
    send_token(sockets[0], 999); CHECK(shutdown(sockets[0], SHUT_WR) == 0);
    CHECK(receive_token(sockets[0]) == 999); eof(sockets[0]); CHECK(close(sockets[0]) == 0);
    for (int i = 0; i < 4; ++i) {
        sockets[i] = connect_to(address); send_token(sockets[i], i + 101);
        CHECK(shutdown(sockets[i], SHUT_WR) == 0);
    }
    marker(control, 'C', 1);
    for (int i = 0; i < 4; ++i) {
        CHECK(receive_token(sockets[i]) == (uint32_t)i + 101);
        eof(sockets[i]); CHECK(close(sockets[i]) == 0);
    }
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
    if (server) serve(address, port); else connect_batches(address, port);
    printf("PASS: TCP %s reuseport group, bind exclusion, listener retirement and survivor\n", argv[1]);
    return 0;
}
