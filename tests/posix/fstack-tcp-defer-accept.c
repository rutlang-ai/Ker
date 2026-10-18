/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
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
static void serve(struct sockaddr_in address, unsigned short port)
{
    int control_listener = listen_at(address, 0);
    address.sin_port = htons(port + 1);
    int listener = listen_at(address, 1), ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, listener, &event) == 0);
    printf("READY %u\n", port); fflush(stdout);
    int control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
    timeout(control); CHECK(close(control_listener) == 0);
    for (int phase = 0; phase < 2; ++phase) {
        /* Linux quantizes seconds into retransmit counts; do not require exact rounding. */
        int seconds = phase ? 0 : 31, actual = -1; socklen_t length = sizeof(actual);
        CHECK(setsockopt(listener, IPPROTO_TCP, TCP_DEFER_ACCEPT, &seconds, sizeof(seconds)) == 0);
        CHECK(getsockopt(listener, IPPROTO_TCP, TCP_DEFER_ACCEPT, &actual, &length) == 0);
        CHECK(length == sizeof(actual) && (phase ? actual == 0 : actual >= seconds));
        marker(control, 'B', 1); marker(control, 'C', 0);
        struct pollfd target = {.fd = listener, .events = POLLIN};
        int fd;
        if (!phase) {
            /* Peer connect completed, but payload is withheld until our D marker. */
            CHECK(poll(&target, 1, 100) == 0);
            CHECK(epoll_wait(ep, &event, 1, 0) == 0);
            errno = 0; CHECK(accept4(listener, NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EAGAIN);
            marker(control, 'D', 1);
            CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
        } else {
            /* Disabling the same listener must allow accept before any payload. */
            CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
        }
        CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && event.data.u64 == TAG &&
              (event.events & EPOLLIN));
        fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);
        if (phase) marker(control, 'D', 1);
        char bytes[4]; transfer(fd, bytes, sizeof(bytes), 0);
        CHECK(!memcmp(bytes, phase ? "off!" : "data", sizeof(bytes))); eof(fd);
        transfer(fd, bytes, sizeof(bytes), 1); CHECK(shutdown(fd, SHUT_WR) == 0);
        CHECK(close(fd) == 0);
        target.revents = 0;
        CHECK(poll(&target, 1, 0) == 0 && epoll_wait(ep, &event, 1, 0) == 0);
        marker(control, 'A', 1);
    }
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0);
    CHECK(close(control) == 0 && close(listener) == 0 && close(ep) == 0);
}
static void connect_phases(struct sockaddr_in address, unsigned short port)
{
    int control = connect_to(address);
    address.sin_port = htons(port + 1);
    for (int phase = 0; phase < 2; ++phase) {
        marker(control, 'B', 0);
        int fd = connect_to(address);
        marker(control, 'C', 1); marker(control, 'D', 0);
        char bytes[4]; const char *payload = phase ? "off!" : "data";
        memcpy(bytes, payload, sizeof(bytes)); transfer(fd, bytes, sizeof(bytes), 1);
        CHECK(shutdown(fd, SHUT_WR) == 0);
        transfer(fd, bytes, sizeof(bytes), 0); CHECK(!memcmp(bytes, payload, sizeof(bytes)));
        eof(fd); CHECK(close(fd) == 0); marker(control, 'A', 0);
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
    if (server) serve(address, port); else connect_phases(address, port);
    printf("PASS: TCP %s deferred data-triggered accept, disable, poll/epoll and EOF\n", argv[1]);
    return 0;
}
