/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
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
static int at_mark(int fd)
{
    int value = -1; CHECK(ioctl(fd, SIOCATMARK, &value) == 0);
    CHECK(sockatmark(fd) == value); return value;
}
static void send_urgent(int fd, int control, int server)
{
    marker(control, 'R', 0);
    char prefix[6], suffix[5], urgent = server ? 'S' : 'C';
    memcpy(prefix, server ? "server" : "client", sizeof(prefix));
    memcpy(suffix, server ? "doneS" : "doneC", sizeof(suffix));
    transfer(fd, prefix, sizeof(prefix), 1);
    CHECK(send(fd, &urgent, 1, MSG_OOB | MSG_NOSIGNAL) == 1);
    marker(control, 'S', 1);
    /* Do not let later ordinary bytes conceal the urgent boundary. */
    marker(control, 'U', 0);
    transfer(fd, suffix, sizeof(suffix), 1); CHECK(shutdown(fd, SHUT_WR) == 0);
}
static void receive_urgent(int fd, int control, int inline_data, int peer_server)
{
    int value = inline_data; socklen_t length = sizeof(value);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, sizeof(value)) == 0);
    value = -1;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, &length) == 0);
    CHECK(length == sizeof(value) && value == inline_data);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLPRI, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    marker(control, 'R', 1); marker(control, 'S', 0);
    struct pollfd target = {.fd = fd, .events = POLLPRI};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLPRI));
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && event.data.u64 == TAG &&
          (event.events & EPOLLPRI));
    CHECK(at_mark(fd) == 0);
    char prefix[6]; transfer(fd, prefix, sizeof(prefix), 0);
    CHECK(!memcmp(prefix, peer_server ? "server" : "client", sizeof(prefix)));
    CHECK(at_mark(fd) == 1);
    char byte = 0, expected = peer_server ? 'S' : 'C';
    if (inline_data) {
        errno = 0; CHECK(recv(fd, &byte, 1, MSG_OOB) == -1 && errno == EINVAL);
        /* Inline urgent data is read through the ordinary stream API. */
        transfer(fd, &byte, 1, 0); CHECK(byte == expected);
    } else {
        CHECK(recv(fd, &byte, 1, MSG_OOB | MSG_PEEK) == 1 && byte == expected);
        CHECK(recv(fd, &byte, 1, MSG_OOB) == 1 && byte == expected);
    }
    marker(control, 'U', 1);
    char suffix[5]; transfer(fd, suffix, sizeof(suffix), 0);
    CHECK(!memcmp(suffix, peer_server ? "doneS" : "doneC", sizeof(suffix)));
    eof(fd); CHECK(at_mark(fd) == 0);
    /* EOF/HUP may remain ready; the consumed urgent byte must not report PRI. */
    target.revents = 0; CHECK(poll(&target, 1, 0) >= 0 && !(target.revents & POLLPRI));
    int count = epoll_wait(ep, &event, 1, 0);
    CHECK(count == 0 || (count == 1 && event.data.u64 == TAG && !(event.events & EPOLLPRI)));
    CHECK(close(ep) == 0);
}
static void serve(struct sockaddr_in address, unsigned short port)
{
    int control_listener = listen_at(address, 0);
    address.sin_port = htons(port + 1); int listener = listen_at(address, 0);
    printf("READY %u\n", port); fflush(stdout);
    int control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
    timeout(control); CHECK(close(control_listener) == 0);
    for (int mode = 0; mode < 2; ++mode) {
        int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);
        receive_urgent(fd, control, mode, 0);
        send_urgent(fd, control, 1);
        marker(control, 'A', 0); CHECK(close(fd) == 0);
    }
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0);
    CHECK(close(control) == 0 && close(listener) == 0);
}
static void connect_modes(struct sockaddr_in address, unsigned short port)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    for (int mode = 0; mode < 2; ++mode) {
        int fd = connect_to(address);
        send_urgent(fd, control, 0);
        receive_urgent(fd, control, mode, 1);
        marker(control, 'A', 1); CHECK(close(fd) == 0);
    }
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    errno = 0; CHECK(sockatmark(-1) == -1 && errno == EBADF);
    int pipes[2]; CHECK(pipe(pipes) == 0);
    errno = 0; CHECK(sockatmark(pipes[0]) == -1 && errno == ENOTTY);
    CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    address.sin_port = htons(port);
    if (server) serve(address, port); else connect_modes(address, port);
    printf("PASS: TCP %s bidirectional MSG_OOB, inline mode, urgent mark and priority readiness\n", argv[1]);
    return 0;
}
