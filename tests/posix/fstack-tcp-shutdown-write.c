/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
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
static volatile sig_atomic_t pipe_signals;
static void pipe_signal(int number)
{
    (void)number; ++pipe_signals;
}
static int socket_error(int fd)
{
    int error = -1; socklen_t length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    CHECK(length == sizeof(error)); return error;
}
static ssize_t failed_write(int fd, int api, int flags)
{
    char byte = '!'; struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    struct mmsghdr batch = {.msg_hdr = message};
    switch (api) {
    case 0: return send(fd, &byte, 1, flags);
    case 1: return sendto(fd, &byte, 1, flags, NULL, 0);
    case 2: return sendmsg(fd, &message, flags);
    case 3: return sendmmsg(fd, &batch, 1, flags);
    case 4: return write(fd, &byte, 1);
    default: return writev(fd, &vector, 1);
    }
}
static void shutdown_writes(int fd, int alias, int peer_fin)
{
    CHECK(shutdown(alias, SHUT_WR) == 0);
    /* Once both FINs are ACKed, Linux may already have closed the TCP state. */
    errno = 0; int repeated = shutdown(fd, SHUT_WR);
    CHECK(repeated == 0 || (peer_fin && repeated == -1 && errno == ENOTCONN));
    sig_atomic_t initial = pipe_signals;
    for (int api = 0; api < 4; ++api) {
        sig_atomic_t before = pipe_signals; errno = 0;
        CHECK(failed_write(api & 1 ? alias : fd, api, MSG_NOSIGNAL) == -1 && errno == EPIPE);
        CHECK(pipe_signals == before);
    }
    for (int api = 0; api < 6; ++api) {
        sig_atomic_t before = pipe_signals; errno = 0;
        CHECK(failed_write(api & 1 ? fd : alias, api, 0) == -1 && errno == EPIPE);
        CHECK(pipe_signals == before + 1);
    }
    CHECK(pipe_signals == initial + 6);
    CHECK(socket_error(fd) == 0 && socket_error(alias) == 0);
}
static void invalid_shutdown(int fd)
{
    errno = 0; CHECK(shutdown(fd, 42) == -1 && errno == EINVAL);
    CHECK(socket_error(fd) == 0);
}
static int watch(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0); return ep;
}
static void peer_eof(int fd, int ep)
{
    eof(fd);
    struct pollfd target = {.fd = fd, .events = POLLIN | POLLRDHUP};
    CHECK(poll(&target, 1, 0) == 1 && (target.revents & POLLIN) && (target.revents & POLLRDHUP));
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && event.data.u64 == TAG &&
          (event.events & EPOLLIN) && (event.events & EPOLLRDHUP));
}
static void serve(struct sockaddr_in address, unsigned short port)
{
    int control_listener = listen_at(address, 0);
    address.sin_port = htons(port + 1); int listener = listen_at(address, 0);
    printf("READY %u\n", port); fflush(stdout);
    int control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
    timeout(control); CHECK(close(control_listener) == 0);
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);
    CHECK(close(listener) == 0);
    int alias = dup(fd), ep = watch(fd); CHECK(alias >= 0);
    invalid_shutdown(alias);
    char request[4]; transfer(alias, request, sizeof(request), 0);
    CHECK(!memcmp(request, "head", sizeof(request))); peer_eof(fd, ep);
    /* Keep the receiving socket open until all peer EPIPE probes have finished. */
    marker(control, 'M', 0); CHECK(socket_error(fd) == 0);
    char reply[] = "reverse-reply"; transfer(fd, reply, sizeof(reply) - 1, 1);
    shutdown_writes(fd, alias, 1); marker(control, 'M', 1);
    marker(control, 'A', 0);
    CHECK(close(alias) == 0 && close(fd) == 0 && close(ep) == 0);
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0 && close(control) == 0);
}
static void connect_shutdown(struct sockaddr_in address, unsigned short port)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    int fd = connect_to(address), alias = dup(fd), ep = watch(fd); CHECK(alias >= 0);
    invalid_shutdown(fd);
    char request[] = "head"; transfer(fd, request, sizeof(request) - 1, 1);
    shutdown_writes(fd, alias, 0); marker(control, 'M', 1);
    char reply[13]; transfer(alias, reply, sizeof(reply), 0);
    CHECK(!memcmp(reply, "reverse-reply", sizeof(reply))); peer_eof(fd, ep);
    marker(control, 'M', 0); CHECK(socket_error(fd) == 0);
    marker(control, 'A', 1);
    CHECK(close(alias) == 0 && close(fd) == 0 && close(ep) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    struct sigaction action = {.sa_handler = pipe_signal};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    sigset_t unblocked; CHECK(sigemptyset(&unblocked) == 0 && sigaddset(&unblocked, SIGPIPE) == 0);
    CHECK(sigprocmask(SIG_UNBLOCK, &unblocked, NULL) == 0);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    address.sin_port = htons(port);
    if (server) serve(address, port); else connect_shutdown(address, port);
    CHECK(pipe_signals == 6);
    printf("PASS: TCP %s alias SHUT_WR, six EPIPE APIs, MSG_NOSIGNAL, SIGPIPE and reverse EOF\n", argv[1]);
    return 0;
}
