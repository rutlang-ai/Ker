/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
static int flags(int fd, int command)
{
    int value = fcntl(fd, command); CHECK(value >= 0); return value;
}
static void nonblocking(int fd, int alias, int enabled)
{
    CHECK(!!(flags(fd, F_GETFL) & O_NONBLOCK) == enabled);
    CHECK(!!(flags(alias, F_GETFL) & O_NONBLOCK) == enabled);
}
static void wait_data(int fd, int ep)
{
    struct pollfd target = {.fd = fd, .events = POLLIN};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN) && event.data.u64 == TAG);
}
static void descriptor_flags(int fd, int alias)
{
    CHECK((flags(fd, F_GETFD) & FD_CLOEXEC) && !(flags(alias, F_GETFD) & FD_CLOEXEC));
    /* These no-argument ioctls affect the public host reservations independently. */
    CHECK(ioctl(alias, FIOCLEX) == 0);
    CHECK((flags(fd, F_GETFD) & FD_CLOEXEC) && (flags(alias, F_GETFD) & FD_CLOEXEC));
    CHECK(ioctl(fd, FIONCLEX) == 0);
    CHECK(!(flags(fd, F_GETFD) & FD_CLOEXEC) && (flags(alias, F_GETFD) & FD_CLOEXEC));
    CHECK(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 && ioctl(alias, FIONCLEX) == 0);
    CHECK((flags(fd, F_GETFD) & FD_CLOEXEC) && !(flags(alias, F_GETFD) & FD_CLOEXEC));
}
static void send_phases(int fd, int control, unsigned int seed)
{
    marker(control, 'N', 0);
    uint32_t head = htonl(seed); transfer(fd, &head, sizeof(head), 1);
    marker(control, 'W', 0);
    unsigned char tail[17];
    for (size_t i = 0; i < sizeof(tail); ++i) tail[i] = (unsigned char)(seed + i * 37);
    transfer(fd, tail, sizeof(tail), 1); CHECK(shutdown(fd, SHUT_WR) == 0);
}
static void receive_phases(int fd, int control, unsigned int seed)
{
    int alias = dup(fd); CHECK(alias >= 0); descriptor_flags(fd, alias); nonblocking(fd, alias, 0);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    unsigned char byte;
    /* Sender waits for N, so all empty-queue probes have an explicit barrier. */
    errno = 0; CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    nonblocking(fd, alias, 0);
    int enabled = 1; CHECK(ioctl(alias, FIONBIO, &enabled) == 0); nonblocking(fd, alias, 1);
    errno = 0; CHECK(read(fd, &byte, 1) == -1 && errno == EAGAIN);
    struct iovec vector = {&byte, 1}; struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    errno = 0; CHECK(recvmsg(alias, &message, 0) == -1 && errno == EAGAIN);
    CHECK(fcntl(fd, F_SETFL, flags(fd, F_GETFL) & ~O_NONBLOCK) == 0); nonblocking(fd, alias, 0);
    errno = 0; CHECK(recv(alias, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    nonblocking(fd, alias, 0);
    CHECK(fcntl(alias, F_SETFL, flags(alias, F_GETFL) | O_NONBLOCK) == 0); nonblocking(fd, alias, 1);
    marker(control, 'N', 1);
    uint32_t head; size_t used = 0;
    while (used < sizeof(head)) {
        wait_data(alias, ep);
        ssize_t count = recv(alias, (char *)&head + used, sizeof(head) - used, 0);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        CHECK(count > 0); used += (size_t)count;
    }
    CHECK(ntohl(head) == seed);
    enabled = 0; CHECK(ioctl(fd, FIONBIO, &enabled) == 0); nonblocking(fd, alias, 0);
    marker(control, 'W', 1);
    unsigned char left[5], right[12];
    struct iovec parts[2] = {{left, sizeof(left)}, {right, sizeof(right)}};
    message = (struct msghdr){.msg_iov = parts, .msg_iovlen = 2};
    CHECK(recvmsg(alias, &message, MSG_WAITALL) == 17 && !(message.msg_flags & MSG_TRUNC));
    for (size_t i = 0; i < 17; ++i)
        CHECK((i < sizeof(left) ? left[i] : right[i - sizeof(left)]) == (unsigned char)(seed + i * 37));
    eof(fd); eof(alias); nonblocking(fd, alias, 0);
    CHECK((flags(fd, F_GETFD) & FD_CLOEXEC) && !(flags(alias, F_GETFD) & FD_CLOEXEC));
    CHECK(close(alias) == 0 && close(ep) == 0);
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
    receive_phases(fd, control, 11); send_phases(fd, control, 197);
    marker(control, 'A', 0); CHECK(close(fd) == 0);
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0 && close(control) == 0);
}
static void connect_modes(struct sockaddr_in address, unsigned short port)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    int fd = connect_to(address);
    send_phases(fd, control, 11); receive_phases(fd, control, 197);
    marker(control, 'A', 1); CHECK(close(fd) == 0);
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
    if (server) serve(address, port); else connect_modes(address, port);
    printf("PASS: TCP %s shared FIONBIO/fcntl, MSG_DONTWAIT, independent CLOEXEC and bidirectional EOF\n", argv[1]);
    return 0;
}
