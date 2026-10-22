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
#include <netinet/tcp.h>
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

static uint64_t monotonic_ns(void)
{
    struct timespec value; CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
static int option(int fd, int name)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_TCP, name, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void scenario(int fd, int control, int sender, int mode, int direction)
{
    int alias = dup(fd); CHECK(alias >= 0);
    unsigned char expected[48];
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(i * 31 + mode * 71 + direction * 109);
    CHECK(option(fd, TCP_CORK) == 0 && option(alias, TCP_CORK) == 0);
    int observed = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        char verdict;
        if (sender) {
            marker(control, 'C', 0);
            int value = 1;
            CHECK(setsockopt(alias, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) == 0);
            CHECK(option(fd, TCP_NODELAY) == 1);
            value = !mode;
            CHECK(setsockopt(fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value)) == 0);
            CHECK(option(alias, TCP_CORK) == value);
            /* Both binaries use host CLOCK_MONOTONIC, including the preloaded
             * application. Timestamp before send bounds all scheduling delay. */
            uint64_t start = monotonic_ns();
            if (!mode) CHECK(write(fd, expected, 17) == 17);
            else {
                struct iovec parts[2] = {{expected, 8}, {expected + 8, 9}};
                struct msghdr message = {.msg_iov = parts, .msg_iovlen = 2};
                CHECK(sendmsg(fd, &message, MSG_MORE | MSG_NOSIGNAL) == 17);
                CHECK(option(alias, TCP_CORK) == 0);
            }
            transfer(control, &start, sizeof(start), 1);
            transfer(control, &verdict, 1, 0); CHECK(verdict == 'Q' || verdict == 'R');
            if (!mode) {
                struct iovec parts[2] = {{expected + 17, 10}, {expected + 27, 21}};
                CHECK(writev(alias, parts, 2) == 31);
                value = 0;
                CHECK(setsockopt(alias, IPPROTO_TCP, TCP_CORK, &value, sizeof(value)) == 0);
                CHECK(option(fd, TCP_CORK) == 0);
            } else CHECK(send(alias, expected + 17, 31, MSG_NOSIGNAL) == 31);
            marker(control, 'D', 0);
        } else {
            marker(control, 'C', 1);
            uint64_t start; transfer(control, &start, sizeof(start), 0);
            struct pollfd pending = {.fd = fd, .events = POLLIN};
            int ready = poll(&pending, 1, 20); CHECK(ready >= 0);
            uint64_t end = monotonic_ns(); CHECK(end >= start);
            /* TCP may legitimately flush a cork after roughly 200ms. Require
             * the negative observation well before that limit; delayed samples
             * are drained and retried, never counted as a deferral pass. */
            verdict = end - start < UINT64_C(100000000) ? 'Q' : 'R';
            if (verdict == 'Q') CHECK(ready == 0);
            transfer(control, &verdict, 1, 1);
            unsigned char actual[48]; transfer(fd, actual, sizeof(actual), 0);
            CHECK(!memcmp(actual, expected, sizeof(actual))); marker(control, 'D', 1);
        }
        if (verdict == 'Q') { observed = 1; break; }
    }
    CHECK(observed); /* Exhausted scheduling retries are not compatibility passes. */
    marker(fd, 'P', sender);
    marker(control, 'A', !sender);
    CHECK(close(alias) == 0);
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
    for (int mode = 0; mode < 2; ++mode) for (int direction = 0; direction < 2; ++direction) {
        int fd = server ? accept4(data_listener, NULL, NULL, SOCK_CLOEXEC) : connect_to(data_address);
        CHECK(fd >= 0); timeout(fd);
        scenario(fd, control, server == direction, mode, direction);
        CHECK(shutdown(fd, SHUT_WR) == 0); eof(fd); CHECK(close(fd) == 0);
    }
    if (server) CHECK(close(data_listener) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
    printf("PASS: TCP %s bidirectional TCP_CORK/MSG_MORE deferral, alias uncork, exact stream and plain-write recovery\n", argv[1]);
    return 0;
}
