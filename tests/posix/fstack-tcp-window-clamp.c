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
static int clamp(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void configure(int fd, int listening)
{
    int alias = dup(fd); CHECK(alias >= 0);
    int receive_buffer = 65536;
    CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)) == 0);
    int value = 4096;
    CHECK(setsockopt(alias, IPPROTO_TCP, TCP_WINDOW_CLAMP, &value, sizeof(value)) == 0);
    CHECK(clamp(fd) == value && clamp(alias) == value);
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &value, 1) == -1 && errno == EINVAL);
    CHECK(clamp(alias) == value);
    int zero = 0; errno = 0;
    int result = setsockopt(alias, IPPROTO_TCP, TCP_WINDOW_CLAMP, &zero, sizeof(zero));
    if (listening) CHECK(result == -1 && errno == EINVAL && clamp(fd) == value);
    else CHECK(result == 0 && clamp(fd) == 0);
    int small = 1;
    CHECK(setsockopt(alias, IPPROTO_TCP, TCP_WINDOW_CLAMP, &small, sizeof(small)) == 0);
    CHECK(clamp(fd) > small && clamp(fd) <= value);
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &value, sizeof(value)) == 0);
    CHECK(clamp(alias) == value && close(alias) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4); int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr remote; CHECK(inet_pton(AF_INET, argv[2], &remote) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port)};
    int listener = -1, fd, control;
    if (server) {
        int control_listener = listen_at(address, 0);
        address.sin_port = htons((uint16_t)(port + 1));
        listener = listen_at(address, 0); configure(listener, 1);
        printf("READY %ld\n", port); fflush(stdout);
        control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
        timeout(control); CHECK(close(control_listener) == 0);
        fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0);
        CHECK(clamp(listener) == 4096); CHECK(close(listener) == 0);
    } else {
        control = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(control >= 0);
        timeout(control); CHECK(connect(control, (void *)&address, sizeof(address)) == 0);
        address.sin_port = htons((uint16_t)(port + 1));
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
        timeout(fd); configure(fd, 0);
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    }
    timeout(fd);
    int alias = dup(fd); CHECK(alias >= 0);
    int effective = clamp(fd);
    CHECK(effective > 0 && effective <= 4096 && clamp(alias) == effective);
    int zero = 0; errno = 0;
    CHECK(setsockopt(alias, IPPROTO_TCP, TCP_WINDOW_CLAMP, &zero, sizeof(zero)) == -1 && errno == EINVAL);
    CHECK(clamp(fd) == effective);
    /* Both initial queries finish before any data can change receive sizing. */
    marker(control, 'R', server);
    unsigned char expected[16384], actual[16384];
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(i * 31 + i / 17);
    if (server) {
        transfer(fd, actual, sizeof(actual), 0); CHECK(!memcmp(actual, expected, sizeof(actual)));
        transfer(alias, actual, sizeof(actual), 1);
    } else {
        transfer(alias, expected, sizeof(expected), 1);
        transfer(fd, actual, sizeof(actual), 0); CHECK(!memcmp(actual, expected, sizeof(actual)));
    }
    marker(fd, 'P', !server); marker(alias, 'A', server);
    int final_clamp = clamp(fd);
    CHECK(final_clamp > 0 && clamp(alias) == final_clamp);
    printf("TCP %s clamp initial=%d after-data=%d\n", argv[1], effective, final_clamp);
    CHECK(shutdown(fd, SHUT_WR) == 0); eof(alias);
    CHECK(close(alias) == 0 && close(fd) == 0 && close(control) == 0);
    printf("PASS: TCP %s window clamp inheritance, alias/error recovery, exact bidirectional 16KiB stream and EOF\n", argv[1]);
    return 0;
}
