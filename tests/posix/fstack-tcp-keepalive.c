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
static int option(int fd, int level, int name)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, level, name, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void configure(int fd)
{
    int alias = dup(fd); CHECK(alias >= 0);
    int enabled = 1;
    CHECK(setsockopt(alias, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) == 0);
    CHECK(option(fd, SOL_SOCKET, SO_KEEPALIVE) == 1);
    const int names[] = {TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT};
    const int values[] = {1, 1, 3};
    for (unsigned int i = 0; i < 3; ++i) {
        CHECK(setsockopt(alias, IPPROTO_TCP, names[i], &values[i], sizeof(values[i])) == 0);
        CHECK(option(fd, IPPROTO_TCP, names[i]) == values[i]);
        const int invalid[] = {0, -1, 2147483647};
        for (unsigned int j = 0; j < 3; ++j) {
            errno = 0;
            CHECK(setsockopt(fd, IPPROTO_TCP, names[i], &invalid[j], sizeof(invalid[j])) == -1);
            CHECK(errno == EINVAL && option(alias, IPPROTO_TCP, names[i]) == values[i]);
        }
    }
    CHECK(close(alias) == 0);
}
static void inherited(int fd)
{
    CHECK(option(fd, SOL_SOCKET, SO_KEEPALIVE) == 1);
    CHECK(option(fd, IPPROTO_TCP, TCP_KEEPIDLE) == 1);
    CHECK(option(fd, IPPROTO_TCP, TCP_KEEPINTVL) == 1);
    CHECK(option(fd, IPPROTO_TCP, TCP_KEEPCNT) == 3);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4); int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr remote; CHECK(inet_pton(AF_INET, argv[2], &remote) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65536);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port)};
    int listener = -1, fd;
    if (server) {
        listener = listen_at(address, 0); configure(listener);
        printf("READY %ld\n", port); fflush(stdout);
        fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0);
        inherited(listener); inherited(fd); CHECK(close(listener) == 0);
    } else {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
        timeout(fd); configure(fd);
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    }
    timeout(fd);
    int alias = dup(fd); CHECK(alias >= 0);
    inherited(alias);
    marker(fd, 'I', !server); marker(alias, 'J', server);
    /* ACK-only keepalive packets must never become application readability. */
    struct pollfd item = {.fd = alias, .events = POLLIN};
    if (!server) CHECK(poll(&item, 1, 4000) == 0);
    marker(fd, 'P', !server); marker(alias, 'A', server);
    int disabled = 0;
    CHECK(setsockopt(alias, SOL_SOCKET, SO_KEEPALIVE, &disabled, sizeof(disabled)) == 0);
    CHECK(option(fd, SOL_SOCKET, SO_KEEPALIVE) == 0);
    CHECK(shutdown(fd, SHUT_WR) == 0); eof(alias);
    CHECK(close(alias) == 0 && close(fd) == 0);
    printf("PASS: TCP %s keepalive inheritance, alias/error recovery, idle probes, resumed stream and EOF\n", argv[1]);
    return 0;
}
