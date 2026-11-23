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
static void algorithm(int fd, char name[16])
{
    memset(name, 0xa5, 16); socklen_t length = 16;
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, &length) == 0);
    CHECK(length > 0 && length <= 16 && memchr(name, 0, length) != NULL && name[0]);
}
static void require_algorithm(int fd, const char *expected)
{
    char actual[16]; algorithm(fd, actual); CHECK(!strcmp(actual, expected));
}
static void select_algorithm(int fd, const char *name)
{
    int alias = dup(fd); CHECK(alias >= 0);
    /* Linux accepts a non-NUL-terminated optval of its stated length. */
    CHECK(setsockopt(alias, IPPROTO_TCP, TCP_CONGESTION, name, strlen(name)) == 0);
    require_algorithm(fd, name); require_algorithm(alias, name);
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "", 0) == -1 && errno == EINVAL);
    require_algorithm(alias, name);
    const char missing[] = "ker_missing_cc";
    errno = 0;
    CHECK(setsockopt(alias, IPPROTO_TCP, TCP_CONGESTION, missing, sizeof(missing) - 1) == -1 && errno == ENOENT);
    require_algorithm(fd, name); CHECK(close(alias) == 0);
}
static void established(int fd)
{
    struct tcp_info info = {0}; socklen_t length = sizeof(info);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0);
    CHECK(info.tcpi_state == TCP_ESTABLISHED && info.tcpi_snd_cwnd > 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4); int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr remote; CHECK(inet_pton(AF_INET, argv[2], &remote) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65536);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port)};
    int listener = -1, fd; char original[16];
    if (server) {
        listener = listen_at(address, 0); algorithm(listener, original); select_algorithm(listener, "reno");
        printf("READY %ld\n", port); fflush(stdout);
        fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0);
        require_algorithm(listener, "reno"); CHECK(close(listener) == 0);
    } else {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
        timeout(fd); algorithm(fd, original); select_algorithm(fd, "reno");
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    }
    timeout(fd);
    int alias = dup(fd); CHECK(alias >= 0);
    require_algorithm(fd, "reno"); require_algorithm(alias, "reno"); established(fd);
    for (int phase = 0; phase < 2; ++phase) {
        if (phase) select_algorithm(alias, original);
        const char *selected = phase ? original : "reno";
        require_algorithm(fd, selected); require_algorithm(alias, selected);
        unsigned char expected[16384], actual[16384];
        for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(i * 31 + i / 17 + phase * 197);
        if (server) {
            transfer(fd, actual, sizeof(actual), 0); CHECK(!memcmp(actual, expected, sizeof(actual)));
            transfer(alias, actual, sizeof(actual), 1);
        } else {
            transfer(alias, expected, sizeof(expected), 1);
            transfer(fd, actual, sizeof(actual), 0); CHECK(!memcmp(actual, expected, sizeof(actual)));
        }
        require_algorithm(fd, selected); established(alias);
    }
    char restored[16]; algorithm(alias, restored); CHECK(!strcmp(restored, original));
    printf("TCP %s congestion default=%s reno=verified restored=%s\n", argv[1], original, restored);
    marker(fd, 'P', !server); marker(alias, 'A', server);
    CHECK(shutdown(fd, SHUT_WR) == 0); eof(alias);
    CHECK(close(alias) == 0 && close(fd) == 0);
    printf("PASS: TCP %s congestion inheritance, alias/error recovery, live restore, two exact bidirectional 16KiB streams and EOF\n", argv[1]);
    return 0;
}
