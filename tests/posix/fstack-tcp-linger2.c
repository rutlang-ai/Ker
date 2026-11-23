/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/tcp.h>
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

static int linger2(int fd)
{
    int value; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_LINGER2, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static int socket_error(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void wait_fin_wait2(int fd)
{
    struct timespec start, now, pause = {.tv_nsec = 10000000};
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    for (;;) {
        struct tcp_info info = {0}; socklen_t length = sizeof(info);
        CHECK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0);
        if (info.tcpi_state == TCP_FIN_WAIT2) return;
        CHECK(info.tcpi_state == TCP_FIN_WAIT1);
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK(now.tv_sec - start.tv_sec < 5);
        CHECK(nanosleep(&pause, NULL) == 0);
    }
}
static void scenario(int fd, int control, int closer)
{
    int alias = dup(fd); CHECK(alias >= 0);
    if (closer) {
        struct linger normal; socklen_t length = sizeof(normal);
        CHECK(getsockopt(fd, SOL_SOCKET, SO_LINGER, &normal, &length) == 0 && normal.l_onoff == 0);
        int value = 2;
        CHECK(setsockopt(alias, IPPROTO_TCP, TCP_LINGER2, &value, sizeof(value)) == 0);
        CHECK(linger2(fd) == 2);
        errno = 0;
        CHECK(setsockopt(fd, IPPROTO_TCP, TCP_LINGER2, &value, 1) == -1 && errno == EINVAL);
        CHECK(linger2(alias) == 2);
        value = 0;
        CHECK(setsockopt(fd, IPPROTO_TCP, TCP_LINGER2, &value, sizeof(value)) == 0);
        CHECK(linger2(alias) > 0);
        value = -1;
        CHECK(setsockopt(alias, IPPROTO_TCP, TCP_LINGER2, &value, sizeof(value)) == 0);
        CHECK(linger2(fd) == -1);
        marker(fd, 'H', 1); CHECK(shutdown(fd, SHUT_WR) == 0);
        marker(control, 'F', 0); wait_fin_wait2(alias);
        CHECK(close(fd) == 0);
        marker(control, 'C', 1); marker(alias, 'P', 0);
        wait_fin_wait2(alias); CHECK(close(alias) == 0);
        marker(control, 'X', 1); marker(control, 'D', 0);
    } else {
        marker(alias, 'H', 0); eof(fd); CHECK(socket_error(fd) == 0);
        marker(control, 'F', 1); marker(control, 'C', 0);
        /* FIN closes only the remote write half; the last alias still receives. */
        marker(fd, 'P', 1); marker(control, 'X', 0);
        struct pollfd item = {.fd = alias, .events = POLLERR};
        CHECK(poll(&item, 1, 5000) == 1 && (item.revents & POLLERR));
        /* Original Linux maps an RST received in CLOSE_WAIT to EPIPE. */
        CHECK(socket_error(alias) == EPIPE && socket_error(fd) == 0);
        eof(fd); eof(alias);
        unsigned char byte = 'Q'; errno = 0;
        CHECK(send(alias, &byte, 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
        CHECK(close(fd) == 0 && close(alias) == 0); marker(control, 'D', 1);
    }
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
    for (int direction = 0; direction < 2; ++direction) {
        int fd = server ? accept4(data_listener, NULL, NULL, SOCK_CLOEXEC) : connect_to(data_address);
        CHECK(fd >= 0); timeout(fd);
        scenario(fd, control, server == direction);
    }
    if (server) CHECK(close(data_listener) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
    printf("PASS: TCP %s TCP_LINGER2, real FIN_WAIT2, last-alias reset and CLOSE_WAIT EPIPE\n", argv[1]);
    return 0;
}
