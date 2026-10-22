/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
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
    struct timeval value = {.tv_sec = 10};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value)) == 0);
}
static int listen_at(struct sockaddr_in address, int nonblock)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), 0);
    int value = 1; CHECK(fd >= 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == 0);
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 4) == 0);
    value = 4096; CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) == 0);
    timeout(fd); return fd;
}
static int connect_to(struct sockaddr_in address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0); timeout(fd);
    int receive_buffer = 4096;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)) == 0);
    CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    struct sockaddr_in peer = {0}; socklen_t length = sizeof(peer);
    CHECK(getpeername(fd, (void *)&peer, &length) == 0 && length == sizeof(peer));
    CHECK(peer.sin_family == AF_INET && peer.sin_addr.s_addr == address.sin_addr.s_addr &&
          peer.sin_port == address.sin_port);
    int error = -1; length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
    return fd;
}
static int user_timeout(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, &length) == 0);
    CHECK(length == sizeof(value)); return value;
}
static void send_stalled(int fd, int control)
{
    int alias = dup(fd); CHECK(alias >= 0);
    CHECK(user_timeout(fd) == 0);
    int value = 1000;
    CHECK(setsockopt(alias, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, sizeof(value)) == 0);
    CHECK(user_timeout(fd) == value);
    int invalid = -1; errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &invalid, sizeof(invalid)) == -1 && errno == EINVAL);
    CHECK(user_timeout(alias) == value);
    int reset = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &reset, sizeof(reset)) == 0);
    CHECK(user_timeout(alias) == 0);
    CHECK(setsockopt(alias, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, sizeof(value)) == 0);
    int send_buffer = 16384;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0);
    marker(control, 'R', 0);
    unsigned char bytes[4096]; memset(bytes, 0x5a, sizeof(bytes));
    uint32_t queued = 0;
    for (;;) {
        ssize_t count = send(alias, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { CHECK(errno == EAGAIN || errno == EWOULDBLOCK); break; }
        CHECK(count > 0); queued += (uint32_t)count; CHECK(queued < 8 * 1024 * 1024);
    }
    CHECK(queued > 0);
    /* Receiver deliberately holds its real receive queue until this error. */
    struct pollfd item = {.fd = fd, .events = POLLERR};
    CHECK(poll(&item, 1, 10000) == 1 && (item.revents & POLLERR));
    int error = 0; socklen_t length = sizeof(error);
    CHECK(getsockopt(alias, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == ETIMEDOUT);
    error = -1; length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
    errno = 0;
    CHECK(send(alias, bytes, 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    marker(control, 'T', 1);
    uint32_t network_count = htonl(queued); transfer(control, &network_count, sizeof(network_count), 1);
    marker(control, 'A', 0);
    CHECK(close(alias) == 0);
    printf("PASS: stalled sender queued=%u, POLLERR/ETIMEDOUT and consumed SO_ERROR/EPIPE verified\n", queued);
}
static void receive_stalled(int fd, int control)
{
    marker(control, 'R', 1); marker(control, 'T', 0);
    uint32_t network_count; transfer(control, &network_count, sizeof(network_count), 0);
    uint32_t queued = ntohl(network_count), received = 0;
    CHECK(queued > 0 && queued < 8 * 1024 * 1024);
    for (;;) {
        unsigned char bytes[4096]; ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { CHECK(errno == ECONNRESET); break; }
        if (!count) break;
        for (ssize_t i = 0; i < count; ++i) CHECK(bytes[i] == 0x5a);
        received += (uint32_t)count; CHECK(received <= queued);
    }
    CHECK(received > 0 && received < queued);
    marker(control, 'A', 1);
    printf("PASS: held receiver verified=%u of queued=%u before timeout teardown\n", received, queued);
}
static void serve(struct sockaddr_in address, unsigned short port, int sending)
{
    int control_listener = listen_at(address, 0);
    address.sin_port = htons(port + 1); int listener = listen_at(address, 0);
    printf("READY %u\n", port); fflush(stdout);
    int control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
    timeout(control); CHECK(close(control_listener) == 0);
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);
    CHECK(close(listener) == 0);
    if (sending) send_stalled(fd, control); else receive_stalled(fd, control);
    CHECK(close(fd) == 0);
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0 && close(control) == 0);
}
static void connect_queue(struct sockaddr_in address, unsigned short port, int sending)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    int fd = connect_to(address);
    if (sending) send_stalled(fd, control); else receive_stalled(fd, control);
    CHECK(close(fd) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int sending = !strcmp(argv[4], "send"); CHECK(sending || !strcmp(argv[4], "receive"));
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    address.sin_port = htons(port);
    if (server) serve(address, port, sending); else connect_queue(address, port, sending);
    printf("PASS: TCP %s TCP_USER_TIMEOUT zero-window expiration and alias cleanup\n", argv[1]);
    return 0;
}
