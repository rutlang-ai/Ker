/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
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
static uint32_t lowat(int fd)
{
    uint32_t value; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &value, &length) == 0);
    CHECK(length == sizeof(value)); return value;
}
static void set_lowat(int fd, uint32_t value)
{
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &value, sizeof(value)) == 0);
    CHECK(lowat(fd) == value);
}
static void send_stalled(int fd, int control)
{
    int alias = dup(fd); CHECK(alias >= 0); CHECK(lowat(fd) == 0);
    set_lowat(alias, 4096); CHECK(lowat(fd) == 4096);
    uint32_t invalid = 0; errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &invalid, 1) == -1 && errno == EINVAL);
    CHECK(lowat(alias) == 4096);
    set_lowat(fd, 0); CHECK(lowat(alias) == 0); set_lowat(alias, 4096);
    int send_buffer = 262144;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0);
    socklen_t length = sizeof(send_buffer);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, &length) == 0);
    marker(control, 'R', 0);
    unsigned char bytes[4096]; memset(bytes, 0x5a, sizeof(bytes));
    uint32_t queued = 0; int unsent = 0, blocked = 0;
    struct pollfd item = {.fd = fd, .events = POLLOUT};
    for (int attempt = 0; attempt < 100 && !blocked; ++attempt) {
        for (;;) {
            ssize_t count = send(alias, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_NOSIGNAL);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) { CHECK(errno == EAGAIN || errno == EWOULDBLOCK); break; }
            CHECK(count > 0); queued += (uint32_t)count; CHECK(queued < 8 * 1024 * 1024);
        }
        int ready = poll(&item, 1, 10); CHECK(ready >= 0);
        CHECK(!(item.revents & (POLLERR | POLLHUP | POLLNVAL)));
        CHECK(ioctl(alias, SIOCOUTQNSD, &unsent) == 0);
        blocked = ready == 0 && unsent >= 4096;
    }
    CHECK(blocked && queued > 0 && queued < (uint32_t)send_buffer / 4);
    /* Toggle the actual threshold while the peer is still forbidden to read. */
    set_lowat(alias, UINT32_MAX); CHECK(lowat(fd) == UINT32_MAX);
    CHECK(poll(&item, 1, 0) == 1 && (item.revents & POLLOUT));
    set_lowat(fd, 4096); CHECK(lowat(alias) == 4096);
    CHECK(poll(&item, 1, 0) == 0);
    marker(control, 'G', 1);
    uint32_t network_count = htonl(queued); transfer(control, &network_count, sizeof(network_count), 1);
    CHECK(poll(&item, 1, 5000) == 1 && (item.revents & POLLOUT));
    marker(alias, 'P', 1); CHECK(shutdown(fd, SHUT_WR) == 0);
    marker(control, 'A', 0); eof(alias);
    CHECK(close(alias) == 0);
    printf("PASS: lowat sender queued=%u unsent=%d sndbuf=%d, threshold-only POLLOUT toggle and resumed delivery\n", queued, unsent, send_buffer);
}
static void receive_stalled(int fd, int control)
{
    marker(control, 'R', 1); marker(control, 'G', 0);
    uint32_t network_count; transfer(control, &network_count, sizeof(network_count), 0);
    uint32_t queued = ntohl(network_count), received = 0;
    CHECK(queued > 0 && queued < 8 * 1024 * 1024);
    while (received < queued) {
        unsigned char bytes[4096];
        size_t wanted = queued - received; if (wanted > sizeof(bytes)) wanted = sizeof(bytes);
        ssize_t count = recv(fd, bytes, wanted, 0);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0);
        for (ssize_t i = 0; i < count; ++i) CHECK(bytes[i] == 0x5a);
        received += (uint32_t)count;
    }
    marker(fd, 'P', 0); eof(fd); CHECK(shutdown(fd, SHUT_WR) == 0);
    marker(control, 'A', 1);
    printf("PASS: lowat receiver verified all %u queued bytes, resumed byte and EOF\n", received);
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
    printf("PASS: TCP %s TCP_NOTSENT_LOWAT backpressure, writable recovery and alias cleanup\n", argv[1]);
    return 0;
}
