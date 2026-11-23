/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
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
#define TOTAL (16 * 1024 + 37)
static unsigned char expected(size_t offset, unsigned int seed)
{
    return (unsigned char)((offset * 31 + offset / 251 + seed) & 255);
}
static void verify(const unsigned char *bytes, size_t length, size_t offset, unsigned int seed)
{
    for (size_t i = 0; i < length; ++i) CHECK(bytes[i] == expected(offset + i, seed));
}
static void available(int fd, int wanted)
{
    int bytes = -1; CHECK(ioctl(fd, FIONREAD, &bytes) == 0 && bytes == wanted);
}
static void untouched(const unsigned char *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i) CHECK(bytes[i] == 0xa5);
}
static void send_queue(int fd, int control, unsigned int seed)
{
    marker(control, 'R', 0);
    unsigned char bytes[TOTAL];
    for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = expected(i, seed);
    transfer(fd, bytes, sizeof(bytes), 1);
    CHECK(shutdown(fd, SHUT_WR) == 0); marker(control, 'S', 1);
}
static void receive_queue(int fd, int control, unsigned int seed)
{
    /* The full queued payload, or its ordered FIN, must precede inspection. */
    int low_water = TOTAL;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &low_water, sizeof(low_water)) == 0);
    marker(control, 'R', 1); marker(control, 'S', 0);
    struct pollfd target = {.fd = fd, .events = POLLIN};
    CHECK(poll(&target, 1, 5000) == 1 && (target.revents & POLLIN));
    available(fd, TOTAL);
    low_water = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &low_water, sizeof(low_water)) == 0);
    int alias = dup(fd); CHECK(alias >= 0);
    unsigned char first[31], second[4096];
    struct iovec vectors[2] = {{first, sizeof(first)}, {second, sizeof(second)}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    CHECK(recvmsg(alias, &message, MSG_PEEK | MSG_WAITALL) == (ssize_t)(sizeof(first) + sizeof(second)));
    CHECK(!(message.msg_flags & MSG_TRUNC));
    verify(first, sizeof(first), 0, seed); verify(second, sizeof(second), sizeof(first), seed);
    available(fd, TOTAL); available(alias, TOTAL);
    unsigned char peek[6001];
    CHECK(recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_WAITALL) == (ssize_t)sizeof(peek));
    verify(peek, sizeof(peek), 0, seed); available(alias, TOTAL);
    /* Linux TCP MSG_TRUNC discards bytes without touching the destination. */
    unsigned char discard[257]; memset(discard, 0xa5, sizeof(discard));
    CHECK(recv(alias, discard, sizeof(discard), MSG_TRUNC) == (ssize_t)sizeof(discard));
    untouched(discard, sizeof(discard)); available(fd, TOTAL - (int)sizeof(discard));
    unsigned char preview[513]; memset(preview, 0xa5, sizeof(preview));
    struct iovec preview_vector = {preview, sizeof(preview)};
    message = (struct msghdr){.msg_iov = &preview_vector, .msg_iovlen = 1};
    CHECK(recvmsg(fd, &message, MSG_PEEK | MSG_TRUNC) == (ssize_t)sizeof(preview));
    untouched(preview, sizeof(preview)); available(alias, TOTAL - (int)sizeof(discard));
    size_t offset = sizeof(discard);
    while (offset < TOTAL) {
        unsigned char left[17], right[1007];
        size_t wanted = TOTAL - offset;
        if (wanted > sizeof(left) + sizeof(right)) wanted = sizeof(left) + sizeof(right);
        size_t left_size = wanted < sizeof(left) ? wanted : sizeof(left);
        struct iovec parts[2] = {{left, left_size}, {right, wanted - left_size}};
        ssize_t count = readv(alias, parts, 2); CHECK(count > 0 && (size_t)count <= wanted);
        size_t left_count = (size_t)count < left_size ? (size_t)count : left_size;
        verify(left, left_count, offset, seed);
        verify(right, (size_t)count - left_count, offset + left_count, seed);
        offset += (size_t)count; available(fd, TOTAL - (int)offset);
    }
    eof(alias); available(fd, 0); eof(fd);
    CHECK(recv(fd, peek, sizeof(peek), MSG_PEEK) == 0); available(alias, 0);
    CHECK(close(alias) == 0);
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
    receive_queue(fd, control, 11); send_queue(fd, control, 197);
    marker(control, 'A', 0); CHECK(close(fd) == 0);
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0 && close(control) == 0);
}
static void connect_queue(struct sockaddr_in address, unsigned short port)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    int fd = connect_to(address);
    send_queue(fd, control, 11); receive_queue(fd, control, 197);
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
    if (server) serve(address, port); else connect_queue(address, port);
    printf("PASS: TCP %s bidirectional peek, FIONREAD, truncation, shared queue and EOF\n", argv[1]);
    return 0;
}
