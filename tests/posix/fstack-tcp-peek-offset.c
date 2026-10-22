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
static int peek_offset(int fd)
{
    int value; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &value, &length) == 0);
    CHECK(length == sizeof(value)); return value;
}
static void set_offset(int fd, int value)
{
    CHECK(setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &value, sizeof(value)) == 0);
    CHECK(peek_offset(fd) == value);
}
static void send_queue(int fd, int control, unsigned int seed)
{
    marker(control, 'R', 0);
    unsigned char bytes[TOTAL];
    for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = expected(i, seed);
    transfer(fd, bytes, sizeof(bytes), 1);
    CHECK(shutdown(fd, SHUT_WR) == 0); marker(control, 'S', 1);
}
static void receive_queue(int fd, int control, unsigned int seed, int use_peek_offset)
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
    if (use_peek_offset) CHECK(peek_offset(fd) == -1 && peek_offset(alias) == -1);
    unsigned char first[31], second[4096];
    for (int i = 0; i < 2; ++i) {
        CHECK(recv(alias, first, sizeof(first), MSG_PEEK | MSG_WAITALL) == (ssize_t)sizeof(first));
        verify(first, sizeof(first), 0, seed);
        if (use_peek_offset) CHECK(peek_offset(fd) == -1);
    }
    if (!use_peek_offset) {
        unsigned char consumed[257];
        transfer(fd, consumed, sizeof(consumed), 0);
        verify(consumed, sizeof(consumed), 0, seed);
        available(alias, TOTAL - (int)sizeof(consumed));
        unsigned char preview[513];
        CHECK(recv(fd, preview, sizeof(preview), MSG_PEEK | MSG_WAITALL) == (ssize_t)sizeof(preview));
        verify(preview, sizeof(preview), sizeof(consumed), seed);
        available(fd, TOTAL - (int)sizeof(consumed));
        size_t offset = sizeof(consumed);
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
        CHECK(recv(fd, preview, sizeof(preview), MSG_PEEK) == 0); available(alias, 0);
        CHECK(close(alias) == 0);
        return;
    }
    set_offset(alias, 17); CHECK(peek_offset(fd) == 17);
    int bad = 0; errno = 0;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &bad, 1) == -1 && errno == EINVAL);
    CHECK(peek_offset(alias) == 17);
    struct iovec vectors[2] = {{first, sizeof(first)}, {second, sizeof(second)}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    CHECK(recvmsg(alias, &message, MSG_PEEK | MSG_WAITALL) == (ssize_t)(sizeof(first) + sizeof(second)));
    verify(first, sizeof(first), 17, seed); verify(second, sizeof(second), 48, seed);
    CHECK(peek_offset(fd) == 4144); available(fd, TOTAL);
    unsigned char consumed[257]; transfer(fd, consumed, sizeof(consumed), 0);
    verify(consumed, sizeof(consumed), 0, seed);
    CHECK(peek_offset(alias) == 3887); available(alias, TOTAL - 257);
    unsigned char preview[513];
    CHECK(recv(fd, preview, sizeof(preview), MSG_PEEK | MSG_WAITALL) == (ssize_t)sizeof(preview));
    verify(preview, sizeof(preview), 4144, seed);
    CHECK(peek_offset(alias) == 4400); available(fd, TOTAL - 257);
    set_offset(alias, 0); CHECK(peek_offset(fd) == 0);
    CHECK(recv(fd, first, sizeof(first), MSG_PEEK | MSG_WAITALL) == (ssize_t)sizeof(first));
    verify(first, sizeof(first), 257, seed); CHECK(peek_offset(alias) == 31);
    set_offset(fd, -1); CHECK(peek_offset(alias) == -1);
    for (int i = 0; i < 2; ++i) {
        CHECK(recv(alias, first, sizeof(first), MSG_PEEK | MSG_WAITALL) == (ssize_t)sizeof(first));
        verify(first, sizeof(first), 257, seed); CHECK(peek_offset(fd) == -1);
    }
    /* A zero cursor clamps at zero as ordinary reads consume the entire queue. */
    set_offset(alias, 0);
    size_t offset = sizeof(consumed);
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
    CHECK(peek_offset(fd) == 0 && peek_offset(alias) == 0);
    eof(alias); available(fd, 0); eof(fd);
    CHECK(recv(fd, preview, sizeof(preview), MSG_PEEK) == 0); available(alias, 0);
    CHECK(close(alias) == 0);
}
static void serve(struct sockaddr_in address, unsigned short port, int use_peek_offset)
{
    int control_listener = listen_at(address, 0);
    address.sin_port = htons(port + 1); int listener = listen_at(address, 0);
    printf("READY %u\n", port); fflush(stdout);
    int control = accept4(control_listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
    timeout(control); CHECK(close(control_listener) == 0);
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);
    CHECK(close(listener) == 0);
    receive_queue(fd, control, 11, use_peek_offset); send_queue(fd, control, 197);
    marker(control, 'A', 0); CHECK(close(fd) == 0);
    eof(control); CHECK(shutdown(control, SHUT_WR) == 0 && close(control) == 0);
}
static void connect_queue(struct sockaddr_in address, unsigned short port, int use_peek_offset)
{
    int control = connect_to(address); address.sin_port = htons(port + 1);
    int fd = connect_to(address);
    send_queue(fd, control, 11); receive_queue(fd, control, 197, use_peek_offset);
    marker(control, 'A', 1); CHECK(close(fd) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
}
static int unsupported_option_error(int error)
{
    return error == EOPNOTSUPP || error == ENOPROTOOPT;
}

static int probe_peek_offset(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("SO_PEEK_OFF capability socket"); return 1; }
    int requested = -1, actual = 0;
    socklen_t length = sizeof(actual);
    if (setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &requested, sizeof(requested)) < 0) {
        int error = errno;
        close(fd);
        if (unsupported_option_error(error)) {
            printf("UNSUPPORTED: SO_PEEK_OFF: %s\n", strerror(error));
            return 77;
        }
        fprintf(stderr, "SO_PEEK_OFF capability probe failed: %s\n", strerror(error));
        return 1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &actual, &length) < 0) {
        int error = errno;
        close(fd);
        if (unsupported_option_error(error)) {
            printf("UNSUPPORTED: SO_PEEK_OFF: %s\n", strerror(error));
            return 77;
        }
        fprintf(stderr, "SO_PEEK_OFF capability readback failed: %s\n", strerror(error));
        return 1;
    }
    if (close(fd) < 0 || length != sizeof(actual) || actual != requested) {
        fprintf(stderr, "SO_PEEK_OFF capability probe returned an unexpected value\n");
        return 1;
    }
    puts("SUPPORTED: SO_PEEK_OFF");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "probe")) return probe_peek_offset();
    CHECK(argc == 5);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    int use_peek_offset = !strcmp(argv[4], "peek");
    CHECK(use_peek_offset || !strcmp(argv[4], "ordinary"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    address.sin_port = htons(port);
    if (server) serve(address, port, use_peek_offset); else connect_queue(address, port, use_peek_offset);
    printf("PASS: TCP %s bidirectional %s, alias sharing, exact bytes and EOF\n", argv[1],
           use_peek_offset ? "SO_PEEK_OFF cursor" : "ordinary peek");
    return 0;
}
