/* Blocking send/backpressure extension of pinned F-Stack host bridge scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TOTAL (512U * 1024U + 13U)
static double now(void)
{
    struct timespec time; CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return time.tv_sec + time.tv_nsec / 1e9;
}
static void expired(double start)
{
    double elapsed = now() - start;
    if (elapsed < 0.05 || elapsed > 5) fprintf(stderr, "send timeout elapsed %.6f seconds\n", elapsed);
    CHECK(elapsed >= 0.05 && elapsed <= 5);
}
static struct timeval get_timeout(int fd)
{
    struct timeval value; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, &length) == 0);
    CHECK(length == sizeof(value)); return value;
}
static void set_timeout(int fd, int option, long seconds, long microseconds)
{
    struct timeval value = {.tv_sec = seconds, .tv_usec = microseconds};
    CHECK(setsockopt(fd, SOL_SOCKET, option, &value, sizeof(value)) == 0);
}
static void ready(int fd, short events)
{
    struct pollfd target = {.fd = fd, .events = events};
    int count;
    do { count = poll(&target, 1, 5000); } while (count < 0 && errno == EINTR);
    CHECK(count == 1 && (target.revents & events));
}
static void send_marker(int fd, char value)
{
    CHECK(send(fd, &value, 1, MSG_NOSIGNAL) == 1);
}
static void expect_marker(int fd, char expected)
{
    char value; CHECK(recv(fd, &value, 1, MSG_WAITALL) == 1 && value == expected);
}
static unsigned char byte_at(size_t offset, unsigned int seed)
{
    return (unsigned char)(offset * 71U + seed);
}
static ssize_t offer(int fd, unsigned char *bytes, size_t length, int api)
{
    size_t split = length / 2;
    struct iovec vectors[] = {{bytes, 0}, {bytes, split}, {bytes + split, length - split}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 3};
    if (api == 1) return writev(fd, vectors, 3);
    if (api == 2) return sendmsg(fd, &message, MSG_NOSIGNAL);
    return send(fd, bytes, length, MSG_NOSIGNAL);
}
static void send_phase(int fd, int control, unsigned int seed)
{
    unsigned char *bytes = malloc(TOTAL); CHECK(bytes);
    for (size_t i = 0; i < TOTAL; ++i) bytes[i] = byte_at(i, seed);
    int size = 4096;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    set_timeout(fd, SO_SNDTIMEO, 0, 120000);
    struct timeval value = get_timeout(fd);
    CHECK(value.tv_sec == 0 && value.tv_usec >= 120000 && value.tv_usec <= 200000);
    int alias = dup(fd); CHECK(alias >= 0);
    struct timeval invalid = {.tv_usec = 1000000}; errno = 0;
    CHECK(setsockopt(alias, SOL_SOCKET, SO_SNDTIMEO, &invalid, sizeof(invalid)) == -1 && errno == EDOM);
    struct timeval unchanged = get_timeout(alias);
    CHECK(unchanged.tv_sec == value.tv_sec && unchanged.tv_usec == value.tv_usec);
    send_marker(control, 'P');
    double start = now();
    ssize_t count = offer(fd, bytes, TOTAL, 0);
    CHECK(count > 0 && (size_t)count < TOTAL); expired(start);
    size_t sent = (size_t)count;
    unsigned int partial = 1, timed_out = 0;
    /* The peer cannot read until R. Account for any progress before requiring
     * each API to demonstrate a no-progress timeout; never resend that prefix. */
    for (int api = 0; api < 3; ++api) {
        int exhausted = 0;
        for (int attempt = 0; attempt < 8; ++attempt) {
            CHECK(sent < TOTAL);
            start = now(); errno = 0;
            count = offer(fd, bytes + sent, TOTAL - sent, api);
            int error = errno;
            if (count < 0) {
                CHECK(error == EAGAIN); expired(start);
                ++timed_out; exhausted = 1; break;
            }
            CHECK(count > 0 && (size_t)count < TOTAL - sent);
            sent += (size_t)count; ++partial;
        }
        CHECK(exhausted);
    }
    set_timeout(alias, SO_SNDTIMEO, 0, 0);
    value = get_timeout(fd); CHECK(value.tv_sec == 0 && value.tv_usec == 0);
    CHECK(close(alias) == 0);
    send_marker(control, 'R');
    while (sent < TOTAL) {
        ready(fd, POLLOUT);
        size_t length = TOTAL - sent;
        if (length > 16384) length = 16384;
        count = offer(fd, bytes + sent, length, 2);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0 && (size_t)count <= length); sent += (size_t)count;
    }
    send_marker(control, 'D'); expect_marker(control, 'A');
    printf("send pressure seed=%u partial=%u timeout_apis=%u bytes=%u\n", seed, partial, timed_out, TOTAL);
    free(bytes);
}
static void receive_phase(int fd, int control, unsigned int seed)
{
    expect_marker(control, 'P');
    /* No data reads before R: progress is bounded by the deliberately small
     * receive window, independently of host/application scheduling. */
    expect_marker(control, 'R');
    int size = 1024 * 1024;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0);
    set_timeout(fd, SO_RCVTIMEO, 5, 0);
    unsigned char bytes[16384]; size_t received = 0;
    while (received < TOTAL) {
        size_t length = TOTAL - received;
        if (length > sizeof(bytes)) length = sizeof(bytes);
        ssize_t count = recv(fd, bytes, length, 0);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0);
        for (ssize_t i = 0; i < count; ++i) CHECK(bytes[i] == byte_at(received + (size_t)i, seed));
        received += (size_t)count;
    }
    expect_marker(control, 'D'); send_marker(control, 'A');
}
static int create(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    int size = 4096;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0);
    set_timeout(fd, SO_RCVTIMEO, 10, 0);
    return fd;
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10);
    CHECK(!*end && port > 0 && port <= 65535); address.sin_port = htons(port);
    int control, data;
    if (server) {
        int listener = create(), enabled = 1;
        CHECK(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0);
        CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 4) == 0);
        printf("READY %ld\n", port); fflush(stdout);
        control = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0);
        data = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(data >= 0);
        CHECK(close(listener) == 0);
    } else {
        control = create(); CHECK(connect(control, (void *)&address, sizeof(address)) == 0);
        data = create(); CHECK(connect(data, (void *)&address, sizeof(address)) == 0);
    }
    int flags = fcntl(data, F_GETFL); CHECK(flags >= 0 && !(flags & O_NONBLOCK));
    if (server) { receive_phase(data, control, 17); send_phase(data, control, 93); }
    else { send_phase(data, control, 17); receive_phase(data, control, 93); }
    CHECK(shutdown(data, SHUT_WR) == 0);
    char byte; CHECK(recv(data, &byte, 1, 0) == 0);
    CHECK(close(data) == 0 && close(control) == 0);
    printf("PASS: TCP %s blocking send timeouts, partial progress and bidirectional recovery\n", argv[1]);
    return 0;
}
