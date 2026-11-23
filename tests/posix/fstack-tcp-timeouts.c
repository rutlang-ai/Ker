/* Ker-specific blocking TCP extension of pinned F-Stack host bridge scenarios. */
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
static double now(void)
{
    struct timespec time; CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return time.tv_sec + time.tv_nsec / 1e9;
}
static void expired(double start)
{
    double elapsed = now() - start;
    /* Permit scheduler/tick rounding; detect immediate return or a broken timer. */
    if (elapsed < 0.05 || elapsed > 5) fprintf(stderr, "timeout elapsed %.6f seconds\n", elapsed);
    CHECK(elapsed >= 0.05 && elapsed <= 5);
}
static struct timeval timeout(int fd)
{
    struct timeval value; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, &length) == 0);
    CHECK(length == sizeof(value)); return value;
}
static void set_timeout(int fd, long seconds, long microseconds)
{
    struct timeval value = {.tv_sec = seconds, .tv_usec = microseconds};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) == 0);
}
static void short_timeout(int fd)
{
    struct timeval value = timeout(fd);
    CHECK(value.tv_sec == 0 && value.tv_usec >= 120000 && value.tv_usec <= 200000);
}
static void readable(int fd)
{
    struct pollfd event = {.fd = fd, .events = POLLIN};
    int count;
    do { count = poll(&event, 1, 5000); } while (count < 0 && errno == EINTR);
    CHECK(count == 1 && (event.revents & POLLIN));
}
static void transmit(int fd, const char *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0); offset += (size_t)count;
    }
}
static void marker(int fd, char expected)
{
    char byte;
    CHECK(recv(fd, &byte, 1, MSG_WAITALL) == 1 && byte == expected);
}
static void empty_reads(int fd)
{
    char bytes[16];
    struct iovec vectors[] = {{bytes, 0}, {bytes, sizeof(bytes)}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    for (int api = 0; api < 3; ++api) {
        double start = now(); errno = 0;
        ssize_t count = api == 0 ? recv(fd, bytes, sizeof(bytes), 0) :
            api == 1 ? recvmsg(fd, &message, 0) : readv(fd, vectors, 2);
        int error = errno;
        CHECK(count == -1 && error == EAGAIN); expired(start);
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10);
    CHECK(!*end && port > 0 && port <= 65535); address.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    if (server) {
        int enabled = 1;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0);
        CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 4) == 0);
        set_timeout(fd, 0, 120000); short_timeout(fd);
        double start = now(); errno = 0;
        CHECK(accept(fd, NULL, NULL) == -1 && errno == EAGAIN); expired(start);
        /* The harness cannot connect until READY, so accept timeout is deterministic. */
        printf("READY %ld\n", port); fflush(stdout);
        /* Avoid imposing a 120ms scheduling deadline on the eventual connect. */
        readable(fd);
        int accepted = accept4(fd, NULL, NULL, SOCK_CLOEXEC); CHECK(accepted >= 0);
        short_timeout(accepted); /* Linux inherits the listener's receive timeout. */
        CHECK(close(fd) == 0); fd = accepted;
        int flags = fcntl(fd, F_GETFL); CHECK(flags >= 0 && !(flags & O_NONBLOCK));
        set_timeout(fd, 5, 0);
        marker(fd, 'R'); transmit(fd, "hello", 5);
        marker(fd, 'S'); transmit(fd, "world", 5);
        CHECK(shutdown(fd, SHUT_WR) == 0);
        marker(fd, 'A'); char byte; CHECK(recv(fd, &byte, 1, 0) == 0);
    } else {
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
        int flags = fcntl(fd, F_GETFL); CHECK(flags >= 0 && !(flags & O_NONBLOCK));
        set_timeout(fd, 0, 120000); short_timeout(fd);
        int alias = dup(fd); CHECK(alias >= 0); short_timeout(alias);
        struct timeval invalid = {.tv_usec = 1000000}; errno = 0;
        CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVTIMEO, &invalid, sizeof(invalid)) == -1 && errno == EDOM);
        short_timeout(fd); /* Rejected values leave the previous timeout intact. */
        empty_reads(fd);
        transmit(fd, "R", 1); readable(fd);
        char bytes[16]; double start = now();
        CHECK(recv(fd, bytes, 10, MSG_WAITALL) == 5 && !memcmp(bytes, "hello", 5));
        expired(start); /* Progress is returned, rather than discarded as EAGAIN. */
        start = now(); errno = 0;
        CHECK(recv(fd, bytes, sizeof(bytes), 0) == -1 && errno == EAGAIN); expired(start);
        set_timeout(alias, 0, 0);
        struct timeval value = timeout(fd); CHECK(value.tv_sec == 0 && value.tv_usec == 0);
        CHECK(close(alias) == 0);
        transmit(fd, "S", 1); readable(fd);
        /* With the timeout disabled, EOF still ends WAITALL after partial progress. */
        CHECK(recv(fd, bytes, sizeof(bytes), MSG_WAITALL) == 5 && !memcmp(bytes, "world", 5));
        CHECK(recv(fd, bytes, sizeof(bytes), 0) == 0);
        transmit(fd, "A", 1); CHECK(shutdown(fd, SHUT_WR) == 0);
    }
    CHECK(close(fd) == 0);
    printf("PASS: TCP %s receive timeouts, inherited options, partial WAITALL and recovery\n", argv[1]);
    return 0;
}
