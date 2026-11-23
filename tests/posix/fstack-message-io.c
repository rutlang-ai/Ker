/* Public POSIX adaptations of pinned F-Stack host bridge scenarios.
 * Real host/native TCP; no ff_* implementation, cmocka, or private Ker API. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define ERROR(call, code) do { errno = 0; CHECK((call) == -1); CHECK(errno == (code)); } while (0)

struct connection { int a, b; struct sockaddr_in server, client; };
static struct connection connection(void)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    struct connection c = {.server = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)}};
    CHECK(bind(listener, (void *)&c.server, sizeof(c.server)) == 0);
    CHECK(listen(listener, 4) == 0);
    socklen_t length = sizeof(c.server);
    CHECK(getsockname(listener, (void *)&c.server, &length) == 0);
    CHECK(length == sizeof(c.server) && c.server.sin_port != 0);
    c.a = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(c.a >= 0);
    CHECK(connect(c.a, (void *)&c.server, sizeof(c.server)) == 0);
    c.b = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    CHECK(c.b >= 0);
    length = sizeof(c.client);
    CHECK(getsockname(c.a, (void *)&c.client, &length) == 0);
    CHECK(length == sizeof(c.client) && c.client.sin_port != 0);
    CHECK(close(listener) == 0);
    return c;
}
static void finish(struct connection c)
{
    CHECK(close(c.a) == 0);
    CHECK(close(c.b) == 0);
}
static void readable(int fd)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    CHECK(poll(&p, 1, 2000) == 1);
    CHECK(p.revents & POLLIN);
}
static void received(int fd, const char *expected)
{
    char buffer[128];
    size_t length = strlen(expected);
    CHECK(length <= sizeof(buffer));
    CHECK(recv(fd, buffer, length, MSG_WAITALL) == (ssize_t)length);
    CHECK(memcmp(buffer, expected, length) == 0);
}
static void address(int fd, int peer, struct sockaddr_in expected)
{
    struct sockaddr_in actual = {0};
    socklen_t length = sizeof(actual);
    CHECK((peer ? getpeername(fd, (void *)&actual, &length) :
        getsockname(fd, (void *)&actual, &length)) == 0);
    CHECK(length == sizeof(actual));
    CHECK(actual.sin_family == expected.sin_family);
    CHECK(actual.sin_addr.s_addr == expected.sin_addr.s_addr);
    CHECK(actual.sin_port == expected.sin_port);
}
static void message_names_shutdown(void)
{
    struct connection c = connection();
    address(c.a, 0, c.client); address(c.a, 1, c.server);
    address(c.b, 0, c.server); address(c.b, 1, c.client);
    char first[] = "header-", second[] = "payload";
    struct iovec outgoing[] = {{first, 7}, {NULL, 0}, {second, 7}};
    struct msghdr send_header = {.msg_iov = outgoing, .msg_iovlen = 3};
    CHECK(sendmsg(c.a, &send_header, MSG_NOSIGNAL) == 14);
    CHECK(shutdown(c.a, SHUT_WR) == 0);
    char left[4], right[10];
    struct iovec incoming[] = {{left, sizeof(left)}, {right, sizeof(right)}};
    struct msghdr recv_header = {.msg_iov = incoming, .msg_iovlen = 2};
    CHECK(recvmsg(c.b, &recv_header, MSG_WAITALL) == 14);
    CHECK(memcmp(left, "head", 4) == 0 && memcmp(right, "er-payload", 10) == 0);
    CHECK(recv_header.msg_flags == 0);
    CHECK(recvmsg(c.b, &recv_header, 0) == 0);
    CHECK(send(c.b, "reverse", 7, MSG_NOSIGNAL) == 7);
    received(c.a, "reverse");
    finish(c);
}
static void vectors(int a, int b)
{
    char first[] = "alpha", second[] = "-beta-", third[] = "gamma!";
    struct iovec outgoing[] = {{first, 5}, {NULL, 0}, {second, 6}, {third, 6}};
    CHECK(writev(a, outgoing, 4) == 17);
    CHECK(shutdown(a, SHUT_WR) == 0);
    char left[8] = {0}, right[16] = {0}, joined[17];
    struct iovec incoming[] = {{NULL, 0}, {left, sizeof(left)}, {right, sizeof(right)}};
    /* EOF makes a short vector read deterministic without assuming TCP framing. */
    size_t used = 0;
    while (used < sizeof(joined)) {
        ssize_t count = readv(b, incoming, 3);
        CHECK(count > 0 && (size_t)count <= sizeof(joined) - used);
        size_t prefix = (size_t)count < sizeof(left) ? (size_t)count : sizeof(left);
        memcpy(joined + used, left, prefix);
        memcpy(joined + used + prefix, right, (size_t)count - prefix);
        used += (size_t)count;
    }
    CHECK(memcmp(joined, "alpha-beta-gamma!", sizeof(joined)) == 0);
    CHECK(readv(b, incoming, 3) == 0);
    CHECK(writev(b, NULL, 0) == 0);
    CHECK(readv(b, NULL, 0) == 0);
}
static void vector_io(void)
{
    struct connection c = connection();
    vectors(c.a, c.b);
    finish(c);
    int host[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, host) == 0);
    vectors(host[0], host[1]);
    CHECK(close(host[0]) == 0 && close(host[1]) == 0);
}
static void nonblocking_ioctl(void)
{
    struct connection c = connection();
    int on = 1, off = 0;
    CHECK(ioctl(c.b, FIONBIO, &on) == 0);
    CHECK(fcntl(c.b, F_GETFL) & O_NONBLOCK);
    char buffer[8];
    struct iovec iov = {buffer, sizeof(buffer)};
    struct msghdr header = {.msg_iov = &iov, .msg_iovlen = 1};
    ERROR(recvmsg(c.b, &header, 0), EAGAIN);
    ERROR(readv(c.b, &iov, 1), EAGAIN);
    CHECK(send(c.a, "peek", 4, MSG_NOSIGNAL) == 4);
    readable(c.b);
    int available = -1;
    CHECK(ioctl(c.b, FIONREAD, &available) == 0 && available == 4);
    CHECK(recvmsg(c.b, &header, MSG_PEEK | MSG_DONTWAIT) == 4);
    CHECK(memcmp(buffer, "peek", 4) == 0);
    CHECK(ioctl(c.b, FIONREAD, &available) == 0 && available == 4);
    received(c.b, "peek");
    CHECK(ioctl(c.b, FIONREAD, &available) == 0 && available == 0);
    CHECK(ioctl(c.b, FIONBIO, &off) == 0);
    CHECK(!(fcntl(c.b, F_GETFL) & O_NONBLOCK));
    ERROR(recv(c.b, buffer, sizeof(buffer), MSG_DONTWAIT), EAGAIN);
    CHECK(!(fcntl(c.b, F_GETFL) & O_NONBLOCK));
    finish(c);
}
static void duplicate_lifetime(void)
{
    struct connection c = connection();
    int alias = dup(c.a);
    CHECK(alias >= 0 && alias != c.a);
    CHECK(fcntl(alias, F_GETFD) == 0);
    CHECK(fcntl(c.a, F_GETFD) & FD_CLOEXEC);
    int on = 1;
    CHECK(ioctl(alias, FIONBIO, &on) == 0);
    CHECK(fcntl(c.a, F_GETFL) & O_NONBLOCK);
    CHECK(send(alias, "alias", 5, MSG_NOSIGNAL) == 5);
    received(c.b, "alias");
    CHECK(close(alias) == 0);
    CHECK(write(c.a, "owner", 5) == 5);
    received(c.b, "owner");
    finish(c);
}
static void fixed_duplicate(void)
{
    struct connection c = connection();
    int host[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, host) == 0);
    /* Native socket replaces a host endpoint and clears descriptor CLOEXEC. */
    CHECK(dup2(c.a, host[0]) == host[0]);
    CHECK(fcntl(host[0], F_GETFD) == 0);
    CHECK(write(host[0], "native", 6) == 6);
    received(c.b, "native");
    /* Host socket replaces that native alias; original native owner survives. */
    int source[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, source) == 0);
    CHECK(dup2(source[0], host[0]) == host[0]);
    CHECK(write(host[0], "host", 4) == 4);
    received(source[1], "host");
    CHECK(close(source[0]) == 0 && close(source[1]) == 0);
    CHECK(write(c.a, "retained", 8) == 8);
    received(c.b, "retained");
    CHECK(close(host[0]) == 0 && close(host[1]) == 0);
    finish(c);
}
static void message_short_read(void)
{
    struct connection c = connection();
    char payload[] = "abcdefgh";
    struct iovec outgoing = {payload, sizeof(payload) - 1};
    struct msghdr header = {.msg_iov = &outgoing, .msg_iovlen = 1};
    CHECK(sendmsg(c.a, &header, MSG_NOSIGNAL) == 8);
    CHECK(shutdown(c.a, SHUT_WR) == 0);
    char a[2], b[1];
    struct iovec incoming[] = {{a, sizeof(a)}, {b, sizeof(b)}};
    header = (struct msghdr){.msg_iov = incoming, .msg_iovlen = 2};
    CHECK(recvmsg(c.b, &header, MSG_WAITALL) == 3);
    CHECK(memcmp(a, "ab", 2) == 0 && b[0] == 'c');
    CHECK(!(header.msg_flags & MSG_TRUNC)); /* Stream remainder is retained. */
    received(c.b, "defgh");
    CHECK(recvmsg(c.b, &header, MSG_WAITALL) == 0);
    finish(c);
}
int main(void)
{
    const struct {const char *name; void (*run)(void);} cases[] = {
        {"message-names-and-half-close", message_names_shutdown},
        {"scatter-gather-tcp-and-host-unix", vector_io},
        {"nonblocking-ioctl-peek-and-queue-length", nonblocking_ioctl},
        {"dup-shared-status-and-independent-lifetime", duplicate_lifetime},
        {"dup2-host-native-replacement", fixed_duplicate},
        {"short-message-read-retains-stream-remainder", message_short_read},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cases[i].run();
        printf("PASS: fstack message I/O %s\n", cases[i].name);
        fflush(stdout);
    }
    return 0;
}
