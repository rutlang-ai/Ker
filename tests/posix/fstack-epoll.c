/* Scenario adaptation of pinned F-Stack test_ff_epoll.c; see provenance.
 * No ff_*, kqueue, mocks, or private Ker interfaces: real POSIX TCP and UDP only. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define EXPECT_ERROR(call, code) do { errno = 0; CHECK((call) == -1); CHECK(errno == (code)); } while (0)

struct connection { int sender, receiver, ep; };
static struct connection connection(void)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (void *)&address, sizeof(address)) == 0);
    CHECK(listen(listener, 4) == 0);
    socklen_t length = sizeof(address);
    CHECK(getsockname(listener, (void *)&address, &length) == 0);
    int sender = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(sender >= 0);
    CHECK(connect(sender, (void *)&address, sizeof(address)) == 0);
    int receiver = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(receiver >= 0);
    CHECK(close(listener) == 0);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    return (struct connection){sender, receiver, ep};
}
static void finish(struct connection c)
{
    CHECK(close(c.ep) == 0);
    CHECK(close(c.receiver) == 0);
    CHECK(close(c.sender) == 0);
}
static void control(struct connection c, int operation, uint32_t flags, uint64_t tag)
{
    struct epoll_event event = {.events = flags, .data.u64 = tag};
    CHECK(epoll_ctl(c.ep, operation, c.receiver, operation == EPOLL_CTL_DEL ? NULL : &event) == 0);
}
static struct epoll_event event(struct connection c, uint32_t required, uint64_t tag)
{
    struct epoll_event result;
    CHECK(epoll_wait(c.ep, &result, 1, 2000) == 1);
    CHECK((result.events & required) == required);
    CHECK(result.data.u64 == tag);
    return result;
}
static void empty(struct connection c)
{
    struct epoll_event result;
    CHECK(epoll_wait(c.ep, &result, 1, 0) == 0);
}
static void put(struct connection c, const char *bytes)
{
    size_t length = strlen(bytes);
    CHECK(send(c.sender, bytes, length, MSG_NOSIGNAL) == (ssize_t)length);
}
static void take(struct connection c, const char *bytes)
{
    char buffer[32];
    size_t length = strlen(bytes);
    CHECK(length <= sizeof(buffer));
    CHECK(recv(c.receiver, buffer, length, MSG_DONTWAIT) == (ssize_t)length);
    CHECK(memcmp(buffer, bytes, length) == 0);
}
static void create_and_arguments(void)
{
    EXPECT_ERROR(epoll_create(0), EINVAL); /* F-Stack ignores size; Linux does not. */
    EXPECT_ERROR(epoll_create1(-1), EINVAL);
    int ep = epoll_create(1);
    CHECK(ep >= 0);
    CHECK(close(ep) == 0);
    struct connection c = connection();
    CHECK(fcntl(c.ep, F_GETFD) & FD_CLOEXEC);
    struct epoll_event result;
    EXPECT_ERROR(epoll_wait(c.ep, &result, 0, 0), EINVAL);
    volatile int negative_maximum = -1;
    EXPECT_ERROR(epoll_wait(c.ep, &result, negative_maximum, 0), EINVAL);
    EXPECT_ERROR(epoll_ctl(c.ep, 99, c.receiver, &result), EINVAL);
    empty(c);
    finish(c);
}
static void add_modify_delete(void)
{
    struct connection c = connection();
    control(c, EPOLL_CTL_ADD, EPOLLIN, UINT64_C(0xfedcba9876543210));
    empty(c);
    struct epoll_event ev = {.events = EPOLLIN};
    EXPECT_ERROR(epoll_ctl(c.ep, EPOLL_CTL_ADD, c.receiver, &ev), EEXIST);
    put(c, "abc");
    event(c, EPOLLIN, UINT64_C(0xfedcba9876543210));
    control(c, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT, UINT64_C(0x123456789abcdef0));
    event(c, EPOLLIN | EPOLLOUT, UINT64_C(0x123456789abcdef0));
    control(c, EPOLL_CTL_DEL, 0, 0);
    empty(c);
    EXPECT_ERROR(epoll_ctl(c.ep, EPOLL_CTL_MOD, c.receiver, &ev), ENOENT);
    EXPECT_ERROR(epoll_ctl(c.ep, EPOLL_CTL_DEL, c.receiver, NULL), ENOENT);
    take(c, "abc");
    finish(c);
}
static void level_triggered(void)
{
    struct connection c = connection();
    control(c, EPOLL_CTL_ADD, EPOLLIN, 1);
    put(c, "ab");
    event(c, EPOLLIN, 1);
    take(c, "a");
    event(c, EPOLLIN, 1);
    take(c, "b");
    empty(c);
    finish(c);
}
static void edge_triggered(void)
{
    struct connection c = connection();
    control(c, EPOLL_CTL_ADD, EPOLLIN | EPOLLET, 2);
    put(c, "ab");
    event(c, EPOLLIN, 2);
    empty(c); /* Unread data must not become a level-triggered repeat. */
    take(c, "ab");
    char byte;
    EXPECT_ERROR(recv(c.receiver, &byte, 1, MSG_DONTWAIT), EAGAIN);
    put(c, "c");
    event(c, EPOLLIN, 2);
    take(c, "c");
    empty(c);
    finish(c);
}
static void oneshot(void)
{
    struct connection c = connection();
    control(c, EPOLL_CTL_ADD, EPOLLIN | EPOLLONESHOT, 3);
    put(c, "a");
    event(c, EPOLLIN, 3);
    empty(c);
    control(c, EPOLL_CTL_MOD, EPOLLIN | EPOLLONESHOT, 4);
    event(c, EPOLLIN, 4); /* Rearming unread data must deliver it again. */
    empty(c);
    take(c, "a");
    put(c, "b");
    empty(c); /* New data cannot rearm a consumed oneshot. */
    control(c, EPOLL_CTL_MOD, EPOLLIN | EPOLLONESHOT, 5);
    event(c, EPOLLIN, 5);
    take(c, "b");
    finish(c);
}
static void write_only(void)
{
    struct connection c = connection();
    control(c, EPOLL_CTL_ADD, EPOLLOUT, 6);
    struct epoll_event result = event(c, EPOLLOUT, 6);
    CHECK(!(result.events & (EPOLLIN | EPOLLERR | EPOLLHUP)));
    control(c, EPOLL_CTL_MOD, EPOLLIN, 7);
    empty(c);
    finish(c);
}
static void eof(void)
{
    struct connection c = connection();
    control(c, EPOLL_CTL_ADD, EPOLLIN | EPOLLRDHUP, 8);
    put(c, "last");
    CHECK(shutdown(c.sender, SHUT_WR) == 0);
    event(c, EPOLLIN, 8);
    take(c, "last");
    event(c, EPOLLIN | EPOLLRDHUP, 8);
    char byte;
    CHECK(recv(c.receiver, &byte, 1, MSG_DONTWAIT) == 0);
    /* Linux half-close uses RDHUP, not the FreeBSD EOF-to-HUP translation. */
    CHECK(send(c.receiver, "reply", 5, MSG_NOSIGNAL) == 5);
    char reply[5];
    CHECK(recv(c.sender, reply, sizeof(reply), MSG_WAITALL) == 5);
    CHECK(memcmp(reply, "reply", 5) == 0);
    finish(c);
}
static void reset(void)
{
    struct connection c = connection();
    control(c, EPOLL_CTL_ADD, EPOLLIN, 9); /* ERR is reported without subscribing. */
    struct linger abortive = {.l_onoff = 1, .l_linger = 0};
    CHECK(setsockopt(c.sender, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive)) == 0);
    CHECK(close(c.sender) == 0);
    event(c, EPOLLERR | EPOLLHUP, 9);
    int error = 0;
    socklen_t length = sizeof(error);
    CHECK(getsockopt(c.receiver, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    CHECK(error == ECONNRESET);
    CHECK(close(c.receiver) == 0);
    CHECK(close(c.ep) == 0);
}
static void null_event_non_delete(void)
{
    struct connection c = connection();
    /* Linux returns EFAULT here; F-Stack's kqueue wrapper uses EINVAL. */
    EXPECT_ERROR(epoll_ctl(c.ep, EPOLL_CTL_ADD, c.receiver, NULL), EFAULT);
    control(c, EPOLL_CTL_ADD, EPOLLIN, UINT64_C(0xabcdef0123456789));
    EXPECT_ERROR(epoll_ctl(c.ep, EPOLL_CTL_MOD, c.receiver, NULL), EFAULT);
    put(c, "after-null");
    event(c, EPOLLIN, UINT64_C(0xabcdef0123456789));
    take(c, "after-null");
    CHECK(epoll_ctl(c.ep, EPOLL_CTL_DEL, c.receiver, NULL) == 0);
    empty(c); finish(c);
}
/* Call through a pointer to avoid libc's nonnull buffer diagnostics: NULL
 * is intentional and Linux only accesses it when an event is ready. */
static int null_wait(int ep, int variant, int maximum)
{
    int (*wait_fn)(int, struct epoll_event *, int, int) = epoll_wait;
    int (*pwait_fn)(int, struct epoll_event *, int, int, const sigset_t *) = epoll_pwait;
    int (*pwait2_fn)(int, struct epoll_event *, int, const struct timespec *, const sigset_t *) = epoll_pwait2;
    struct timespec zero = {0};
    if (variant == 0) return wait_fn(ep, NULL, maximum, 0);
    if (variant == 1) return pwait_fn(ep, NULL, maximum, 0, NULL);
    return pwait2_fn(ep, NULL, maximum, &zero, NULL);
}
static void null_wait_recovery(void)
{
    for (int variant = 0; variant < 3; ++variant) {
        struct connection c = connection();
        EXPECT_ERROR(null_wait(c.ep, variant, 0), EINVAL);
        CHECK(null_wait(c.ep, variant, 1) == 0);
        control(c, EPOLL_CTL_ADD, EPOLLIN | EPOLLET | EPOLLONESHOT,
            UINT64_C(0xdeadbeef01234567));
        put(c, "fault-recovery");
        /* First establish readiness, without consuming the epoll event. */
        struct pollfd ready = {.fd = c.ep, .events = POLLIN};
        CHECK(poll(&ready, 1, 2000) == 1);
        EXPECT_ERROR(null_wait(c.ep, variant, 1), EFAULT);
        event(c, EPOLLIN, UINT64_C(0xdeadbeef01234567));
        empty(c);
        take(c, "fault-recovery");
        CHECK(null_wait(c.ep, variant, 1) == 0);
        finish(c);
    }
    /* A host event in a mixed-domain epoll must also survive copy failure. */
    struct connection c = connection();
    int pipefd[2];
    CHECK(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLONESHOT, .data.u64 = 42};
    CHECK(epoll_ctl(c.ep, EPOLL_CTL_ADD, pipefd[0], &ev) == 0);
    CHECK(write(pipefd[1], "h", 1) == 1);
    EXPECT_ERROR(null_wait(c.ep, 0, 1), EFAULT);
    event(c, EPOLLIN, 42);
    empty(c);
    CHECK(close(pipefd[0]) == 0);
    CHECK(close(pipefd[1]) == 0);
    finish(c);
}
/* An empty datagram is readable even though FIONREAD is zero. It is not
 * stream EOF: PEEK leaves it queued, receiving consumes it, and the socket
 * must still receive the following nonempty datagram. */
static int datagram_wait(int ep, struct epoll_event *out, int variant, int timeout)
{
    if (variant == 0) return epoll_wait(ep, out, 1, timeout);
    if (variant == 1) return epoll_pwait(ep, out, 1, timeout, NULL);
    struct timespec duration = {.tv_sec = timeout / 1000,
        .tv_nsec = (timeout % 1000) * 1000000L};
    return epoll_pwait2(ep, out, 1, &duration, NULL);
}
static void datagram_event(int ep, int variant, int timeout, uint64_t tag)
{
    struct epoll_event out = {0};
    CHECK(datagram_wait(ep, &out, variant, timeout) == 1);
    CHECK(out.events & EPOLLIN);
    CHECK(!(out.events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)));
    CHECK(out.data.u64 == tag);
}
static void empty_datagram_readiness(void)
{
    const uint32_t modes[] = {0, EPOLLET, EPOLLONESHOT};
    for (int family_index = 0; family_index < 2; ++family_index)
    for (size_t mode = 0; mode < sizeof(modes) / sizeof(modes[0]); ++mode)
    for (int variant = 0; variant < 3; ++variant) {
        int family = family_index ? AF_INET6 : AF_INET;
        int rx = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        int tx = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        CHECK(rx >= 0 && tx >= 0);
        struct sockaddr_storage address = {0};
        socklen_t length;
        if (family == AF_INET) {
            struct sockaddr_in value = {.sin_family = AF_INET,
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
            memcpy(&address, &value, sizeof(value)); length = sizeof(value);
        } else {
            struct sockaddr_in6 value = {.sin6_family = AF_INET6,
                .sin6_addr = IN6ADDR_LOOPBACK_INIT};
            memcpy(&address, &value, sizeof(value)); length = sizeof(value);
        }
        CHECK(bind(rx, (void *)&address, length) == 0);
        CHECK(getsockname(rx, (void *)&address, &length) == 0);
        int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
        uint64_t tag = UINT64_C(0xfedcba9800000000) + family_index * 100 + mode * 10 + variant;
        struct epoll_event registration = {.events = EPOLLIN | EPOLLRDHUP | modes[mode],
            .data.u64 = tag};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, rx, &registration) == 0);
        struct epoll_event out;
        CHECK(datagram_wait(ep, &out, variant, 0) == 0);
        char byte = 'z';
        CHECK(sendto(tx, &byte, 0, 0, (void *)&address, length) == 0);
        datagram_event(ep, variant, 2000, tag);
        int available = -1;
        CHECK(ioctl(rx, FIONREAD, &available) == 0 && available == 0);
        CHECK(recv(rx, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == 0);
        if (mode == 0) datagram_event(ep, variant, 0, tag);
        else CHECK(datagram_wait(ep, &out, variant, 0) == 0);
        if (modes[mode] & EPOLLONESHOT) {
            registration.data.u64 = ++tag;
            CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, rx, &registration) == 0);
            datagram_event(ep, variant, 2000, tag);
            CHECK(datagram_wait(ep, &out, variant, 0) == 0);
        }
        CHECK(recv(rx, &byte, 1, MSG_DONTWAIT) == 0);
        EXPECT_ERROR(recv(rx, &byte, 1, MSG_DONTWAIT), EAGAIN);
        CHECK(datagram_wait(ep, &out, variant, 0) == 0);
        if (modes[mode] & EPOLLONESHOT) {
            registration.data.u64 = ++tag;
            CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, rx, &registration) == 0);
        }
        byte = 'z';
        CHECK(sendto(tx, &byte, 1, 0, (void *)&address, length) == 1);
        datagram_event(ep, variant, 2000, tag);
        CHECK(ioctl(rx, FIONREAD, &available) == 0 && available == 1);
        byte = 0;
        CHECK(recv(rx, &byte, 1, MSG_DONTWAIT) == 1 && byte == 'z');
        EXPECT_ERROR(recv(rx, &byte, 1, MSG_DONTWAIT), EAGAIN);
        CHECK(datagram_wait(ep, &out, variant, 0) == 0);
        CHECK(close(ep) == 0 && close(rx) == 0 && close(tx) == 0);
    }
}
int main(void)
{
    const struct {const char *name; void (*run)(void);} cases[] = {
        {"create-and-invalid-arguments", create_and_arguments},
        {"null-event-and-registration-recovery", null_event_non_delete},
        {"null-wait-buffer-and-oneshot-recovery", null_wait_recovery},
        {"add-modify-delete-and-u64-data", add_modify_delete},
        {"level-triggered-unread-data", level_triggered},
        {"edge-triggered-drain-and-new-data", edge_triggered},
        {"oneshot-explicit-rearm", oneshot},
        {"write-only-readiness-and-modify", write_only},
        {"half-close-buffered-data-and-eof", eof},
        {"reset-error-and-hangup", reset},
        {"empty-UDP-datagram-IPv4-IPv6-LT-ET-ONESHOT-wait-variants", empty_datagram_readiness},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cases[i].run();
        printf("PASS: fstack epoll %s\n", cases[i].name);
        fflush(stdout);
    }
    return 0;
}
