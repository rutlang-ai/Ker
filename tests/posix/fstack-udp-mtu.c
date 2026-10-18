/* Linux-specific MTU/fragmentation extension of the pinned F-Stack UDP example. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define MAXIMUM 65507
static const size_t lengths[] = {1472, 1473, 4096, MAXIMUM};
static void fill(unsigned char *bytes, size_t length, int record, int reply)
{
    for (size_t i = 0; i < length; ++i) bytes[i] = (unsigned char)(i * 71 + record * 29 + reply * 93);
}
static void wait_event(int ep, unsigned int flags)
{
    struct epoll_event event;
    int count;
    do { count = epoll_wait(ep, &event, 1, 5000); } while (count < 0 && errno == EINTR);
    if (count != 1 || !(event.events & flags))
        fprintf(stderr, "epoll result=%d flags=%#x expected=%#x\n", count, count == 1 ? event.events : 0, flags);
    CHECK(count == 1 && (event.events & flags) && event.data.u64 == 0x4d5455);
}
static void discovery(int fd, int mode)
{
    CHECK(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)) == 0);
    int actual = -1; socklen_t length = sizeof(actual);
    CHECK(getsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &actual, &length) == 0);
    CHECK(length == sizeof(actual) && actual == mode);
}
static void drain_error(int fd, int ep, struct sockaddr_in peer)
{
    unsigned char bytes[1473];
    wait_event(ep, EPOLLERR);
    union { struct cmsghdr align; unsigned char bytes[512]; } control;
    struct sockaddr_in destination = {0};
    struct iovec vector = {bytes, sizeof(bytes)};
    struct msghdr message = {.msg_name = &destination, .msg_namelen = sizeof(destination),
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)};
    /* Linux local MTU errors carry metadata, with no quoted payload. */
    CHECK(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == 0);
    CHECK((message.msg_flags & MSG_ERRQUEUE) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    CHECK(message.msg_namelen == sizeof(destination) && destination.sin_family == AF_INET);
    CHECK(destination.sin_addr.s_addr == peer.sin_addr.s_addr && destination.sin_port == peer.sin_port);
    int found = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level != IPPROTO_IP || c->cmsg_type != IP_RECVERR) continue;
        CHECK(c->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in)));
        struct sock_extended_err *error = (void *)CMSG_DATA(c);
        CHECK(error->ee_errno == EMSGSIZE && error->ee_origin == SO_EE_ORIGIN_LOCAL);
        CHECK(error->ee_info == 1500 && error->ee_type == 0 && error->ee_code == 0);
        CHECK(SO_EE_OFFENDER(error)->sa_family == AF_UNSPEC);
        ++found;
    }
    CHECK(found == 1);
    message.msg_controllen = sizeof(control.bytes);
    errno = 0;
    CHECK(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == -1 && errno == EAGAIN);
    struct epoll_event event;
    int count = epoll_wait(ep, &event, 1, 0);
    /* The peer may already have sent recovery data; only ERR must clear. */
    CHECK(count == 0 || (count == 1 && !(event.events & EPOLLERR) &&
        event.data.u64 == 0x4d5455));
}
static void oversized(int fd, int ep, struct sockaddr_in peer)
{
    CHECK(connect(fd, (void *)&peer, sizeof(peer)) == 0);
    int mtu = 0; socklen_t length = sizeof(mtu);
    CHECK(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &length) == 0);
    CHECK(length == sizeof(mtu) && mtu == 1500);
    discovery(fd, IP_PMTUDISC_DO);
    unsigned char bytes[1473] = {0};
    errno = 0;
    CHECK(send(fd, bytes, sizeof(bytes), 0) == -1 && errno == EMSGSIZE);
    drain_error(fd, ep, peer);
}
static void transmit(int fd, int record, int reply)
{
    unsigned char bytes[MAXIMUM]; fill(bytes, lengths[record], record, reply);
    ssize_t count;
    do { count = send(fd, bytes, lengths[record], 0); } while (count < 0 && errno == EINTR);
    CHECK(count == (ssize_t)lengths[record]);
}
static void receive(int fd, int ep, struct sockaddr_in *peer, int record, int reply)
{
    wait_event(ep, EPOLLIN);
    unsigned char bytes[MAXIMUM], expected[MAXIMUM]; fill(expected, lengths[record], record, reply);
    struct sockaddr_in source = {0};
    struct iovec vector = {bytes, sizeof(bytes)};
    struct msghdr message = {.msg_name = &source, .msg_namelen = sizeof(source),
        .msg_iov = &vector, .msg_iovlen = 1};
    CHECK(recvmsg(fd, &message, 0) == (ssize_t)lengths[record]);
    CHECK(!(message.msg_flags & MSG_TRUNC) && !memcmp(bytes, expected, lengths[record]));
    CHECK(message.msg_namelen == sizeof(source) && source.sin_family == AF_INET);
    CHECK(source.sin_addr.s_addr == peer->sin_addr.s_addr && source.sin_port != 0);
    if (peer->sin_port) CHECK(source.sin_port == peer->sin_port);
    *peer = source;
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in local = {.sin_family = AF_INET}, peer = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &local.sin_addr) == 1);
    CHECK(inet_pton(AF_INET, argv[3], &peer.sin_addr) == 1);
    char *end; long port = strtol(argv[4], &end, 10);
    CHECK(!*end && port > 0 && port <= 65535);
    if (server) local.sin_port = htons(port); else peer.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    int enabled = 1;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)) == 0);
    CHECK(bind(fd, (void *)&local, sizeof(local)) == 0);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x4d5455};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    if (server) { printf("READY %ld\n", port); fflush(stdout); }
    else oversized(fd, ep, peer);
    for (int record = 0; record < 4; ++record) {
        if (record == 1) discovery(fd, IP_PMTUDISC_DONT);
        if (!server) transmit(fd, record, 0);
        receive(fd, ep, &peer, record, !server);
        if (server) {
            if (!record) oversized(fd, ep, peer);
            transmit(fd, record, 1);
        }
    }
    unsigned char too_large[MAXIMUM + 1] = {0};
    errno = 0;
    CHECK(send(fd, too_large, sizeof(too_large), 0) == -1 && errno == EMSGSIZE);
    drain_error(fd, ep, peer);
    /* Rejection above must not consume, split or poison a subsequent datagram. */
    if (!server) transmit(fd, 0, 0);
    receive(fd, ep, &peer, 0, !server);
    if (server) transmit(fd, 0, 1);
    errno = 0;
    CHECK(recv(fd, too_large, sizeof(too_large), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(close(ep) == 0 && close(fd) == 0);
    printf("PASS: UDP %s MTU errors, 1472/1473/4096/65507-byte datagrams and same-socket recovery\n", argv[1]);
    return 0;
}
