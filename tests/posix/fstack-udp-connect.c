/* Ker-specific Linux connect lifecycle extension of the pinned F-Stack UDP example. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TAG UINT64_C(0xfedcba9876543210)
static void same(struct sockaddr_in actual, struct sockaddr_in expected)
{
    CHECK(actual.sin_family == AF_INET && actual.sin_addr.s_addr == expected.sin_addr.s_addr &&
          actual.sin_port == expected.sin_port);
}
static void local_matches(int fd, struct sockaddr_in expected)
{
    struct sockaddr_in actual = {0}; socklen_t length = sizeof(actual);
    CHECK(getsockname(fd, (void *)&actual, &length) == 0 && length == sizeof(actual)); same(actual, expected);
}
static void peer_matches(int fd, struct sockaddr_in expected)
{
    struct sockaddr_in actual = {0}; socklen_t length = sizeof(actual);
    CHECK(getpeername(fd, (void *)&actual, &length) == 0 && length == sizeof(actual)); same(actual, expected);
}
static int open_at(struct sockaddr_in address)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0); local_matches(fd, address); return fd;
}
static int watch(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0); return ep;
}
static void wait_event(int ep, unsigned int wanted)
{
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & wanted) && event.data.u64 == TAG);
}
static void transmit(int fd, const struct sockaddr_in *destination, uint32_t token)
{
    token = htonl(token);
    CHECK(sendto(fd, &token, sizeof(token), 0, (const void *)destination,
        destination ? sizeof(*destination) : 0) == sizeof(token));
}
static uint32_t receive_any(int fd, int ep, struct sockaddr_in *source)
{
    wait_event(ep, EPOLLIN);
    uint32_t token; socklen_t length = sizeof(*source);
    CHECK(recvfrom(fd, &token, sizeof(token), MSG_TRUNC, (void *)source, &length) == sizeof(token));
    CHECK(length == sizeof(*source)); return ntohl(token);
}
static void receive(int fd, int ep, struct sockaddr_in peer, uint32_t token)
{
    struct sockaddr_in source = {0}; CHECK(receive_any(fd, ep, &source) == token); same(source, peer);
}
static void empty(int fd)
{
    uint32_t token; errno = 0; CHECK(recv(fd, &token, sizeof(token), MSG_DONTWAIT) == -1 && errno == EAGAIN);
}
static int socket_error(int fd)
{
    int error = -1; socklen_t length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && length == sizeof(error)); return error;
}
static void rejected_source(int fd, int ep, struct sockaddr_in destination, uint32_t token)
{
    transmit(fd, &destination, token);
    /* Positive ICMP receipt proves the mismatched source was processed and rejected. */
    wait_event(ep, EPOLLERR); CHECK(socket_error(fd) == ECONNREFUSED);
    uint32_t quoted; struct iovec vector = {&quoted, sizeof(quoted)};
    union { struct cmsghdr align; unsigned char bytes[512]; } control;
    struct sockaddr_in target = {0};
    struct msghdr message = {.msg_name = &target, .msg_namelen = sizeof(target),
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)};
    CHECK(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == sizeof(quoted) && ntohl(quoted) == token);
    CHECK((message.msg_flags & MSG_ERRQUEUE) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    CHECK(message.msg_namelen == sizeof(target)); same(target, destination);
    int found = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level != IPPROTO_IP || c->cmsg_type != IP_RECVERR) continue;
        CHECK(c->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in)));
        struct sock_extended_err *error = (void *)CMSG_DATA(c);
        CHECK(error->ee_errno == ECONNREFUSED && error->ee_origin == SO_EE_ORIGIN_ICMP &&
              error->ee_type == ICMP_DEST_UNREACH && error->ee_code == ICMP_PORT_UNREACH);
        struct sockaddr_in *offender = (void *)SO_EE_OFFENDER(error);
        CHECK(offender->sin_family == AF_INET && offender->sin_addr.s_addr == destination.sin_addr.s_addr);
        ++found;
    }
    CHECK(found == 1 && socket_error(fd) == 0);
    message.msg_controllen = sizeof(control.bytes); errno = 0;
    CHECK(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == -1 && errno == EAGAIN);
}
static void serve(struct in_addr local, struct in_addr remote, unsigned short port)
{
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = local, .sin_port = htons(port)};
    struct sockaddr_in b = a; b.sin_port = htons(port + 1);
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port + 2)};
    int sockets[2] = {open_at(a), open_at(b)}, eps[2];
    for (int i = 0; i < 2; ++i) {
        int enabled = 1; CHECK(setsockopt(sockets[i], IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)) == 0);
        eps[i] = watch(sockets[i]);
    }
    printf("READY %u\n", port); fflush(stdout);
    receive(sockets[0], eps[0], peer, 1);
    rejected_source(sockets[1], eps[1], peer, 90); transmit(sockets[0], &peer, 11);
    receive(sockets[1], eps[1], peer, 2); transmit(sockets[1], &peer, 12);
    receive(sockets[0], eps[0], peer, 3);
    rejected_source(sockets[0], eps[0], peer, 91); transmit(sockets[1], &peer, 13);
    receive(sockets[1], eps[1], peer, 4); transmit(sockets[1], &peer, 14);
    receive(sockets[0], eps[0], peer, 5);
    transmit(sockets[0], &peer, 15); transmit(sockets[1], &peer, 16);
    for (int i = 0; i < 2; ++i) {
        empty(sockets[i]); CHECK(socket_error(sockets[i]) == 0);
        CHECK(close(sockets[i]) == 0 && close(eps[i]) == 0);
    }
}
static void connect_lifecycle(struct in_addr local, struct in_addr remote, unsigned short port)
{
    struct sockaddr_in own = {.sin_family = AF_INET, .sin_addr = local, .sin_port = htons(port + 2)};
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = remote, .sin_port = htons(port)};
    struct sockaddr_in b = a; b.sin_port = htons(port + 1);
    /* Explicit nonzero bind locks both local address and port across AF_UNSPEC. */
    int fd = open_at(own), alias = dup(fd), ep = watch(fd); CHECK(alias >= 0);
    CHECK(connect(alias, (void *)&a, sizeof(a)) == 0); peer_matches(fd, a);
    transmit(alias, NULL, 1); receive(fd, ep, a, 11); empty(alias);
    CHECK(connect(fd, (void *)&b, sizeof(b)) == 0); peer_matches(alias, b); local_matches(fd, own);
    transmit(alias, NULL, 2); receive(fd, ep, b, 12);
    /* Explicit destination overrides this send, without changing connected receive filtering. */
    transmit(fd, &a, 3); receive(alias, ep, b, 13); peer_matches(fd, b); empty(fd);
    transmit(alias, NULL, 4); receive(fd, ep, b, 14);
    struct sockaddr disconnect = {.sa_family = AF_UNSPEC};
    CHECK(connect(alias, &disconnect, sizeof(disconnect)) == 0);
    struct sockaddr_in actual; socklen_t length = sizeof(actual); errno = 0;
    CHECK(getpeername(fd, (void *)&actual, &length) == -1 && errno == ENOTCONN);
    local_matches(fd, own); local_matches(alias, own);
    uint32_t token = 0; errno = 0;
    CHECK(send(alias, &token, sizeof(token), 0) == -1 && errno == EDESTADDRREQ);
    CHECK(socket_error(fd) == 0);
    transmit(fd, &a, 5);
    unsigned int seen = 0;
    for (int i = 0; i < 2; ++i) {
        struct sockaddr_in source = {0}; uint32_t reply = receive_any(alias, ep, &source);
        CHECK(reply == 15 || reply == 16); unsigned int bit = 1U << (reply - 15);
        CHECK(!(seen & bit)); seen |= bit; same(source, reply == 15 ? a : b);
    }
    CHECK(seen == 3); empty(fd); CHECK(socket_error(alias) == 0);
    CHECK(close(alias) == 0 && close(fd) == 0 && close(ep) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr local, remote;
    CHECK(inet_pton(AF_INET, argv[2], &local) == 1 && inet_pton(AF_INET, argv[3], &remote) == 1);
    char *end; long port = strtol(argv[4], &end, 10); CHECK(!*end && port > 0 && port < 65534);
    if (server) serve(local, remote, port); else connect_lifecycle(local, remote, port);
    printf("PASS: UDP %s reconnect, source filtering, explicit destination, AF_UNSPEC and bound alias\n", argv[1]);
    return 0;
}
