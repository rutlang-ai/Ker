/* Linux-specific error-queue extension of the F-Stack UDP socket scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static const char payload[] = "quoted UDP payload with recovery";
static void wait_event(int ep, unsigned int flags)
{
    struct epoll_event event;
    int n;
    do { n = epoll_wait(ep, &event, 1, 5000); } while (n < 0 && errno == EINTR);
    CHECK(n == 1 && (event.events & flags) && event.data.u64 == 0x455252);
}
int main(int argc, char **argv)
{
    CHECK(argc == 6);
    int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    int connected = !strcmp(argv[5], "connected");
    CHECK(connected || !strcmp(argv[5], "unconnected"));
    char *end;
    long port = strtol(argv[3], &end, 10);
    CHECK(!*end && port > 0 && port < 65535);
    long closed_port = strtol(argv[4], &end, 10);
    CHECK(!*end && closed_port > 0 && closed_port <= 65535 && closed_port != port);
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, argv[2], &peer.sin_addr) == 1);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    /* ERR must be reported even though the application requests only IN. */
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x455252};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    char bytes[128];
    if (server) {
        CHECK(bind(fd, (void *)&peer, sizeof(peer)) == 0);
        printf("READY %ld\n", port); fflush(stdout);
        wait_event(ep, EPOLLIN);
        socklen_t length = sizeof(peer);
        CHECK(recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&peer, &length) == sizeof(payload));
        CHECK(length == sizeof(peer) && !memcmp(bytes, payload, sizeof(payload)));
        CHECK(sendto(fd, bytes, sizeof(payload), 0, (void *)&peer, sizeof(peer)) == sizeof(payload));
    } else {
        int enabled = 1;
        CHECK(setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)) == 0);
        struct sockaddr_in missing = peer;
        missing.sin_port = htons(closed_port);
        if (connected) CHECK(connect(fd, (void *)&missing, sizeof(missing)) == 0);
        CHECK(sendto(fd, payload, sizeof(payload), 0,
            connected ? NULL : (void *)&missing, connected ? 0 : sizeof(missing)) == sizeof(payload));
        wait_event(ep, EPOLLERR);
        int error = 0; socklen_t length = sizeof(error);
        CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
        CHECK(length == sizeof(error) && error == ECONNREFUSED);
        /* Reading SO_ERROR clears the pending errno, but not the error queue. */
        wait_event(ep, EPOLLERR);
        union { struct cmsghdr align; unsigned char bytes[512]; } control;
        struct sockaddr_in destination = {0};
        struct iovec vector = {bytes, sizeof(bytes)};
        struct msghdr message = {.msg_name = &destination, .msg_namelen = sizeof(destination),
            .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes,
            .msg_controllen = sizeof(control.bytes)};
        CHECK(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == sizeof(payload));
        CHECK((message.msg_flags & MSG_ERRQUEUE) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
        CHECK(!memcmp(bytes, payload, sizeof(payload)));
        CHECK(message.msg_namelen == sizeof(destination) && destination.sin_family == AF_INET);
        CHECK(destination.sin_port == missing.sin_port && destination.sin_addr.s_addr == missing.sin_addr.s_addr);
        int found = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (c->cmsg_level != IPPROTO_IP || c->cmsg_type != IP_RECVERR) continue;
            CHECK(c->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in)));
            struct sock_extended_err *extended = (void *)CMSG_DATA(c);
            CHECK(extended->ee_errno == ECONNREFUSED && extended->ee_origin == SO_EE_ORIGIN_ICMP);
            CHECK(extended->ee_type == ICMP_DEST_UNREACH && extended->ee_code == ICMP_PORT_UNREACH);
            struct sockaddr_in *offender = (void *)SO_EE_OFFENDER(extended);
            CHECK(offender->sin_family == AF_INET && offender->sin_addr.s_addr == peer.sin_addr.s_addr);
            ++found;
        }
        CHECK(found == 1);
        message.msg_controllen = sizeof(control.bytes);
        errno = 0;
        CHECK(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == -1 && errno == EAGAIN);
        CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
        CHECK(epoll_wait(ep, &event, 1, 0) == 0);
        if (connected) CHECK(connect(fd, (void *)&peer, sizeof(peer)) == 0);
        CHECK(sendto(fd, payload, sizeof(payload), 0,
            connected ? NULL : (void *)&peer, connected ? 0 : sizeof(peer)) == sizeof(payload));
        wait_event(ep, EPOLLIN);
        CHECK(recv(fd, bytes, sizeof(bytes), 0) == sizeof(payload));
        CHECK(!memcmp(bytes, payload, sizeof(payload)));
        errno = 0;
        CHECK(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    }
    CHECK(close(ep) == 0 && close(fd) == 0);
    printf("PASS: UDP %s %s error queue and same-socket recovery\n", argv[1], argv[5]);
    return 0;
}
