/* Linux-specific ancillary-data extension of the pinned F-Stack UDP example. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define SIZE 37
static void fill(unsigned char *bytes, int record, int reply)
{
    for (int i = 0; i < SIZE; ++i) bytes[i] = (unsigned char)(i * 71 + record * 29 + reply * 93);
}
static void transmit(int fd, struct sockaddr_in peer, struct in_addr local, int interface,
    int record, int reply)
{
    unsigned char bytes[SIZE]; fill(bytes, record, reply);
    struct iovec vector = {bytes, sizeof(bytes)};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))]; } control = {0};
    struct msghdr message = {.msg_name = &peer, .msg_namelen = sizeof(peer),
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = IPPROTO_IP; c->cmsg_type = IP_PKTINFO;
    c->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo info = {.ipi_ifindex = interface, .ipi_spec_dst = local};
    memcpy(CMSG_DATA(c), &info, sizeof(info));
    ssize_t count;
    do { count = sendmsg(fd, &message, 0); } while (count < 0 && errno == EINTR);
    CHECK(count == sizeof(bytes));
}
static void receive(int fd, int ep, struct sockaddr_in *peer, struct in_addr local,
    int *interface, int record, int reply)
{
    struct timespec before, after;
    CHECK(clock_gettime(CLOCK_REALTIME, &before) == 0);
    struct epoll_event event;
    int count;
    do { count = epoll_wait(ep, &event, 1, 5000); } while (count < 0 && errno == EINTR);
    CHECK(count == 1 && (event.events & EPOLLIN) && event.data.u64 == 0x434d5347);
    unsigned char bytes[SIZE], expected[SIZE]; fill(expected, record, reply);
    struct sockaddr_in source = {0};
    struct iovec vector = {bytes, sizeof(bytes)};
    union { struct cmsghdr align; unsigned char bytes[512]; } control;
    /* The middle datagram deliberately cannot hold even a cmsg header. */
    size_t capacity = record == 1 ? 1 : sizeof(control.bytes);
    struct msghdr message = {.msg_name = &source, .msg_namelen = sizeof(source),
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control.bytes,
        .msg_controllen = capacity};
    ssize_t length;
    do { length = recvmsg(fd, &message, 0); } while (length < 0 && errno == EINTR);
    CHECK(clock_gettime(CLOCK_REALTIME, &after) == 0);
    CHECK(length == SIZE && !memcmp(bytes, expected, SIZE));
    CHECK(!(message.msg_flags & MSG_TRUNC) && message.msg_controllen <= capacity);
    CHECK(message.msg_namelen == sizeof(source) && source.sin_family == AF_INET);
    CHECK(source.sin_addr.s_addr == peer->sin_addr.s_addr && source.sin_port != 0);
    if (peer->sin_port) CHECK(source.sin_port == peer->sin_port);
    *peer = source;
    if (record == 1) {
        CHECK(message.msg_flags & MSG_CTRUNC);
        return;
    }
    CHECK(!(message.msg_flags & MSG_CTRUNC));
    int packet_info = 0, timestamp = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            CHECK(c->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)));
            struct in_pktinfo info; memcpy(&info, CMSG_DATA(c), sizeof(info));
            CHECK(info.ipi_ifindex > 0 && info.ipi_addr.s_addr == local.s_addr);
            CHECK(info.ipi_spec_dst.s_addr == local.s_addr);
            if (*interface) CHECK(info.ipi_ifindex == *interface);
            *interface = info.ipi_ifindex; ++packet_info;
        } else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
            CHECK(c->cmsg_len == CMSG_LEN(sizeof(struct timespec)));
            struct timespec time; memcpy(&time, CMSG_DATA(c), sizeof(time));
            CHECK(time.tv_sec > 0 && time.tv_nsec >= 0 && time.tv_nsec < 1000000000L);
            if (time.tv_sec < before.tv_sec - 1 || time.tv_sec > after.tv_sec + 1)
                fprintf(stderr, "receive timestamp=%ld, host realtime interval=[%ld,%ld]\n",
                    time.tv_sec, before.tv_sec, after.tv_sec);
            CHECK(time.tv_sec >= before.tv_sec - 1 && time.tv_sec <= after.tv_sec + 1);
            ++timestamp;
        } else CHECK(0);
    }
    CHECK(packet_info == 1 && timestamp == 1);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = !strcmp(argv[1], "server");
    CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr local;
    CHECK(inet_pton(AF_INET, argv[2], &local) == 1);
    struct sockaddr_in peer = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[3], &peer.sin_addr) == 1);
    char *end; long port = strtol(argv[4], &end, 10);
    CHECK(!*end && port > 0 && port <= 65535);
    if (!server) peer.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    int enabled = 1;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof(enabled)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled)) == 0);
    for (int option = 0; option < 2; ++option) {
        int value = 0; socklen_t length = sizeof(value);
        CHECK(getsockopt(fd, option ? SOL_SOCKET : IPPROTO_IP,
            option ? SO_TIMESTAMPNS : IP_PKTINFO, &value, &length) == 0);
        CHECK(length == sizeof(value) && value == 1);
    }
    /* Wildcard server binding requires packet metadata to identify the destination. */
    struct sockaddr_in bind_address = {.sin_family = AF_INET,
        .sin_port = server ? htons(port) : 0, .sin_addr = server ? (struct in_addr){0} : local};
    CHECK(bind(fd, (void *)&bind_address, sizeof(bind_address)) == 0);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x434d5347};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    if (server) { printf("READY %ld\n", port); fflush(stdout); }
    int interface = 0;
    for (int record = 0; record < 3; ++record) {
        if (!server) transmit(fd, peer, local, interface, record, 0);
        receive(fd, ep, &peer, local, &interface, record, !server);
        if (server) transmit(fd, peer, local, interface, record, 1);
    }
    unsigned char byte; errno = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(close(ep) == 0 && close(fd) == 0);
    printf("PASS: UDP %s packet info, source selection, timestamps and control truncation recovery\n", argv[1]);
    return 0;
}
