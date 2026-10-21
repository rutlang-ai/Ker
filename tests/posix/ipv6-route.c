#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno);                          \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
static const char payload[] = "routed-ipv6";
static struct sockaddr_in6 endpoint(const char *text, int port) {
    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    CHECK(inet_pton(AF_INET6, text, &address.sin6_addr) == 1);
    return address;
}
static int make_socket(int type, int port) {
    int fd = socket(AF_INET6, type, 0), one = 1, hops = 64;
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 8};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) == 0);
    CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) == 0);
    if (type == SOCK_DGRAM)
        CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one)) == 0);
    struct sockaddr_in6 local = endpoint("2001:db8:1::2", port);
    CHECK(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0);
    return fd;
}
static void echo_stream(int fd, int outgoing) {
    char buffer[sizeof(payload)];
    if (outgoing)
        CHECK(send(fd, payload, sizeof(payload), MSG_NOSIGNAL) == sizeof(payload));
    CHECK(recv(fd, buffer, sizeof(buffer), MSG_WAITALL) == sizeof(buffer));
    CHECK(memcmp(buffer, payload, sizeof(buffer)) == 0);
    if (!outgoing)
        CHECK(send(fd, buffer, sizeof(buffer), MSG_NOSIGNAL) == sizeof(buffer));
}
static struct sockaddr_in6 receive_datagram(int fd) {
    struct sockaddr_in6 peer = {0}, expected = endpoint("2001:db8:2::2", 0);
    char buffer[sizeof(payload)], control[CMSG_SPACE(sizeof(int))];
    struct iovec vector = {.iov_base = buffer, .iov_len = sizeof(buffer)};
    struct msghdr message = {.msg_name = &peer,
                             .msg_namelen = sizeof(peer),
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control,
                             .msg_controllen = sizeof(control)};
    CHECK(recvmsg(fd, &message, 0) == sizeof(buffer));
    CHECK(!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) && memcmp(buffer, payload, sizeof(buffer)) == 0);
    CHECK(peer.sin6_family == AF_INET6 && memcmp(&peer.sin6_addr, &expected.sin6_addr, 16) == 0);
    int hops = -1;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header))
        if (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_HOPLIMIT &&
            header->cmsg_len == CMSG_LEN(sizeof(hops)))
            memcpy(&hops, CMSG_DATA(header), sizeof(hops));
    CHECK(hops == 63);
    return peer;
}
int main(int argc, char **argv) {
    CHECK(argc == 3);
    int port = atoi(argv[1]);
    struct sockaddr_in6 remote = endpoint("2001:db8:2::2", port + 1);
    int tcp = make_socket(SOCK_STREAM, 0), udp = make_socket(SOCK_DGRAM, 0);
    if (!strcmp(argv[2], "unrouted")) {
        CHECK(connect(tcp, (struct sockaddr *)&remote, sizeof(remote)) == -1 && errno == ENETUNREACH);
        CHECK(connect(udp, (struct sockaddr *)&remote, sizeof(remote)) == -1 && errno == ENETUNREACH);
        CHECK(close(tcp) == 0 && close(udp) == 0);
        puts("PASS: no implicit IPv6 default route");
        return 0;
    }
    int listener = make_socket(SOCK_STREAM, port), receiver = make_socket(SOCK_DGRAM, port);
    CHECK(listen(listener, 1) == 0);
    puts("READY");
    fflush(stdout);
    CHECK(connect(tcp, (struct sockaddr *)&remote, sizeof(remote)) == 0);
    echo_stream(tcp, 1);
    CHECK(close(tcp) == 0);
    CHECK(connect(udp, (struct sockaddr *)&remote, sizeof(remote)) == 0);
    CHECK(send(udp, payload, sizeof(payload), 0) == sizeof(payload));
    (void)receive_datagram(udp);
    CHECK(close(udp) == 0);
    struct sockaddr_in6 peer;
    socklen_t length = sizeof(peer);
    int accepted = accept(listener, (struct sockaddr *)&peer, &length);
    CHECK(accepted >= 0 && peer.sin6_family == AF_INET6 &&
          memcmp(&peer.sin6_addr, &remote.sin6_addr, 16) == 0);
    echo_stream(accepted, 0);
    CHECK(close(accepted) == 0 && close(listener) == 0);
    peer = receive_datagram(receiver);
    CHECK(sendto(receiver, payload, sizeof(payload), 0, (struct sockaddr *)&peer, sizeof(peer)) ==
          sizeof(payload));
    CHECK(close(receiver) == 0);
    puts("PASS: original Linux routed IPv6 TCP/UDP both directions, hop limit 63");
    return 0;
}
