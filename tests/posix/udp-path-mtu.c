#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);                           \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
static int family;
static unsigned char payload[1400];
static void error_queue(int fd, int local) {
    struct pollfd event = {.fd = fd, .events = POLLIN};
    CHECK(poll(&event, 1, 5000) == 1 && (event.revents & POLLERR));
    unsigned char data[1400];
    union {
        struct cmsghdr align;
        char bytes[512];
    } control;
    struct sockaddr_storage destination;
    struct iovec vector = {data, sizeof(data)};
    struct msghdr message = {.msg_name = &destination,
                             .msg_namelen = sizeof(destination),
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = &control,
                             .msg_controllen = sizeof(control)};
    ssize_t count = recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT);
    CHECK(count >= 0 && count <= (ssize_t)sizeof(data) && !memcmp(data, payload, (size_t)count));
    CHECK((message.msg_flags & MSG_ERRQUEUE) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
          destination.ss_family == family);
    int found = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c))
        if (c->cmsg_level == (family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6) &&
            c->cmsg_type == (family == AF_INET ? IP_RECVERR : IPV6_RECVERR)) {
            struct sock_extended_err e;
            CHECK(c->cmsg_len >= CMSG_LEN(sizeof(e)));
            memcpy(&e, CMSG_DATA(c), sizeof(e));
            if (e.ee_errno != EMSGSIZE || e.ee_info != 1280)
                fprintf(stderr, "MTU error errno=%u origin=%u type=%u code=%u info=%u\n", e.ee_errno,
                        e.ee_origin, e.ee_type, e.ee_code, e.ee_info);
            CHECK(e.ee_errno == EMSGSIZE && e.ee_info == 1280);
            CHECK(e.ee_origin == (local               ? SO_EE_ORIGIN_LOCAL
                                  : family == AF_INET ? SO_EE_ORIGIN_ICMP
                                                      : SO_EE_ORIGIN_ICMP6));
            CHECK(e.ee_type == (local ? 0 : family == AF_INET ? ICMP_DEST_UNREACH : ICMP6_PACKET_TOO_BIG));
            CHECK(e.ee_code == (local || family == AF_INET6 ? 0 : ICMP_FRAG_NEEDED));
            found++;
        }
    CHECK(found == 1);
}
int main(int argc, char **argv) {
    CHECK(argc == 3);
    family = atoi(argv[1]) == 4 ? AF_INET : AF_INET6;
    int port = atoi(argv[2]);
    int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 8};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    int one = 1, mode = IP_PMTUDISC_DO;
    CHECK(setsockopt(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                     family == AF_INET ? IP_RECVERR : IPV6_RECVERR, &one, sizeof(one)) == 0);
    CHECK(setsockopt(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                     family == AF_INET ? IP_MTU_DISCOVER : IPV6_MTU_DISCOVER, &mode, sizeof(mode)) == 0);
    if (family == AF_INET) {
        struct sockaddr_in local = {.sin_family = AF_INET},
                           remote = {.sin_family = AF_INET, .sin_port = htons(port + 1)};
        CHECK(inet_pton(AF_INET, "198.18.0.2", &local.sin_addr) == 1 &&
              inet_pton(AF_INET, "198.19.0.2", &remote.sin_addr) == 1);
        CHECK(bind(fd, (void *)&local, sizeof(local)) == 0 &&
              connect(fd, (void *)&remote, sizeof(remote)) == 0);
    } else {
        struct sockaddr_in6 local = {.sin6_family = AF_INET6},
                            remote = {.sin6_family = AF_INET6, .sin6_port = htons(port + 1)};
        CHECK(inet_pton(AF_INET6, "2001:db8:1::2", &local.sin6_addr) == 1 &&
              inet_pton(AF_INET6, "2001:db8:2::2", &remote.sin6_addr) == 1);
        CHECK(bind(fd, (void *)&local, sizeof(local)) == 0 &&
              connect(fd, (void *)&remote, sizeof(remote)) == 0);
    }
    for (unsigned int i = 0; i < sizeof(payload); i++)
        payload[i] = (unsigned char)(i * 71);
    CHECK(send(fd, payload, sizeof(payload), 0) == sizeof(payload));
    error_queue(fd, 0);
    int mtu = 0;
    socklen_t length = sizeof(mtu);
    CHECK(getsockopt(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6, family == AF_INET ? IP_MTU : IPV6_MTU,
                     &mtu, &length) == 0 &&
          mtu == 1280);
    int pending;
    length = sizeof(pending);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending, &length) == 0);
    errno = 0;
    CHECK(send(fd, payload, sizeof(payload), 0) == -1 && errno == EMSGSIZE);
    error_queue(fd, 1);
    CHECK(send(fd, payload, 1232, 0) == 1232);
    unsigned char reply[1400];
    CHECK(recv(fd, reply, sizeof(reply), 0) == 1232 && !memcmp(reply, payload, 1232));
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending, &length) == 0 && pending == 0);
    CHECK(close(fd) == 0);
    printf("PASS: IPv%d real router PMTU1280, ICMP metadata, cached MTU, local EMSGSIZE and recovery\n",
           family == AF_INET ? 4 : 6);
    return 0;
}
