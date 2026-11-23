/* UDP public-API matrix, identical assertions on host and original Linux. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);                           \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
#define ERROR(x, e)                                                                                          \
    do {                                                                                                     \
        errno = 0;                                                                                           \
        CHECK((x) == -1 && errno == (e));                                                                    \
    } while (0)
struct endpoint {
    union {
        struct sockaddr sa;
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } address;
    socklen_t length;
};
static int family;
static unsigned int cases;
static struct endpoint local(void) {
    struct endpoint e = {.length =
                             family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)};
    e.address.sa.sa_family = family;
    if (family == AF_INET)
        e.address.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    else
        e.address.v6.sin6_addr = in6addr_loopback;
    return e;
}
static int open_udp(int nonblock) {
    int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), IPPROTO_UDP);
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 2};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}
static int bound(struct endpoint *e, int nonblock) {
    *e = local();
    int fd = open_udp(nonblock);
    CHECK(bind(fd, &e->address.sa, e->length) == 0);
    socklen_t length = e->length;
    CHECK(getsockname(fd, &e->address.sa, &length) == 0 && length == e->length);
    return fd;
}
static void set(int fd, int level, int name, int value) {
    CHECK(setsockopt(fd, level, name, &value, sizeof(value)) == 0);
}
static int get(int fd, int level, int name) {
    int value = -1;
    socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, level, name, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void ready(int fd, int flags) {
    struct pollfd p = {.fd = fd, .events = flags};
    CHECK(poll(&p, 1, 2000) == 1 && (p.revents & flags));
}
static void empty(int fd) {
    char byte;
    ERROR(recv(fd, &byte, 1, MSG_DONTWAIT), EAGAIN);
}
static void send_to(int fd, struct endpoint e, const void *data, size_t length, int flags) {
    CHECK(sendto(fd, data, length, flags, &e.address.sa, e.length) == (ssize_t)length);
}
static long long now(void) {
    struct timespec t;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
static void pass(const char *name) {
    ++cases;
    printf("PASS family=%d %s\n", family, name);
    fflush(stdout);
}
static void creation(void) {
    struct endpoint e;
    int fd = bound(&e, 1);
    CHECK(get(fd, SOL_SOCKET, SO_TYPE) == SOCK_DGRAM && get(fd, SOL_SOCKET, SO_DOMAIN) == family &&
          get(fd, SOL_SOCKET, SO_PROTOCOL) == IPPROTO_UDP);
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    struct endpoint peer = local();
    socklen_t length = peer.length;
    ERROR(getpeername(fd, &peer.address.sa, &length), ENOTCONN);
    char byte = 'x';
    ERROR(send(fd, &byte, 1, 0), EDESTADDRREQ);
    int alias = dup(fd);
    CHECK(alias >= 0 && !(fcntl(alias, F_GETFD) & FD_CLOEXEC));
    CHECK(fcntl(alias, F_SETFL, fcntl(alias, F_GETFL) & ~O_NONBLOCK) == 0 &&
          !(fcntl(fd, F_GETFL) & O_NONBLOCK));
    int other = open_udp(0);
    ERROR(bind(other, &e.address.sa, e.length), EADDRINUSE);
    CHECK(close(other) == 0 && close(alias) == 0 && close(fd) == 0);
    pass("creation flags, duplicate fd, bind collision, unconnected errors");
}
static void messages(void) {
    struct endpoint a, b;
    int rx = bound(&a, 0), tx = bound(&b, 0), ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0xfedcba9876543210ULL};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, rx, &event) == 0);
    size_t lengths[] = {0, 1, 33, 257};
    unsigned char bytes[257], out[257];
    for (unsigned int n = 0; n < 4; n++) {
        for (size_t i = 0; i < sizeof(bytes); i++)
            bytes[i] = (unsigned char)(i * 71 + n);
        send_to(tx, a, bytes, lengths[n], 0);
        ready(rx, POLLIN);
        struct epoll_event got;
        CHECK(epoll_wait(ep, &got, 1, 2000) == 1 && got.data.u64 == event.data.u64 && (got.events & EPOLLIN));
        int count = -1;
        CHECK(ioctl(rx, FIONREAD, &count) == 0 && count == (int)lengths[n]);
        memset(out, 0xa5, sizeof(out));
        struct iovec v = {out, 7};
        struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
        CHECK(recvmsg(rx, &m, MSG_PEEK | MSG_TRUNC) == (ssize_t)lengths[n]);
        CHECK(!!(m.msg_flags & MSG_TRUNC) == (lengths[n] > 7));
        CHECK(memcmp(out, bytes, lengths[n] < 7 ? lengths[n] : 7) == 0 && out[7] == 0xa5);
        struct iovec vectors[] = {{out, 3}, {out + 3, 4}};
        struct endpoint source = local();
        m = (struct msghdr){
            .msg_name = &source.address, .msg_namelen = source.length, .msg_iov = vectors, .msg_iovlen = 2};
        CHECK(recvmsg(rx, &m, 0) == (ssize_t)(lengths[n] < 7 ? lengths[n] : 7));
        CHECK(!!(m.msg_flags & MSG_TRUNC) == (lengths[n] > 7) && m.msg_namelen == b.length &&
              memcmp(&source.address, &b.address, b.length) == 0);
        empty(rx);
        CHECK(epoll_wait(ep, &got, 1, 0) == 0);
    }
    struct mmsghdr batch[4] = {0};
    struct iovec vectors[4];
    unsigned char records[4][33];
    for (int i = 0; i < 4; i++) {
        memset(records[i], i, sizeof(records[i]));
        vectors[i] = (struct iovec){records[i], (size_t)i * 11};
        batch[i].msg_hdr = (struct msghdr){
            .msg_name = &a.address, .msg_namelen = a.length, .msg_iov = &vectors[i], .msg_iovlen = 1};
    }
    CHECK(sendmmsg(tx, batch, 4, 0) == 4);
    for (int i = 0; i < 4; i++)
        CHECK(batch[i].msg_len == (unsigned)i * 11);
    memset(records, 0xa5, sizeof(records));
    for (int i = 0; i < 4; i++) {
        vectors[i].iov_len = 5;
        batch[i].msg_hdr.msg_name = NULL;
        batch[i].msg_hdr.msg_namelen = 0;
    }
    unsigned int received = 0;
    while (received < 4) {
        int n = recvmmsg(rx, batch + received, 4 - received, MSG_TRUNC | MSG_WAITFORONE, NULL);
        CHECK(n > 0);
        for (int i = 0; i < n; i++) {
            unsigned int k = received + (unsigned)i;
            CHECK(batch[k].msg_len == k * 11 && !!(batch[k].msg_hdr.msg_flags & MSG_TRUNC) == (k != 0));
            for (unsigned int j = 0; j < (k * 11 < 5 ? k * 11 : 5); j++)
                CHECK(records[k][j] == k);
            CHECK(records[k][5] == 0xa5);
        }
        received += (unsigned)n;
    }
    empty(rx);
    send_to(tx, a, "k", 1, 0);
    struct timespec timeout = {.tv_sec = 1};
    struct iovec single = {out, sizeof(out)};
    struct mmsghdr one = {.msg_hdr = {.msg_iov = &single, .msg_iovlen = 1}};
    CHECK(recvmmsg(rx, &one, 1, 0, &timeout) == 1 && one.msg_len == 1 && out[0] == 'k' &&
          timeout.tv_sec >= 0 && timeout.tv_sec <= 1 && timeout.tv_nsec >= 0 && timeout.tv_nsec < 1000000000);
    CHECK(close(ep) == 0 && close(rx) == 0 && close(tx) == 0);
    pass("zero datagrams, epoll, peek, truncation, FIONREAD, vectors, mmsg, timeout pointer");
}
static void lifecycle(void) {
    struct endpoint a, b, c;
    int reserve = bound(&a, 0), good = bound(&b, 0), other = bound(&c, 0);
    CHECK(close(reserve) == 0);
    int rx = open_udp(0);
    CHECK(bind(rx, &a.address.sa, a.length) == 0);
    CHECK(connect(rx, &b.address.sa, b.length) == 0);
    send_to(other, a, "bad", 3, 0);
    send_to(good, a, "good", 4, 0);
    char bytes[8];
    CHECK(recv(rx, bytes, sizeof(bytes), 0) == 4 && !memcmp(bytes, "good", 4));
    empty(rx);
    struct sockaddr disconnect = {.sa_family = AF_UNSPEC};
    CHECK(connect(rx, &disconnect, sizeof(disconnect)) == 0);
    struct endpoint got = local();
    socklen_t length = got.length;
    ERROR(getpeername(rx, &got.address.sa, &length), ENOTCONN);
    length = a.length;
    CHECK(getsockname(rx, &got.address.sa, &length) == 0);
    /* Explicit binding retains the port; address after disconnect follows Linux. */
    CHECK((family == AF_INET ? got.address.v4.sin_port : got.address.v6.sin6_port) ==
          (family == AF_INET ? a.address.v4.sin_port : a.address.v6.sin6_port));
    send_to(other, a, "again", 5, 0);
    CHECK(recv(rx, bytes, sizeof(bytes), 0) == 5 && !memcmp(bytes, "again", 5));
    CHECK(close(rx) == 0 && close(good) == 0 && close(other) == 0);
    pass("connected source filtering, AF_UNSPEC disconnect and same-socket recovery");
}
static void timeouts(void) {
    struct endpoint a, b;
    int rx = bound(&a, 0), tx = bound(&b, 0);
    struct timeval timeout = {.tv_usec = 100000};
    CHECK(setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    char byte;
    long long before = now();
    ERROR(recv(rx, &byte, 1, 0), EAGAIN);
    long long elapsed = now() - before;
    CHECK(elapsed >= 50000000 && elapsed < 2000000000LL);
    send_to(tx, a, "r", 1, 0);
    CHECK(recv(rx, &byte, 1, 0) == 1 && byte == 'r');
    send_to(tx, a, "w", 1, 0);
    struct iovec v = {&byte, 1};
    struct mmsghdr messages[2] = {0};
    for (int i = 0; i < 2; i++)
        messages[i].msg_hdr = (struct msghdr){.msg_iov = &v, .msg_iovlen = 1};
    before = now();
    CHECK(recvmmsg(rx, messages, 2, MSG_WAITFORONE, NULL) == 1 && byte == 'w' &&
          now() - before < 2000000000LL);
    CHECK(close(rx) == 0 && close(tx) == 0);
    pass("receive timeout, recovery and WAITFORONE nonblocking remainder");
}
static void ancillary(void) {
    struct endpoint a, b;
    int rx = bound(&a, 0), tx = bound(&b, 0), one = 1;
    set(rx, SOL_SOCKET, SO_TIMESTAMPNS, one);
    set(rx, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6, family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO,
        one);
    set(rx, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6, family == AF_INET ? IP_RECVTTL : IPV6_RECVHOPLIMIT,
        one);
    set(rx, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6, family == AF_INET ? IP_RECVTOS : IPV6_RECVTCLASS,
        one);
    set(tx, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6, family == AF_INET ? IP_TTL : IPV6_UNICAST_HOPS,
        37);
    set(tx, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6, family == AF_INET ? IP_TOS : IPV6_TCLASS, 0x2c);
    for (int short_control = 1; short_control >= 0; short_control--) {
        send_to(tx, a, "metadata", 8, 0);
        char bytes[16];
        union {
            struct cmsghdr align;
            char bytes[512];
        } control;
        struct iovec v = {bytes, sizeof(bytes)};
        struct msghdr m = {.msg_iov = &v,
                           .msg_iovlen = 1,
                           .msg_control = &control,
                           .msg_controllen = short_control ? 1 : sizeof(control)};
        CHECK(recvmsg(rx, &m, 0) == 8 && !memcmp(bytes, "metadata", 8));
        CHECK(!!(m.msg_flags & MSG_CTRUNC) == short_control);
        if (short_control)
            continue;
        int packet = 0, hops = 0, traffic = 0, timestamp = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
                struct timespec t;
                CHECK(c->cmsg_len == CMSG_LEN(sizeof(t)));
                memcpy(&t, CMSG_DATA(c), sizeof(t));
                CHECK(t.tv_sec > 0 && t.tv_nsec >= 0 && t.tv_nsec < 1000000000);
                timestamp++;
            }
            if (family == AF_INET && c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo info;
                CHECK(c->cmsg_len == CMSG_LEN(sizeof(info)));
                memcpy(&info, CMSG_DATA(c), sizeof(info));
                CHECK(info.ipi_ifindex > 0 && info.ipi_addr.s_addr == a.address.v4.sin_addr.s_addr);
                packet++;
            }
            if (family == AF_INET6 && c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
                struct in6_pktinfo info;
                CHECK(c->cmsg_len == CMSG_LEN(sizeof(info)));
                memcpy(&info, CMSG_DATA(c), sizeof(info));
                CHECK(info.ipi6_ifindex > 0 && !memcmp(&info.ipi6_addr, &a.address.v6.sin6_addr, 16));
                packet++;
            }
            if (c->cmsg_level == (family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6) &&
                c->cmsg_type == (family == AF_INET ? IP_TTL : IPV6_HOPLIMIT)) {
                int value;
                memcpy(&value, CMSG_DATA(c), sizeof(value));
                CHECK(value == 37);
                hops++;
            }
            if (c->cmsg_level == (family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6) &&
                c->cmsg_type == (family == AF_INET ? IP_TOS : IPV6_TCLASS)) {
                int value = 0;
                memcpy(&value, CMSG_DATA(c), family == AF_INET ? 1 : sizeof(value));
                CHECK(value == 0x2c);
                traffic++;
            }
        }
        CHECK(packet == 1 && hops == 1 && traffic == 1 && timestamp == 1);
    }
    CHECK(close(rx) == 0 && close(tx) == 0);
    pass("packet info, TTL/hop limit, TOS/tclass, timestamp and CTRUNC recovery");
}
static void errors(void) {
    for (int connected = 0; connected < 2; connected++) {
        struct endpoint missing, good, source;
        int reserve = bound(&missing, 0), server = bound(&good, 0), fd = bound(&source, 0);
        CHECK(close(reserve) == 0);
        set(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6, family == AF_INET ? IP_RECVERR : IPV6_RECVERR,
            1);
        if (connected)
            CHECK(connect(fd, &missing.address.sa, missing.length) == 0);
        if (connected)
            CHECK(send(fd, "error", 5, 0) == 5);
        else
            send_to(fd, missing, "error", 5, 0);
        ready(fd, POLLERR);
        CHECK(get(fd, SOL_SOCKET, SO_ERROR) == ECONNREFUSED);
        char bytes[128];
        union {
            struct cmsghdr align;
            char bytes[512];
        } control;
        struct iovec v = {bytes, sizeof(bytes)};
        struct endpoint dest = local();
        struct msghdr m = {.msg_iov = &v,
                           .msg_iovlen = 1,
                           .msg_name = &dest.address,
                           .msg_namelen = dest.length,
                           .msg_control = &control,
                           .msg_controllen = sizeof(control)};
        CHECK(recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT) == 5 && !memcmp(bytes, "error", 5));
        CHECK((m.msg_flags & MSG_ERRQUEUE) && !(m.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
        CHECK(m.msg_namelen == missing.length && !memcmp(&dest.address, &missing.address, missing.length));
        int found = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
            if (c->cmsg_level == (family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6) &&
                c->cmsg_type == (family == AF_INET ? IP_RECVERR : IPV6_RECVERR)) {
                struct sock_extended_err e;
                CHECK(c->cmsg_len >= CMSG_LEN(sizeof(e)));
                memcpy(&e, CMSG_DATA(c), sizeof(e));
                CHECK(e.ee_errno == ECONNREFUSED &&
                      e.ee_origin == (family == AF_INET ? SO_EE_ORIGIN_ICMP : SO_EE_ORIGIN_ICMP6) &&
                      e.ee_type == (family == AF_INET ? ICMP_DEST_UNREACH : ICMP6_DST_UNREACH) &&
                      e.ee_code == (family == AF_INET ? ICMP_PORT_UNREACH : ICMP6_DST_UNREACH_NOPORT));
                found++;
            }
        CHECK(found == 1 && get(fd, SOL_SOCKET, SO_ERROR) == 0);
        m.msg_controllen = sizeof(control);
        ERROR(recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT), EAGAIN);
        if (connected)
            CHECK(connect(fd, &good.address.sa, good.length) == 0);
        send_to(fd, good, "recover", 7, 0);
        CHECK(recv(server, bytes, sizeof(bytes), 0) == 7 && !memcmp(bytes, "recover", 7));
        CHECK(close(server) == 0 && close(fd) == 0);
    }
    pass("ICMP/ICMPv6 connected and unconnected error queues, SO_ERROR and recovery");
}
static void cork(void) {
    struct endpoint a, b;
    int rx = bound(&a, 0), tx = bound(&b, 0);
    CHECK(connect(tx, &a.address.sa, a.length) == 0);
    set(tx, IPPROTO_UDP, UDP_CORK, 1);
    CHECK(send(tx, "ab", 2, 0) == 2 && send(tx, "cd", 2, 0) == 2);
    empty(rx);
    set(tx, IPPROTO_UDP, UDP_CORK, 0);
    char bytes[8];
    CHECK(recv(rx, bytes, sizeof(bytes), 0) == 4 && !memcmp(bytes, "abcd", 4));
    CHECK(send(tx, "ef", 2, MSG_MORE) == 2);
    empty(rx);
    CHECK(send(tx, "gh", 2, 0) == 2);
    CHECK(recv(rx, bytes, sizeof(bytes), 0) == 4 && !memcmp(bytes, "efgh", 4));
    set(tx, IPPROTO_UDP, UDP_CORK, 1);
    CHECK(send(tx, "discard", 7, 0) == 7);
    CHECK(close(tx) == 0);
    empty(rx);
    CHECK(close(rx) == 0);
    pass("UDP_CORK, MSG_MORE, flush and close without flush");
}
static void pressure(void) {
    struct endpoint a, b;
    int rx = bound(&a, 0), tx = bound(&b, 0);
    set(rx, SOL_SOCKET, SO_RCVBUF, 4096);
    set(rx, SOL_SOCKET, SO_RXQ_OVFL, 1);
    unsigned char bytes[256];
    memset(bytes, 0x39, sizeof(bytes));
    for (int i = 0; i < 128; i++)
        send_to(tx, a, bytes, sizeof(bytes), 0);
    unsigned int received = 0;
    while (recv(rx, bytes, sizeof(bytes), MSG_DONTWAIT) == sizeof(bytes))
        received++;
    CHECK(errno == EAGAIN && received > 0 && received < 128);
    send_to(tx, a, "recovered", 9, 0);
    union {
        struct cmsghdr align;
        char bytes[128];
    } control;
    struct iovec v = {bytes, sizeof(bytes)};
    struct msghdr m = {
        .msg_iov = &v, .msg_iovlen = 1, .msg_control = &control, .msg_controllen = sizeof(control)};
    CHECK(recvmsg(rx, &m, 0) == 9 && !memcmp(bytes, "recovered", 9));
    unsigned int drops = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_RXQ_OVFL) {
            CHECK(c->cmsg_len == CMSG_LEN(sizeof(drops)));
            memcpy(&drops, CMSG_DATA(c), sizeof(drops));
        }
    CHECK(drops > 0);
    CHECK(close(rx) == 0 && close(tx) == 0);
    pass("receive-buffer exhaustion, SO_RXQ_OVFL and post-drop recovery");
}
static void segmentation(void) {
    struct endpoint a, b;
    int rx = bound(&a, 0), tx = bound(&b, 0);
    unsigned char data[111], out[111];
    for (unsigned int i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)i;
    struct iovec v = {data, sizeof(data)};
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(unsigned short))];
    } control = {0};
    struct msghdr m = {.msg_name = &a.address,
                       .msg_namelen = a.length,
                       .msg_iov = &v,
                       .msg_iovlen = 1,
                       .msg_control = &control,
                       .msg_controllen = sizeof(control)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = IPPROTO_UDP;
    c->cmsg_type = UDP_SEGMENT;
    c->cmsg_len = CMSG_LEN(sizeof(unsigned short));
    unsigned short segment = 37;
    memcpy(CMSG_DATA(c), &segment, sizeof(segment));
    CHECK(sendmsg(tx, &m, 0) == sizeof(data));
    for (unsigned int i = 0; i < 3; i++)
        CHECK(recv(rx, out, sizeof(out), 0) == 37 && !memcmp(out, data + i * 37, 37));
    set(rx, IPPROTO_UDP, UDP_GRO, 1);
    CHECK(get(rx, IPPROTO_UDP, UDP_GRO) == 1);
    CHECK(sendmsg(tx, &m, 0) == sizeof(data));
    unsigned int total = 0;
    while (total < sizeof(data)) {
        union {
            struct cmsghdr align;
            char bytes[128];
        } metadata;
        struct iovec receive = {out, sizeof(out)};
        struct msghdr message = {.msg_iov = &receive,
                                 .msg_iovlen = 1,
                                 .msg_control = &metadata,
                                 .msg_controllen = sizeof(metadata)};
        ssize_t n = recvmsg(rx, &message, 0);
        CHECK(n > 0 && total + (unsigned)n <= sizeof(data) && !memcmp(out, data + total, (size_t)n));
        int gro = 0;
        for (c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c))
            if (c->cmsg_level == IPPROTO_UDP && c->cmsg_type == UDP_GRO) {
                CHECK(c->cmsg_len == CMSG_LEN(sizeof(int)));
                memcpy(&gro, CMSG_DATA(c), sizeof(gro));
                CHECK(gro == 37);
            }
        CHECK(n == 37 || (gro == 37 && n % 37 == 0));
        total += (unsigned)n;
    }
    empty(rx);
    CHECK(close(rx) == 0 && close(tx) == 0);
    pass("UDP_SEGMENT and UDP_GRO metadata/byte boundaries");
}
static void reuseport(void) {
    struct endpoint address = local(), source;
    int receivers[2] = {open_udp(0), open_udp(0)}, sender = bound(&source, 0);
    for (int i = 0; i < 2; i++)
        set(receivers[i], SOL_SOCKET, SO_REUSEPORT, 1);
    CHECK(bind(receivers[0], &address.address.sa, address.length) == 0);
    socklen_t length = address.length;
    CHECK(getsockname(receivers[0], &address.address.sa, &length) == 0);
    CHECK(bind(receivers[1], &address.address.sa, address.length) == 0);
    int selected = -1;
    char byte;
    for (int i = 0; i < 8; i++) {
        send_to(sender, address, "r", 1, 0);
        struct pollfd events[] = {{.fd = receivers[0], .events = POLLIN},
                                  {.fd = receivers[1], .events = POLLIN}};
        CHECK(poll(events, 2, 2000) == 1);
        int member = events[0].revents & POLLIN ? 0 : 1;
        if (selected < 0)
            selected = member;
        CHECK(member == selected && recv(receivers[member], &byte, 1, 0) == 1 && byte == 'r');
        empty(receivers[1 - member]);
    }
    CHECK(close(receivers[selected]) == 0);
    send_to(sender, address, "s", 1, 0);
    CHECK(recv(receivers[1 - selected], &byte, 1, 0) == 1 && byte == 's');
    CHECK(close(receivers[1 - selected]) == 0);
    int rebound = open_udp(0);
    CHECK(bind(rebound, &address.address.sa, address.length) == 0);
    send_to(sender, address, "t", 1, 0);
    CHECK(recv(rebound, &byte, 1, 0) == 1 && byte == 't');
    CHECK(close(rebound) == 0 && close(sender) == 0);
    pass("reuseport stable-flow single delivery, member close and port rebind");
}
static void dual_stack(void) {
    family = AF_INET6;
    int receiver = open_udp(0);
    set(receiver, IPPROTO_IPV6, IPV6_V6ONLY, 0);
    struct endpoint address = local();
    address.address.v6.sin6_addr = in6addr_any;
    CHECK(bind(receiver, &address.address.sa, address.length) == 0);
    socklen_t length = address.length;
    CHECK(getsockname(receiver, &address.address.sa, &length) == 0);
    family = AF_INET;
    struct endpoint source, target = local();
    int sender = bound(&source, 0);
    target.address.v4.sin_port = address.address.v6.sin6_port;
    send_to(sender, target, "mapped", 6, 0);
    struct sockaddr_in6 peer;
    length = sizeof(peer);
    char bytes[16];
    CHECK(recvfrom(receiver, bytes, sizeof(bytes), 0, (void *)&peer, &length) == 6 &&
          !memcmp(bytes, "mapped", 6));
    CHECK(peer.sin6_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&peer.sin6_addr));
    CHECK(!memcmp(&peer.sin6_addr.s6_addr[12], &source.address.v4.sin_addr, 4));
    CHECK(sendto(receiver, bytes, 6, 0, (void *)&peer, sizeof(peer)) == 6 &&
          recv(sender, bytes, sizeof(bytes), 0) == 6);
    CHECK(close(receiver) == 0 && close(sender) == 0);
    family = AF_INET6;
    receiver = open_udp(0);
    set(receiver, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    address = local();
    address.address.v6.sin6_addr = in6addr_any;
    CHECK(bind(receiver, &address.address.sa, address.length) == 0);
    length = address.length;
    CHECK(getsockname(receiver, &address.address.sa, &length) == 0);
    family = AF_INET;
    int separate = open_udp(0);
    target = local();
    target.address.v4.sin_port = address.address.v6.sin6_port;
    CHECK(bind(separate, &target.address.sa, target.length) == 0);
    sender = bound(&source, 0);
    send_to(sender, target, "4", 1, 0);
    CHECK(recv(separate, bytes, sizeof(bytes), 0) == 1 && bytes[0] == '4');
    empty(receiver);
    CHECK(close(sender) == 0 && close(separate) == 0 && close(receiver) == 0);
    family = AF_INET6;
    pass("IPv4-mapped UDP roundtrip, IPV6_V6ONLY and independent IPv4 bind");
}
int main(void) {
    for (int i = 0; i < 2; i++) {
        family = i ? AF_INET6 : AF_INET;
        creation();
        messages();
        lifecycle();
        timeouts();
        ancillary();
        errors();
        cork();
        pressure();
        segmentation();
        reuseport();
    }
    dual_stack();
    printf("PASS: UDP contract matrix %u groups on both address families\n", cases);
    return 0;
}
