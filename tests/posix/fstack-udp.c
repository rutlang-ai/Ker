/* UDP socket extensions of pinned F-Stack checksum/API scenarios.
 * Real POSIX calls on original Linux; no Ker-owned UDP protocol behavior. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define RECORDS 4
#define CAPACITY 257
static const size_t lengths[RECORDS] = {0, 1, 33, CAPACITY};
static unsigned char byte_at(unsigned int index, size_t offset, unsigned int seed)
{
    return (unsigned char)((index * 29U + offset * 71U + seed) & 255U);
}
static void fill(unsigned char *bytes, unsigned int index, unsigned int seed)
{
    for (size_t i = 0; i < lengths[index]; ++i) bytes[i] = byte_at(index, i, seed);
}
static void verify(const unsigned char *bytes, unsigned int index, size_t length, unsigned int seed)
{
    CHECK(length <= lengths[index]);
    for (size_t i = 0; i < length; ++i) CHECK(bytes[i] == byte_at(index, i, seed));
}
static void address_matches(struct sockaddr_in actual, struct sockaddr_in expected)
{
    CHECK(actual.sin_family == AF_INET && actual.sin_port != 0);
    if (expected.sin_port) {
        CHECK(actual.sin_port == expected.sin_port);
        CHECK(actual.sin_addr.s_addr == expected.sin_addr.s_addr);
    }
}
static void ready(int ep)
{
    struct epoll_event event;
    int result;
    do {result = epoll_wait(ep, &event, 1, 5000);} while (result < 0 && errno == EINTR);
    CHECK(result == 1 && (event.events & EPOLLIN) && event.data.u64 == 0x554450);
    CHECK(!(event.events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)));
}
static void writable(int fd)
{
    struct pollfd event = {fd, POLLOUT, 0};
    int count;
    do {count = poll(&event, 1, 5000);} while (count < 0 && errno == EINTR);
    CHECK(count == 1 && (event.revents & POLLOUT));
}
static void single_send(int fd, struct sockaddr_in peer, unsigned int index, unsigned int seed,
    int message, int connected)
{
    unsigned char bytes[CAPACITY]; fill(bytes, index, seed);
    size_t split = lengths[index] / 2;
    struct iovec vectors[] = {{bytes, split}, {bytes + split, lengths[index] - split}};
    struct msghdr header = {.msg_iov = vectors, .msg_iovlen = 2};
    if (!connected) {header.msg_name = &peer; header.msg_namelen = sizeof(peer);}
    for (;;) {
        ssize_t count = message ? sendmsg(fd, &header, MSG_NOSIGNAL) :
            sendto(fd, bytes, lengths[index], MSG_NOSIGNAL, (void *)&peer, sizeof(peer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && errno == EAGAIN) {writable(fd); continue;}
        CHECK(count == (ssize_t)lengths[index]); break;
    }
}
static void single_receive(int fd, int ep, struct sockaddr_in *peer, unsigned int index,
    unsigned int seed, int message)
{
    ready(ep);
    unsigned char bytes[CAPACITY];
    struct sockaddr_in from = {0};
    socklen_t length = sizeof(from);
    if (message) {
        int available = -1;
        CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == (int)lengths[index]);
        /* A short PEEK reports full size with input MSG_TRUNC and consumes nothing. */
        struct iovec peek = {bytes, 5};
        struct msghdr header = {.msg_name = &from, .msg_namelen = sizeof(from),
            .msg_iov = &peek, .msg_iovlen = 1};
        CHECK(recvmsg(fd, &header, MSG_PEEK | MSG_TRUNC) == (ssize_t)lengths[index]);
        CHECK(!!(header.msg_flags & MSG_TRUNC) == (lengths[index] > peek.iov_len));
        CHECK(header.msg_namelen == sizeof(from));
        address_matches(from, *peer);
        verify(bytes, index, lengths[index] < 5 ? lengths[index] : 5, seed);
        CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == (int)lengths[index]);
        struct iovec vectors[] = {{bytes, 11}, {bytes + 11, sizeof(bytes) - 11}};
        header = (struct msghdr){.msg_name = &from, .msg_namelen = sizeof(from),
            .msg_iov = vectors, .msg_iovlen = 2};
        CHECK(recvmsg(fd, &header, 0) == (ssize_t)lengths[index]);
        CHECK(!(header.msg_flags & MSG_TRUNC) && header.msg_namelen == sizeof(from));
    } else {
        CHECK(recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&from, &length) == (ssize_t)lengths[index]);
        CHECK(length == sizeof(from));
    }
    address_matches(from, *peer); *peer = from;
    verify(bytes, index, lengths[index], seed);
}
static void batch_send(int fd, struct sockaddr_in peer, unsigned int seed)
{
    unsigned char bytes[RECORDS][CAPACITY];
    struct iovec vectors[RECORDS][2];
    struct mmsghdr messages[RECORDS] = {0};
    for (unsigned int i = 0; i < RECORDS; ++i) {
        fill(bytes[i], i, seed);
        vectors[i][0] = (struct iovec){bytes[i], lengths[i] / 2};
        vectors[i][1] = (struct iovec){bytes[i] + lengths[i] / 2, lengths[i] - lengths[i] / 2};
        messages[i].msg_hdr = (struct msghdr){.msg_name = &peer, .msg_namelen = sizeof(peer),
            .msg_iov = vectors[i], .msg_iovlen = 2};
    }
    unsigned int sent = 0;
    while (sent < RECORDS) {
        int count = sendmmsg(fd, messages + sent, RECORDS - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && errno == EAGAIN) {writable(fd); continue;}
        CHECK(count > 0 && (unsigned int)count <= RECORDS - sent);
        for (int i = 0; i < count; ++i) CHECK(messages[sent + i].msg_len == lengths[sent + i]);
        sent += (unsigned int)count;
    }
}
static void batch_receive(int fd, int ep, struct sockaddr_in *peer, unsigned int seed)
{
    unsigned int received = 0;
    while (received < RECORDS) {
        ready(ep);
        unsigned char bytes[RECORDS][CAPACITY];
        struct sockaddr_in from[RECORDS] = {0};
        struct iovec vectors[RECORDS];
        struct mmsghdr messages[RECORDS] = {0};
        for (unsigned int i = 0; i < RECORDS; ++i) {
            vectors[i] = (struct iovec){bytes[i], sizeof(bytes[i])};
            messages[i].msg_hdr = (struct msghdr){.msg_name = &from[i], .msg_namelen = sizeof(from[i]),
                .msg_iov = &vectors[i], .msg_iovlen = 1};
        }
        int count = recvmmsg(fd, messages, RECORDS - received, MSG_DONTWAIT, NULL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        CHECK(count > 0 && (unsigned int)count <= RECORDS - received);
        for (int i = 0; i < count; ++i) {
            CHECK(messages[i].msg_len == lengths[received]);
            CHECK(!(messages[i].msg_hdr.msg_flags & MSG_TRUNC));
            CHECK(messages[i].msg_hdr.msg_namelen == sizeof(from[i]));
            address_matches(from[i], *peer); *peer = from[i];
            verify(bytes[i], received, messages[i].msg_len, seed); ++received;
        }
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = strcmp(argv[1], "server") == 0;
    CHECK(server || strcmp(argv[1], "client") == 0);
    int message = strcmp(argv[4], "message") == 0, batch = strcmp(argv[4], "batch") == 0;
    CHECK(message || batch || strcmp(argv[4], "basic") == 0);
    char *end; long port = strtol(argv[3], &end, 10);
    CHECK(!*end && port > 0 && port <= 65535);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x554450};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    struct sockaddr_in peer = server ? (struct sockaddr_in){0} : address;
    if (server) {
        CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
        printf("READY %ld\n", port); fflush(stdout);
    } else if (message) {
        CHECK(connect(fd, (void *)&peer, sizeof(peer)) == 0);
        struct sockaddr_in actual; socklen_t length = sizeof(actual);
        CHECK(getpeername(fd, (void *)&actual, &length) == 0 && length == sizeof(actual));
        address_matches(actual, peer);
    }
    if (batch) {
        if (!server) batch_send(fd, peer, 17);
        batch_receive(fd, ep, &peer, server ? 17 : 93);
        if (server) batch_send(fd, peer, 93);
    } else for (unsigned int i = 0; i < RECORDS; ++i) {
        if (!server) single_send(fd, peer, i, 17, message, message);
        single_receive(fd, ep, &peer, i, server ? 17 : 93, message);
        if (server) single_send(fd, peer, i, 93, message, 0);
    }
    unsigned char byte;
    errno = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(close(ep) == 0 && close(fd) == 0);
    printf("PASS: F-Stack UDP %s, 4 distinct datagrams each direction including empty payload\n", argv[4]);
    return 0;
}
