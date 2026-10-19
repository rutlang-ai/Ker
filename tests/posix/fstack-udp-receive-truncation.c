/* Ker-specific receive-truncation extension of the pinned F-Stack UDP example. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TAG UINT64_C(0xfedcba9876543210)
static const size_t lengths[] = {0, 1, 33, 257};
struct buffers { unsigned char left[3], right[4]; };
struct request { uint32_t mode, record; };
static void same(struct sockaddr_in actual, struct sockaddr_in expected)
{
    CHECK(actual.sin_family == AF_INET && actual.sin_addr.s_addr == expected.sin_addr.s_addr && actual.sin_port != 0);
    if (expected.sin_port) CHECK(actual.sin_port == expected.sin_port);
}
static unsigned char pattern(int mode, int record, int sub, size_t offset)
{
    return (unsigned char)(mode * 31 + record * 17 + sub * 73 + offset * 43);
}
static int watch(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0); return ep;
}
static void wait_data(int ep)
{
    struct epoll_event event;
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && (event.events & EPOLLIN) && event.data.u64 == TAG);
}
static void empty(int fd, int ep)
{
    unsigned char byte; errno = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    int available = -1; CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == 0);
    struct epoll_event event; CHECK(epoll_wait(ep, &event, 1, 0) == 0);
}
static void send_request(int fd, struct sockaddr_in peer, int mode, int record)
{
    struct request request = {htonl(mode), htonl(record)};
    CHECK(sendto(fd, &request, sizeof(request), 0, (void *)&peer, sizeof(peer)) == sizeof(request));
}
static struct sockaddr_in receive_request(int fd, int ep, struct sockaddr_in peer, int mode, int record)
{
    wait_data(ep); struct request request; struct sockaddr_in source = {0}; socklen_t length = sizeof(source);
    CHECK(recvfrom(fd, &request, sizeof(request), MSG_TRUNC, (void *)&source, &length) == sizeof(request));
    CHECK(length == sizeof(source) && ntohl(request.mode) == (uint32_t)mode && ntohl(request.record) == (uint32_t)record);
    same(source, peer); return source;
}
static void send_reply(int fd, struct sockaddr_in peer, int mode, int record, int sub)
{
    unsigned char bytes[257]; size_t length = lengths[(record + sub) % 4];
    for (size_t i = 0; i < length; ++i) bytes[i] = pattern(mode, record, sub, i);
    CHECK(sendto(fd, bytes, length, 0, (void *)&peer, sizeof(peer)) == (ssize_t)length);
}
static void verify_buffers(struct buffers *buffer, size_t length, int mode, int record, int sub)
{
    for (size_t i = 0; i < 7; ++i) {
        unsigned char actual = i < 3 ? buffer->left[i] : buffer->right[i - 3];
        CHECK(actual == (i < length ? pattern(mode, record, sub, i) : 0xa5));
    }
}
static void check_message(struct msghdr *message, struct sockaddr_in source, struct sockaddr_in peer,
    size_t length, struct buffers *buffer, int mode, int record, int sub)
{
    CHECK(message->msg_namelen == sizeof(source)); same(source, peer);
    CHECK(!!(message->msg_flags & MSG_TRUNC) == (length > 7));
    CHECK(!(message->msg_flags & MSG_CTRUNC)); verify_buffers(buffer, length, mode, record, sub);
}
static void receive_replies(int fd, int ep, struct sockaddr_in peer, int mode, int record)
{
    int total = mode == 2 ? 2 : 1, done = 0;
    while (done < total) {
        wait_data(ep);
        size_t length = lengths[(record + done) % 4]; int available = -1;
        CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == (int)length);
        if (!mode) {
            unsigned char bytes[7]; memset(bytes, 0xa5, sizeof(bytes));
            struct sockaddr_in source = {0}; socklen_t size = sizeof(source);
            CHECK(recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&source, &size) == (ssize_t)(length < 7 ? length : 7));
            CHECK(size == sizeof(source)); same(source, peer);
            for (size_t i = 0; i < sizeof(bytes); ++i)
                CHECK(bytes[i] == (i < length ? pattern(mode, record, 0, i) : 0xa5));
            ++done;
        } else {
            struct buffers buffers[2]; memset(buffers, 0xa5, sizeof(buffers));
            struct sockaddr_in sources[2] = {0}; struct iovec vectors[2][2]; struct mmsghdr messages[2] = {0};
            for (int i = 0; i < total - done; ++i) {
                vectors[i][0] = (struct iovec){buffers[i].left, sizeof(buffers[i].left)};
                vectors[i][1] = (struct iovec){buffers[i].right, sizeof(buffers[i].right)};
                messages[i].msg_hdr = (struct msghdr){.msg_name = &sources[i], .msg_namelen = sizeof(sources[i]),
                    .msg_iov = vectors[i], .msg_iovlen = 2};
            }
            int count;
            if (mode == 1) {
                ssize_t copied = recvmsg(fd, &messages[0].msg_hdr, 0);
                CHECK(copied == (ssize_t)(length < 7 ? length : 7)); count = 1;
            } else {
                count = recvmmsg(fd, messages, total - done, MSG_TRUNC | MSG_DONTWAIT, NULL);
                CHECK(count > 0 && count <= total - done);
            }
            for (int i = 0; i < count; ++i) {
                size_t full = lengths[(record + done + i) % 4];
                if (mode == 2) CHECK(messages[i].msg_len == full);
                check_message(&messages[i].msg_hdr, sources[i], peer, full, &buffers[i], mode, record, done + i);
            }
            done += count;
        }
    }
    /* Peer waits for the next request, so no truncated suffix or other packet may remain. */
    empty(fd, ep);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct in_addr local; CHECK(inet_pton(AF_INET, argv[2], &local) == 1);
    struct sockaddr_in peer = {.sin_family = AF_INET}; CHECK(inet_pton(AF_INET, argv[3], &peer.sin_addr) == 1);
    char *end; long port = strtol(argv[4], &end, 10); CHECK(!*end && port > 0 && port <= 65535);
    if (!server) peer.sin_port = htons(port);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = local, .sin_port = server ? htons(port) : 0};
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
    socklen_t size = sizeof(address); CHECK(getsockname(fd, (void *)&address, &size) == 0);
    CHECK(size == sizeof(address) && address.sin_addr.s_addr == local.s_addr && address.sin_port != 0);
    int ep = watch(fd); if (server) { printf("READY %ld\n", port); fflush(stdout); }
    for (int mode = 0; mode < 3; ++mode) for (int record = 0; record < 4; ++record) {
        if (server) {
            peer = receive_request(fd, ep, peer, mode, record);
            for (int sub = 0; sub < (mode == 2 ? 2 : 1); ++sub) send_reply(fd, peer, mode, record, sub);
        } else {
            send_request(fd, peer, mode, record); receive_replies(fd, ep, peer, mode, record);
        }
    }
    uint32_t ack = htonl(0x11223344);
    if (server) {
        peer = receive_request(fd, ep, peer, 3, 0); empty(fd, ep);
        CHECK(sendto(fd, &ack, sizeof(ack), 0, (void *)&peer, sizeof(peer)) == sizeof(ack));
    } else {
        send_request(fd, peer, 3, 0); wait_data(ep);
        struct sockaddr_in source = {0}; socklen_t length = sizeof(source); uint32_t actual;
        CHECK(recvfrom(fd, &actual, sizeof(actual), MSG_TRUNC, (void *)&source, &length) == sizeof(actual) && actual == ack);
        CHECK(length == sizeof(source)); same(source, peer); empty(fd, ep);
    }
    CHECK(close(ep) == 0 && close(fd) == 0);
    printf("PASS: UDP %s consuming truncation, scatter/batch flags, canaries and zero-length recovery\n", argv[1]);
    return 0;
}
