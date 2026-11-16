#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define DATA_SIZE 262147U
#define PEEK_SIZE 17U

static void wait_for(int fd, short events)
{
    struct pollfd ready = {.fd = fd, .events = events};
    CHECK(poll(&ready, 1, 5000) == 1);
    CHECK((ready.revents & events) && !(ready.revents & (POLLERR | POLLNVAL)));
}

static void nonblocking(int fd, int enabled)
{
    int flags = fcntl(fd, F_GETFL);
    CHECK(flags >= 0 && fcntl(fd, F_SETFL, enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) == 0);
}

/* Include empty entries and odd boundaries; rebuild from the actual returned
 * byte count because TCP may complete anywhere within an iovec. */
static void vectors(struct iovec iov[5], unsigned char *bytes, size_t length)
{
    const size_t sizes[4] = {1, 7, 4093, DATA_SIZE};
    iov[0] = (struct iovec){.iov_base = NULL, .iov_len = 0};
    for (unsigned int i = 0; i < 4; ++i) {
        size_t count = length < sizes[i] ? length : sizes[i];
        iov[i + 1] = (struct iovec){.iov_base = bytes, .iov_len = count};
        bytes += count;
        length -= count;
    }
    CHECK(length == 0);
}

static void transmit(int fd, unsigned char *bytes)
{
    int small = 4096;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    nonblocking(fd, 1);
    unsigned int calls = 0, partial = 0;
    size_t offset = 0;
    CHECK(writev(fd, NULL, 0) == 0);
    while (offset < DATA_SIZE) {
        struct iovec iov[5];
        vectors(iov, bytes + offset, DATA_SIZE - offset);
        struct msghdr message = {.msg_iov = iov, .msg_iovlen = 5};
        ssize_t count = calls % 2 ? sendmsg(fd, &message, MSG_NOSIGNAL) : writev(fd, iov, 5);
        if (count < 0) {
            CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
            wait_for(fd, POLLOUT);
            continue;
        }
        CHECK(count > 0 && (size_t)count <= DATA_SIZE - offset);
        calls++;
        partial += (size_t)count < DATA_SIZE - offset;
        offset += (size_t)count;
    }
    CHECK(calls > 1 && partial > 0);
    CHECK(shutdown(fd, SHUT_WR) == 0);
}

static void receive_stream(int fd, const unsigned char *expected)
{
    unsigned char bytes[DATA_SIZE], peek[PEEK_SIZE];
    memset(bytes, 0xa5, sizeof(bytes));
    nonblocking(fd, 0);
    struct iovec peek_iov[] = {{peek, 3}, {peek + 3, PEEK_SIZE - 3}};
    struct msghdr message = {.msg_iov = peek_iov, .msg_iovlen = 2};
    CHECK(recvmsg(fd, &message, MSG_PEEK | MSG_WAITALL) == PEEK_SIZE);
    CHECK(message.msg_flags == 0 && !memcmp(peek, expected, PEEK_SIZE));
    CHECK(recv(fd, bytes, PEEK_SIZE, MSG_WAITALL) == PEEK_SIZE);
    CHECK(!memcmp(peek, bytes, PEEK_SIZE));
    nonblocking(fd, 1);
    CHECK(readv(fd, NULL, 0) == 0);
    size_t offset = PEEK_SIZE;
    unsigned int calls = 0;
    while (offset < DATA_SIZE) {
        struct iovec iov[5];
        size_t capacity = DATA_SIZE - offset;
        if (capacity > 8191) capacity = 8191;
        vectors(iov, bytes + offset, capacity);
        message = (struct msghdr){.msg_iov = iov, .msg_iovlen = 5};
        ssize_t count = calls % 2 ? recvmsg(fd, &message, 0) : readv(fd, iov, 5);
        if (count < 0) {
            CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
            wait_for(fd, POLLIN);
            continue;
        }
        CHECK(count > 0 && (size_t)count <= capacity && message.msg_flags == 0);
        calls++;
        offset += (size_t)count;
    }
    CHECK(!memcmp(bytes, expected, sizeof(bytes)));
    nonblocking(fd, 0);
    CHECK(recv(fd, peek, sizeof(peek), MSG_PEEK) == 0);
    CHECK(readv(fd, peek_iov, 2) == 0);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.fd = fd};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    CHECK(epoll_wait(ep, &event, 1, 5000) == 1 && event.data.fd == fd);
    CHECK((event.events & (EPOLLIN | EPOLLRDHUP)) == (EPOLLIN | EPOLLRDHUP));
    CHECK(close(ep) == 0);
}

int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int serving = !strcmp(argv[1], "server");
    CHECK(serving || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[3]))};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    unsigned char expected[DATA_SIZE];
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(i * 29U + (i >> 8) * 17U);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    if (serving) {
        int reuse = 1;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
        CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 8) == 0);
        printf("READY %s\n", argv[3]); fflush(stdout);
        int accepted = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        CHECK(accepted >= 0 && close(fd) == 0);
        fd = accepted;
        receive_stream(fd, expected);
        /* Peer FIN closes only its write direction. */
        transmit(fd, expected);
    } else {
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
        transmit(fd, expected);
        receive_stream(fd, expected);
    }
    CHECK(close(fd) == 0);
    puts("PASS: vectored TCP short writes, peek/waitall, exact bytes, half-close and RDHUP");
    return 0;
}
