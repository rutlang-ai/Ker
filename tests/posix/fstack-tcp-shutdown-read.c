/* Ker-specific Linux extension of pinned F-Stack socket/readiness scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TAG UINT64_C(0xfedcba9876543210)
static void transfer(int fd, void *data, size_t length, int sending)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = sending ? send(fd, (char *)data + done, length - done, MSG_NOSIGNAL) :
                                 recv(fd, (char *)data + done, length - done, 0);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0); done += (size_t)count;
    }
}
static void marker(int fd, char expected, int sending)
{
    char byte = expected; transfer(fd, &byte, 1, sending); CHECK(byte == expected);
}
static void eof(int fd)
{
    char byte; CHECK(recv(fd, &byte, 1, 0) == 0);
}
static void timeout(int fd)
{
    struct timeval value = {.tv_sec = 5};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value)) == 0);
}
static int listen_at(struct sockaddr_in address, int nonblock)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), 0);
    int value = 1; CHECK(fd >= 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == 0);
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 4) == 0);
    timeout(fd); return fd;
}
static int connect_to(struct sockaddr_in address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0); timeout(fd);
    CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    struct sockaddr_in peer = {0}; socklen_t length = sizeof(peer);
    CHECK(getpeername(fd, (void *)&peer, &length) == 0 && length == sizeof(peer));
    CHECK(peer.sin_family == AF_INET && peer.sin_addr.s_addr == address.sin_addr.s_addr &&
          peer.sin_port == address.sin_port);
    int error = -1; length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
    return fd;
}
#define PAYLOAD 37
#define TAG_ALIAS UINT64_C(0x0123456789abcdef)
static void queued(int fd, int wanted)
{
    struct timespec start, now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    for (;;) {
        int bytes = -1; CHECK(ioctl(fd, FIONREAD, &bytes) == 0);
        if (bytes == wanted) return;
        CHECK(bytes >= 0 && bytes < wanted);
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK((now.tv_sec - start.tv_sec) * 1000000000LL + now.tv_nsec - start.tv_nsec < 5000000000LL);
        struct timespec delay = {.tv_nsec = 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
}
static void clean_error(int fd)
{
    int error = -1; socklen_t length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && length == sizeof(error) && error == 0);
}
static void terminal_readiness(int fd, int alias, int ep)
{
    struct pollfd targets[] = {{fd, POLLIN | POLLRDHUP, 0}, {alias, POLLIN | POLLRDHUP, 0}};
    CHECK(poll(targets, 2, 0) == 2);
    for (unsigned int i = 0; i < 2; ++i) {
        CHECK((targets[i].revents & (POLLIN | POLLRDHUP)) == (POLLIN | POLLRDHUP));
        CHECK(!(targets[i].revents & (POLLERR | POLLHUP | POLLNVAL)));
    }
    struct epoll_event events[2];
    CHECK(epoll_wait(ep, events, 2, 2000) == 2);
    unsigned int seen = 0;
    for (unsigned int i = 0; i < 2; ++i) {
        unsigned int bit = events[i].data.u64 == TAG ? 1 : 2;
        CHECK(events[i].data.u64 == TAG || events[i].data.u64 == TAG_ALIAS);
        CHECK(!(seen & bit)); seen |= bit;
        CHECK((events[i].events & (EPOLLIN | EPOLLRDHUP)) == (EPOLLIN | EPOLLRDHUP));
        CHECK(!(events[i].events & (EPOLLERR | EPOLLHUP)));
    }
    CHECK(seen == 3);
}
static void receiver(int fd, int control, int with_data, unsigned char *payload)
{
    int alias = dup(fd), ep = epoll_create1(EPOLL_CLOEXEC); CHECK(alias >= 0 && ep >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.u64 = TAG};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    event.data.u64 = TAG_ALIAS; CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, alias, &event) == 0);
    int low = 128; CHECK(setsockopt(alias, SOL_SOCKET, SO_RCVLOWAT, &low, sizeof(low)) == 0);
    int actual_low = 0; socklen_t option_length = sizeof(actual_low);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &actual_low, &option_length) == 0 &&
          option_length == sizeof(actual_low) && actual_low == low);
    marker(control, 'R', 1); marker(control, 'S', 0);
    queued(fd, with_data ? PAYLOAD : 0);
    struct pollfd target = {.fd = fd, .events = POLLIN | POLLRDHUP};
    CHECK(poll(&target, 1, 0) == 0 && target.revents == 0);
    CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    errno = 0; CHECK(shutdown(alias, 42) == -1 && errno == EINVAL);
    unsigned char bytes[PAYLOAD]; memset(bytes, 0xa5, sizeof(bytes));
    if (with_data) {
        CHECK(recv(fd, bytes, sizeof(bytes), MSG_PEEK | MSG_DONTWAIT) == PAYLOAD);
        CHECK(!memcmp(bytes, payload, sizeof(bytes)));
    } else {
        CHECK(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    }
    CHECK(shutdown(alias, SHUT_RD) == 0 && shutdown(fd, SHUT_RD) == 0);
    option_length = sizeof(actual_low);
    CHECK(getsockopt(alias, SOL_SOCKET, SO_RCVLOWAT, &actual_low, &option_length) == 0 &&
          option_length == sizeof(actual_low) && actual_low == low);
    terminal_readiness(fd, alias, ep);
    queued(alias, with_data ? PAYLOAD : 0);
    if (with_data) {
        memset(bytes, 0xa5, sizeof(bytes));
        CHECK(recv(alias, bytes, sizeof(bytes), MSG_PEEK | MSG_WAITALL) == PAYLOAD);
        CHECK(!memcmp(bytes, payload, sizeof(bytes))); queued(fd, PAYLOAD);
        memset(bytes, 0xa5, sizeof(bytes));
        struct iovec first[] = {{bytes, 3}, {bytes + 3, 14}};
        CHECK(readv(fd, first, 2) == 17 && !memcmp(bytes, payload, 17)); queued(alias, PAYLOAD - 17);
        for (unsigned int i = 17; i < sizeof(bytes); ++i) CHECK(bytes[i] == 0xa5);
        struct iovec rest[] = {{bytes + 17, 1}, {bytes + 18, PAYLOAD - 18}};
        struct msghdr message = {.msg_iov = rest, .msg_iovlen = 2};
        CHECK(recvmsg(alias, &message, MSG_WAITALL) == PAYLOAD - 17 && message.msg_flags == 0);
        CHECK(!memcmp(bytes, payload, sizeof(bytes)));
    }
    queued(fd, 0);
    memset(bytes, 0xa5, sizeof(bytes));
    CHECK(recv(fd, bytes, sizeof(bytes), MSG_PEEK | MSG_DONTWAIT) == 0);
    struct iovec iov[] = {{bytes, 5}, {bytes + 5, PAYLOAD - 5}};
    struct msghdr message = {.msg_iov = iov, .msg_iovlen = 2};
    CHECK(recvmsg(alias, &message, MSG_DONTWAIT) == 0 && message.msg_flags == 0);
    CHECK(readv(fd, iov, 2) == 0);
    for (unsigned int i = 0; i < sizeof(bytes); ++i) CHECK(bytes[i] == 0xa5);
    terminal_readiness(fd, alias, ep); clean_error(fd); clean_error(alias);
    /* Peer has not sent FIN: S/D on the separate control connection bracket
     * every local EOF assertion. RCV_SHUTDOWN must leave sending usable. */
    CHECK(close(fd) == 0);
    transfer(alias, payload, PAYLOAD, 1);
    CHECK(shutdown(alias, SHUT_WR) == 0); marker(control, 'D', 1);
    marker(control, 'F', 0); clean_error(alias);
    CHECK(close(alias) == 0 && close(ep) == 0); marker(control, 'C', 1);
}
static void sender(int fd, int control, int with_data, unsigned char *payload)
{
    marker(control, 'R', 0);
    if (with_data) transfer(fd, payload, PAYLOAD, 1);
    marker(control, 'S', 1); marker(control, 'D', 0);
    unsigned char reply[PAYLOAD]; transfer(fd, reply, sizeof(reply), 0);
    CHECK(!memcmp(reply, payload, sizeof(reply))); eof(fd); clean_error(fd);
    CHECK(shutdown(fd, SHUT_WR) == 0); marker(control, 'F', 1);
    marker(control, 'C', 0); CHECK(close(fd) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int server = !strcmp(argv[1], "server"); CHECK(server || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65535);
    address.sin_port = htons(port);
    int listener = -1, control;
    if (server) {
        listener = listen_at(address, 0); printf("READY %ld\n", port); fflush(stdout);
        control = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(control >= 0); timeout(control);
    } else control = connect_to(address);
    for (unsigned int i = 0; i < 4; ++i) {
        int fd;
        if (server) {fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);}
        else fd = connect_to(address);
        unsigned char payload[PAYLOAD];
        for (unsigned int j = 0; j < sizeof(payload); ++j) payload[j] = (unsigned char)(i * 41 + j * 17);
        if (server == !(i & 1)) receiver(fd, control, i >= 2, payload);
        else sender(fd, control, i >= 2, payload);
    }
    if (server) CHECK(close(listener) == 0);
    CHECK(shutdown(control, SHUT_WR) == 0); eof(control); CHECK(close(control) == 0);
    printf("PASS: TCP %s SHUT_RD empty/queued, aliases, low-water EOF/readiness and reverse send\n", argv[1]);
    return 0;
}
