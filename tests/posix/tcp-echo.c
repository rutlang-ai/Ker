#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define SIZE (1024U * 1024U)
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %s\n", \
    __FILE__, __LINE__, #x, strerror(errno)); exit(1); } } while (0)
static uint16_t port;
static const char *address;
static bool slow_server, slow_client;
static _Thread_local size_t transfer_offset, transfer_length;

static void wait_ready(int ep, int fd, uint32_t events)
{
    struct epoll_event event = {.events = events, .data.fd = fd};
    if (epoll_ctl(ep, EPOLL_CTL_MOD, fd, &event))
        CHECK(errno == ENOENT && epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    int count;
    do count = epoll_wait(ep, &event, 1, 5000); while (count < 0 && errno == EINTR);
    if (count != 1) {
        struct tcp_info info = {0};
        socklen_t length = sizeof(info);
        getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length);
        fprintf(stderr, "wait fd=%d events=%x count=%d offset=%zu/%zu state=%u unacked=%u retrans=%u\n",
            fd, events, count, transfer_offset, transfer_length, info.tcpi_state, info.tcpi_unacked, info.tcpi_total_retrans);
    }
    CHECK(count == 1 && event.data.fd == fd);
}

static void transfer(int fd, void *buffer, size_t length, int writing)
{
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = writing ? send(fd, (char *)buffer + offset, length - offset, MSG_NOSIGNAL) :
            recv(fd, (char *)buffer + offset, length - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            transfer_offset = offset;
            transfer_length = length;
            wait_ready(ep, fd, writing ? EPOLLOUT : EPOLLIN);
            continue;
        }
        CHECK(count > 0);
        offset += (size_t)count;
    }
    CHECK(close(ep) == 0);
}

static void expect_eof(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    char byte;
    for (;;) {
        ssize_t count = recv(fd, &byte, 1, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            wait_ready(ep, fd, EPOLLIN | EPOLLRDHUP);
            continue;
        }
        CHECK(count == 0);
        break;
    }
    CHECK(close(ep) == 0);
}

static struct sockaddr_in endpoint(void)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, address, &addr.sin_addr) == 1);
    return addr;
}

static void connected(int fd)
{
    int error = -1;
    socklen_t length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
    struct tcp_info info;
    length = sizeof(info);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0 &&
        length > 0 && info.tcpi_state == TCP_ESTABLISHED);
    int small = 4096;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
}

static void report(int fd)
{
    struct tcp_info info = {0};
    socklen_t length = sizeof(info);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0);
    printf("TCP_INFO total_retrans=%u\n", info.tcpi_total_retrans);
}

static int listen_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    int reuse = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
    if (slow_server) {
        int small = 4096;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
    }
    struct sockaddr_in addr = endpoint();
    CHECK(bind(fd, (void *)&addr, sizeof(addr)) == 0 && listen(fd, 8) == 0);
    socklen_t length = sizeof(addr);
    CHECK(getsockname(fd, (void *)&addr, &length) == 0);
    port = ntohs(addr.sin_port);
    return fd;
}

static void *server(void *arg)
{
    int listener = *(int *)arg;
    int ep = epoll_create1(EPOLL_CLOEXEC), fd;
    CHECK(ep >= 0);
    for (;;) {
        fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd >= 0) break;
        if (errno == EINTR) continue;
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
        wait_ready(ep, listener, EPOLLIN);
    }
    connected(fd);
    if (slow_server) { struct timespec delay = {.tv_sec = 1}; nanosleep(&delay, NULL); }
    unsigned char *buffer = malloc(SIZE);
    CHECK(buffer);
    transfer(fd, buffer, SIZE, 0);
    expect_eof(fd);
    transfer(fd, buffer, SIZE, 1);
    CHECK(shutdown(fd, SHUT_WR) == 0);
    report(fd);
    CHECK(close(fd) == 0 && close(listener) == 0 && close(ep) == 0);
    free(buffer);
    return NULL;
}

static void client(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    if (slow_client) {
        int small = 4096;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
    }
    struct sockaddr_in addr = endpoint();
    if (connect(fd, (void *)&addr, sizeof(addr))) {
        CHECK(errno == EINPROGRESS);
        int ep = epoll_create1(EPOLL_CLOEXEC);
        CHECK(ep >= 0);
        wait_ready(ep, fd, EPOLLOUT);
        CHECK(close(ep) == 0);
    }
    connected(fd);
    unsigned char *buffer = malloc(SIZE);
    CHECK(buffer);
    for (size_t i = 0; i < SIZE; ++i) buffer[i] = (unsigned char)(i * 17U + (i >> 8));
    transfer(fd, buffer, SIZE, 1);
    CHECK(shutdown(fd, SHUT_WR) == 0);
    if (slow_client) { struct timespec delay = {.tv_sec = 1}; nanosleep(&delay, NULL); }
    memset(buffer, 0, SIZE);
    transfer(fd, buffer, SIZE, 0);
    for (size_t i = 0; i < SIZE; ++i)
        CHECK(buffer[i] == (unsigned char)(i * 17U + (i >> 8)));
    expect_eof(fd);
    report(fd);
    CHECK(close(fd) == 0);
    free(buffer);
    puts("PASS: POSIX TCP 1MiB echo, epoll, nonblocking connect/accept, half-close");
}

static void wait_for_fault_release(const char *path, unsigned int timeout_ms)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    CHECK(fd >= 0);
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    unsigned char token = 0;
    for (;;) {
        struct timespec now;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        int timeout = (int)((deadline.tv_sec - now.tv_sec) * 1000 +
            (deadline.tv_nsec - now.tv_nsec) / 1000000);
        CHECK(timeout > 0);
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        int result;
        do result = poll(&descriptor, 1, timeout); while (result < 0 && errno == EINTR);
        CHECK(result > 0);
        CHECK(!(descriptor.revents & POLLNVAL));
        CHECK(!(descriptor.revents & POLLERR) || (descriptor.revents & POLLHUP));
        if (descriptor.revents & POLLIN) {
            ssize_t count;
            do count = read(fd, &token, sizeof(token)); while (count < 0 && errno == EINTR);
            CHECK(count == 1 && token == 0xa5);
            break;
        }
        CHECK(descriptor.revents & POLLHUP);
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        while (nanosleep(&pause, &pause) && errno == EINTR) {}
    }
    CHECK(close(fd) == 0);
}

int main(int argc, char **argv)
{
    bool gated_client = argc == 5 && !strcmp(argv[1], "gated-client");
    bool gate_check = argc == 6 && !strcmp(argv[1], "fault-gate-check");
    CHECK(argc == 4 || gated_client || gate_check);
    signal(SIGPIPE, SIG_IGN);
    address = argv[2];
    char *end;
    unsigned long value = strtoul(argv[3], &end, 10);
    CHECK(!*end && value <= 65535);
    port = (uint16_t)value;
    slow_server = !strcmp(argv[1], "slow-server");
    slow_client = !strcmp(argv[1], "slow-client");
    if (gated_client) {
        printf("READY %u\n", port);
        fflush(stdout);
        wait_for_fault_release(argv[4], 20000);
        client();
    } else if (gate_check) {
        char *timeout_end;
        unsigned long timeout = strtoul(argv[5], &timeout_end, 10);
        CHECK(!*timeout_end && timeout > 0 && timeout <= 20000);
        printf("READY %u\n", port);
        fflush(stdout);
        wait_for_fault_release(argv[4], (unsigned int)timeout);
        puts("PASS: bounded TCP fault gate");
    } else if (!strcmp(argv[1], "client") || slow_client) client();
    else if (!strcmp(argv[1], "server") || slow_server) {
        int listener = listen_socket();
        printf("READY %u\n", port);
        fflush(stdout);
        server(&listener);
    } else {
        CHECK(!strcmp(argv[1], "loopback"));
        int listener = listen_socket();
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, server, &listener) == 0);
        client();
        CHECK(pthread_join(thread, NULL) == 0);
    }
    return 0;
}
