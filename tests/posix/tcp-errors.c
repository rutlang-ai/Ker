#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static volatile sig_atomic_t pipes;
static void pipe_signal(int number) { (void)number; pipes++; }
static int64_t milliseconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static struct sockaddr_in endpoint(unsigned int port)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, "198.18.0.1", &address.sin_addr) == 1);
    return address;
}
static int connect_to(unsigned int port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = endpoint(port);
    CHECK(fd >= 0 && connect(fd, (void *)&address, sizeof(address)) == 0);
    return fd;
}
static void peer(void)
{
    struct sockaddr_in address = endpoint(25008);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), reuse = 1;
    CHECK(listener >= 0 && setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
    CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 8) == 0);
    puts("READY 25008"); fflush(stdout);
    for (unsigned int i = 0; i < 2; ++i) {
        int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        CHECK(fd >= 0);
        char token = i ? 'T' : 'R', answer;
        CHECK(send(fd, &token, 1, MSG_NOSIGNAL) == 1 && recv(fd, &answer, 1, 0) == 1);
        CHECK(answer == (i ? 't' : 'r'));
        if (!i) {
            struct linger reset = {1, 0};
            CHECK(setsockopt(fd, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) == 0);
        }
        CHECK(close(fd) == 0);
    }
    CHECK(close(listener) == 0);
}
static void native(void)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(listener >= 0 && bind(listener, (void *)&local, sizeof(local)) == 0 && listen(listener, 1) == 0);
    CHECK(accept4(listener, NULL, NULL, SOCK_NONBLOCK) == -1 && errno == EAGAIN);
    CHECK(close(listener) == 0);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in unused = endpoint(25009);
    CHECK(fd >= 0 && connect(fd, (void *)&unused, sizeof(unused)) == -1 && errno == EINPROGRESS);
    struct pollfd wait = {fd, POLLOUT, 0};
    CHECK(poll(&wait, 1, 5000) == 1);
    int error = 0;
    socklen_t length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == ECONNREFUSED);
    CHECK(close(fd) == 0);
    fd = connect_to(25008);
    char byte;
    CHECK(recv(fd, &byte, 1, 0) == 1 && byte == 'R');
    CHECK(send(fd, "r", 1, MSG_NOSIGNAL) == 1);
    CHECK(recv(fd, &byte, 1, 0) == -1 && errno == ECONNRESET);
    CHECK(send(fd, "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE && pipes == 0);
    CHECK(write(fd, "x", 1) == -1 && errno == EPIPE && pipes == 1);
    CHECK(close(fd) == 0);
    fd = connect_to(25008);
    CHECK(recv(fd, &byte, 1, 0) == 1 && byte == 'T');
    struct timeval timeout = {.tv_usec = 100000};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    int64_t start = milliseconds();
    CHECK(recv(fd, &byte, 1, 0) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK(milliseconds() - start >= 50 && milliseconds() - start < 2000);
    CHECK(send(fd, "t", 1, MSG_NOSIGNAL) == 1);
    timeout = (struct timeval){0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(recv(fd, &byte, 1, 0) == 0 && close(fd) == 0);
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    int retries = 1;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &retries, sizeof(retries)) == 0);
    struct sockaddr_in blackhole = endpoint(25010);
    start = milliseconds();
    CHECK(connect(fd, (void *)&blackhole, sizeof(blackhole)) == -1 && errno == EINPROGRESS);
    wait = (struct pollfd){fd, POLLOUT, 0};
    CHECK(poll(&wait, 1, 12000) == 1);
    error = 0; length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == ETIMEDOUT);
    CHECK(milliseconds() - start >= 1000 && milliseconds() - start < 12000);
    CHECK(close(fd) == 0);
    puts("PASS: accept EAGAIN, refused connect, RST, EPIPE/SIGPIPE, receive deadline, native SYN timeout");
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    struct sigaction action = {.sa_handler = pipe_signal};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
    if (argv[1][0] == 'p') peer(); else native();
    return 0;
}
