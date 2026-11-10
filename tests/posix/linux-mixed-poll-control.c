/* Exercise real resident UDP readiness alongside ordinary host pipe descriptors. */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "line %d: %s (errno %d)\n", __LINE__, #test, errno); exit(1); } } while (0)
static long milliseconds(void)
{
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static volatile sig_atomic_t alarmed;
static void alarm_handler(int signo) { (void)signo; alarmed++; }
int main(void)
{
#ifdef KER_MIXED_CONTROL_IPV6
    int rx = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), tx = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), pipefd[2];
#else
    int rx = socket(AF_INET, SOCK_DGRAM, 0), tx = socket(AF_INET, SOCK_DGRAM, 0), pipefd[2];
#endif
    CHECK(rx >= 0 && tx >= 0 && pipe(pipefd) == 0);
#ifdef KER_MIXED_CONTROL_IPV6
    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    int protocol = 0; socklen_t protocol_size = sizeof(protocol);
    CHECK(getsockopt(rx, SOL_SOCKET, SO_PROTOCOL, &protocol, &protocol_size) == 0 &&
          protocol_size == sizeof(protocol) && protocol == IPPROTO_UDP);
#else
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
#endif
    CHECK(bind(rx, (void *)&address, sizeof(address)) == 0);
    socklen_t size = sizeof(address); CHECK(getsockname(rx, (void *)&address, &size) == 0);
    struct pollfd fds[] = {{.fd = pipefd[0], .events = POLLIN}, {.fd = rx, .events = POLLIN}, {.fd = -1, .events = POLLIN}};
    long start = milliseconds();
    CHECK(poll(fds, 3, 50) == 0); CHECK(milliseconds() - start >= 40 && milliseconds() - start < 2000);
    CHECK(write(pipefd[1], "h", 1) == 1);
    CHECK(poll(fds, 3, 0) == 1 && fds[0].revents == POLLIN && fds[1].revents == 0 && fds[2].revents == 0);
    char byte; CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'h');
    CHECK(sendto(tx, "n", 1, 0, (void *)&address, size) == 1);
    CHECK(poll(fds, 3, 1000) == 1 && fds[0].revents == 0 && fds[1].revents == POLLIN);
    CHECK(write(pipefd[1], "b", 1) == 1);
    CHECK(poll(fds, 3, 0) == 2 && fds[0].revents == POLLIN && fds[1].revents == POLLIN);
    fd_set reads, writes; FD_ZERO(&reads); FD_ZERO(&writes);
    FD_SET(pipefd[0], &reads); FD_SET(rx, &reads); FD_SET(tx, &writes);
    int maxfd = pipefd[0] > rx ? pipefd[0] : rx; if (tx > maxfd) maxfd = tx;
    struct timeval timeout = {0};
    CHECK(select(maxfd + 1, &reads, &writes, NULL, &timeout) == 3);
    CHECK(FD_ISSET(pipefd[0], &reads) && FD_ISSET(rx, &reads) && FD_ISSET(tx, &writes));
    CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'b');
    CHECK(recv(rx, &byte, 1, 0) == 1 && byte == 'n');
    FD_ZERO(&reads); FD_SET(pipefd[0], &reads); FD_SET(rx, &reads);
    timeout = (struct timeval){.tv_usec = 50000}; start = milliseconds();
    CHECK(select(maxfd + 1, &reads, NULL, NULL, &timeout) == 0);
    CHECK(milliseconds() - start >= 40 && milliseconds() - start < 2000);
    CHECK(!FD_ISSET(pipefd[0], &reads) && !FD_ISSET(rx, &reads));
    CHECK(timeout.tv_sec == 0 && timeout.tv_usec == 0);
    struct sigaction handler = {.sa_handler = alarm_handler}, previous;
    CHECK(sigemptyset(&handler.sa_mask) == 0 && sigaction(SIGALRM, &handler, &previous) == 0);
    struct itimerval timer = {.it_value = {.tv_usec = 20000}};
    CHECK(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    start = milliseconds();
    CHECK(poll(fds, 3, 1000) == -1 && errno == EINTR && alarmed == 1);
    CHECK(milliseconds() - start < 2000);
    FD_ZERO(&reads); FD_SET(pipefd[0], &reads); FD_SET(rx, &reads);
    timeout = (struct timeval){.tv_sec = 1};
    CHECK(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    CHECK(select(maxfd + 1, &reads, NULL, NULL, &timeout) == -1 && errno == EINTR && alarmed == 2);
    CHECK(timeout.tv_sec == 0 && timeout.tv_usec > 0 && timeout.tv_usec < 1000000);
    timer = (struct itimerval){0};
    CHECK(setitimer(ITIMER_REAL, &timer, NULL) == 0 && sigaction(SIGALRM, &previous, NULL) == 0);
    CHECK(close(pipefd[1]) == 0);
    CHECK(poll(fds, 3, 0) == 1 && (fds[0].revents & POLLHUP));
    CHECK(close(pipefd[0]) == 0);
    CHECK(poll(fds, 3, 0) == 1 && fds[0].revents == POLLNVAL);
    FD_ZERO(&reads); FD_SET(pipefd[0], &reads); FD_SET(rx, &reads); timeout = (struct timeval){0};
    CHECK(select(maxfd + 1, &reads, NULL, NULL, &timeout) == -1 && errno == EBADF);
    CHECK(close(rx) == 0 && close(tx) == 0);
#ifdef KER_MIXED_CONTROL_IPV6
    puts("PASS mixed native IPv6 UDP17 and host poll/select timeout readiness EBADF EINTR");
#else
    puts("PASS mixed native UDP and host poll/select");
#endif
    return 0;
}
