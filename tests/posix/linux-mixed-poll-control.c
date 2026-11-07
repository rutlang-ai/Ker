/* Exercise real resident UDP readiness alongside ordinary host pipe descriptors. */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
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
int main(void)
{
    int rx = socket(AF_INET, SOCK_DGRAM, 0), tx = socket(AF_INET, SOCK_DGRAM, 0), pipefd[2];
    CHECK(rx >= 0 && tx >= 0 && pipe(pipefd) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
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
    CHECK(close(pipefd[1]) == 0);
    CHECK(poll(fds, 3, 0) == 1 && (fds[0].revents & POLLHUP));
    CHECK(close(pipefd[0]) == 0);
    CHECK(poll(fds, 3, 0) == 1 && fds[0].revents == POLLNVAL);
    FD_ZERO(&reads); FD_SET(pipefd[0], &reads); FD_SET(rx, &reads); timeout = (struct timeval){0};
    CHECK(select(maxfd + 1, &reads, NULL, NULL, &timeout) == -1 && errno == EBADF);
    CHECK(close(rx) == 0 && close(tx) == 0);
    puts("PASS mixed native UDP and host poll/select");
    return 0;
}
