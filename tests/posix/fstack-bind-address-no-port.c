/* Original-Linux extension of F-Stack socket/descriptor migration scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static int new_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 5};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}
static int option(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &value, &length) == 0);
    CHECK(length == sizeof(value)); return value;
}
static void configure(int fd, int value)
{
    CHECK(setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &value, sizeof(value)) == 0);
    CHECK(option(fd) == value);
}
static struct sockaddr_in local_name(int fd)
{
    struct sockaddr_in address; socklen_t length = sizeof(address);
    CHECK(getsockname(fd, (void *)&address, &length) == 0);
    CHECK(length == sizeof(address) && address.sin_family == AF_INET);
    return address;
}
static void transfer(int fd, unsigned char *bytes, size_t length, int sending)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = sending ? send(fd, bytes + done, length - done, MSG_NOSIGNAL) :
                                 recv(fd, bytes + done, length - done, 0);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0); done += (size_t)count;
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    struct sockaddr_in local = {.sin_family = AF_INET}, remote = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, argv[1], &local.sin_addr) == 1);
    CHECK(inet_pton(AF_INET, argv[2], &remote.sin_addr) == 1);
    char *end; long port = strtol(argv[3], &end, 10); CHECK(!*end && port > 0 && port < 65533);
    /* Ordinary bind reserves the sole configured automatic port immediately. */
    int eager = new_socket(), extra = new_socket(); CHECK(option(eager) == 0);
    CHECK(bind(eager, (void *)&local, sizeof(local)) == 0);
    CHECK(ntohs(local_name(eager).sin_port) == 40000);
    errno = 0; CHECK(bind(extra, (void *)&local, sizeof(local)) == -1 && errno == EADDRINUSE);
    CHECK(close(extra) == 0 && close(eager) == 0);
    /* Listen still needs a port; an explicit nonzero bind is never deferred. */
    int listener = new_socket(); configure(listener, 1);
    CHECK(bind(listener, (void *)&local, sizeof(local)) == 0 && local_name(listener).sin_port == 0);
    CHECK(listen(listener, 1) == 0 && ntohs(local_name(listener).sin_port) == 40000);
    CHECK(close(listener) == 0);
    int fixed = new_socket(); configure(fixed, 1);
    struct sockaddr_in fixed_address = local; fixed_address.sin_port = htons(40001);
    CHECK(bind(fixed, (void *)&fixed_address, sizeof(fixed_address)) == 0);
    CHECK(ntohs(local_name(fixed).sin_port) == 40001); CHECK(close(fixed) == 0);
    int fds[3], aliases[3];
    for (int i = 0; i < 3; ++i) {
        fds[i] = new_socket(); aliases[i] = dup(fds[i]); CHECK(aliases[i] >= 0);
        configure(aliases[i], 1); CHECK(option(fds[i]) == 1);
        configure(fds[i], 0); CHECK(option(aliases[i]) == 0);
        configure(aliases[i], 1);
        if (!i) {
            struct sockaddr_in unavailable = local;
            CHECK(inet_pton(AF_INET, "198.18.0.99", &unavailable.sin_addr) == 1);
            errno = 0;
            CHECK(bind(fds[i], (void *)&unavailable, sizeof(unavailable)) == -1 && errno == EADDRNOTAVAIL);
            CHECK(local_name(fds[i]).sin_port == 0 && option(aliases[i]) == 1);
        }
        CHECK(bind(fds[i], (void *)&local, sizeof(local)) == 0);
        struct sockaddr_in actual = local_name(aliases[i]);
        CHECK(actual.sin_port == 0 && actual.sin_addr.s_addr == local.sin_addr.s_addr);
    }
    /* Hold all three connections open: differing remote ports permit tuple reuse. */
    for (int i = 0; i < 3; ++i) {
        remote.sin_port = htons((uint16_t)(port + i));
        CHECK(connect(aliases[i], (void *)&remote, sizeof(remote)) == 0);
        CHECK(ntohs(local_name(fds[i]).sin_port) == 40000);
    }
    for (int i = 0; i < 3; ++i) {
        unsigned char expected[16], actual[16];
        for (int j = 0; j < 16; ++j) expected[j] = (unsigned char)(i * 31 + j);
        transfer(aliases[i], expected, sizeof(expected), 1);
        transfer(fds[i], actual, sizeof(actual), 0); CHECK(!memcmp(expected, actual, sizeof(actual)));
        CHECK(shutdown(fds[i], SHUT_WR) == 0);
        unsigned char byte; CHECK(recv(aliases[i], &byte, 1, 0) == 0);
        CHECK(close(fds[i]) == 0 && close(aliases[i]) == 0);
    }
    puts("PASS: deferred bind, alias settings, eager exhaustion, listen/explicit allocation and three live source-port40000 connections");
    return 0;
}
