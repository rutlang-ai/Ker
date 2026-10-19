/* Scenario adaptation of pinned test_ff_host_set_v6only, extended with real
 * Linux dual-stack traffic. No FreeBSD bridge or protocol implementation. */
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
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static int option(int fd)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &length) == 0);
    CHECK(length == sizeof(value)); return value;
}
static int listener(int only, uint16_t port)
{
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only)) == 0);
    CHECK(option(fd) == only);
    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = port,
        .sin6_addr = IN6ADDR_ANY_INIT};
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
    CHECK(listen(fd, 4) == 0); return fd;
}
static uint16_t port_of(int fd)
{
    struct sockaddr_in6 address; socklen_t size = sizeof(address);
    CHECK(getsockname(fd, (void *)&address, &size) == 0);
    CHECK(size == sizeof(address) && address.sin6_family == AF_INET6);
    return address.sin6_port;
}
static void mapped(const struct sockaddr_in6 *address, const char *ipv4)
{
    CHECK(address->sin6_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&address->sin6_addr));
    struct in_addr expected; CHECK(inet_pton(AF_INET, ipv4, &expected) == 1);
    CHECK(memcmp(&address->sin6_addr.s6_addr[12], &expected, 4) == 0);
}
static void transfer(int fd)
{
    const char payload[] = "dual-stack-payload";
    char received[sizeof(payload)];
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP,
        .data.u64 = UINT64_C(0xfedcba9876543210)}, ready;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    CHECK(send(fd, payload, sizeof(payload), MSG_NOSIGNAL) == sizeof(payload));
    CHECK(shutdown(fd, SHUT_WR) == 0);
    CHECK(epoll_wait(ep, &ready, 1, 5000) == 1);
    CHECK(ready.events & EPOLLIN); CHECK(ready.data.u64 == event.data.u64);
    CHECK(recv(fd, received, sizeof(received), MSG_WAITALL) == sizeof(received));
    CHECK(memcmp(received, payload, sizeof(payload)) == 0);
    CHECK(recv(fd, received, 1, 0) == 0);
    CHECK(close(ep) == 0);
}
static void bind_isolation(void)
{
    int six = listener(1, 0), alias = dup(six); CHECK(alias >= 0);
    CHECK(option(alias) == 1);
    struct sockaddr_in four = {.sin_family = AF_INET, .sin_port = port_of(six),
        .sin_addr.s_addr = htonl(INADDR_ANY)};
    int ipv4 = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(ipv4 >= 0);
    CHECK(bind(ipv4, (void *)&four, sizeof(four)) == 0); CHECK(listen(ipv4, 4) == 0);
    CHECK(close(six) == 0); CHECK(close(alias) == 0); CHECK(close(ipv4) == 0);
    six = listener(0, 0); four.sin_port = port_of(six);
    ipv4 = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(ipv4 >= 0);
    errno = 0; CHECK(bind(ipv4, (void *)&four, sizeof(four)) == -1 && errno == EADDRINUSE);
    CHECK(close(ipv4) == 0); CHECK(close(six) == 0);
    puts("PASS: V6ONLY namespace separation and dual-stack bind conflict");
}
static void loopback(void)
{
    bind_isolation();
    for (int only = 0; only <= 1; ++only) {
        int server = listener(only, 0);
        int sender = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(sender >= 0);
        struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = port_of(server),
            .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        CHECK(connect(sender, (void *)&address, sizeof(address)) == 0);
        struct sockaddr_in6 peer; socklen_t size = sizeof(peer);
        int receiver = accept4(server, (void *)&peer, &size, SOCK_CLOEXEC); CHECK(receiver >= 0);
        CHECK(size == sizeof(peer) && IN6_IS_ADDR_LOOPBACK(&peer.sin6_addr));
        CHECK(option(receiver) == only);
        char byte;
        CHECK(send(sender, "6", 1, MSG_NOSIGNAL) == 1);
        CHECK(recv(receiver, &byte, 1, MSG_WAITALL) == 1 && byte == '6');
        CHECK(shutdown(sender, SHUT_WR) == 0); CHECK(recv(receiver, &byte, 1, 0) == 0);
        CHECK(close(receiver) == 0); CHECK(close(sender) == 0); CHECK(close(server) == 0);
    }
    puts("PASS: IPv6 loopback V6ONLY on/off payload and EOF");
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "loopback")) { loopback(); return 0; }
    CHECK(argc == 5);
    int port = atoi(argv[3]); CHECK(port > 0 && port <= 65535);
    int fd;
    if (!strcmp(argv[1], "server")) {
        int server = listener(0, htons(port));
        printf("READY %d\n", port); fflush(stdout);
        struct sockaddr_in6 peer; socklen_t length = sizeof(peer);
        fd = accept4(server, (void *)&peer, &length, SOCK_CLOEXEC); CHECK(fd >= 0);
        CHECK(length == sizeof(peer)); mapped(&peer, argv[4]);
        struct sockaddr_in6 local; length = sizeof(local);
        CHECK(getsockname(fd, (void *)&local, &length) == 0); mapped(&local, argv[2]);
        CHECK(option(fd) == 0); CHECK(close(server) == 0);
    } else {
        CHECK(!strcmp(argv[1], "client"));
        fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
        int only = 0; CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only)) == 0);
        char text[64]; CHECK(snprintf(text, sizeof(text), "::ffff:%s", argv[2]) > 0);
        struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
        CHECK(inet_pton(AF_INET6, text, &address.sin6_addr) == 1);
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
        struct sockaddr_in6 peer; socklen_t length = sizeof(peer);
        CHECK(getpeername(fd, (void *)&peer, &length) == 0); mapped(&peer, argv[2]);
    }
    transfer(fd); CHECK(close(fd) == 0);
    puts("PASS: mapped IPv4 TCP tuple, epoll, payload, half-close and EOF");
    return 0;
}
