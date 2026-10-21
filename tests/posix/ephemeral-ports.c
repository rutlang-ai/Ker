// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static unsigned int first, last, reserved;
static int socket_ranges;
static unsigned int port_of(int fd)
{
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    CHECK(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    unsigned int port = address.ss_family == AF_INET ?
        ntohs(((struct sockaddr_in *)&address)->sin_port) :
        ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    CHECK(port >= first && port <= last && port != reserved);
    return port;
}
static int bind_auto(int fd, int family)
{
    if (family == AF_INET) {
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        return bind(fd, (struct sockaddr *)&address, sizeof(address));
    }
    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    return bind(fd, (struct sockaddr *)&address, sizeof(address));
}
static int new_socket(int family, int type)
{
    int fd = socket(family, type, 0); CHECK(fd >= 0);
    if (family == AF_INET6) {
        int one = 1;
        CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) == 0);
    }
    return fd;
}
static void allocation(int family, int type)
{
    unsigned int extent = last - first + 1 - (reserved >= first && reserved <= last);
    unsigned int count = extent <= 32 ? extent : 8;
    int fds[32]; unsigned int ports[32];
    for (unsigned int i = 0; i < count; i++) {
        fds[i] = new_socket(family, type);
        CHECK(bind_auto(fds[i], family) == 0);
        ports[i] = port_of(fds[i]);
        for (unsigned int j = 0; j < i; j++) CHECK(ports[i] != ports[j]);
        if (type == SOCK_STREAM) CHECK(listen(fds[i], 1) == 0);
    }
    if (extent <= 32) {
        int extra = new_socket(family, type);
        errno = 0;
        CHECK(bind_auto(extra, family) == -1 && errno == EADDRINUSE);
        CHECK(close(extra) == 0);
        unsigned int slot = count / 2, released = ports[slot];
        CHECK(close(fds[slot]) == 0);
        fds[slot] = new_socket(family, type);
        CHECK(bind_auto(fds[slot], family) == 0);
        CHECK(port_of(fds[slot]) == released);
    }
    for (unsigned int i = 0; i < count; i++) CHECK(close(fds[i]) == 0);
    /* The automatic range must not become a restriction on explicit bind. */
    int fixed = new_socket(family, type);
    if (family == AF_INET) {
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(23456),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        CHECK(bind(fixed, (struct sockaddr *)&address, sizeof(address)) == 0);
    } else {
        struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(23456),
            .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        CHECK(bind(fixed, (struct sockaddr *)&address, sizeof(address)) == 0);
    }
    CHECK(close(fixed) == 0);
    printf("PASS: %s %s allocation%s\n", family == AF_INET ? "IPv4" : "IPv6",
        type == SOCK_STREAM ? "TCP" : "UDP", extent <= 32 ? ", exhaustion, release and reuse" : " defaults");
}
static uint32_t packed_range(unsigned int low, unsigned int high)
{
    return (uint32_t)low | ((uint32_t)high << 16);
}
static void check_range(int fd, uint32_t expected)
{
    uint32_t actual = UINT32_MAX;
    socklen_t length = sizeof(actual);
    CHECK(getsockopt(fd, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &actual, &length) == 0);
    CHECK(length == sizeof(actual) && actual == expected);
}
static void set_range(int fd, unsigned int low, unsigned int high)
{
    uint32_t range = packed_range(low, high);
    CHECK(setsockopt(fd, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range)) == 0);
    check_range(fd, range);
}
static void socket_allocation(int family, int type)
{
    CHECK(last - first == 15 && reserved == 0);
    int held[4]; unsigned int ports[4];
    for (unsigned int i = 0; i < 4; i++) {
        held[i] = new_socket(family, type);
        check_range(held[i], 0);
        set_range(held[i], first, first + 3);
        CHECK(bind_auto(held[i], family) == 0);
        ports[i] = port_of(held[i]); CHECK(ports[i] <= first + 3);
        for (unsigned int j = 0; j < i; j++) CHECK(ports[i] != ports[j]);
    }
    int extra = new_socket(family, type);
    set_range(extra, first, first + 3);
    uint32_t reversed = packed_range(first + 3, first);
    errno = 0;
    CHECK(setsockopt(extra, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &reversed,
        sizeof(reversed)) == -1 && errno == EINVAL);
    check_range(extra, packed_range(first, first + 3));
    uint32_t valid = packed_range(first + 4, first + 7);
    errno = 0;
    CHECK(setsockopt(extra, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &valid,
        sizeof(valid) - 1) == -1 && errno == EINVAL);
    check_range(extra, packed_range(first, first + 3));
    errno = 0;
    CHECK(bind_auto(extra, family) == -1 && errno == EADDRINUSE);
    /* dup shares socket policy; a failed automatic bind can recover after reset. */
    int alias = dup(extra); CHECK(alias >= 0);
    check_range(alias, packed_range(first, first + 3));
    set_range(alias, 0, 0); check_range(extra, 0);
    CHECK(close(extra) == 0);
    CHECK(bind_auto(alias, family) == 0);
    CHECK(port_of(alias) > first + 3);
    CHECK(close(alias) == 0);
    /* A distinct socket retains the namespace default, even while the narrower
     * range is fully occupied. This proves state isolation without randomness
     * assumptions about which of the other ports the kernel will choose. */
    int sibling = new_socket(family, type); check_range(sibling, 0);
    CHECK(bind_auto(sibling, family) == 0 && port_of(sibling) > first + 3);
    CHECK(close(sibling) == 0);
    unsigned int released = ports[2]; CHECK(close(held[2]) == 0);
    held[2] = new_socket(family, type); set_range(held[2], first, first + 3);
    CHECK(bind_auto(held[2], family) == 0 && port_of(held[2]) == released);
    for (unsigned int i = 0; i < 4; i++) CHECK(close(held[i]) == 0);
    /* A zero endpoint retains that namespace endpoint. Out-of-namespace
     * endpoints are ignored by Linux rather than expanding the global range. */
    int low = new_socket(family, type); set_range(low, 0, first);
    CHECK(bind_auto(low, family) == 0 && port_of(low) == first); CHECK(close(low) == 0);
    int high = new_socket(family, type); set_range(high, last, 0);
    CHECK(bind_auto(high, family) == 0 && port_of(high) == last); CHECK(close(high) == 0);
    int broad[16];
    for (unsigned int i = 0; i < 16; i++) {
        broad[i] = new_socket(family, type); set_range(broad[i], 1024, 65535);
        CHECK(bind_auto(broad[i], family) == 0); (void)port_of(broad[i]);
    }
    int overflow = new_socket(family, type); set_range(overflow, 1024, 65535);
    errno = 0; CHECK(bind_auto(overflow, family) == -1 && errno == EADDRINUSE);
    CHECK(close(overflow) == 0);
    for (unsigned int i = 0; i < 16; i++) CHECK(close(broad[i]) == 0);
    printf("PASS: %s %s per-socket range, dup/reset, isolation, exhaustion/reuse and namespace bounds\n",
        family == AF_INET ? "IPv4" : "IPv6", type == SOCK_STREAM ? "TCP" : "UDP");
}
static void independent_peer(int type, unsigned int destination)
{
    int fd = socket(AF_INET, type, 0); CHECK(fd >= 0);
    if (socket_ranges) set_range(fd, first + 8, first + 11);
    struct timeval timeout = {.tv_sec = 8};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(destination)};
    CHECK(inet_pton(AF_INET, "198.18.0.1", &peer.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0);
    unsigned int port = port_of(fd);
    if (socket_ranges) CHECK(port >= first + 8 && port <= first + 11);
    /* Echo exact payload; the host independently checks the observed source port. */
    const char payload[] = "ephemeral-ports";
    if (type == SOCK_STREAM) {
        size_t sent = 0;
        while (sent < sizeof(payload)) {
            ssize_t n = send(fd, payload + sent, sizeof(payload) - sent, MSG_NOSIGNAL);
            CHECK(n > 0); sent += (size_t)n;
        }
        char reply[sizeof(payload)]; size_t got = 0;
        while (got < sizeof(reply)) {
            ssize_t n = recv(fd, reply + got, sizeof(reply) - got, 0);
            CHECK(n > 0); got += (size_t)n;
        }
        CHECK(memcmp(payload, reply, sizeof(payload)) == 0);
    } else {
        CHECK(send(fd, payload, sizeof(payload), 0) == sizeof(payload));
        char reply[sizeof(payload) + 1];
        CHECK(recv(fd, reply, sizeof(reply), 0) == sizeof(payload));
        CHECK(memcmp(payload, reply, sizeof(payload)) == 0);
    }
    CHECK(close(fd) == 0);
    printf("PASS: independent host %s observed native source port %u\n",
        type == SOCK_STREAM ? "TCP" : "UDP", port);
}
int main(int argc, char **argv)
{
    CHECK(argc == 5 || (argc == 6 && !strcmp(argv[5], "socket-ranges")));
    socket_ranges = argc == 6;
    first = (unsigned int)atoi(argv[1]); last = (unsigned int)atoi(argv[2]);
    reserved = (unsigned int)atoi(argv[3]);
    CHECK(first > 0 && last <= 65535 && first <= last);
    if (socket_ranges) {
        socket_allocation(AF_INET, SOCK_STREAM); socket_allocation(AF_INET, SOCK_DGRAM);
        socket_allocation(AF_INET6, SOCK_STREAM); socket_allocation(AF_INET6, SOCK_DGRAM);
    } else {
        allocation(AF_INET, SOCK_STREAM); allocation(AF_INET, SOCK_DGRAM);
        allocation(AF_INET6, SOCK_STREAM); allocation(AF_INET6, SOCK_DGRAM);
    }
    independent_peer(SOCK_STREAM, (unsigned int)atoi(argv[4]));
    independent_peer(SOCK_DGRAM, (unsigned int)atoi(argv[4]) + 1);
    return 0;
}
