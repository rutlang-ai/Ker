#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static const char payload[] = "native-ipv6";
static int make_socket(int family, int type)
{
    int fd = socket(family, type, 0), one = 1;
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 8};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    if (family == AF_INET6) CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) == 0);
    return fd;
}
static struct sockaddr_in6 endpoint(const char *text, int port)
{
    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    CHECK(inet_pton(AF_INET6, text, &address.sin6_addr) == 1);
    return address;
}
static void echo(int fd, int outgoing)
{
    char buffer[sizeof(payload)];
    if (outgoing) CHECK(send(fd, payload, sizeof(payload), MSG_NOSIGNAL) == sizeof(payload));
    CHECK(recv(fd, buffer, sizeof(buffer), MSG_WAITALL) == sizeof(buffer));
    CHECK(memcmp(buffer, payload, sizeof(buffer)) == 0);
    if (!outgoing) CHECK(send(fd, buffer, sizeof(buffer), MSG_NOSIGNAL) == sizeof(buffer));
}
int main(int argc, char **argv)
{
    CHECK(argc == 2 || (argc == 3 && (strcmp(argv[2], "primary-only") == 0 || strcmp(argv[2], "max") == 0)));
    int count = argc == 3 && strcmp(argv[2], "primary-only") == 0 ? 1 : 3;
    int port = atoi(argv[1]);
    const char *addresses[] = {"2001:db8:1::2", "2001:db8:1::3", "2001:db8:1::4"};
    int tcp[3], udp[3];
    struct sockaddr_in6 host = endpoint("2001:db8:1::1", port + 1);
    struct sockaddr_in6 absent = endpoint("2001:db8:1::99", port);
    int bad = make_socket(AF_INET6, SOCK_STREAM);
    CHECK(bind(bad, (struct sockaddr *)&absent, sizeof(absent)) == -1 && errno == EADDRNOTAVAIL);
    CHECK(close(bad) == 0);
    for (int i = 0; i < count; ++i) {
        struct sockaddr_in6 local = endpoint(addresses[i], port);
        tcp[i] = make_socket(AF_INET6, SOCK_STREAM);
        udp[i] = make_socket(AF_INET6, SOCK_DGRAM);
        CHECK(bind(tcp[i], (struct sockaddr *)&local, sizeof(local)) == 0);
        CHECK(bind(udp[i], (struct sockaddr *)&local, sizeof(local)) == 0);
        CHECK(listen(tcp[i], 1) == 0);
    }
    if (argc == 3 && strcmp(argv[2], "max") == 0) {
        for (int i = 3; i < 35; ++i) {
            char text[INET6_ADDRSTRLEN];
            CHECK(snprintf(text, sizeof(text), "2001:db8:1::%x", i) > 0);
            struct sockaddr_in6 local = endpoint(text, 0);
            int fd = make_socket(AF_INET6, SOCK_DGRAM);
            CHECK(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0);
            CHECK(close(fd) == 0);
        }
    }
    puts("READY"); fflush(stdout);
    for (int i = 0; i < count; ++i) {
        struct sockaddr_in6 local = endpoint(addresses[i], 0), peer;
        socklen_t length = sizeof(peer);
        int accepted = accept(tcp[i], (struct sockaddr *)&peer, &length);
        CHECK(accepted >= 0 && peer.sin6_family == AF_INET6 &&
            memcmp(&peer.sin6_addr, &host.sin6_addr, sizeof(host.sin6_addr)) == 0);
        struct sockaddr_in6 bound;
        length = sizeof(bound);
        CHECK(getsockname(accepted, (struct sockaddr *)&bound, &length) == 0);
        CHECK(bound.sin6_port == htons(port) &&
            memcmp(&bound.sin6_addr, &local.sin6_addr, sizeof(local.sin6_addr)) == 0);
        echo(accepted, 0); CHECK(close(accepted) == 0); CHECK(close(tcp[i]) == 0);
        char buffer[sizeof(payload)];
        length = sizeof(peer);
        CHECK(recvfrom(udp[i], buffer, sizeof(buffer), 0, (struct sockaddr *)&peer, &length) == sizeof(buffer));
        CHECK(peer.sin6_family == AF_INET6 && memcmp(&peer.sin6_addr, &host.sin6_addr, sizeof(host.sin6_addr)) == 0);
        CHECK(memcmp(buffer, payload, sizeof(buffer)) == 0);
        CHECK(sendto(udp[i], buffer, sizeof(buffer), 0, (struct sockaddr *)&peer, length) == sizeof(buffer));
        CHECK(close(udp[i]) == 0);
        int outgoing = make_socket(AF_INET6, SOCK_STREAM);
        CHECK(bind(outgoing, (struct sockaddr *)&local, sizeof(local)) == 0);
        CHECK(connect(outgoing, (struct sockaddr *)&host, sizeof(host)) == 0);
        echo(outgoing, 1); CHECK(close(outgoing) == 0);
        outgoing = make_socket(AF_INET6, SOCK_DGRAM);
        CHECK(bind(outgoing, (struct sockaddr *)&local, sizeof(local)) == 0);
        CHECK(connect(outgoing, (struct sockaddr *)&host, sizeof(host)) == 0);
        echo(outgoing, 1); CHECK(close(outgoing) == 0);
    }
    puts("PASS: original Linux IPv6 primary/VIP TCP/UDP in both directions");
    return 0;
}
