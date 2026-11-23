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
    CHECK(argc == 2);
    int port = atoi(argv[1]);
    struct sockaddr_in6 local = endpoint("2001:db8:1::2", port);
    int tcp = make_socket(AF_INET6, SOCK_STREAM), udp = make_socket(AF_INET6, SOCK_DGRAM);
    CHECK(bind(tcp, (struct sockaddr *)&local, sizeof(local)) == 0);
    CHECK(bind(udp, (struct sockaddr *)&local, sizeof(local)) == 0);
    CHECK(listen(tcp, 1) == 0);
    struct sockaddr_in6 absent = endpoint("2001:db8:1::99", port);
    int bad = make_socket(AF_INET6, SOCK_STREAM);
    CHECK(bind(bad, (struct sockaddr *)&absent, sizeof(absent)) == -1 && errno == EADDRNOTAVAIL);
    CHECK(close(bad) == 0);
    int ipv4 = make_socket(AF_INET, SOCK_STREAM);
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &v4.sin_addr) == 1);
    CHECK(bind(ipv4, (struct sockaddr *)&v4, sizeof(v4)) == 0 && listen(ipv4, 1) == 0);
    puts("READY"); fflush(stdout);
    struct sockaddr_in6 peer;
    socklen_t length = sizeof(peer);
    int accepted = accept(tcp, (struct sockaddr *)&peer, &length);
    struct sockaddr_in6 host = endpoint("2001:db8:1::1", port + 1);
    CHECK(accepted >= 0 && peer.sin6_family == AF_INET6 &&
        memcmp(&peer.sin6_addr, &host.sin6_addr, sizeof(host.sin6_addr)) == 0);
    echo(accepted, 0); CHECK(close(accepted) == 0); CHECK(close(tcp) == 0);
    char buffer[sizeof(payload)];
    length = sizeof(peer);
    CHECK(recvfrom(udp, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer, &length) == sizeof(buffer));
    CHECK(peer.sin6_family == AF_INET6 && memcmp(&peer.sin6_addr, &host.sin6_addr, sizeof(host.sin6_addr)) == 0);
    CHECK(memcmp(buffer, payload, sizeof(buffer)) == 0);
    CHECK(sendto(udp, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer, length) == sizeof(buffer));
    CHECK(close(udp) == 0);
    int outgoing = make_socket(AF_INET6, SOCK_STREAM);
    local.sin6_port = 0;
    CHECK(bind(outgoing, (struct sockaddr *)&local, sizeof(local)) == 0);
    CHECK(connect(outgoing, (struct sockaddr *)&host, sizeof(host)) == 0);
    echo(outgoing, 1); CHECK(close(outgoing) == 0);
    outgoing = make_socket(AF_INET6, SOCK_DGRAM);
    CHECK(bind(outgoing, (struct sockaddr *)&local, sizeof(local)) == 0);
    CHECK(connect(outgoing, (struct sockaddr *)&host, sizeof(host)) == 0);
    echo(outgoing, 1); CHECK(close(outgoing) == 0);
    accepted = accept(ipv4, NULL, NULL); CHECK(accepted >= 0);
    echo(accepted, 0); CHECK(close(accepted) == 0); CHECK(close(ipv4) == 0);
    puts("PASS: original Linux dual-stack IPv6 TCP/UDP and IPv4 TCP");
    return 0;
}
