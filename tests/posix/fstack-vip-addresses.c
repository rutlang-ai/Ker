#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static struct sockaddr_in endpoint(const char *ip, unsigned int port)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, ip, &address.sin_addr) == 1);
    return address;
}
static int stream(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 5};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    return fd;
}
static void echo(int fd, int outgoing)
{
    char bytes[8];
    if (outgoing) CHECK(send(fd, "vip-test", 8, MSG_NOSIGNAL) == 8);
    CHECK(recv(fd, bytes, sizeof(bytes), MSG_WAITALL) == sizeof(bytes));
    CHECK(memcmp(bytes, "vip-test", 8) == 0);
    if (!outgoing) CHECK(send(fd, bytes, sizeof(bytes), MSG_NOSIGNAL) == sizeof(bytes));
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    unsigned int port = (unsigned int)strtoul(argv[1], NULL, 10);
    int control = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(control >= 0);
    struct ifreq entries[64];
    struct ifconf list = {.ifc_len = sizeof(entries), .ifc_req = entries};
    CHECK(ioctl(control, SIOCGIFCONF, &list) == 0);
    unsigned int seen[3] = {0}, nonloopback = 0;
    for (int i = 0; i < list.ifc_len / (int)sizeof(entries[0]); i++) {
        struct ifreq request = entries[i];
        CHECK(ioctl(control, SIOCGIFFLAGS, &request) == 0);
        if (request.ifr_flags & IFF_LOOPBACK) continue;
        CHECK(request.ifr_flags & IFF_UP);
        nonloopback++;
        for (unsigned int j = 0; j < 3; j++) {
            struct sockaddr_in expected = endpoint(argv[j + 2], 0);
            struct sockaddr_in *actual = (struct sockaddr_in *)&entries[i].ifr_addr;
            if (actual->sin_addr.s_addr == expected.sin_addr.s_addr) {
                CHECK(ioctl(control, SIOCGIFNETMASK, &request) == 0);
                CHECK(((struct sockaddr_in *)&request.ifr_netmask)->sin_addr.s_addr == inet_addr("255.255.255.0"));
                seen[j]++;
            }
        }
    }
    CHECK(nonloopback == 3 && seen[0] == 1 && seen[1] == 1 && seen[2] == 1);
    CHECK(close(control) == 0);
    int invalid = stream();
    struct sockaddr_in absent = endpoint("198.18.0.99", 0);
    CHECK(bind(invalid, (struct sockaddr *)&absent, sizeof(absent)) == -1 && errno == EADDRNOTAVAIL);
    CHECK(close(invalid) == 0);
    int listeners[3];
    for (unsigned int i = 0; i < 3; i++) {
        listeners[i] = stream();
        struct sockaddr_in address = endpoint(argv[i + 2], port);
        CHECK(bind(listeners[i], (struct sockaddr *)&address, sizeof(address)) == 0);
        CHECK(listen(listeners[i], 1) == 0);
    }
    puts("READY"); fflush(stdout);
    for (unsigned int i = 0; i < 3; i++) {
        int accepted = accept(listeners[i], NULL, NULL);
        CHECK(accepted >= 0);
        struct sockaddr_in local, expected = endpoint(argv[i + 2], port);
        socklen_t length = sizeof(local);
        CHECK(getsockname(accepted, (struct sockaddr *)&local, &length) == 0);
        CHECK(local.sin_addr.s_addr == expected.sin_addr.s_addr);
        echo(accepted, 0);
        CHECK(close(accepted) == 0 && close(listeners[i]) == 0);
    }
    for (unsigned int i = 1; i < 3; i++) {
        int fd = stream();
        struct sockaddr_in source = endpoint(argv[i + 2], 0), host = endpoint("198.18.0.1", port + 1);
        CHECK(bind(fd, (struct sockaddr *)&source, sizeof(source)) == 0);
        CHECK(connect(fd, (struct sockaddr *)&host, sizeof(host)) == 0);
        echo(fd, 1);
        CHECK(close(fd) == 0);
    }
    puts("PASS: original Linux primary/VIP addresses, netmasks, inbound TCP and explicit VIP source binding");
    return 0;
}
