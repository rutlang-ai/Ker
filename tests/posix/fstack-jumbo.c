/* Configurable-MTU scenarios over real Linux UDP, including DF jumbo frames. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static const size_t sizes[] = {0, 1, 1472, 8972};
static void pattern(unsigned char *data, size_t size, unsigned int seed)
{
    for (size_t i = 0; i < size; ++i) data[i] = (unsigned char)(i * 71 + seed);
}
static void route_and_limit(int fd)
{
    int mtu = 0; socklen_t length = sizeof(mtu);
    CHECK(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &length) == 0 && mtu == 9000);
    unsigned char oversized[8973] = {0};
    errno = 0;
    CHECK(send(fd, oversized, sizeof(oversized), MSG_NOSIGNAL) == -1 && errno == EMSGSIZE);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int passive = !strcmp(argv[1], "server");
    CHECK(passive || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[3]))};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 5};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    int discovery = IP_PMTUDISC_DO;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &discovery, sizeof(discovery)) == 0);
    if (passive) {
        CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
        printf("READY %s\n", argv[3]); fflush(stdout);
    } else {
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
        route_and_limit(fd);
    }
    unsigned char bytes[8973], expected[8973];
    for (size_t record = 0; record < sizeof(sizes) / sizeof(sizes[0]); ++record) {
        size_t size = sizes[record];
        if (!passive) {
            pattern(bytes, size, 17);
            CHECK(send(fd, bytes, size, MSG_NOSIGNAL) == (ssize_t)size);
        }
        struct sockaddr_in peer = {0}; socklen_t length = sizeof(peer);
        CHECK(recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&peer, &length) == (ssize_t)size);
        pattern(expected, size, passive ? 17 : 93);
        CHECK(memcmp(bytes, expected, size) == 0);
        if (passive) {
            if (record == 0) {
                CHECK(connect(fd, (void *)&peer, length) == 0);
                route_and_limit(fd);
            }
            pattern(bytes, size, 93);
            CHECK(send(fd, bytes, size, MSG_NOSIGNAL) == (ssize_t)size);
        }
    }
    CHECK(close(fd) == 0);
    puts("PASS: MTU 9000, DF jumbo UDP and EMSGSIZE boundary");
    return 0;
}
