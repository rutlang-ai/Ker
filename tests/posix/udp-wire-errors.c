/* Raw packets are test vectors; all validation/reassembly is original Linux. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);                           \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
static int family;
static void receive(int fd, unsigned char tag, size_t size) {
    unsigned char data[4096];
    struct sockaddr_storage peer;
    socklen_t length = sizeof(peer);
    CHECK(recvfrom(fd, data, sizeof(data), 0, (void *)&peer, &length) == (ssize_t)size);
    CHECK(peer.ss_family == family);
    if (data[0] != tag)
        fprintf(stderr, "tag received=%u expected=%u\n", data[0], tag);
    CHECK(data[0] == tag);
    for (size_t i = 1; i < size; i++)
        CHECK(data[i] == (unsigned char)(i * 71));
    if (family == AF_INET)
        CHECK(((struct sockaddr_in *)&peer)->sin_addr.s_addr == inet_addr("198.18.0.1"));
    else {
        struct in6_addr source;
        CHECK(inet_pton(AF_INET6, "2001:db8:1::1", &source) == 1);
        CHECK(!memcmp(&source, &((struct sockaddr_in6 *)&peer)->sin6_addr, 16));
    }
}
int main(int argc, char **argv) {
    CHECK(argc == 3);
    family = atoi(argv[1]) == 4 ? AF_INET : AF_INET6;
    int port = atoi(argv[2]);
    int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 8};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    if (family == AF_INET) {
        struct sockaddr_in a = {
            .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = inet_addr("198.18.0.2")};
        CHECK(bind(fd, (void *)&a, sizeof(a)) == 0);
    } else {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
        CHECK(inet_pton(AF_INET6, "2001:db8:1::2", &a.sin6_addr) == 1);
        CHECK(bind(fd, (void *)&a, sizeof(a)) == 0);
    }
    struct ifreq entries[16];
    struct ifconf list = {.ifc_len = sizeof(entries), .ifc_req = entries};
    CHECK(ioctl(fd, SIOCGIFCONF, &list) == 0);
    int found = 0;
    for (int i = 0; i < list.ifc_len / (int)sizeof(entries[0]); i++)
        if (((struct sockaddr_in *)&entries[i].ifr_addr)->sin_addr.s_addr == inet_addr("198.18.0.2")) {
            struct ifreq request = entries[i];
            CHECK(ioctl(fd, SIOCGIFHWADDR, &request) == 0);
            unsigned char *mac = (void *)request.ifr_hwaddr.sa_data;
            printf("READY %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            found = 1;
            break;
        }
    CHECK(found);
    fflush(stdout);
    if (family == AF_INET)
        receive(fd, 'Z', 24);
    receive(fd, 'G', 24);
    receive(fd, 'F', 4096);
    receive(fd, '2', 24);
    receive(fd, '1', 24);
    receive(fd, '1', 24);
    puts("REASSEMBLED");
    fflush(stdout);
    struct pollfd event = {.fd = fd, .events = POLLIN};
    CHECK(poll(&event, 1, 2200) == 0);
    puts("TIMEOUT_CHECKED");
    fflush(stdout);
    receive(fd, 'R', 24);
    unsigned char byte;
    errno = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(close(fd) == 0);
    printf("PASS: IPv%d checksum rejection, reverse fragments, reassembly timeout, reorder/duplicates and "
           "recovery\n",
           family == AF_INET ? 4 : 6);
    return 0;
}
