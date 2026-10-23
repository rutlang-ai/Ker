/* Exercise upstream Linux raw ICMP sockets; echo replies come from the kernels. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void check(int ok, const char *what)
{
    if (!ok) { perror(what); exit(1); }
}
static unsigned short checksum(const unsigned char *p, size_t size)
{
    unsigned sum = 0;
    while (size > 1) { sum += (p[0] << 8) | p[1]; p += 2; size -= 2; }
    if (size) sum += p[0] << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (unsigned short)~sum;
}
static void echo(int family, int mtu, const char *target)
{
    int protocol = family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    int fd = socket(family, SOCK_RAW, protocol), policy = IP_PMTUDISC_DO;
    struct timeval timeout = {5, 0};
    struct sockaddr_storage remote = {0};
    socklen_t length;
    check(fd >= 0, "raw ICMP socket");
    check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "timeout");
    if (family == AF_INET) {
        struct sockaddr_in *p = (struct sockaddr_in *)&remote;
        p->sin_family = AF_INET; length = sizeof(*p);
        check(inet_pton(family, target, &p->sin_addr) == 1, "IPv4 target");
        check(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &policy, sizeof(policy)) == 0, "IPv4 DF");
    } else {
        struct sockaddr_in6 *p = (struct sockaddr_in6 *)&remote;
        p->sin6_family = AF_INET6; length = sizeof(*p);
        check(inet_pton(family, target, &p->sin6_addr) == 1, "IPv6 target");
        check(setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &policy, sizeof(policy)) == 0, "IPv6 DF");
    }
    check(connect(fd, (struct sockaddr *)&remote, length) == 0, "connect ICMP");
    int sizes[] = {0, 1, mtu - (family == AF_INET ? 28 : 48)};
    for (unsigned seq = 0; seq < 3; seq++) {
        unsigned char packet[9000] = {0}, received[10000];
        size_t size = (size_t)sizes[seq] + 8;
        packet[0] = family == AF_INET ? 8 : 128;
        packet[4] = 0x4b; packet[5] = 0x45; packet[7] = seq;
        for (size_t i = 8; i < size; i++) packet[i] = (unsigned char)(i * 17 + seq);
        if (family == AF_INET) {
            unsigned short sum = checksum(packet, size);
            packet[2] = sum >> 8; packet[3] = sum & 255;
        }
        check(send(fd, packet, size, 0) == (ssize_t)size, "send full echo");
        int found = 0;
        for (unsigned attempt = 0; attempt < 16 && !found; attempt++) {
            ssize_t count = recv(fd, received, sizeof(received), 0);
            check(count > 0, "receive echo reply");
            size_t offset = family == AF_INET ? (received[0] & 15) * 4u : 0;
            if ((size_t)count < offset + 8) continue;
            unsigned char *reply = received + offset;
            if (reply[0] != (family == AF_INET ? 0 : 129) || reply[4] != 0x4b ||
                reply[5] != 0x45 || reply[6] != 0 || reply[7] != seq) continue;
            check((size_t)count == offset + size && reply[1] == 0 &&
                  memcmp(reply + 8, packet + 8, size - 8) == 0, "echo payload differs");
            if (family == AF_INET) check(checksum(reply, size) == 0, "ICMP checksum");
            found = 1;
        }
        check(found, "missing matching echo");
    }
    close(fd);
    printf("PASS: IPv%d ICMP payloads 0, 1, %d without fragmentation\n", family == AF_INET ? 4 : 6, sizes[2]);
}
int main(int argc, char **argv)
{
    check(argc == 5, "usage: icmp-mtu native|peer MTU IPv4 IPv6");
    int mtu = atoi(argv[2]);
    check(mtu == 1500 || mtu == 9000, "MTU");
    if (strcmp(argv[1], "native") == 0) {
        puts("READY"); fflush(stdout);
        check(getchar() == 'G', "peer gate");
    }
    echo(AF_INET, mtu, argv[3]); echo(AF_INET6, mtu, argv[4]);
    return 0;
}
