/* Raw socket probes. Both kernels generate their own echo replies. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_MTU 9000
#define ECHO_HEADER_SIZE 8

static void check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s (errno=%d)\n", message, errno);
        exit(EXIT_FAILURE);
    }
}

static unsigned short checksum(const unsigned char *bytes, size_t size)
{
    unsigned sum = 0;
    for (; size > 1; bytes += 2, size -= 2)
        sum += (bytes[0] << 8) | bytes[1];
    if (size)
        sum += bytes[0] << 8;
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (unsigned short)~sum;
}

static void receive_reply(int fd, int ipv4, const unsigned char *request, size_t size)
{
    unsigned char received[MAX_MTU];
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        ssize_t count = recv(fd, received, sizeof(received), 0);
        check(count > 0, "receive ICMP reply");
        size_t offset = ipv4 ? (received[0] & 15) * 4u : 0;
        if ((size_t)count < offset + ECHO_HEADER_SIZE)
            continue;
        const unsigned char *reply = received + offset;
        if (reply[0] != (ipv4 ? 0 : 129) || memcmp(reply + 4, request + 4, 4) != 0)
            continue;
        check((size_t)count == offset + size && reply[1] == 0 &&
              memcmp(reply + ECHO_HEADER_SIZE, request + ECHO_HEADER_SIZE,
                     size - ECHO_HEADER_SIZE) == 0, "echo payload differs");
        if (ipv4)
            check(checksum(reply, size) == 0, "bad ICMPv4 checksum");
        return;
    }
    check(0, "missing matching ICMP echo reply");
}

static void echo(int family, int mtu, const char *target)
{
    int ipv4 = family == AF_INET;
    int fd = socket(family, SOCK_RAW, ipv4 ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    check(fd >= 0, "open raw ICMP socket");

    const struct timeval timeout = {.tv_sec = 5};
    check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
          "set receive timeout");
    int policy = ipv4 ? IP_PMTUDISC_DO : IPV6_PMTUDISC_DO;
    check(setsockopt(fd, ipv4 ? IPPROTO_IP : IPPROTO_IPV6,
          ipv4 ? IP_MTU_DISCOVER : IPV6_MTU_DISCOVER, &policy, sizeof(policy)) == 0,
          "set path MTU policy");

    if (ipv4) {
        struct sockaddr_in remote = {.sin_family = AF_INET};
        check(inet_pton(AF_INET, target, &remote.sin_addr) == 1, "parse IPv4 peer");
        check(connect(fd, (struct sockaddr *)&remote, sizeof(remote)) == 0, "connect IPv4 peer");
    } else {
        struct sockaddr_in6 remote = {.sin6_family = AF_INET6};
        check(inet_pton(AF_INET6, target, &remote.sin6_addr) == 1, "parse IPv6 peer");
        check(connect(fd, (struct sockaddr *)&remote, sizeof(remote)) == 0, "connect IPv6 peer");
    }

    const size_t payload_sizes[] = {0, 1, (size_t)mtu - (ipv4 ? 28 : 48)};
    unsigned char packet[MAX_MTU] = {0};
    packet[0] = ipv4 ? 8 : 128;
    memcpy(packet + 4, "KE", 2);
    for (unsigned sequence = 0; sequence < 3; ++sequence) {
        size_t size = ECHO_HEADER_SIZE + payload_sizes[sequence];
        packet[2] = packet[3] = 0;
        packet[7] = sequence;
        for (size_t i = ECHO_HEADER_SIZE; i < size; ++i)
            packet[i] = (unsigned char)(i * 17 + sequence);
        if (ipv4) {
            unsigned short sum = checksum(packet, size);
            packet[2] = sum >> 8;
            packet[3] = sum & 255;
        }
        check(send(fd, packet, size, 0) == (ssize_t)size, "send ICMP probe");
        receive_reply(fd, ipv4, packet, size);
    }
    packet[7] = 3;
    size_t oversize = ECHO_HEADER_SIZE + payload_sizes[2] + 1;
    if (ipv4) {
        packet[2] = packet[3] = 0;
        unsigned short sum = checksum(packet, oversize);
        packet[2] = sum >> 8;
        packet[3] = sum & 255;
    }
    errno = 0;
    check(send(fd, packet, oversize, 0) == -1 && errno == EMSGSIZE, "reject oversized ICMP probe");
    check(close(fd) == 0, "close ICMP socket");
    printf("PASS IPv%d payloads 0, 1 and %zu, then EMSGSIZE\n", ipv4 ? 4 : 6, payload_sizes[2]);
}

int main(int argc, char **argv)
{
    check(argc == 5, "usage: icmp-mtu native|peer MTU IPv4 IPv6");
    int mtu = atoi(argv[2]);
    check(mtu == 1500 || mtu == MAX_MTU, "MTU must be 1500 or 9000");
    if (strcmp(argv[1], "native") == 0) {
        puts("READY");
        fflush(stdout);
        check(getchar() == 'G', "host probe gate");
    } else {
        check(strcmp(argv[1], "peer") == 0, "invalid probe role");
    }
    echo(AF_INET, mtu, argv[3]);
    echo(AF_INET6, mtu, argv[4]);
    return 0;
}
