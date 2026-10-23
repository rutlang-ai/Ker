/* Exercise upstream Linux raw ICMP sockets; echo replies come from the kernels. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>
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
static void echo(int family, int mtu, const char *target, unsigned phase)
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
        packet[4] = 0x4b; packet[5] = 0x45; packet[7] = seq + phase * 3;
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
                reply[5] != 0x45 || reply[6] != 0 || reply[7] != seq + phase * 3) continue;
            check((size_t)count == offset + size && reply[1] == 0 &&
                  memcmp(reply + 8, packet + 8, size - 8) == 0, "echo payload differs");
            if (family == AF_INET) check(checksum(reply, size) == 0, "ICMP checksum");
            found = 1;
        }
        check(found, "missing matching echo");
    }
    unsigned char oversized[9001] = {0};
    oversized[0] = family == AF_INET ? 8 : 128;
    errno = 0;
    check(send(fd, oversized, (size_t)mtu - (family == AF_INET ? 20 : 40) + 1, 0) == -1 &&
          errno == EMSGSIZE, "oversize DF echo must fail EMSGSIZE");
    close(fd);
    printf("PASS: IPv%d ICMP payloads 0, 1, %d without fragmentation\n", family == AF_INET ? 4 : 6, sizes[2]);
}
static void dynamic(const char *target4, const char *target6, int reject, int fault)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0), alias = dup(fd);
    check(fd >= 0 && alias >= 0, "MTU socket aliases");
    struct ifreq interface = {0};
    /* Discover the actual primary native interface, not a host interface. */
    interface.ifr_ifindex = 2;
    check(ioctl(fd, SIOCGIFNAME, &interface) == 0, "native interface name");
    check(strcmp(interface.ifr_name, "lo") != 0, "non-loopback interface");
    check(ioctl(fd, SIOCGIFMTU, &interface) == 0 && interface.ifr_mtu == 1500, "initial native MTU");
    struct ifreq missing = {0};
    strcpy(missing.ifr_name, "ker-missing"); missing.ifr_mtu = 9000; errno = 0;
    check(ioctl(alias, SIOCSIFMTU, &missing) == -1 && errno == ENODEV, "unknown interface rejected");
    errno = 0;
    check(ioctl(alias, SIOCSIFMTU, NULL) == -1 && errno == EFAULT, "NULL MTU request rejected");
    struct ifreq loopback = {0}; strcpy(loopback.ifr_name, "lo");
    check(ioctl(fd, SIOCGIFMTU, &loopback) == 0 && loopback.ifr_mtu > 9000, "loopback MTU remains Linux-owned");
    int invalid[] = {0, 1279, 9001};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        interface.ifr_mtu = invalid[i]; errno = 0;
        check(ioctl(alias, SIOCSIFMTU, &interface) == -1 && errno == EINVAL, "invalid MTU rejected");
        check(ioctl(fd, SIOCGIFMTU, &interface) == 0 && interface.ifr_mtu == 1500, "invalid MTU preserved state");
    }
    if (reject == 2) {
        interface.ifr_mtu = 1501; errno = 0;
        check(ioctl(alias, SIOCSIFMTU, &interface) == -1 && errno == EINVAL, "deployment ceiling enforced");
        check(ioctl(fd, SIOCGIFMTU, &interface) == 0 && interface.ifr_mtu == 1500, "ceiling preserved MTU");
    }
    if (reject == 1) {
        interface.ifr_mtu = 9000; errno = 0;
        check(ioctl(alias, SIOCSIFMTU, &interface) == -1 && errno == EIO, "PMD rejection propagated");
        check(ioctl(fd, SIOCGIFMTU, &interface) == 0 && interface.ifr_mtu == 1500, "Linux/PMD rollback");
        puts("ROLLBACK"); fflush(stdout);
        check(getchar() == 'R', "rollback verification gate");
    }
    if (fault) {
        interface.ifr_mtu = 9000;
        (void)ioctl(alias, SIOCSIFMTU, &interface);
        check(0, "ambiguous PMD readback unexpectedly succeeded");
    }
    int values[] = {1500, reject == 2 ? 1500 : 9000, 1500};
    for (unsigned phase = 0; phase < 3; phase++) {
        interface.ifr_mtu = values[phase];
        int result = -1;
        for (unsigned attempt = 0; attempt < 100; attempt++) {
            result = ioctl(alias, SIOCSIFMTU, &interface);
            if (!result || errno != EBUSY) break;
            struct timespec wait = {0, 1000000}; nanosleep(&wait, NULL);
        }
        check(result == 0, "live native/PMD MTU change");
        check(ioctl(fd, SIOCGIFMTU, &interface) == 0 && interface.ifr_mtu == values[phase], "live MTU readback");
        printf("PHASE %u %d\n", phase, values[phase]); fflush(stdout);
        check(getchar() == 'G', "dynamic peer gate");
        echo(AF_INET, values[phase], target4, phase);
        echo(AF_INET6, values[phase], target6, phase);
        printf("DONE %u\n", phase); fflush(stdout);
        check(getchar() == 'N', "dynamic phase gate");
    }
    close(alias); close(fd);
}
int main(int argc, char **argv)
{
    check(argc == 5 || argc == 6, "usage: icmp-mtu native|peer MTU IPv4 IPv6");
    int mtu = atoi(argv[2]);
    check(mtu == 1500 || mtu == 9000, "MTU");
    if (strncmp(argv[1], "dynamic", 7) == 0) {
        puts("READY"); fflush(stdout);
        dynamic(argv[3], argv[4], strcmp(argv[1], "dynamic-ceiling") == 0 ? 2 :
            strcmp(argv[1], "dynamic-reject") == 0, strcmp(argv[1], "dynamic-fault") == 0); return 0;
    }
    if (strcmp(argv[1], "native") == 0) {
        puts("READY"); fflush(stdout);
        check(getchar() == 'G', "peer gate");
    }
    unsigned phase = argc == 6 ? (unsigned)atoi(argv[5]) : 0;
    echo(AF_INET, mtu, argv[3], phase); echo(AF_INET6, mtu, argv[4], phase);
    return 0;
}
