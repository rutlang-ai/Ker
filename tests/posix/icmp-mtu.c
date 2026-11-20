/* Raw socket probes. Both kernels generate their own echo replies. */
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
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

static void echo(int family, int mtu, const char *target, unsigned phase)
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
        packet[7] = phase * 4 + sequence;
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
    packet[7] = phase * 4 + 3;
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
}

static void set_mtu(int fd, struct ifreq *interface, int mtu, int expected_error)
{
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
        interface->ifr_mtu = mtu;
        errno = 0;
        int result = ioctl(fd, SIOCSIFMTU, interface);
        if (result >= 0 || errno != EBUSY) {
            check(expected_error ? result == -1 && errno == expected_error : result == 0,
                  "live MTU update returned unexpected result");
            return;
        }
        const struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    check(0, "live MTU update stayed busy");
}

static void read_mtu(int fd, struct ifreq *interface, int expected)
{
    check(ioctl(fd, SIOCGIFMTU, interface) == 0 && interface->ifr_mtu == expected,
          "native MTU readback differs");
}

static void live(const char *role, const char *target4, const char *target6)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "open native interface control socket");
    int alias = dup(fd);
    check(alias >= 0, "duplicate interface control socket");
    /* The single Linux packet interface follows loopback. Resolve its name
     * using the private kernel so no host-interface name is assumed. */
    struct ifreq interface = {.ifr_ifindex = 2};
    check(ioctl(fd, SIOCGIFNAME, &interface) == 0 && strcmp(interface.ifr_name, "lo") != 0,
          "find native packet interface");
    read_mtu(fd, &interface, 1500);

    errno = 0;
    check(ioctl(alias, SIOCSIFMTU, NULL) == -1 && errno == EFAULT, "null MTU request");
    struct ifreq missing = {.ifr_name = "ker-missing", .ifr_mtu = MAX_MTU};
    errno = 0;
    check(ioctl(alias, SIOCSIFMTU, &missing) == -1 && errno == ENODEV, "unknown interface");
    struct ifreq loopback = {.ifr_name = "lo"};
    check(ioctl(fd, SIOCGIFMTU, &loopback) == 0 && loopback.ifr_mtu > MAX_MTU,
          "loopback remains Linux-owned");
    int loopback_mtu = loopback.ifr_mtu;
    set_mtu(alias, &loopback, loopback_mtu - 1, 0);
    read_mtu(fd, &loopback, loopback_mtu - 1);
    set_mtu(alias, &loopback, loopback_mtu, 0);
    set_mtu(alias, &interface, 1279, EINVAL);
    set_mtu(alias, &interface, 9001, EINVAL);
    read_mtu(fd, &interface, 1500);

    if (strcmp(role, "live-fatal") == 0) {
        set_mtu(alias, &interface, MAX_MTU, EIO);
        check(0, "fatal MTU transaction returned to the app");
    }
    if (strcmp(role, "live-rollback") == 0) {
        set_mtu(alias, &interface, MAX_MTU, EIO);
        read_mtu(fd, &interface, 1500);
        puts("ROLLBACK");
        fflush(stdout);
        check(getchar() == 'N', "rollback verification gate");
    }
    int ceiling = strcmp(role, "live-ceiling") == 0;
    if (ceiling) {
        set_mtu(alias, &interface, 1501, EINVAL);
        read_mtu(fd, &interface, 1500);
    }

    const int sizes[] = {1500, ceiling ? 1500 : MAX_MTU, 1500};
    for (unsigned phase = 0; phase < 3; ++phase) {
        set_mtu(alias, &interface, sizes[phase], 0);
        read_mtu(fd, &interface, sizes[phase]);
        printf("PHASE %u %d\n", phase, interface.ifr_mtu);
        fflush(stdout);
        check(getchar() == 'G', "live peer probe gate");
        echo(AF_INET, sizes[phase], target4, phase);
        echo(AF_INET6, sizes[phase], target6, phase);
        printf("DONE %u\n", phase);
        fflush(stdout);
        check(getchar() == 'N', "live phase completion gate");
    }
    check(close(alias) == 0 && close(fd) == 0, "close MTU control sockets");
}

int main(int argc, char **argv)
{
    check(argc == 5 || argc == 6, "usage: icmp-mtu ROLE MTU IPv4 IPv6 [PHASE]");
    int mtu = atoi(argv[2]);
    check(mtu == 1500 || mtu == MAX_MTU, "MTU must be 1500 or 9000");
    int is_live = strncmp(argv[1], "live", 4) == 0;
    if (is_live || strcmp(argv[1], "native") == 0) {
        puts("READY");
        fflush(stdout);
        check(getchar() == 'G', "host probe gate");
    } else {
        check(strcmp(argv[1], "peer") == 0, "invalid probe role");
    }
    if (is_live) {
        live(argv[1], argv[3], argv[4]);
        return 0;
    }
    int phase = argc == 6 ? atoi(argv[5]) : 0;
    check(phase >= 0 && phase <= 2, "invalid phase");
    echo(AF_INET, mtu, argv[3], (unsigned)phase);
    echo(AF_INET6, mtu, argv[4], (unsigned)phase);
    puts("PASS IPv4 and IPv6 echo and EMSGSIZE");
    return 0;
}
