#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static const char payload[] = "native-ipv6";
static const char ipv4_final_ack[] = "native-vlan-final-ack";
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
static int interface_index(int fd, int tag)
{
    char name[IFNAMSIZ];
    snprintf(name, sizeof(name), "ker.%d", tag);
    struct ifreq request = {0};
    strcpy(request.ifr_name, name);
    CHECK(ioctl(fd, SIOCGIFINDEX, &request) == 0 && request.ifr_ifindex > 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0);
    return request.ifr_ifindex;
}
static void udp_echo(int fd, int outgoing, int index, const struct in6_addr *local)
{
    unsigned char buffer[1453], expected[1452];
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(i * 17 + 3);
    if (outgoing) CHECK(send(fd, expected, sizeof(expected), 0) == sizeof(expected));
    unsigned char control[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct sockaddr_in6 peer;
    struct iovec vector = {.iov_base = buffer, .iov_len = sizeof(buffer)};
    struct msghdr message = {.msg_name = &peer, .msg_namelen = sizeof(peer),
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    CHECK(recvmsg(fd, &message, 0) == sizeof(expected) && !message.msg_flags);
    CHECK(!memcmp(buffer, expected, sizeof(expected)));
    int found = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level != IPPROTO_IPV6 || c->cmsg_type != IPV6_PKTINFO) continue;
        CHECK(c->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)));
        struct in6_pktinfo info; memcpy(&info, CMSG_DATA(c), sizeof(info));
        CHECK(info.ipi6_ifindex == (unsigned int)index && !memcmp(&info.ipi6_addr, local, sizeof(*local)));
        ++found;
    }
    CHECK(found == 1);
    if (!outgoing) CHECK(sendto(fd, buffer, sizeof(expected), 0, (void *)&peer, sizeof(peer)) == sizeof(expected));
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "max")) {
        for (int tag = 100; tag < 116; ++tag) for (int i = 2; i < 10; ++i) {
            char text[INET6_ADDRSTRLEN];
            snprintf(text, sizeof(text), "2001:db8:1234:5678:9abc:def0:%x:%x", tag, i);
            struct sockaddr_in6 local = endpoint(text, 0);
            int fd = make_socket(AF_INET6, SOCK_DGRAM);
            interface_index(fd, tag);
            CHECK(bind(fd, (void *)&local, sizeof(local)) == 0);
            CHECK(close(fd) == 0);
        }
        puts("PASS: maximum 16 IPv6 VLANs with eight addresses each");
        return 0;
    }
    int port = atoi(argv[1]);
    const char *addresses[] = {"2001:db8:100::2", "2001:db8:100::3", "2001:db8:200::2"};
    const int tags[] = {100, 100, 200};
    int tcp[3], udp[3], indices[3], one = 1;
    for (int i = 0; i < 3; ++i) {
        struct sockaddr_in6 local = endpoint(addresses[i], port);
        tcp[i] = make_socket(AF_INET6, SOCK_STREAM);
        udp[i] = make_socket(AF_INET6, SOCK_DGRAM);
        interface_index(tcp[i], tags[i]);
        indices[i] = interface_index(udp[i], tags[i]);
        CHECK(setsockopt(udp[i], IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) == 0);
        CHECK(bind(tcp[i], (void *)&local, sizeof(local)) == 0);
        CHECK(bind(udp[i], (void *)&local, sizeof(local)) == 0);
        CHECK(listen(tcp[i], 1) == 0);
    }
    /* IPv4 remains usable on the same mixed-address VLAN. */
    int ipv4 = make_socket(AF_INET, SOCK_DGRAM);
    interface_index(ipv4, 100);
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, "198.19.100.2", &v4.sin_addr) == 1);
    CHECK(bind(ipv4, (void *)&v4, sizeof(v4)) == 0);
    struct ifreq hardware = {0}; strcpy(hardware.ifr_name, "ker.100");
    CHECK(ioctl(udp[0], SIOCGIFHWADDR, &hardware) == 0);
    unsigned char *mac = (unsigned char *)hardware.ifr_hwaddr.sa_data;
    printf("READY %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    fflush(stdout);
    for (int i = 0; i < 3; ++i) {
        struct sockaddr_in6 local = endpoint(addresses[i], 0), peer;
        char host_text[INET6_ADDRSTRLEN];
        snprintf(host_text, sizeof(host_text), "2001:db8:%d::1", tags[i]);
        struct sockaddr_in6 host = endpoint(host_text, port + 1);
        socklen_t length = sizeof(peer);
        int accepted = accept(tcp[i], (void *)&peer, &length);
        CHECK(accepted >= 0 && !memcmp(&peer.sin6_addr, &host.sin6_addr, sizeof(host.sin6_addr)));
        echo(accepted, 0); CHECK(close(accepted) == 0); CHECK(close(tcp[i]) == 0);
        udp_echo(udp[i], 0, indices[i], &local.sin6_addr); CHECK(close(udp[i]) == 0);
        int outgoing = make_socket(AF_INET6, SOCK_STREAM);
        interface_index(outgoing, tags[i]);
        CHECK(bind(outgoing, (void *)&local, sizeof(local)) == 0);
        CHECK(connect(outgoing, (void *)&host, sizeof(host)) == 0);
        echo(outgoing, 1); CHECK(close(outgoing) == 0);
        outgoing = make_socket(AF_INET6, SOCK_DGRAM);
        interface_index(outgoing, tags[i]);
        CHECK(setsockopt(outgoing, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) == 0);
        CHECK(bind(outgoing, (void *)&local, sizeof(local)) == 0);
        CHECK(connect(outgoing, (void *)&host, sizeof(host)) == 0);
        udp_echo(outgoing, 1, indices[i], &local.sin6_addr); CHECK(close(outgoing) == 0);
    }
    char buffer[sizeof(payload)];
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    CHECK(recvfrom(ipv4, buffer, sizeof(buffer), 0, (void *)&peer, &length) == sizeof(payload));
    CHECK(!memcmp(buffer, payload, sizeof(payload)));
    CHECK(sendto(ipv4, buffer, sizeof(buffer), 0, (void *)&peer, length) == sizeof(payload));
    struct sockaddr_in ack_peer = {0};
    socklen_t ack_length = sizeof(ack_peer);
    char ack[sizeof(ipv4_final_ack)];
    CHECK(recvfrom(ipv4, ack, sizeof(ack), 0, (void *)&ack_peer, &ack_length) == sizeof(ack));
    CHECK(!memcmp(ack, ipv4_final_ack, sizeof(ack)) && ack_peer.sin_family == peer.sin_family &&
          ack_peer.sin_port == peer.sin_port && ack_peer.sin_addr.s_addr == peer.sin_addr.s_addr);
    CHECK(close(ipv4) == 0);
    puts("PASS: device-bound IPv6 VLAN TCP/UDP, metadata, VIPs and mixed IPv4");
    return 0;
}
