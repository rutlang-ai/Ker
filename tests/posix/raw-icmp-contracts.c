/* Echo requests are test stimuli; all IP/ICMP processing and replies come from
 * the selected original Linux kernel, never a Ker protocol implementation. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/icmp.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do {if (!(x)) {fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1);}} while (0)
struct echo {unsigned char bytes[40];};
static void ready(int fd) {struct pollfd p = {fd, POLLIN, 0}; CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLIN));}
static uint16_t checksum(const void *data, size_t length)
{
    const unsigned char *p = data; unsigned sum = 0;
    while (length > 1) {sum += ((unsigned)p[0] << 8) | p[1]; p += 2; length -= 2;}
    if (length) sum += (unsigned)p[0] << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return htons((uint16_t)~sum);
}
static void echo_contract(int family)
{
    int fd = socket(family, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    CHECK(fd >= 0); int alias = fcntl(fd, F_DUPFD_CLOEXEC, 0); CHECK(alias >= 0 && close(fd) == 0); fd = alias;
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    struct sockaddr_storage storage = {0}; socklen_t size;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&storage; a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); size = sizeof(*a);
        struct icmp_filter filter = {.data = ~(UINT32_C(1) << ICMP_ECHOREPLY)};
        CHECK(setsockopt(fd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) == 0);
    } else {
        struct sockaddr_in6 *a = (void *)&storage; a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback; size = sizeof(*a);
        struct icmp6_filter filter; ICMP6_FILTER_SETBLOCKALL(&filter); ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
        CHECK(setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) == 0);
    }
    CHECK(bind(fd, (void *)&storage, size) == 0);
    struct echo request = {0}; request.bytes[0] = family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    uint16_t id = htons(0x4b31), sequence = htons(73);
    memcpy(request.bytes + 4, &id, 2); memcpy(request.bytes + 6, &sequence, 2);
    memcpy(request.bytes + 8, "original-linux-raw-echo-contract", 31);
    if (family == AF_INET) {uint16_t sum = checksum(&request, sizeof(request)); memcpy(request.bytes + 2, &sum, 2);}
    CHECK(sendto(fd, &request, sizeof(request), 0, (void *)&storage, size) == sizeof(request));
    ready(fd); unsigned char bytes[256]; struct sockaddr_storage sender; socklen_t sender_size = sizeof(sender);
    ssize_t count = recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&sender, &sender_size); CHECK(count > 0 && sender.ss_family == family);
    size_t offset = 0;
    if (family == AF_INET) {
        CHECK(count >= 20 && (bytes[0] >> 4) == 4 && bytes[9] == IPPROTO_ICMP);
        offset = (bytes[0] & 15) * 4; CHECK(offset >= 20 && (size_t)count >= offset + sizeof(request));
        CHECK(((struct sockaddr_in *)(void *)&sender)->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        CHECK(checksum(bytes + offset, count - offset) == 0);
    } else CHECK(IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)(void *)&sender)->sin6_addr));
    CHECK((size_t)count == offset + sizeof(request));
    CHECK(bytes[offset] == (family == AF_INET ? ICMP_ECHOREPLY : ICMP6_ECHO_REPLY) && bytes[offset + 1] == 0);
    CHECK(memcmp(bytes + offset + 4, request.bytes + 4, sizeof(request) - 4) == 0);
    errno = 0; CHECK(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(close(fd) == 0);
}
static void header_inclusion_contract(void)
{
    int fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW); CHECK(fd >= 0);
    int included = 0; socklen_t size = sizeof(included);
    CHECK(getsockopt(fd, IPPROTO_IP, IP_HDRINCL, &included, &size) == 0 && included == 1);
    struct ifreq request = {0}; strcpy(request.ifr_name, "lo"); CHECK(ioctl(fd, SIOCGIFINDEX, &request) == 0);
    int capture = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK, htons(ETHERTYPE_IP)); CHECK(capture >= 0);
    int ignore = 1; CHECK(setsockopt(capture, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore, sizeof(ignore)) == 0);
    struct sockaddr_ll link = {.sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IP), .sll_ifindex = request.ifr_ifindex};
    CHECK(bind(capture, (void *)&link, sizeof(link)) == 0);
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9), BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMP, 0, 4),
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0), BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP_ECHO, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, UINT32_MAX), BPF_STMT(BPF_RET | BPF_K, 0)};
    struct sock_fprog program = {.len = sizeof(instructions) / sizeof(instructions[0]), .filter = instructions};
    CHECK(setsockopt(capture, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == 0);
    unsigned char packet[64] = {0x46, 0x2e, 0, 1, 0x43, 0x21, 0, 0, 31, IPPROTO_ICMP, 0x11, 0x11};
    uint32_t loopback = htonl(INADDR_LOOPBACK); memcpy(packet + 16, &loopback, 4);
    packet[20] = 1; packet[21] = 1; /* NOP, NOP, EOL, padding. */
    packet[24] = ICMP_ECHO; packet[28] = 0x4b; packet[29] = 0x32; packet[31] = 74;
    memcpy(packet + 32, "original-linux-header-inclusion", 31);
    uint16_t sum = checksum(packet + 24, sizeof(packet) - 24); memcpy(packet + 26, &sum, 2);
    struct sockaddr_in destination = {.sin_family = AF_INET, .sin_addr.s_addr = loopback};
    errno = 0; CHECK(sendto(fd, packet, 19, 0, (void *)&destination, sizeof(destination)) == -1 && errno == EINVAL);
    packet[0] = 0x44; errno = 0;
    CHECK(sendto(fd, packet, sizeof(packet), 0, (void *)&destination, sizeof(destination)) == -1 && errno == EINVAL);
    packet[0] = 0x4f; errno = 0;
    CHECK(sendto(fd, packet, 24, 0, (void *)&destination, sizeof(destination)) == -1 && errno == EINVAL);
    packet[0] = 0x46;
    unsigned char *oversize = calloc(65536, 1); CHECK(oversize); memcpy(oversize, packet, sizeof(packet)); errno = 0;
    CHECK(sendto(fd, oversize, 65536, 0, (void *)&destination, sizeof(destination)) == -1 && errno == EMSGSIZE); free(oversize);
    unsigned char bytes[256]; errno = 0;
    CHECK(recv(capture, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(sendto(fd, packet, sizeof(packet), 0, (void *)&destination, sizeof(destination)) == sizeof(packet));
    ready(capture); ssize_t count = recv(capture, bytes, sizeof(bytes), 0); CHECK(count == sizeof(packet));
    CHECK(bytes[0] == 0x46 && bytes[1] == packet[1] && bytes[8] == packet[8] && bytes[9] == IPPROTO_ICMP);
    CHECK(bytes[2] == 0 && bytes[3] == sizeof(packet) && bytes[4] == packet[4] && bytes[5] == packet[5]);
    CHECK(memcmp(bytes + 12, &loopback, 4) == 0 && memcmp(bytes + 16, &loopback, 4) == 0);
    CHECK(checksum(bytes, 24) == 0 && memcmp(bytes + 20, packet + 20, sizeof(packet) - 20) == 0);
    CHECK(close(capture) == 0 && close(fd) == 0);
    /* Failed header sends must not poison later ordinary echo operation. */
    echo_contract(AF_INET);
}
static void tcp_coexistence(void)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 1) == 0);
    socklen_t size = sizeof(address); CHECK(getsockname(listener, (void *)&address, &size) == 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(client >= 0 && connect(client, (void *)&address, size) == 0);
    int server = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(server >= 0 && write(client, "icmp", 4) == 4);
    char bytes[4]; CHECK(recv(server, bytes, sizeof(bytes), MSG_WAITALL) == 4 && memcmp(bytes, "icmp", 4) == 0);
    CHECK(close(server) == 0 && close(client) == 0 && close(listener) == 0);
}
int main(void)
{
    echo_contract(AF_INET); echo_contract(AF_INET6); header_inclusion_contract(); tcp_coexistence();
    puts("PASS: original Linux raw ICMPv4/ICMPv6 echo, filtering and descriptor lifetime"); return 0;
}
