#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#define CHECK(x) do { if (!(x)) {fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1);} } while (0)
#define ERROR(call, code) do {errno = 0; CHECK((call) == -1); CHECK(errno == (code));} while (0)
static int capture_socket(int type, int index)
{
    int fd = socket(AF_PACKET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETHERTYPE_IP)); CHECK(fd >= 0);
    int domain = -1; socklen_t length = sizeof(domain);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) == 0 && domain == AF_PACKET);
    int ignore = 1; CHECK(setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore, sizeof(ignore)) == 0);
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IP), .sll_ifindex = index};
    CHECK(bind(fd, (void *)&address, sizeof(address)) == 0);
    address.sll_ifindex = INT_MAX; ERROR(bind(fd, (void *)&address, sizeof(address)), ENODEV);
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0); CHECK(copy >= 0 && close(fd) == 0); fd = copy;
    length = sizeof(address); CHECK(getsockname(fd, (void *)&address, &length) == 0);
    CHECK(address.sll_family == AF_PACKET && address.sll_ifindex == index && address.sll_protocol == htons(ETHERTYPE_IP));
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    ERROR(ioctl(fd, FIONBIO, (void *)NULL), EFAULT);
    ERROR(ioctl(fd, FIONREAD, (void *)NULL), EFAULT);
    ERROR(ioctl(fd, SIOCOUTQ, (void *)NULL), EFAULT);
    return fd;
}
static void capture(int fd, int raw, int index, uint16_t port, const char *payload, size_t payload_length)
{
    struct pollfd event = {fd, POLLIN, 0}; CHECK(poll(&event, 1, 2000) == 1 && (event.revents & POLLIN));
    int available = -1; CHECK(ioctl(fd, FIONREAD, &available) == 0 && available > 0);
    char first; ssize_t required = recv(fd, &first, 1, MSG_PEEK | MSG_TRUNC); CHECK(required == available);
    unsigned char bytes[2048]; struct sockaddr_ll sender; socklen_t length = sizeof(sender);
    ssize_t received = recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&sender, &length);
    CHECK(received == required && length >= sizeof(sender));
    CHECK(sender.sll_family == AF_PACKET && sender.sll_ifindex == index && sender.sll_protocol == htons(ETHERTYPE_IP));
    CHECK(sender.sll_hatype == ARPHRD_LOOPBACK && sender.sll_pkttype == PACKET_HOST);
    size_t offset = raw ? sizeof(struct ether_header) : 0;
    if (raw) CHECK(bytes[12] == 8 && bytes[13] == 0);
    CHECK((size_t)received >= offset + 28 && (bytes[offset] >> 4) == 4 && bytes[offset + 9] == IPPROTO_UDP);
    size_t header = (bytes[offset] & 15) * 4;
    CHECK(header >= 20 && (size_t)received == offset + header + 8 + payload_length);
    uint16_t destination; memcpy(&destination, bytes + offset + header + 2, 2); CHECK(destination == port);
    CHECK(memcmp(bytes + offset + header + 8, payload, payload_length) == 0);
    ERROR(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT), EAGAIN);
}
static void filtered_datagram(int udp, const struct sockaddr_in *address)
{
    static const char payload[] = "packet-filter-contract";
    CHECK(sendto(udp, payload, sizeof(payload), 0, (const void *)address, sizeof(*address)) == sizeof(payload));
    char bytes[sizeof(payload)]; CHECK(recv(udp, bytes, sizeof(bytes), 0) == sizeof(bytes));
    CHECK(memcmp(bytes, payload, sizeof(bytes)) == 0);
}
static void filter_contracts(int udp, int index, const struct sockaddr_in *address)
{
    for (int raw = 0; raw <= 1; ++raw) {
        int fd = capture_socket(raw ? SOCK_RAW : SOCK_DGRAM, index);
        struct sock_filter instruction = BPF_STMT(BPF_RET | BPF_K, 0);
        struct sock_fprog program = {.len = 1, .filter = &instruction};
        CHECK(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == 0);
        filtered_datagram(udp, address);
        struct pollfd event = {fd, POLLIN, 0}; CHECK(poll(&event, 1, 0) == 0);
        /* A rejected program must leave the installed drop filter intact. */
        instruction.code = BPF_JMP | BPF_JA; instruction.k = 8;
        ERROR(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)), EINVAL);
        filtered_datagram(udp, address); CHECK(poll(&event, 1, 0) == 0);
        instruction.code = BPF_RET | BPF_K; instruction.k = 8;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == 0);
        filtered_datagram(udp, address);
        CHECK(poll(&event, 1, 2000) == 1 && (event.revents & POLLIN));
        unsigned char bytes[128]; CHECK(recv(fd, bytes, sizeof(bytes), MSG_TRUNC) == 8);
        ERROR(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT), EAGAIN);
        int unused = 0;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &unused, sizeof(unused)) == 0);
        filtered_datagram(udp, address);
        CHECK(poll(&event, 1, 2000) == 1 && (event.revents & POLLIN));
        CHECK(recv(fd, bytes, sizeof(bytes), 0) > 8);
        instruction.k = 0;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == 0);
        int locked = 1;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &locked, sizeof(locked)) == 0);
        ERROR(setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &unused, sizeof(unused)), EPERM);
        instruction.k = UINT32_MAX;
        ERROR(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)), EPERM);
        locked = 0;
        ERROR(setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &locked, sizeof(locked)), EPERM);
        int copy = dup(fd); CHECK(copy >= 0 && close(fd) == 0);
        filtered_datagram(udp, address); event.fd = copy;
        CHECK(poll(&event, 1, 0) == 0 && close(copy) == 0);
    }
}
static void packet_metadata(int udp, int index, const struct sockaddr_in *address)
{
    int fd = capture_socket(SOCK_DGRAM, index), enabled = 1;
    CHECK(setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &enabled, sizeof(enabled)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled)) == 0);
    filtered_datagram(udp, address);
    unsigned char bytes[256]; union {struct cmsghdr align; unsigned char bytes[256];} control;
    struct iovec vector = {bytes, sizeof(bytes)};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct pollfd event = {fd, POLLIN, 0}; CHECK(poll(&event, 1, 2000) == 1);
    ssize_t received = recvmsg(fd, &message, 0); CHECK(received > 28 && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    int auxiliary = 0, timestamp = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == SOL_PACKET && c->cmsg_type == PACKET_AUXDATA) {
            CHECK(c->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata)));
            struct tpacket_auxdata data; memcpy(&data, CMSG_DATA(c), sizeof(data));
            CHECK(data.tp_len == (unsigned)received && data.tp_snaplen == (unsigned)received);
            CHECK(!(data.tp_status & TP_STATUS_VLAN_VALID)); ++auxiliary;
        }
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
            CHECK(c->cmsg_len >= CMSG_LEN(sizeof(struct timespec)));
            struct timespec stamp, now; memcpy(&stamp, CMSG_DATA(c), sizeof(stamp));
            CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
            CHECK(stamp.tv_sec > 0 && stamp.tv_nsec >= 0 && stamp.tv_nsec < 1000000000);
            CHECK(llabs((long long)stamp.tv_sec - now.tv_sec) <= 2); ++timestamp;
        }
    }
    CHECK(auxiliary == 1 && timestamp == 1);
    filtered_datagram(udp, address);
    message.msg_controllen = 1; message.msg_flags = 0;
    CHECK(poll(&event, 1, 2000) == 1 && recvmsg(fd, &message, 0) == received);
    CHECK(message.msg_flags & MSG_CTRUNC);
    CHECK(close(fd) == 0);
    /* Packet statistics count admitted and dropped capture copies, then reset
     * on retrieval; UDP delivery remains independent of capture pressure. */
    fd = capture_socket(SOCK_DGRAM, index); int capacity = 4096;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) == 0);
    enum {sent = 128};
    for (int i = 0; i < sent; ++i) filtered_datagram(udp, address);
    struct tpacket_stats stats; socklen_t length = sizeof(stats);
    CHECK(getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &length) == 0 && length == sizeof(stats));
    CHECK(stats.tp_packets == sent && stats.tp_drops > 0 && stats.tp_drops < sent);
    unsigned delivered = 0;
    while (recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) >= 0) ++delivered;
    CHECK(errno == EAGAIN && delivered + stats.tp_drops == sent);
    length = sizeof(stats);
    CHECK(getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &length) == 0);
    CHECK(stats.tp_packets == 0 && stats.tp_drops == 0 && close(fd) == 0);
}
static void capture_tcp(int fd, int raw, int index, uint16_t port, const char *payload, size_t payload_length)
{
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        struct pollfd event = {fd, POLLIN, 0}; CHECK(poll(&event, 1, 2000) == 1 && (event.revents & POLLIN));
        unsigned char bytes[2048]; struct sockaddr_ll sender; socklen_t length = sizeof(sender);
        ssize_t received = recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&sender, &length);
        CHECK(received > 0 && length >= sizeof(sender) && sender.sll_family == AF_PACKET &&
            sender.sll_ifindex == index && sender.sll_protocol == htons(ETHERTYPE_IP) && sender.sll_pkttype == PACKET_HOST);
        size_t offset = raw ? sizeof(struct ether_header) : 0; CHECK((size_t)received >= offset + 20);
        if (bytes[offset + 9] != IPPROTO_TCP) continue;
        size_t header = (bytes[offset] & 15) * 4;
        size_t total = ((unsigned)bytes[offset + 2] << 8) | bytes[offset + 3];
        CHECK(header >= 20 && total >= header + 20 && (size_t)received >= offset + total);
        size_t transport = (bytes[offset + header + 12] >> 4) * 4;
        CHECK(transport >= 20 && total >= header + transport);
        uint16_t destination; memcpy(&destination, bytes + offset + header + 2, 2);
        if (destination == port && total - header - transport == payload_length &&
            memcmp(bytes + offset + header + transport, payload, payload_length) == 0) return;
    }
    CHECK(!"TCP payload did not appear in original packet socket capture");
}
static void tcp_coexistence(int datagram, int raw, int index)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 1) == 0);
    socklen_t length = sizeof(address); CHECK(getsockname(listener, (void *)&address, &length) == 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(client >= 0);
    CHECK(connect(client, (void *)&address, sizeof(address)) == 0);
    int server = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(server >= 0);
    static const char payload[] = "ker-packet-tcp-coexistence";
    CHECK(write(client, payload, sizeof(payload)) == sizeof(payload));
    char received[sizeof(payload)]; CHECK(recv(server, received, sizeof(received), MSG_WAITALL) == sizeof(received));
    CHECK(memcmp(received, payload, sizeof(payload)) == 0);
    capture_tcp(datagram, 0, index, address.sin_port, payload, sizeof(payload));
    capture_tcp(raw, 1, index, address.sin_port, payload, sizeof(payload));
    CHECK(close(server) == 0 && close(client) == 0 && close(listener) == 0);
}
int main(void)
{
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(udp >= 0);
    struct ifreq request = {0}; strcpy(request.ifr_name, "lo"); CHECK(ioctl(udp, SIOCGIFINDEX, &request) == 0);
    int index = request.ifr_ifindex;
    int datagram = capture_socket(SOCK_DGRAM, index), raw = capture_socket(SOCK_RAW, index);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(udp, (void *)&address, sizeof(address)) == 0);
    socklen_t length = sizeof(address); CHECK(getsockname(udp, (void *)&address, &length) == 0);
    static const char payload[] = "ker-original-packet-socket";
    CHECK(sendto(udp, payload, sizeof(payload), 0, (void *)&address, sizeof(address)) == sizeof(payload));
    char received[sizeof(payload)]; CHECK(recv(udp, received, sizeof(received), 0) == sizeof(received));
    CHECK(memcmp(received, payload, sizeof(payload)) == 0);
    capture(datagram, 0, index, address.sin_port, payload, sizeof(payload));
    capture(raw, 1, index, address.sin_port, payload, sizeof(payload));
    CHECK(close(raw) == 0 && close(datagram) == 0);
    filter_contracts(udp, index, &address);
    packet_metadata(udp, index, &address);
    datagram = capture_socket(SOCK_DGRAM, index); raw = capture_socket(SOCK_RAW, index);
    tcp_coexistence(datagram, raw, index);
    CHECK(close(raw) == 0 && close(datagram) == 0 && close(udp) == 0);
    puts(dlsym(RTLD_DEFAULT, "ker_posix_kernel_release") ?
        "PASS: imported original Linux packet socket capture, metadata and ownership" :
        "PASS: host Linux packet socket reference capture, metadata and ownership");
    return 0;
}
