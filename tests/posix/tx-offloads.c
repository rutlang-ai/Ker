#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <time.h>
static void check(bool success, const char *message)
{
    if (!success) { perror(message); exit(1); }
}
#ifdef KER_TEST_NATIVE_BUFFERS
#include "native-buffer-test.h"
#endif
static void reconfigure(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "MTU native socket");
    struct ifreq entries[16], interface = {0};
    struct ifconf list = {.ifc_len = sizeof(entries), .ifc_req = entries};
    check(!ioctl(fd, SIOCGIFCONF, &list), "native interface lookup");
    struct in_addr wanted;
    check(inet_pton(AF_INET, "198.18.0.2", &wanted) == 1, "native local address");
    for (unsigned index = 0; index < (unsigned)list.ifc_len / sizeof(entries[0]); index++) {
        struct sockaddr_in *address = (void *)&entries[index].ifr_addr;
        if (address->sin_addr.s_addr == wanted.s_addr) interface = entries[index];
    }
    check(interface.ifr_name[0], "native interface found");
    int values[] = {1600, 1500};
    for (unsigned index = 0; index < 2; index++) {
        interface.ifr_mtu = values[index];
        int result = -1;
        for (unsigned attempt = 0; attempt < 100; attempt++) {
            result = ioctl(fd, SIOCSIFMTU, &interface);
            if (!result || errno != EBUSY) break;
            struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
        }
        check(!result && !ioctl(fd, SIOCGIFMTU, &interface) && interface.ifr_mtu == values[index],
            "offload queue restart/MTU readback");
    }
    check(!close(fd), "MTU socket close");
}
int main(int argc, char **argv)
{
#ifdef KER_TEST_NATIVE_BUFFERS
    if (argc == 2 && !strcmp(argv[1], "contracts")) {
        buffer_init(); buffer_guards(); buffer_finish(); return 0;
    }
#endif
    bool failure = argc == 3 && !strcmp(argv[2], "failure");
    bool wait_for_link = argc == 3 && !strcmp(argv[2], "wait");
    bool tap_extension = argc == 3 && !strcmp(argv[2], "tap-extension");
    check(argc == 2 || failure || wait_for_link || tap_extension,
        "usage: tx-offloads PORT [failure|wait|tap-extension]");
    if (wait_for_link) { puts("READY"); fflush(stdout); check(getchar() == 'G', "wait for independent link"); }
    int port = atoi(argv[1]);
#ifdef KER_TEST_NATIVE_BUFFERS
    buffer_init(); buffer_guards();
#endif
    if (argc == 2 || wait_for_link || tap_extension) reconfigure();
    for (unsigned family = 0; family < 2; family++) {
        struct sockaddr_storage target = {0};
        socklen_t size;
        if (!family) {
            struct sockaddr_in *a = (void *)&target;
            a->sin_family = AF_INET; a->sin_port = htons((uint16_t)port);
            check(inet_pton(AF_INET, "198.18.0.1", &a->sin_addr) == 1, "target4"); size = sizeof(*a);
        } else {
            struct sockaddr_in6 *a = (void *)&target;
            a->sin6_family = AF_INET6; a->sin6_port = htons((uint16_t)port);
            check(inet_pton(AF_INET6, "2001:db8:1::1", &a->sin6_addr) == 1, "target6"); size = sizeof(*a);
        }
        int fd = socket(family ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
        check(fd >= 0 && !connect(fd, (void *)&target, size), "native UDP");
        struct timeval timeout = {.tv_sec = 5};
        check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "UDP timeout");
        if (failure) {
            check(send(fd, "failure", 7, 0) == 7, "offload failure trigger");
            sleep(5);
            return 0;
        }
        int send_flags = MSG_NOSIGNAL;
#ifdef KER_TEST_NATIVE_BUFFERS
        buffer_socket(fd, family, false); send_flags |= MSG_ZEROCOPY;
#endif
        unsigned lengths[] = {0, 1, 511, 1400};
        for (unsigned index = 0; index < 4; index++) {
            unsigned char reply[1400];
#ifdef KER_TEST_NATIVE_BUFFERS
            unsigned char *bytes = buffer_allocate(1400); check(bytes, "UDP native mapping");
#else
            unsigned char bytes[1400];
#endif
            for (unsigned i = 0; i < lengths[index]; i++) bytes[i] = (unsigned char)(i * 17 + family);
            check(send(fd, bytes, lengths[index], send_flags) == lengths[index], "UDP send");
            check(recv(fd, reply, sizeof(reply), 0) == lengths[index] &&
                !memcmp(bytes, reply, lengths[index]), "UDP exact reply");
#ifdef KER_TEST_NATIVE_BUFFERS
            buffer_sent(lengths[index], true); buffer_complete(fd);
            check(!buffer_release(bytes), "UDP release after completion");
#endif
        }
        if (family && tap_extension) {
            /* Linux emits CHECKSUM_PARTIAL metadata for this valid IPv6
             * Hop-by-Hop UDP datagram; the TAP PMD must keep it on the
             * kernel-seeded byte-range checksum path. */
            unsigned char extension[8] = {IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0};
            unsigned char control[CMSG_SPACE(sizeof(extension))] = {0};
            unsigned char payload[] = "tap-ipv6-extension";
            struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload)};
            struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = control, .msg_controllen = sizeof(control)};
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_HOPOPTS;
            cmsg->cmsg_len = CMSG_LEN(sizeof(extension));
            memcpy(CMSG_DATA(cmsg), extension, sizeof(extension));
            check(sendmsg(fd, &message, 0) == sizeof(payload), "IPv6 Hop-by-Hop UDP send");
        }
        check(!close(fd), "UDP close");
        fd = socket(family ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        check(fd >= 0 && !connect(fd, (void *)&target, size), "native TCP");
        check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
            !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)), "TCP timeout");
        enum { block_size = 32768 };
#ifdef KER_TEST_NATIVE_BUFFERS
        buffer_socket(fd, family, true);
        unsigned char *block = buffer_allocate(4097); check(block, "TCP native mapping");
        memset(block, 0x73, 4097);
        unsigned char *grown = buffer_resize(block, block_size); check(grown, "grow TCP native mapping");
        block = grown;
        for (unsigned i = 0; i < block_size; i++)
            check(block[i] == (i < 4097 ? 0x73 : 0), "resized TCP prefix and zero extension");
#else
        unsigned char block[block_size];
#endif
        for (unsigned index = 0; index < 16; index++) {
            for (unsigned i = 0; i < block_size; i++) {
                unsigned position = index * (unsigned)block_size + i;
                block[i] = (unsigned char)((position * 17) ^ (position >> 8) ^ (position >> 16) ^ family);
            }
            unsigned offset = 0;
            while (offset < block_size) {
                ssize_t count = send(fd, block + offset, block_size - offset, send_flags);
                check(count > 0, "TCP bulk send"); offset += (unsigned)count;
#ifdef KER_TEST_NATIVE_BUFFERS
                buffer_sent((size_t)count, false);
#endif
            }
#ifdef KER_TEST_NATIVE_BUFFERS
            buffer_complete(fd); /* Wait before rewriting or resizing referenced bytes. */
            if (index == 7) {
                unsigned char *smaller = buffer_resize(block, 4097); check(smaller, "shrink after TCP completions");
                block = smaller;
                for (unsigned i = 0; i < 4097; i++) {
                    unsigned position = index * (unsigned)block_size + i;
                    check(block[i] == (unsigned char)((position * 17) ^ (position >> 8) ^ (position >> 16) ^ family),
                          "shrink preserves completed TCP prefix");
                }
                unsigned char *larger = buffer_resize(block, block_size); check(larger, "regrow after TCP completions");
                block = larger;
                for (unsigned i = 4097; i < block_size; i++) check(!block[i], "regrown TCP tail zeroed");
                printf("BUFFER_RESIZE family=%u after_completions\n", family);
            }
#endif
            struct timespec capture_budget = {.tv_nsec = 5000000};
            nanosleep(&capture_budget, NULL);
        }
#ifdef KER_TEST_NATIVE_BUFFERS
        check(!buffer_release(block), "TCP mapping release after completions");
#endif
        check(!shutdown(fd, SHUT_WR), "TCP half close");
        char ack[8];
        check(recv(fd, ack, sizeof(ack), MSG_WAITALL) == sizeof(ack) && !memcmp(ack, "ACK-DONE", sizeof(ack)), "TCP bulk ack");
        check(recv(fd, ack, sizeof(ack), 0) == 0 && !close(fd), "TCP peer EOF/close");
        printf("PASS: original Linux IPv%u TCP512KiB and UDP boundary lengths\n", family ? 6 : 4);
    }
#ifdef KER_TEST_NATIVE_BUFFERS
    buffer_finish();
#endif
    return 0;
}
