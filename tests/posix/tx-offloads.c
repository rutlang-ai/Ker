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
#include <unistd.h>
#include <time.h>
static void check(bool success, const char *message)
{
    if (!success) { perror(message); exit(1); }
}
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
    check(argc == 2 || argc == 3, "usage: tx-offloads PORT [failure]");
    int port = atoi(argv[1]);
    if (argc == 2) reconfigure();
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
        if (argc == 3) {
            check(send(fd, "failure", 7, 0) == 7, "offload failure trigger");
            sleep(5);
            return 1;
        }
        unsigned lengths[] = {0, 1, 511, 1400};
        for (unsigned index = 0; index < 4; index++) {
            unsigned char bytes[1400], reply[1400];
            for (unsigned i = 0; i < lengths[index]; i++) bytes[i] = (unsigned char)(i * 17 + family);
            check(send(fd, bytes, lengths[index], 0) == lengths[index], "UDP send");
            check(recv(fd, reply, sizeof(reply), 0) == lengths[index] &&
                !memcmp(bytes, reply, lengths[index]), "UDP exact reply");
        }
        check(!close(fd), "UDP close");
        fd = socket(family ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        check(fd >= 0 && !connect(fd, (void *)&target, size), "native TCP");
        check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
            !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)), "TCP timeout");
        unsigned char block[32768];
        for (unsigned i = 0; i < sizeof(block); i++) block[i] = (unsigned char)(i * 17 + family);
        for (unsigned index = 0; index < 16; index++) {
            unsigned offset = 0;
            while (offset < sizeof(block)) {
                ssize_t count = send(fd, block + offset, sizeof(block) - offset, MSG_NOSIGNAL);
                check(count > 0, "TCP bulk send"); offset += (unsigned)count;
            }
            struct timespec capture_budget = {.tv_nsec = 5000000};
            nanosleep(&capture_budget, NULL);
        }
        check(!shutdown(fd, SHUT_WR), "TCP half close");
        char ack[8];
        check(recv(fd, ack, sizeof(ack), MSG_WAITALL) == sizeof(ack) && !memcmp(ack, "ACK-DONE", sizeof(ack)), "TCP bulk ack");
        check(recv(fd, ack, sizeof(ack), 0) == 0 && !close(fd), "TCP peer EOF/close");
        printf("PASS: original Linux IPv%u TCP512KiB and UDP boundary lengths\n", family ? 6 : 4);
    }
    return 0;
}
