/* Inspect the actual imported Linux interfaces after constructor startup. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    assert(argc == 2);
    int marker = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(marker >= 0);
    assert(close(marker) == 0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct ifreq entries[16];
    struct ifconf list = {.ifc_len = sizeof(entries), .ifc_req = entries};
    assert(ioctl(fd, SIOCGIFCONF, &list) == 0);
    int loopback = 0, configured = 0;
    for (int i = 0; i < list.ifc_len / (int)sizeof(entries[0]); i++) {
        struct ifreq request = entries[i];
        struct sockaddr_in *address = (struct sockaddr_in *)&entries[i].ifr_addr;
        assert(ioctl(fd, SIOCGIFFLAGS, &request) == 0);
        assert(request.ifr_flags & IFF_UP);
        if (request.ifr_flags & IFF_LOOPBACK) loopback++;
        if (address->sin_addr.s_addr == inet_addr("198.18.0.2")) {
            assert(ioctl(fd, SIOCGIFMTU, &request) == 0);
            assert(request.ifr_mtu == 1500);
            configured++;
        }
    }
    assert(loopback == 1 && configured == 1);
    assert(close(fd) == 0);
    puts("PASS: native interfaces ready");
    return 0;
}
