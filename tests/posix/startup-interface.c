/* Inspect the actual imported Linux interfaces after constructor startup. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static void realtime_seconds(void)
{
    int (*current_time)(int64_t *, long *) = dlsym(RTLD_DEFAULT, "ker_posix_get_current_time");
    CHECK(current_time);
    struct timespec before, after;
    int64_t seconds = -1;
    CHECK(clock_gettime(CLOCK_REALTIME, &before) == 0);
    CHECK(current_time(&seconds, NULL) == 0);
    CHECK(clock_gettime(CLOCK_REALTIME, &after) == 0);
    CHECK(seconds > 1577836800 && seconds >= before.tv_sec - 1 && seconds <= after.tv_sec + 1);
    puts("PASS: native realtime seconds available to the application");
}

int main(int argc, char **argv)
{
    int verify_realtime = argc == 3 && !strcmp(argv[2], "--check-realtime");
    CHECK(argc == 2 || verify_realtime);
    int marker = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(marker >= 0);
    CHECK(close(marker) == 0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    struct ifreq entries[16];
    struct ifconf list = {.ifc_len = sizeof(entries), .ifc_req = entries};
    CHECK(ioctl(fd, SIOCGIFCONF, &list) == 0);
    int loopback = 0, configured = 0;
    for (int i = 0; i < list.ifc_len / (int)sizeof(entries[0]); i++) {
        struct ifreq request = entries[i];
        struct sockaddr_in *address = (struct sockaddr_in *)&entries[i].ifr_addr;
        CHECK(ioctl(fd, SIOCGIFFLAGS, &request) == 0);
        CHECK(request.ifr_flags & IFF_UP);
        if (request.ifr_flags & IFF_LOOPBACK) loopback++;
        if (address->sin_addr.s_addr == inet_addr("198.18.0.2")) {
            CHECK(ioctl(fd, SIOCGIFMTU, &request) == 0);
            CHECK(request.ifr_mtu == 1500);
            configured++;
        }
    }
    CHECK(loopback == 1 && configured == 1);
    CHECK(close(fd) == 0);
    if (verify_realtime) realtime_seconds();
    puts("PASS: native interfaces ready");
    return 0;
}
