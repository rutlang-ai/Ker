#define _GNU_SOURCE
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { perror(#x); exit(1); } } while (0)
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    const int levels[] = {IPPROTO_IP, IPPROTO_TCP, IPPROTO_TCP, IPPROTO_TCP, IPPROTO_TCP};
    const int options[] = {IP_TTL, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT, TCP_SYNCNT};
    const int defaults[] = {64, 7200, 75, 9, 6};
    const int configured[] = {atoi(argv[1]), 42, 7, 4, 3};
    const int *expected = atoi(argv[3]) ? defaults : configured;
    for (unsigned int i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        int value = -1;
        socklen_t size = sizeof(value);
        CHECK(getsockopt(fd, levels[i], options[i], &value, &size) == 0);
        CHECK(size == sizeof(value) && value == expected[i]);
    }
    CHECK(close(fd) == 0);
    FILE *marker = fopen(argv[2], "w");
    CHECK(marker != NULL);
    CHECK(fputs("PASS: five native network sysctls effective\n", marker) >= 0);
    CHECK(fclose(marker) == 0);
    puts("PASS: five native network sysctls effective");
    return 0;
}
