/* Negotiate ECN in the actual TCP implementation and inspect TCP_INFO. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int passive = !strcmp(argv[1], "server");
    CHECK(passive || !strcmp(argv[1], "client"));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[3]))};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 5};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    if (passive) {
        int one = 1;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 1) == 0);
        printf("READY %s\n", argv[3]); fflush(stdout);
        int child = accept4(fd, NULL, NULL, SOCK_CLOEXEC); CHECK(child >= 0);
        CHECK(close(fd) == 0); fd = child;
    } else CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    struct tcp_info info = {0}; socklen_t length = sizeof(info);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0);
    CHECK(!!(info.tcpi_options & TCPI_OPT_ECN) == atoi(argv[4]));
    char byte = 'e';
    if (!passive) CHECK(send(fd, &byte, 1, MSG_NOSIGNAL) == 1);
    CHECK(recv(fd, &byte, 1, MSG_WAITALL) == 1 && byte == 'e');
    if (passive) CHECK(send(fd, &byte, 1, MSG_NOSIGNAL) == 1);
    CHECK(close(fd) == 0);
    printf("PASS: TCP_INFO ECN=%s and payload verified\n", argv[4]);
    return 0;
}
