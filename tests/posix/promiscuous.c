#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static const char payload[] = "native-mac-only";
static int endpoint(int type, int port)
{
    int fd = socket(AF_INET, type, 0), one = 1;
    struct timeval timeout = {.tv_sec = 8};
    CHECK(fd >= 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &local.sin_addr) == 1);
    CHECK(bind(fd, (void *)&local, sizeof(local)) == 0);
    return fd;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    int port = atoi(argv[1]);
    int udp = endpoint(SOCK_DGRAM, port), listener = endpoint(SOCK_STREAM, port);
    CHECK(listen(listener, 1) == 0);
    const char *mac = getenv("LKL_HIJACK_NET_MAC");
    CHECK(mac != NULL);
    printf("READY %s\n", mac); fflush(stdout);
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    char buffer[256];
    /* Foreign-MAC probes precede this valid datagram. They must never enter
     * a normal Linux UDP socket, including when the PMD is promiscuous. */
    CHECK(recvfrom(udp, buffer, sizeof(buffer), 0, (void *)&peer, &length) == sizeof(payload));
    CHECK(!memcmp(buffer, payload, sizeof(payload)));
    CHECK(sendto(udp, buffer, sizeof(payload), 0, (void *)&peer, length) == sizeof(payload));
    CHECK(close(udp) == 0);
    int accepted = accept(listener, NULL, NULL);
    CHECK(accepted >= 0);
    CHECK(recv(accepted, buffer, sizeof(payload), MSG_WAITALL) == sizeof(payload));
    CHECK(!memcmp(buffer, payload, sizeof(payload)));
    CHECK(send(accepted, buffer, sizeof(payload), MSG_NOSIGNAL) == sizeof(payload));
    CHECK(close(accepted) == 0 && close(listener) == 0);
    puts("PASS: original Linux TCP/UDP MAC admission");
    return 0;
}
