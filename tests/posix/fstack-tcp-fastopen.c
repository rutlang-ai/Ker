/* Linux extension of pinned F-Stack host socket bridge scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static const char request[] = "original-linux-fastopen";
static void timeout(int fd)
{
    struct timeval value = {.tv_sec = 8};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value)) == 0);
}
static void transfer(int fd, void *buffer, size_t length, int sending)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = sending ? send(fd, (char *)buffer + done, length - done, MSG_NOSIGNAL) :
                                 recv(fd, (char *)buffer + done, length - done, 0);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0); done += (size_t)count;
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 4 || (argc == 5 && !strcmp(argv[4], "cookies")));
    int connections = argc == 5 ? 3 : 2;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[3]))};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    if (!strcmp(argv[1], "server")) {
        int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), one = 1, queue = 4;
        CHECK(listener >= 0); timeout(listener);
        CHECK(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        CHECK(setsockopt(listener, IPPROTO_TCP, TCP_FASTOPEN, &queue, sizeof(queue)) == 0);
        int actual = -1; socklen_t length = sizeof(actual);
        CHECK(getsockopt(listener, IPPROTO_TCP, TCP_FASTOPEN, &actual, &length) == 0 && actual == queue);
        CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 4) == 0);
        printf("READY %s\n", argv[3]); fflush(stdout);
        for (int phase = 0; phase < connections; ++phase) {
            int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);
            char data[sizeof(request)]; transfer(fd, data, sizeof(data), 0);
            CHECK(!memcmp(data, request, sizeof(data)));
            transfer(fd, data, sizeof(data), 1);
            CHECK(shutdown(fd, SHUT_WR) == 0);
            CHECK(recv(fd, data, 1, 0) == 0); CHECK(close(fd) == 0);
        }
        CHECK(close(listener) == 0);
    } else {
        CHECK(!strcmp(argv[1], "client"));
        for (int phase = 0; phase < connections; ++phase) {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0); timeout(fd);
            if (phase < connections - 1) {
                ssize_t sent = sendto(fd, request, sizeof(request), MSG_FASTOPEN | MSG_NOSIGNAL,
                                     (void *)&address, sizeof(address));
                CHECK(sent > 0 && sent <= (ssize_t)sizeof(request));
                if (sent < (ssize_t)sizeof(request))
                    transfer(fd, (char *)request + sent, sizeof(request) - (size_t)sent, 1);
            } else {
                CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
                transfer(fd, (void *)request, sizeof(request), 1);
            }
            struct sockaddr_in peer = {0}; socklen_t length = sizeof(peer);
            CHECK(getpeername(fd, (void *)&peer, &length) == 0 && length == sizeof(peer));
            CHECK(peer.sin_addr.s_addr == address.sin_addr.s_addr && peer.sin_port == address.sin_port);
            char data[sizeof(request)]; transfer(fd, data, sizeof(data), 0);
            CHECK(!memcmp(data, request, sizeof(data)));
            CHECK(recv(fd, data, 1, 0) == 0);
            CHECK(shutdown(fd, SHUT_WR) == 0 && close(fd) == 0);
        }
    }
    puts("PASS: exact Fast Open and ordinary-connect streams, peer identity and bidirectional EOF");
    return 0;
}
