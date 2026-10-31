/* Readiness tags belong to this caller; Linux owns all socket behavior. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include "host-readiness.h"
#include "host-readiness-native.h"
enum { LISTENER = 101, DATAGRAM = 102, STREAM = 103, STALE = 104 };
static void watch(int epfd, int fd, int tag)
{
    example_host_kqueue_ctl(epfd, 0, fd, STALE, 0);
    example_host_kqueue_ctl(epfd, 0, fd, tag, 0);
}
int main(int argc, char **argv)
{
    REQUIRE(argc == 2);
    char *end;
    long port = strtol(argv[1], &end, 10);
    REQUIRE(*argv[1] && !*end && port > 0 && port <= 65535);
    example_require_native();
    int epfd = example_host_epoll_create1(0);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    int udp = socket(AF_INET, SOCK_DGRAM, 0), peer = -1;
    REQUIRE(epfd >= 0 && tcp >= 0 && udp >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    REQUIRE(bind(tcp, (void *)&address, sizeof(address)) == 0 && listen(tcp, 1) == 0);
    REQUIRE(bind(udp, (void *)&address, sizeof(address)) == 0);
    watch(epfd, tcp, LISTENER);
    watch(epfd, udp, DATAGRAM);
    puts("READY host-readiness"); fflush(stdout);
    int got_udp = 0, got_tcp = 0;
    char stream[128]; size_t used = 0;
    struct timespec pause = {.tv_nsec = 1000000};
    for (unsigned tries = 0; tries < 10000 && !(got_udp && got_tcp); ++tries) {
        int triples[12], count = example_host_kqueue_poll(epfd, triples, 4);
        REQUIRE(count >= 0 && count <= 4);
        if (!count) { nanosleep(&pause, NULL); continue; }
        for (int i = 0; i < count; ++i) {
            int tag = triples[i * 3];
            REQUIRE(triples[i * 3 + 1] == 0 && triples[i * 3 + 2] == 0);
            if (tag == LISTENER) {
                REQUIRE(peer < 0);
                peer = accept(tcp, NULL, NULL); REQUIRE(peer >= 0);
                example_host_kqueue_ctl(epfd, 1, tcp, LISTENER, 0);
                watch(epfd, peer, STREAM);
            } else if (tag == DATAGRAM) {
                char bytes[128]; struct sockaddr_in sender; socklen_t length = sizeof(sender);
                ssize_t size = recvfrom(udp, bytes, sizeof(bytes), 0, (void *)&sender, &length);
                REQUIRE(size > 0 && sendto(udp, bytes, (size_t)size, 0, (void *)&sender, length) == size);
                got_udp = 1;
                example_host_kqueue_ctl(epfd, 1, udp, DATAGRAM, 0);
            } else {
                REQUIRE(tag == STREAM && peer >= 0 && used < sizeof(stream));
                ssize_t size = recv(peer, stream + used, sizeof(stream) - used, 0);
                REQUIRE(size > 0); used += (size_t)size;
                if (!memchr(stream, '\0', used)) continue;
                size_t sent = 0;
                while (sent < used) {
                    ssize_t size_out = send(peer, stream + sent, used - sent, 0);
                    REQUIRE(size_out > 0); sent += (size_t)size_out;
                }
                got_tcp = 1;
                example_host_kqueue_ctl(epfd, 1, peer, STREAM, 0);
            }
        }
    }
    REQUIRE(got_udp && got_tcp);
    REQUIRE(example_host_close(peer) == 0 && example_host_close(tcp) == 0);
    REQUIRE(example_host_close(udp) == 0 && example_host_close(epfd) == 0);
    example_finish_native();
    puts("PASS: native TCP/UDP consumed remapped readiness tags");
    return 0;
}
