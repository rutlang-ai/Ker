/* Readiness tags belong to this caller; Linux owns all socket behavior. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/mman.h>
#include <time.h>
#include "host-readiness.h"
#include "host-readiness-native.h"
#include "host-mapping.h"
#include "caller-clock.h"
enum { LISTENER = 101, DATAGRAM = 102, STREAM = 103, STALE = 104 };
static void watch(int epfd, int fd, int tag)
{
    example_host_kqueue_ctl(epfd, 0, fd, STALE, 0);
    example_host_kqueue_ctl(epfd, 0, fd, tag, 0);
}
static uint64_t now_ns(void)
{
    struct timespec now;
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}
int main(int argc, char **argv)
{
    REQUIRE(argc == 2 || argc == 3);
    char *end;
    long port = strtol(argv[1], &end, 10);
    REQUIRE(*argv[1] && !*end && port > 0 && port <= 65535);
    example_require_native();
    unsigned long frequency = 1000;
    if (argc == 3) {
        errno = 0;
        frequency = strtoul(argv[2], &end, 10);
        REQUIRE(*argv[2] && !*end && errno == 0 && frequency <= UINT_MAX);
    }
    /* Nanosecond CLOCK_MONOTONIC ticks, independent of TSC/EAL frequency. */
    uint64_t interval_ns = example_caller_interval_ticks(UINT64_C(1000000000), (unsigned)frequency);
    if (!interval_ns) {
        fputs("Unsupported caller poll frequency\n", stderr);
        example_finish_native();
        return 2;
    }
    /* Use the caller's original fail-stop allocation policy for network data. */
    unsigned char *mapping = example_host_mmap(NULL, 4096, ff_PROT_READ | ff_PROT_WRITE,
        ff_MAP_SHARED | ff_MAP_ANON, -1, 0);
    for (unsigned i = 0; i < 4096; ++i) REQUIRE(mapping[i] == 0);
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
    enum { BUFFER_SIZE = 128 };
    char *stream = (char *)mapping;
    size_t used = 0;
    struct timespec pause = {.tv_sec = (time_t)(interval_ns / UINT64_C(1000000000)),
                             .tv_nsec = (long)(interval_ns % UINT64_C(1000000000))};
    uint64_t waited_ns = 0, waits = 0, started = now_ns();
    for (unsigned tries = 0; tries < 10000 && !(got_udp && got_tcp); ++tries) {
        REQUIRE(now_ns() - started < UINT64_C(10000000000));
        uint64_t before = now_ns();
        struct timespec remaining = pause;
        while (nanosleep(&remaining, &remaining) != 0) REQUIRE(errno == EINTR);
        waited_ns += now_ns() - before;
        ++waits;
        int triples[12], count = example_host_kqueue_poll(epfd, triples, 4);
        REQUIRE(count >= 0 && count <= 4);
        if (!count) continue;
        for (int i = 0; i < count; ++i) {
            int tag = triples[i * 3];
            REQUIRE(triples[i * 3 + 1] == 0 && triples[i * 3 + 2] == 0);
            if (tag == LISTENER) {
                REQUIRE(peer < 0);
                peer = accept(tcp, NULL, NULL); REQUIRE(peer >= 0);
                example_host_kqueue_ctl(epfd, 1, tcp, LISTENER, 0);
                watch(epfd, peer, STREAM);
            } else if (tag == DATAGRAM) {
                char *bytes = (char *)mapping + 2048;
                struct sockaddr_in sender; socklen_t length = sizeof(sender);
                ssize_t size = recvfrom(udp, bytes, BUFFER_SIZE, 0, (void *)&sender, &length);
                REQUIRE(size > 0 && sendto(udp, bytes, (size_t)size, 0, (void *)&sender, length) == size);
                got_udp = 1;
                example_host_kqueue_ctl(epfd, 1, udp, DATAGRAM, 0);
            } else {
                REQUIRE(tag == STREAM && peer >= 0 && used < BUFFER_SIZE);
                ssize_t size = recv(peer, stream + used, BUFFER_SIZE - used, 0);
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
    printf("CALLER_CADENCE interval_ns=%" PRIu64 " waits=%" PRIu64 " waited_ns=%" PRIu64 "\n",
           interval_ns, waits, waited_ns);
    REQUIRE(example_host_close(peer) == 0 && example_host_close(tcp) == 0);
    REQUIRE(example_host_close(udp) == 0 && example_host_close(epfd) == 0);
    REQUIRE(example_host_munmap(mapping, 4096) == 0);
    unsigned char resident;
    errno = 0;
    REQUIRE(mincore(mapping, 4096, &resident) == -1 && errno == ENOMEM);
    puts("HOST_MAPPING_BUFFER_RECLAIMED");
    example_finish_native();
    puts("PASS: native TCP/UDP consumed remapped readiness tags");
    return 0;
}
