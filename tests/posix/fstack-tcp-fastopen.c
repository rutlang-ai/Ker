/* Linux extension of pinned F-Stack host socket bridge scenarios. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
static void writable_without_error(int fd, int timeout_ms)
{
    struct pollfd ready = {.fd = fd, .events = POLLOUT};
    int result;
    do { result = poll(&ready, 1, timeout_ms); } while (result < 0 && errno == EINTR);
    CHECK(result == 1 && (ready.revents & POLLOUT));
    CHECK(!(ready.revents & (POLLERR | POLLHUP | POLLNVAL)));
    int error = -1; socklen_t length = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    CHECK(length == sizeof(error) && error == 0);
}
static void set_keys(int fd, unsigned char value, int backup)
{
    unsigned char key[32], actual[32];
    size_t key_length = backup ? 32 : 16;
    memset(key, value, 16);
    if (backup) memset(key + 16, 0x31, 16);
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_KEY, key, key_length) == 0);
    socklen_t length = sizeof(actual);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_KEY, actual, &length) == 0);
    CHECK(length == key_length && !memcmp(key, actual, key_length));
}
int main(int argc, char **argv)
{
    CHECK(argc == 4 || (argc == 5 && (!strcmp(argv[4], "cookies") || !strcmp(argv[4], "nonblocking") || !strcmp(argv[4], "rotation") || !strcmp(argv[4], "backup") || !strcmp(argv[4], "deferred") || !strcmp(argv[4], "cancel") || !strcmp(argv[4], "deferred-nonblocking"))));
    int deferred_nonblocking = argc == 5 && !strcmp(argv[4], "deferred-nonblocking");
    int cancel = argc == 5 && !strcmp(argv[4], "cancel");
    int deferred = deferred_nonblocking || cancel || (argc == 5 && !strcmp(argv[4], "deferred"));
    int nonblocking = argc == 5 && !strcmp(argv[4], "nonblocking");
    int backup = argc == 5 && !strcmp(argv[4], "backup");
    int rotation = backup || (argc == 5 && !strcmp(argv[4], "rotation"));
    int connections = backup ? 6 : (rotation ? 4 : (argc == 5 ? 3 : 2));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[3]))};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    if (!strcmp(argv[1], "server")) {
        int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), one = 1, queue = 4;
        CHECK(listener >= 0); timeout(listener);
        CHECK(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        CHECK(setsockopt(listener, IPPROTO_TCP, TCP_FASTOPEN, &queue, sizeof(queue)) == 0);
        if (rotation) set_keys(listener, 0x31, 0);
        int actual = -1; socklen_t length = sizeof(actual);
        CHECK(getsockopt(listener, IPPROTO_TCP, TCP_FASTOPEN, &actual, &length) == 0 && actual == queue);
        CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 4) == 0);
        printf("READY %s\n", argv[3]); fflush(stdout);
        for (int phase = 0; phase < connections; ++phase) {
            int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); CHECK(fd >= 0); timeout(fd);
            char data[sizeof(request)]; transfer(fd, data, sizeof(data), 0);
            CHECK(!memcmp(data, request, sizeof(data)));
            /* Rotate before the echo: the client cannot start phase 1 until it receives this echo. */
            if (rotation && !backup && phase == 0) set_keys(listener, 0x72, 0);
            /* Keep source A's cookie untouched while source B refreshes under B+A. */
            if (backup && phase == 1) set_keys(listener, 0x72, 1);
            /* Source A will next present its retained A cookie after this retirement. */
            if (backup && phase == 2) set_keys(listener, 0x72, 0);
            transfer(fd, data, sizeof(data), 1);
            CHECK(shutdown(fd, SHUT_WR) == 0);
            CHECK(recv(fd, data, 1, 0) == 0); CHECK(close(fd) == 0);
        }
        CHECK(close(listener) == 0);
    } else {
        CHECK(!strcmp(argv[1], "client"));
        if (cancel) ++connections; /* One attempt is closed without becoming a server stream. */
        for (int phase = 0; phase < connections; ++phase) {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0); timeout(fd);
            if (backup && phase < connections - 1) {
                struct sockaddr_in local = {.sin_family = AF_INET};
                const char *source_a, *source_b;
                if ((ntohl(address.sin_addr.s_addr) >> 24) == 127) {
                    source_a = "127.0.0.2"; source_b = "127.0.0.3";
                } else if (ntohl(address.sin_addr.s_addr) == 0xc6120001) {
                    /* Native client: the primary and VIP addresses belong to this stack. */
                    source_a = "198.18.0.2"; source_b = "198.18.0.3";
                } else {
                    /* Native server: the host Linux client uses its veth addresses. */
                    source_a = "198.18.0.1"; source_b = "198.18.0.4";
                }
                const char *source = (phase == 0 || phase == 3) ? source_a : source_b;
                CHECK(inet_pton(AF_INET, source, &local.sin_addr) == 1);
                CHECK(bind(fd, (void *)&local, sizeof(local)) == 0);
            }
            if (deferred && phase < connections - 1) {
                int enabled = 1, actual = 0; socklen_t length = sizeof(actual);
                CHECK(setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &enabled, sizeof(enabled)) == 0);
                CHECK(getsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &actual, &length) == 0);
                CHECK(length == sizeof(actual) && actual == enabled);
                int flags = fcntl(fd, F_GETFL); CHECK(flags >= 0);
                if (deferred_nonblocking) CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
                int connected = connect(fd, (void *)&address, sizeof(address));
                if (deferred_nonblocking && phase == 0) {
                    CHECK(connected == -1 && errno == EINPROGRESS);
                    writable_without_error(fd, 8000);
                } else {
                    CHECK(connected == 0);
                    if (deferred_nonblocking) writable_without_error(fd, 0);
                }
                if (phase == 1 || (cancel && phase == 2)) {
                    struct tcp_info info = {0}; length = sizeof(info);
                    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0);
                    CHECK(info.tcpi_state == TCP_SYN_SENT);
                    if (deferred_nonblocking) {
                        int actual_flags = fcntl(fd, F_GETFL);
                        CHECK(actual_flags >= 0 && (actual_flags & O_NONBLOCK));
                    }
                    struct sockaddr_in local = {0}; length = sizeof(local);
                    CHECK(getsockname(fd, (void *)&local, &length) == 0);
                    if (cancel && phase == 1) {
                        CHECK(close(fd) == 0);
                        CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
                        printf("CANCELLED %u\n", ntohs(local.sin_port)); fflush(stdout);
                        CHECK(getchar() == 'C');
                        continue;
                    }
                    printf("DEFERRED %u\n", ntohs(local.sin_port)); fflush(stdout);
                    CHECK(getchar() == 'W');
                }
                if (deferred_nonblocking) CHECK(fcntl(fd, F_SETFL, flags) == 0);
                transfer(fd, (void *)request, sizeof(request), 1);
                if (deferred_nonblocking && phase == 1)
                    puts("PASS: nonblocking connect EINPROGRESS without cookie; cached connect returns zero and POLLOUT before SYN");
            } else if (phase < connections - 1) {
                int flags = fcntl(fd, F_GETFL); CHECK(flags >= 0);
                if (nonblocking) CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
                ssize_t sent = sendto(fd, request, sizeof(request), MSG_FASTOPEN | MSG_NOSIGNAL,
                                     (void *)&address, sizeof(address));
                if (nonblocking) {
                    if (phase == 0) CHECK(sent == -1 && errno == EINPROGRESS);
                    else CHECK(sent > 0 && sent <= (ssize_t)sizeof(request));
                    writable_without_error(fd, 8000);
                    CHECK(fcntl(fd, F_SETFL, flags) == 0);
                    if (phase == 0) {
                        sent = 0;
                        puts("PASS: nonblocking no-cookie EINPROGRESS, POLLOUT and SO_ERROR=0; resend required");
                    } else puts("PASS: nonblocking cached-cookie send accepted");
                } else CHECK(sent > 0 && sent <= (ssize_t)sizeof(request));
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
