#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "owner request runtime:%d: %s (errno=%d: %s)\n", \
        __LINE__, #x, errno, strerror(errno)); return 1; } } while (0)
#define WAIT_NS UINT64_C(5000000000)

extern int ker_ff_owner_requests_test_snapshot(uint32_t mark, uint64_t *count);
extern int ker_ff_owner_requests_test_syncookies(int value);
extern int ker_ff_owner_requests_test_fastopen(void);

static uint64_t now_ns(void)
{
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int path(char *out, size_t size, const char *suffix)
{
    const char *prefix = getenv("KER_C13_CONTROL");
    if (!prefix || !*prefix) return -EINVAL;
    int n = snprintf(out, size, "%s.%s", prefix, suffix);
    return n < 0 || (size_t)n >= size ? -ENAMETOOLONG : 0;
}

static int write_state(const char *state, uint64_t count)
{
    char file_path[512];
    int status = path(file_path, sizeof(file_path), "state");
    if (status) return status;
    FILE *file = fopen(file_path, "w");
    if (!file) return -errno;
    int n = fprintf(file, "%s count=%llu\n", state,
        (unsigned long long)count);
    if (fclose(file) && n >= 0) return -errno;
    return n < 0 ? -EIO : 0;
}

static int wait_command(const char *expected)
{
    char file_path[512];
    int status = path(file_path, sizeof(file_path), "command");
    if (status) return status;
    uint64_t start = now_ns();
    if (!start) return -EIO;
    for (;;) {
        FILE *file = fopen(file_path, "r");
        if (file) {
            char command[64] = {0};
            int found = fscanf(file, "%63s", command) == 1;
            fclose(file);
            if (found && !strcmp(command, expected)) {
                (void)unlink(file_path);
                return 0;
            }
        }
        uint64_t now = now_ns();
        if (!now || now < start || now - start >= WAIT_NS) return -ETIMEDOUT;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
}

static int query_expect(uint32_t mark, uint64_t expected)
{
    uint64_t count = UINT64_MAX;
    int status = ker_ff_owner_requests_test_snapshot(mark, &count);
    if (status) {
        fprintf(stderr, "request query failed: %d (%s)\n", status,
            status < 0 ? strerror(-status) : "unexpected status");
        return status;
    }
    if (count != expected) {
        fprintf(stderr, "request query count=%llu expected=%llu\n",
            (unsigned long long)count, (unsigned long long)expected);
        return -EPROTO;
    }
    return 0;
}

int main(void)
{
    const char *mark_text = getenv("KER_C13_MARK");
    const char *port_text = getenv("KER_C13_PORT");
    if (!mark_text || !port_text) return 2;
    char *end = NULL;
    unsigned long mark = strtoul(mark_text, &end, 0);
    if (!*mark_text || *end || !mark || mark > UINT32_MAX) return 2;
    unsigned long port = strtoul(port_text, &end, 10);
    if (!*port_text || *end || !port || port > UINT16_MAX) return 2;
    REQUIRE(ker_ff_owner_requests_test_fastopen() == 0);

    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    REQUIRE(listener >= 0);
    int reuse = 1;
    REQUIRE(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
    uint32_t owner_mark = (uint32_t)mark;
    REQUIRE(setsockopt(listener, SOL_SOCKET, SO_MARK, &owner_mark,
        sizeof(owner_mark)) == 0);
    int fastopen_queue = 16;
    REQUIRE(setsockopt(listener, IPPROTO_TCP, TCP_FASTOPEN, &fastopen_queue,
        sizeof(fastopen_queue)) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_port = htons((uint16_t)port)};
    REQUIRE(inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) == 1);
    REQUIRE(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    REQUIRE(listen(listener, 16) == 0);
    REQUIRE(write_state("READY", 0) == 0);

    REQUIRE(wait_command("QUERY1") == 0);
    REQUIRE(query_expect(owner_mark, 1) == 0);
    REQUIRE(write_state("SYN_REQUEST", 1) == 0);
    REQUIRE(wait_command("ACCEPT1") == 0);
    int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    REQUIRE(accepted >= 0);
    REQUIRE(query_expect(owner_mark, 0) == 0);
    REQUIRE(write_state("FIRST_ACCEPTED", 0) == 0);
    REQUIRE(close(accepted) == 0);
    REQUIRE(wait_command("NEXT1") == 0);

    REQUIRE(write_state("TFO_READY", 0) == 0);
    REQUIRE(wait_command("QUERY2") == 0);
    REQUIRE(query_expect(owner_mark, 0) == 0);
    REQUIRE(write_state("TFO_SYN", 0) == 0);
    REQUIRE(wait_command("ACCEPT2") == 0);
    accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    REQUIRE(accepted >= 0);
    REQUIRE(query_expect(owner_mark, 0) == 0);
    REQUIRE(write_state("TFO_ACCEPTED", 0) == 0);
    REQUIRE(close(accepted) == 0);
    REQUIRE(wait_command("NEXT2") == 0);

    REQUIRE(ker_ff_owner_requests_test_syncookies(2) == 0);
    REQUIRE(write_state("COOKIE_READY", 0) == 0);
    REQUIRE(wait_command("QUERY3") == 0);
    REQUIRE(query_expect(owner_mark, 0) == 0);
    REQUIRE(write_state("COOKIE_SYN", 0) == 0);
    REQUIRE(wait_command("ACCEPT3") == 0);
    accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    REQUIRE(accepted >= 0);
    REQUIRE(query_expect(owner_mark, 0) == 0);
    REQUIRE(write_state("COOKIE_ACCEPTED", 0) == 0);
    REQUIRE(close(accepted) == 0);
    REQUIRE(wait_command("NEXT3") == 0);
    REQUIRE(ker_ff_owner_requests_test_syncookies(0) == 0);

    int listener6 = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    REQUIRE(listener6 >= 0);
    REQUIRE(setsockopt(listener6, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
    REQUIRE(setsockopt(listener6, SOL_SOCKET, SO_MARK, &owner_mark,
        sizeof(owner_mark)) == 0);
    int v6only = 1;
    REQUIRE(setsockopt(listener6, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
        sizeof(v6only)) == 0);
    struct sockaddr_in6 address6 = {.sin6_family = AF_INET6,
        .sin6_port = htons((uint16_t)(port + 1))};
    REQUIRE(inet_pton(AF_INET6, "2001:db8::2", &address6.sin6_addr) == 1);
    REQUIRE(bind(listener6, (struct sockaddr *)&address6, sizeof(address6)) == 0);
    REQUIRE(listen(listener6, 16) == 0);
    REQUIRE(write_state("IPV6_READY", 0) == 0);
    REQUIRE(wait_command("QUERY4") == 0);
    REQUIRE(query_expect(owner_mark, 1) == 0);
    REQUIRE(write_state("IPV6_SYN_REQUEST", 1) == 0);
    REQUIRE(wait_command("ACCEPT4") == 0);
    accepted = accept4(listener6, NULL, NULL, SOCK_CLOEXEC);
    REQUIRE(accepted >= 0);
    REQUIRE(query_expect(owner_mark, 0) == 0);
    REQUIRE(write_state("IPV6_ACCEPTED", 0) == 0);
    REQUIRE(wait_command("NEXT4") == 0);
    REQUIRE(close(accepted) == 0);
    REQUIRE(close(listener6) == 0);

    REQUIRE(close(listener) == 0);
    REQUIRE(write_state("DONE", 0) == 0);
    return 0;
}
