#define _GNU_SOURCE
#include "lifecycle.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <lkl.h>
#include <lkl_host.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static long milliseconds(void)
{
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static void queued_family(int family)
{
    long server = lkl_sys_socket(family, LKL_SOCK_STREAM, 0); CHECK(server >= 0);
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in6 v6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    void *address = family == AF_INET ? (void *)&v4 : (void *)&v6;
    int size = family == AF_INET ? sizeof(v4) : sizeof(v6);
    int buffer = 4096;
    CHECK(lkl_sys_setsockopt(server, LKL_SOL_SOCKET, LKL_SO_RCVBUF, (void *)&buffer, sizeof(buffer)) == 0);
    CHECK(lkl_sys_bind(server, address, size) == 0);
    CHECK(lkl_sys_listen(server, 1) == 0);
    CHECK(lkl_sys_getsockname(server, address, &size) == 0);
    long sender = lkl_sys_socket(family, LKL_SOCK_STREAM, 0); CHECK(sender >= 0);
    CHECK(lkl_sys_setsockopt(sender, LKL_SOL_SOCKET, LKL_SO_SNDBUF, (void *)&buffer, sizeof(buffer)) == 0);
    CHECK(lkl_sys_connect(sender, address, size) == 0);
    long receiver = lkl_sys_accept(server, NULL, NULL); CHECK(receiver >= 0);
    unsigned char bytes[32768]; memset(bytes, 0x6d, sizeof(bytes));
    size_t sent = 0;
    for (;;) {
        long result = lkl_sys_sendto(sender, bytes, sizeof(bytes), LKL_MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
        if (result == -LKL_EAGAIN) break;
        CHECK(result > 0); sent += result; CHECK(sent < 8 * 1024 * 1024);
    }
    CHECK(sent > 0);
    /* A full send queue must be visible even when it belongs only to tcp6. */
    CHECK(ker_native_drain(0) == -ETIMEDOUT);
    size_t received = 0; long deadline = milliseconds() + 5000;
    while (received < sent) {
        long result = lkl_sys_recvfrom(receiver, bytes, sizeof(bytes), LKL_MSG_DONTWAIT, NULL, NULL);
        if (result == -LKL_EAGAIN) {
            CHECK(milliseconds() < deadline);
            struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL); continue;
        }
        CHECK(result > 0);
        for (long i = 0; i < result; ++i) CHECK(bytes[i] == 0x6d);
        received += result;
    }
    CHECK(ker_native_drain(1000) == 0);
    CHECK(lkl_sys_close(sender) == 0); CHECK(lkl_sys_close(receiver) == 0);
    CHECK(lkl_sys_close(server) == 0);
    printf("PASS: original Linux IPv%d queued bytes block drain, then recover\n", family == AF_INET ? 4 : 6);
}
int main(void)
{
    lkl_host_ops.print = NULL;
    CHECK(lkl_init(&lkl_host_ops) == 0);
    CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
    CHECK(lkl_mount_fs("proc") == 0);
    CHECK(lkl_if_up(1) == 0);
    CHECK(ker_native_drain(0) == 0);
    queued_family(AF_INET); queued_family(AF_INET6);
    CHECK(lkl_sys_halt() == 0); lkl_cleanup();
    return 0;
}
