/* A caller explicitly selects and binds its source. Every socket operation
 * below is consumed by the original Linux runtime under ker-run. */
#define _GNU_SOURCE
#include <ker/address-policy.h>
#include <ker/posix.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static unsigned calls;
static uint16_t expected_port;
static int deny;
static int choose_source(uint16_t family, void *destination, uint16_t port, void *source)
{
    CHECK(port == expected_port && destination && source);
    ++calls;
    if (deny) return EACCES;
    if (family == AF_INET) {
        CHECK(((struct in_addr *)destination)->s_addr == htonl(INADDR_LOOPBACK));
        CHECK(inet_pton(AF_INET, "127.0.0.2", source) == 1);
    } else {
        CHECK(family == AF_INET6 && !memcmp(destination, &in6addr_loopback, 16));
        memcpy(source, &in6addr_loopback, 16);
    }
    return 0;
}
static int open_client(int family, const struct sockaddr_storage *remote, socklen_t size)
{
    struct sockaddr_storage local = {0};
    local.ss_family = (sa_family_t)family;
    void *destination, *source;
    uint16_t port;
    if (family == AF_INET) {
        destination = &((struct sockaddr_in *)(void *)remote)->sin_addr;
        source = &((struct sockaddr_in *)(void *)&local)->sin_addr;
        port = ((const struct sockaddr_in *)(const void *)remote)->sin_port;
    } else {
        destination = &((struct sockaddr_in6 *)(void *)remote)->sin6_addr;
        source = &((struct sockaddr_in6 *)(void *)&local)->sin6_addr;
        port = ((const struct sockaddr_in6 *)(const void *)remote)->sin6_port;
    }
    int error = ker_address_policy_select(family == AF_INET ? 2 : 28, destination, port, source);
    if (error) { errno = error; return -1; }
    int fd = socket(family, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    /* Explicit caller policy: bind(port0), then Linux chooses the ephemeral
     * port and owns handshake, delivery, ACK and teardown. */
    CHECK(!bind(fd, (const void *)&local, size));
    CHECK(!connect(fd, (const void *)remote, size));
    return fd;
}
static void exchange(int family, int enabled)
{
    struct sockaddr_storage remote = {0}, local = {0}, peer = {0};
    socklen_t size = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    remote.ss_family = (sa_family_t)family;
    if (family == AF_INET) ((struct sockaddr_in *)(void *)&remote)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    else ((struct sockaddr_in6 *)(void *)&remote)->sin6_addr = in6addr_loopback;
    int listener = socket(family, SOCK_STREAM, 0); CHECK(listener >= 0);
    CHECK(!bind(listener, (void *)&remote, size) && !listen(listener, 2));
    CHECK(!getsockname(listener, (void *)&remote, &size));
    expected_port = family == AF_INET ? ((struct sockaddr_in *)(void *)&remote)->sin_port :
        ((struct sockaddr_in6 *)(void *)&remote)->sin6_port;
    unsigned before = calls;
    if (enabled) {
        deny = 1;
        CHECK(open_client(family, &remote, size) == -1 && errno == EACCES);
        deny = 0;
        CHECK(calls == before+1);
    }
    int client = open_client(family, &remote, size); CHECK(client >= 0);
    CHECK(calls == before+(enabled ? 2U : 0U));
    int accepted = accept(listener, (void *)&peer, &size); CHECK(accepted >= 0);
    CHECK(!getsockname(client, (void *)&local, &size));
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&local, *b = (void *)&peer;
        CHECK(a->sin_port && a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr);
        CHECK(a->sin_addr.s_addr == htonl(enabled ? 0x7f000002U : INADDR_LOOPBACK));
    } else {
        struct sockaddr_in6 *a = (void *)&local, *b = (void *)&peer;
        CHECK(a->sin6_port && a->sin6_port == b->sin6_port);
        CHECK(!memcmp(&a->sin6_addr, &b->sin6_addr, 16) && !memcmp(&a->sin6_addr, &in6addr_loopback, 16));
    }
    struct timeval timeout = {.tv_sec=3};
    CHECK(!setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    CHECK(!setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    char payload[64], data[64];
    int length = snprintf(payload, sizeof(payload), "original-linux-address-policy-%d-%d", family, enabled);
    CHECK(length > 0 && (size_t)length < sizeof(payload));
    CHECK(send(client, payload, (size_t)length, 0) == length);
    CHECK(recv(accepted, data, (size_t)length, MSG_WAITALL) == length && !memcmp(data, payload, (size_t)length));
    CHECK(send(accepted, payload, (size_t)length, 0) == length);
    CHECK(recv(client, data, (size_t)length, MSG_WAITALL) == length && !memcmp(data, payload, (size_t)length));
    CHECK(!shutdown(client, SHUT_WR));
    CHECK(recv(accepted, data, 1, 0) == 0);
    CHECK(!close(client) && !close(accepted) && !close(listener));
    printf("ADDRESS_NATIVE_EXCHANGE %d %d\n", family, enabled);
}
static int (*native_run)(ker_posix_loop_func, void *);
static void (*native_stop)(void);
static int stop(void *opaque) { (void)opaque; native_stop(); return 0; }
int main(void)
{
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    native_run = dlsym(RTLD_DEFAULT, "ker_posix_run");
    native_stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    CHECK(release && release() && *release() && native_run && native_stop);
    printf("ADDRESS_NATIVE_KERNEL %s\n", release());
    CHECK(!ker_address_policy_register(NULL));
    exchange(AF_INET, 0); exchange(AF_INET6, 0);
    CHECK(!ker_address_policy_register(choose_source));
    exchange(AF_INET, 1); exchange(AF_INET6, 1);
    CHECK(!ker_address_policy_register(NULL));
    exchange(AF_INET, 0); exchange(AF_INET6, 0);
    CHECK(calls == 4);
    CHECK(!native_run(stop, NULL));
    puts("PASS: original Linux source selection, exact dual-stack payloads and unregister recovery");
    return 0;
}
