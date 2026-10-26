/* Resolve the installed ABI under ker-run and use actual native UDP sockets. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static int (*current_time)(int64_t *, long *);
static int (*native_run)(ker_posix_loop_func, void *);
static void (*native_stop)(void);
static int64_t host_time(void)
{
    struct timespec value; CHECK(!clock_gettime(CLOCK_REALTIME, &value));
    return (int64_t)value.tv_sec * 1000000000LL + value.tv_nsec;
}
static int64_t sample(void)
{
    int64_t before = host_time(), seconds = -1; long nanoseconds = -1;
    CHECK(!current_time(&seconds, &nanoseconds));
    int64_t after = host_time();
    CHECK(seconds > 1577836800 && nanoseconds >= 0 && nanoseconds < 1000000000L);
    int64_t value = seconds * 1000000000LL + nanoseconds;
    /* Boot synchronization precedes app exec. Host observations bracket the
     * native read; allow one second of clock drift, not scheduler duration. */
    CHECK(value >= before-1000000000LL && value <= after+1000000000LL);
    return value;
}
static void datagram(unsigned family)
{
    int domain = family ? AF_INET6 : AF_INET;
    int sender = socket(domain, SOCK_DGRAM, 0), receiver = socket(domain, SOCK_DGRAM, 0);
    CHECK(sender >= 0 && receiver >= 0);
    struct sockaddr_storage address = {0};
    socklen_t size = family ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (family) {
        struct sockaddr_in6 *a = (void *)&address;
        a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback;
    } else {
        struct sockaddr_in *a = (void *)&address;
        a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    CHECK(!bind(receiver, (void *)&address, size) && !getsockname(receiver, (void *)&address, &size));
    CHECK(!connect(sender, (void *)&address, size));
    struct timeval timeout = {.tv_sec=3};
    CHECK(!setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    int64_t before = sample();
    const char *payload = family ? "native-time-ipv6" : "native-time-ipv4";
    CHECK(send(sender, payload, strlen(payload), 0) == (ssize_t)strlen(payload));
    long ns = -1; int64_t sec = -1;
    CHECK(!current_time(NULL, &ns) && ns >= 0 && ns < 1000000000L);
    CHECK(!current_time(&sec, NULL) && sec > 1577836800);
    CHECK(!current_time(NULL, NULL));
    char received[64];
    CHECK(recv(receiver, received, sizeof(received), 0) == (ssize_t)strlen(payload));
    CHECK(!memcmp(received, payload, strlen(payload)) && sample() >= before);
    CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(!close(receiver) && !close(sender));
    printf("TIME_NATIVE_FAMILY %u\n", family);
}
static int stop(void *opaque) { (void)opaque; native_stop(); return 0; }
int main(void)
{
    current_time = dlsym(RTLD_DEFAULT, "ker_posix_get_current_time");
    native_run = dlsym(RTLD_DEFAULT, "ker_posix_run");
    native_stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    CHECK(current_time && native_run && native_stop && release && release() && *release());
    int64_t first = sample();
    struct timespec delay = {.tv_nsec=2000000};
    while (nanosleep(&delay, &delay)) CHECK(errno == EINTR);
    CHECK(sample() > first);
    datagram(0); datagram(1);
    puts("TIME_SOURCE_CASE test_ff_get_current_time_null_sec");
    puts("TIME_SOURCE_CASE test_ff_get_current_time_null_nsec");
    CHECK(!native_run(stop, NULL));
    for (unsigned outputs = 0; outputs < 4; outputs++) {
        int64_t sec = 91; long ns = 92;
        CHECK(current_time(outputs & 1 ? &sec : NULL, outputs & 2 ? &ns : NULL) == -1 &&
              errno == ENETDOWN && sec == 91 && ns == 92);
    }
    CHECK(!release());
    puts("PASS: dynamic native current-time ABI, dual-stack UDP and explicit shutdown");
    return 0;
}
