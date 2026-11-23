/* Resolve the installed ABI under ker-run and use actual native UDP sockets. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
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
static void datagram(unsigned family, unsigned reader, unsigned round)
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
    char payload[64];
    int length = snprintf(payload, sizeof(payload), "native-time-ipv%u-reader%u-round%u",
                          family ? 6 : 4, reader, round);
    CHECK(length > 0 && (size_t)length < sizeof(payload));
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
#define READERS 4U
#define ROUNDS 8U
static pthread_barrier_t reader_barrier;
static void synchronize(void)
{
    int result = pthread_barrier_wait(&reader_barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *parallel_reader(void *opaque)
{
    unsigned id = *(unsigned *)opaque;
    synchronize();
    for (unsigned round = 0; round < ROUNDS; round++) {
        datagram(0, id, round);
        datagram(1, id, round);
    }
    int expected = id & 1 ? E2BIG : ERANGE;
    errno = expected;
    synchronize();
    CHECK(errno == expected);
    printf("TIME_NATIVE_READER %u\n", id);
    return opaque;
}
static void parallel(void)
{
    unsigned ids[READERS]; pthread_t threads[READERS];
    CHECK(!pthread_barrier_init(&reader_barrier, NULL, READERS));
    for (unsigned i = 0; i < READERS; i++) {
        ids[i] = i;
        CHECK(!pthread_create(&threads[i], NULL, parallel_reader, &ids[i]));
    }
    for (unsigned i = 0; i < READERS; i++) {
        void *result;
        CHECK(!pthread_join(threads[i], &result) && result == &ids[i]);
    }
    CHECK(!pthread_barrier_destroy(&reader_barrier));
}
int main(int argc, char **argv)
{
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--parallel")));
    current_time = dlsym(RTLD_DEFAULT, "ker_posix_get_current_time");
    native_run = dlsym(RTLD_DEFAULT, "ker_posix_run");
    native_stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    CHECK(current_time && native_run && native_stop && release && release() && *release());
    int64_t first = sample();
    struct timespec delay = {.tv_nsec=2000000};
    while (nanosleep(&delay, &delay)) CHECK(errno == EINTR);
    CHECK(sample() > first);
    if (argc == 2) parallel();
    else { datagram(0, 0, 0); datagram(1, 0, 0); }
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
