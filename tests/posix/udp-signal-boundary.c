/* Record the existing host-signal boundary; this is not a parity/pass claim. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);                           \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal handler needs lock-free atomic stores");
static atomic_int entering, observed, handled;
static pthread_t main_thread;
static long main_tid;
static int native;
static void handler(int signal) {
    (void)signal;
    atomic_store_explicit(&handled, 1, memory_order_relaxed);
}
static long long now(void) {
    struct timespec t;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
static void *interrupt(void *unused) {
    (void)unused;
    while (!atomic_load_explicit(&entering, memory_order_acquire))
        sched_yield();
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/syscall", main_tid);
    long long deadline = now() + 2000000000LL;
    while (now() < deadline) {
        FILE *file = fopen(path, "r");
        CHECK(file != NULL);
        long number = -1;
        int fields = fscanf(file, "%ld", &number);
        CHECK(fclose(file) == 0);
        if (fields == 1 && number == (native ? SYS_futex : SYS_recvfrom)) {
            atomic_store_explicit(&observed, 1, memory_order_release);
            CHECK(pthread_kill(main_thread, SIGUSR1) == 0);
            return NULL;
        }
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return NULL;
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    native = !strcmp(argv[1], "native");
    CHECK(native || !strcmp(argv[1], "host"));
    struct sigaction action = {.sa_handler = handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    main_thread = pthread_self();
    main_tid = syscall(SYS_gettid);
    for (int family = AF_INET; family <= AF_INET6; family += (AF_INET6 - AF_INET)) {
        atomic_store(&entering, 0);
        atomic_store(&observed, 0);
        atomic_store(&handled, 0);
        int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        CHECK(fd >= 0);
        struct timeval timeout = {.tv_usec = 500000};
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        if (family == AF_INET) {
            struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
            CHECK(bind(fd, (void *)&a, sizeof(a)) == 0);
        } else {
            struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
            CHECK(bind(fd, (void *)&a, sizeof(a)) == 0);
        }
        pthread_t sender;
        CHECK(pthread_create(&sender, NULL, interrupt, NULL) == 0);
        char byte;
        atomic_store_explicit(&entering, 1, memory_order_release);
        ssize_t result = recvfrom(fd, &byte, 1, 0, NULL, NULL);
        int error = errno;
        CHECK(pthread_join(sender, NULL) == 0 && atomic_load(&observed) && atomic_load(&handled));
        CHECK(result == -1 && error == (native ? EAGAIN : EINTR));
        CHECK(close(fd) == 0);
        printf("%s family=%d host SIGUSR1: recvfrom returned %s\n",
               native ? "UNSUPPORTED_BOUNDARY" : "HOST_REFERENCE", family,
               native ? "EAGAIN after configured timeout (no native signal bridge)" : "EINTR");
    }
    return 0;
}
