#define _GNU_SOURCE
#include <ker/posix.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

static int (*run)(ker_posix_loop_func, void *);
static void (*stop)(void);
static unsigned calls;
static atomic_bool waiting = true;
static pthread_t caller;
static char *mode;

static int cycle(void *argument)
{
    CHECK(argument == mode && pthread_equal(pthread_self(), caller));
    ++calls;
    if (calls == 1) {
        CHECK(run(NULL, NULL) == -1 && errno == EBUSY);
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(46543)};
        const char payload[] = "run-stop-original-linux";
        char result[sizeof(payload)];
        struct timeval timeout = {.tv_sec = 3};
        CHECK(fd >= 0 && inet_pton(AF_INET, "198.18.0.1", &peer.sin_addr) == 1);
        CHECK(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        CHECK(!connect(fd, (struct sockaddr *)&peer, sizeof(peer)));
        CHECK(send(fd, payload, sizeof(payload), 0) == sizeof(payload));
        CHECK(recv(fd, result, sizeof(result), 0) == sizeof(result));
        CHECK(!memcmp(payload, result, sizeof(result)));
        /* The runtime closes the live socket after the last iteration. */
    }
    if (calls == (!strcmp(mode, "repeat") ? 3u : 1u)) {
        stop();
        stop();
    }
    return -13;
}

static void *external_stop(void *argument)
{
    (void)argument;
    while (atomic_load_explicit(&waiting, memory_order_acquire)) {
        stop();
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    mode = argv[1];
    bool wait = !strcmp(mode, "wait");
    run = dlsym(RTLD_DEFAULT, "ker_posix_run");
    stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    CHECK(run && stop);
    int fd = atoi(getenv("KER_RUN_FD"));
    CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
    caller = pthread_self();
    stop();
    pthread_t helper;
    if (wait) CHECK(!pthread_create(&helper, NULL, external_stop, NULL));
    CHECK(!run(wait ? NULL : cycle, mode));
    atomic_store_explicit(&waiting, false, memory_order_release);
    if (wait) CHECK(!pthread_join(helper, NULL));
    CHECK(calls == (wait ? 0u : !strcmp(mode, "repeat") ? 3u : 1u));
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(run(NULL, NULL) == -1 && errno == ENETDOWN);
    CHECK(socket(AF_INET, SOCK_DGRAM, 0) == -1 && errno == ENETDOWN);
    printf("RUN_SOURCE_CASE %s calls=%u\n", mode, calls);
    return 0;
}
