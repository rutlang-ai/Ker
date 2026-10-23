#define _GNU_SOURCE
#include <ker/posix.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int (*run_loop)(ker_posix_loop_func, void *);
static void (*stop_loop)(void);
static uint64_t (*capabilities)(void);
static const char *(*release)(void);
static atomic_bool finish_thread, callback_complete;
struct state { const char *mode; unsigned calls; pthread_t owner; int port; };
static struct state *expected;
static void check(bool valid, const char *operation)
{
    if (!valid) { perror(operation); exit(1); }
}
static void traffic(int port)
{
    const char *targets[] = {"198.18.0.1", "198.19.0.1", "2001:db8:1::1", "2001:db8:2::1"};
    for (unsigned index = 0; index < 4; index++) {
        int family = index < 2 ? AF_INET : AF_INET6;
        struct sockaddr_storage address = {0};
        socklen_t size;
        if (family == AF_INET) {
            struct sockaddr_in *a = (void *)&address;
            a->sin_family = AF_INET; a->sin_port = htons((uint16_t)port);
            check(inet_pton(AF_INET, targets[index], &a->sin_addr) == 1, "IPv4 target");
            size = sizeof(*a);
        } else {
            struct sockaddr_in6 *a = (void *)&address;
            a->sin6_family = AF_INET6; a->sin6_port = htons((uint16_t)port);
            check(inet_pton(AF_INET6, targets[index], &a->sin6_addr) == 1, "IPv6 target");
            size = sizeof(*a);
        }
        for (unsigned tcp = 0; tcp < 2; tcp++) {
            int fd = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
            check(fd >= 0, "native callback socket");
            struct timeval timeout = {.tv_sec = 3};
            check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "native timeout");
            check(!connect(fd, (void *)&address, size), "native callback connect");
            char sent[64], received[64];
            int length = snprintf(sent, sizeof(sent), "run-stop-family%u-protocol%u", index, tcp);
            check(send(fd, sent, (size_t)length, MSG_NOSIGNAL) == length, "callback send");
            check(recv(fd, received, (size_t)length, tcp ? MSG_WAITALL : 0) == length &&
                !memcmp(sent, received, (size_t)length), "callback receive exact payload");
            if (!tcp) check(!close(fd), "callback UDP close");
            /* Deliberately leave TCP open: run must close native descriptors
             * and the independent peer must observe EOF before EAL cleanup. */
        }
    }
}
static int callback(void *opaque)
{
    struct state *state = opaque;
    check(state == expected && pthread_equal(state->owner, pthread_self()), "callback argument/thread identity");
    state->calls++;
    if (state->calls == 1) {
        errno = 0;
        check(run_loop(NULL, NULL) == -1 && errno == EBUSY, "nested run rejected");
        traffic(state->port);
        atomic_store(&callback_complete, true);
    }
    if (!strcmp(state->mode, "repeat")) {
        if (state->calls == 3) { stop_loop(); stop_loop(); }
    } else if (strcmp(state->mode, "external")) {
        stop_loop(); stop_loop();
    } else {
        struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
    }
    return state->calls == 1 ? -17 : 42; /* Must not stop the runtime. */
}
static void *stop_from_thread(void *opaque)
{
    struct state *state = opaque;
    bool checked = false;
    while (!atomic_load(&finish_thread)) {
        if (atomic_load(&callback_complete)) {
            if (!checked && !strcmp(state->mode, "external")) {
                errno = 0;
                check(run_loop(NULL, NULL) == -1 && errno == EBUSY, "concurrent run rejected");
                checked = true;
            }
            stop_loop();
        }
        struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
    }
    return NULL;
}
int main(int argc, char **argv)
{
    check(argc == 4, "usage: run-stop MODE PORT WORKER_PID_FILE");
    run_loop = dlsym(RTLD_DEFAULT, "ker_posix_run");
    stop_loop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    capabilities = dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    release = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    check(run_loop && stop_loop && capabilities && release && capabilities() && release(), "native run exports/ready");
    const char *control = getenv("KER_RUN_FD");
    check(control && (fcntl(atoi(control), F_GETFD) & FD_CLOEXEC), "private run channel CLOEXEC");
    int private_fds[6] = {atoi(getenv("KER_PACKET_FD")), atoi(getenv("KER_PACKET_CONTROL_FD")),
        atoi(getenv("KER_STARTUP_FD")), atoi(control), -1, -1};
    check(sscanf(getenv("KER_PACKET_INTERFACES"), "%d|%d", &private_fds[4], &private_fds[5]) == 2,
        "additional private channels");
    struct state state = {.mode = argv[1], .owner = pthread_self(), .port = atoi(argv[2])};
    expected = &state;
    stop_loop(); stop_loop(); /* An idle request must not poison the next run. */
    pthread_t helper;
    bool threaded = !strcmp(state.mode, "external") || !strcmp(state.mode, "null");
    if (!strcmp(state.mode, "null")) {
        traffic(state.port);
        atomic_store(&callback_complete, true);
    }
    if (threaded) check(!pthread_create(&helper, NULL, stop_from_thread, &state), "external stopper");
    int result = run_loop(!strcmp(state.mode, "null") ? NULL : callback, &state);
    int error = errno;
    atomic_store(&finish_thread, true);
    if (threaded) check(!pthread_join(helper, NULL), "stopper joined");
    if (!strcmp(state.mode, "worker-failure")) check(result == -1 && error == EIO, "failed EAL acknowledgement propagated");
    else check(result == 0, "run completed full kernel/EAL teardown");
    check(!capabilities() && !release(), "native instance inactive before return");
    errno = 0; check(socket(AF_INET, SOCK_STREAM, 0) == -1 && errno == ENETDOWN, "native socket after halt rejected");
    errno = 0; check(run_loop(callback, &state) == -1 && errno == ENETDOWN, "second run rejected after teardown");
    stop_loop(); stop_loop();
    if (!strcmp(state.mode, "repeat")) check(state.calls == 3, "callback return ignored through third iteration");
    else if (!strcmp(state.mode, "null")) check(state.calls == 0, "null callback not invoked");
    else if (strcmp(state.mode, "external")) check(state.calls == 1, "exactly one callback");
    else check(state.calls >= 1, "external stop after real native callback");
    for (unsigned index = 0; index < 6; index++) {
        errno = 0;
        check(fcntl(private_fds[index], F_GETFD) == -1 && errno == EBADF, "private channel closed before return");
    }
    FILE *pids = fopen(argv[3], "r"); check(pids != NULL, "worker PID evidence");
    int pid, workers = 0;
    while (fscanf(pids, "%d", &pid) == 1) {
        errno = 0; check(kill(pid, 0) == -1 && errno == ESRCH, "worker fully reaped before API return"); workers++;
    }
    fclose(pids); check(workers >= 2, "both interface workers were recorded");
    printf("PASS: %s calls=%u; real dual-interface IPv4/IPv6 TCP/UDP; kernel halted and %d workers reaped before return\n",
        state.mode, state.calls, workers); fflush(stdout);
    /* Returning from run is not process exit. Keep the application alive
     * beyond the launcher's historical five-second teardown timeout. */
    if (!strcmp(state.mode, "oneshot")) sleep(6);
    return 0;
}
