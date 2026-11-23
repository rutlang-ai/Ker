#define _GNU_SOURCE
#include "packet-device.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <lkl_host.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static int fail_allocation;
static void *allocation;
static unsigned allocations, releases;
void *__real_calloc(size_t, size_t);
void __real_free(void *);
void *__wrap_calloc(size_t count, size_t size)
{
    if (fail_allocation) { fail_allocation = 0; errno = ENOMEM; return NULL; }
    void *result = __real_calloc(count, size);
    if (result) { CHECK(!allocation); allocation = result; allocations++; }
    return result;
}
void __wrap_free(void *pointer)
{
    if (pointer && pointer == allocation) { releases++; allocation = NULL; }
    __real_free(pointer);
}
static unsigned descriptors(void)
{
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) if (entry->d_name[0] != '.') count++;
    CHECK(closedir(directory) == 0);
    return count;
}
static void pair(int fd[2])
{
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fd) == 0);
}
static double now(void)
{
    struct timespec time;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return time.tv_sec + time.tv_nsec / 1e9;
}
static void allocation_failures(void)
{
    int fd[2]; pair(fd);
    unsigned before = descriptors();
    fail_allocation = 1;
    CHECK(!ker_packet_device_create(fd[0]) && errno == ENOMEM);
    CHECK(fcntl(fd[0], F_GETFD) >= 0 && descriptors() == before && !allocation);
    struct rlimit old, limit;
    CHECK(getrlimit(RLIMIT_NOFILE, &old) == 0);
    limit = old; limit.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    struct lkl_netdev *device = ker_packet_device_create(fd[0]);
    int error = errno;
    CHECK(setrlimit(RLIMIT_NOFILE, &old) == 0);
    CHECK(!device && error == EMFILE && !allocation);
    CHECK(fcntl(fd[0], F_GETFD) >= 0 && descriptors() == before);
    CHECK(close(fd[0]) == 0 && close(fd[1]) == 0);
}
static void context_contracts(void)
{
    unsigned before = descriptors(), allocated = allocations;
    errno = 0;
    CHECK(!ker_packet_device_create(-1) && errno == EBADF);
    int plain = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(plain >= 0);
    errno = 0;
    CHECK(!ker_packet_device_create(plain) && errno == ENOTSOCK);
    CHECK(fcntl(plain, F_GETFD) == FD_CLOEXEC && close(plain) == 0);
    int stream[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, stream) == 0);
    CHECK(!ker_packet_device_create(stream[0]) && errno == EPROTOTYPE);
    CHECK(fcntl(stream[0], F_GETFD) == 0);
    CHECK(write(stream[0], "S", 1) == 1);
    char byte;
    CHECK(read(stream[1], &byte, 1) == 1 && byte == 'S');
    CHECK(close(stream[0]) == 0 && close(stream[1]) == 0);
    int internet = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(internet >= 0);
    CHECK(!ker_packet_device_create(internet) && errno == EAFNOSUPPORT);
    CHECK(fcntl(internet, F_GETFD) == 0 && close(internet) == 0);
    int unconnected = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(unconnected >= 0);
    CHECK(!ker_packet_device_create(unconnected) && errno == ENOTCONN);
    CHECK(fcntl(unconnected, F_GETFD) == 0 && close(unconnected) == 0);
    CHECK(allocations == allocated && descriptors() == before);
    for (unsigned kind = 0; kind < 2; kind++) {
        int fd[2];
        CHECK(socketpair(AF_UNIX, kind ? SOCK_SEQPACKET : SOCK_DGRAM, 0, fd) == 0);
        fail_allocation = 1;
        CHECK(!ker_packet_device_create(fd[0]) && errno == ENOMEM);
        CHECK(fcntl(fd[0], F_GETFD) == 0 && fcntl(fd[1], F_GETFD) == 0);
        struct lkl_netdev *device = ker_packet_device_create(fd[0]);
        CHECK(device && (fcntl(fd[0], F_GETFD) & FD_CLOEXEC) && fcntl(fd[1], F_GETFD) == 0);
        unsigned saved = descriptors();
        CHECK(device->ops->tx(NULL, NULL, 0) == -1 && errno == EINVAL);
        CHECK(device->ops->rx(NULL, NULL, 0) == -1 && errno == EINVAL);
        char data[] = "borrowed bytes";
        struct iovec vector = {data, sizeof(data)};
        CHECK(device->ops->tx(NULL, &vector, 1) == -1 && errno == EINVAL);
        CHECK(vector.iov_base == data && vector.iov_len == sizeof(data) &&
            !memcmp(data, "borrowed bytes", sizeof(data)) && descriptors() == saved);
        CHECK(device->ops->tx(device, &vector, 1) == sizeof(data));
        char received[sizeof(data)];
        CHECK(recv(fd[1], received, sizeof(received), 0) == sizeof(data) && !memcmp(data, received, sizeof(data)));
        unsigned freed = releases;
        device->ops->free(device);
        CHECK(releases == freed + 1 && !allocation);
        CHECK(fcntl(fd[0], F_GETFD) == -1 && errno == EBADF);
        CHECK(fcntl(fd[1], F_GETFD) == 0 && close(fd[1]) == 0);
    }
    CHECK(descriptors() == before);
    puts("PASS: context roundtrip, invalid transport rejection, failure preserves fd/flags, success owns only its fd; NULL context rejects without freeing borrowed vectors");
}
struct poll_task { struct lkl_netdev *device; atomic_int tid; int result; };
static void *poll_thread(void *argument)
{
    struct poll_task *task = argument;
    sigset_t signals;
    sigemptyset(&signals); sigaddset(&signals, SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &signals, NULL) == 0);
    atomic_store(&task->tid, (int)syscall(SYS_gettid));
    task->result = task->device->ops->poll(task->device);
    return NULL;
}
/* Observe an actual blocked ppoll, without assuming a sleep is long enough. */
static void blocked(struct poll_task *task)
{
    double deadline = now() + 3;
    while (now() < deadline) {
        int tid = atomic_load(&task->tid);
        if (tid) {
            char path[128], line[512];
            snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
            FILE *file = fopen(path, "r");
            CHECK(file);
            int read = fgets(line, sizeof(line), file) != NULL;
            CHECK(fclose(file) == 0);
            long number;
            if (read && sscanf(line, "%ld", &number) == 1 && number == SYS_ppoll) return;
        }
        sched_yield();
    }
    CHECK(0 && "poll callback never blocked in ppoll");
}
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal-safe atomic flag");
static atomic_int interrupted;
static void signal_handler(int signal_number) { (void)signal_number; atomic_store_explicit(&interrupted, 1, memory_order_relaxed); }
static void stop_poll(struct lkl_netdev *device)
{
    struct poll_task task = {.device = device};
    atomic_init(&task.tid, 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, poll_thread, &task) == 0);
    blocked(&task);
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    double deadline = now() + 3;
    while (!atomic_load_explicit(&interrupted, memory_order_relaxed) && now() < deadline) sched_yield();
    CHECK(atomic_load_explicit(&interrupted, memory_order_relaxed));
    blocked(&task); /* EINTR must resume waiting, not return an error. */
    device->ops->poll_hup(device);
    device->ops->poll_hup(device);
    struct timespec until;
    CHECK(clock_gettime(CLOCK_REALTIME, &until) == 0);
    until.tv_sec += 3;
    CHECK(pthread_timedjoin_np(thread, NULL, &until) == 0);
    CHECK(task.result == LKL_DEV_NET_POLL_HUP);
    CHECK(device->ops->poll(device) == LKL_DEV_NET_POLL_HUP);
    char buffer[8]; struct iovec vector = {buffer, sizeof(buffer)};
    CHECK(device->ops->rx(device, &vector, 1) == -1 && errno == ESHUTDOWN);
    CHECK(device->ops->tx(device, &vector, 1) == -1 && errno == ESHUTDOWN);
}
static void transfer_and_stop(void)
{
    int fd[2]; pair(fd);
    unsigned before = descriptors();
    struct lkl_netdev *device = ker_packet_device_create(fd[0]);
    CHECK(device && device->ops && device->has_vnet_hdr == 1);
    CHECK(device->ops->tx && device->ops->rx && device->ops->poll && device->ops->poll_hup && device->ops->free);
    CHECK(descriptors() == before + 1); /* Private eventfd only. */
    char first[] = "header", last[] = "Ethernet payload";
    struct iovec tx[] = {{first, sizeof(first)}, {last, sizeof(last)}};
    char expected[sizeof(first) + sizeof(last)], received[sizeof(expected)];
    memcpy(expected, first, sizeof(first)); memcpy(expected + sizeof(first), last, sizeof(last));
    CHECK(device->ops->tx(device, tx, 2) == sizeof(expected));
    CHECK(recv(fd[1], received, sizeof(received), 0) == sizeof(expected));
    CHECK(!memcmp(received, expected, sizeof(expected)));
    struct iovec rx[] = {{received, 3}, {received + 3, sizeof(received) - 3}};
    CHECK(device->ops->rx(device, rx, 2) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK(send(fd[1], expected, sizeof(expected), 0) == sizeof(expected));
    CHECK(device->ops->poll(device) & LKL_DEV_NET_POLL_RX);
    memset(received, 0, sizeof(received));
    CHECK(device->ops->rx(device, rx, 2) == sizeof(expected));
    CHECK(!memcmp(received, expected, sizeof(expected)));
    CHECK(device->ops->tx(device, tx, 0) == -1 && errno == EINVAL);
    CHECK(device->ops->rx(device, rx, IOV_MAX + 1) == -1 && errno == EINVAL);
    CHECK(send(fd[1], expected, sizeof(expected), 0) == sizeof(expected));
    struct iovec small = {received, 3};
    CHECK(device->ops->rx(device, &small, 1) == -1 && errno == EMSGSIZE);
    CHECK(device->ops->rx(device, rx, 2) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    int buffer_size = 4096;
    CHECK(setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) == 0);
    unsigned queued = 0;
    while (device->ops->tx(device, tx, 2) >= 0) CHECK(++queued < 10000);
    CHECK(queued && (errno == EAGAIN || errno == EWOULDBLOCK));
    unsigned drained = 0;
    while (recv(fd[1], received, sizeof(received), 0) >= 0) {
        CHECK(!memcmp(received, expected, sizeof(expected))); drained++;
    }
    CHECK(drained == queued && (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK(device->ops->poll(device) & LKL_DEV_NET_POLL_TX);
    CHECK(device->ops->tx(device, tx, 2) == sizeof(expected));
    CHECK(recv(fd[1], received, sizeof(received), 0) == sizeof(expected));
    stop_poll(device);
    unsigned freed = releases;
    device->ops->free(device);
    CHECK(!allocation && releases == freed + 1);
    CHECK(fcntl(fd[0], F_GETFD) == -1 && errno == EBADF);
    CHECK(fcntl(fd[1], F_GETFD) >= 0 && descriptors() == before - 1);
    CHECK(close(fd[1]) == 0);
}
int main(void)
{
    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    unsigned before = descriptors();
    allocation_failures();
    context_contracts();
    transfer_and_stop();
    for (unsigned i = 0; i < 64; i++) {
        int fd[2]; pair(fd);
        struct lkl_netdev *device = ker_packet_device_create(fd[0]);
        CHECK(device);
        device->ops->free(device);
        CHECK(close(fd[1]) == 0);
    }
    CHECK(!allocation && allocations == releases && descriptors() == before);
    puts("PASS: production packet device allocation/free, fd ownership, vectors, truncation, backpressure, EINTR and blocked-poll stop");
    return 0;
}
