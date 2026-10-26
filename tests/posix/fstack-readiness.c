/* Ker-specific poll/select extensions of pinned F-Stack readiness scenarios.
 * Real public POSIX TCP APIs; no kqueue translation or synthetic events. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define ERROR(call, code) do { errno = 0; CHECK((call) == -1); CHECK(errno == (code)); } while (0)
extern const char *ker_posix_kernel_release(void) __attribute__((weak));
struct pair {int sender, receiver;};
static int listener(struct sockaddr_in *address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    *address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (void *)address, sizeof(*address)) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof(*address);
    CHECK(getsockname(fd, (void *)address, &length) == 0);
    return fd;
}
static int connect_to(struct sockaddr_in address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0 && connect(fd, (void *)&address, sizeof(address)) == 0);
    return fd;
}
static short wait_for(int fd, short events)
{
    struct pollfd p = {fd, events, 0};
    CHECK(poll(&p, 1, 2000) == 1);
    CHECK((p.revents & events) == events);
    return p.revents;
}
static struct pair connected(void)
{
    struct sockaddr_in address;
    int fd = listener(&address), sender = connect_to(address);
    wait_for(fd, POLLIN);
    int receiver = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(receiver >= 0 && close(fd) == 0);
    return (struct pair){sender, receiver};
}
static void finish(struct pair p) {CHECK(close(p.sender) == 0 && close(p.receiver) == 0);}
static void queued(int fd, int count)
{
    /* Synchronize delivery without assuming a write is immediately readable. */
    for (int i = 0; i < 2000; ++i) {
        int available;
        CHECK(ioctl(fd, FIONREAD, &available) == 0);
        if (available == count) return;
        CHECK(available < count);
        struct timespec delay = {.tv_nsec = 1000000};
        CHECK(nanosleep(&delay, NULL) == 0);
    }
    CHECK(0 && "TCP data was not queued before deadline");
}
static int select_now(int fd, int read_ready, int write_ready, int exception)
{
    CHECK(fd < FD_SETSIZE);
    fd_set reads, writes, errors;
    FD_ZERO(&reads); FD_ZERO(&writes); FD_ZERO(&errors);
    if (read_ready) FD_SET(fd, &reads);
    if (write_ready) FD_SET(fd, &writes);
    if (exception) FD_SET(fd, &errors);
    struct timeval zero = {0};
    int result = select(fd + 1, &reads, &writes, &errors, &zero);
    if (result >= 0) {
        CHECK(!FD_ISSET(fd, &reads) || read_ready);
        CHECK(!FD_ISSET(fd, &writes) || write_ready);
        CHECK(!FD_ISSET(fd, &errors) || exception);
        CHECK(result == !!FD_ISSET(fd, &reads) + !!FD_ISSET(fd, &writes) + !!FD_ISSET(fd, &errors));
    }
    return result;
}
static void accept_readiness(void)
{
    struct sockaddr_in address;
    int fd = listener(&address);
    struct pollfd event = {fd, POLLIN, POLLIN};
    CHECK(poll(&event, 1, 0) == 0 && event.revents == 0);
    CHECK(select_now(fd, 1, 0, 0) == 0);
    ERROR(accept4(fd, NULL, NULL, SOCK_NONBLOCK), EAGAIN);
    int sender = connect_to(address);
    wait_for(fd, POLLIN);
    CHECK(select_now(fd, 1, 0, 0) == 1);
    int receiver = accept4(fd, NULL, NULL, SOCK_NONBLOCK);
    CHECK(receiver >= 0);
    event.revents = POLLIN;
    CHECK(poll(&event, 1, 0) == 0 && event.revents == 0);
    CHECK(select_now(fd, 1, 0, 0) == 0);
    CHECK(close(fd) == 0);
    finish((struct pair){sender, receiver});
}
static void read_write_and_counts(void)
{
    struct pair p = connected();
    CHECK(select_now(p.receiver, 1, 0, 0) == 0);
    CHECK(select_now(p.receiver, 1, 1, 0) == 1);
    CHECK(send(p.sender, "ab", 2, MSG_NOSIGNAL) == 2);
    queued(p.receiver, 2);
    struct pollfd events[2] = {{p.receiver, POLLIN | POLLOUT, 0}, {p.receiver, POLLIN, 0}};
    CHECK(poll(events, 2, 0) == 2); /* Count array entries, not individual bits. */
    CHECK((events[0].revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT));
    CHECK(events[1].revents & POLLIN);
    CHECK(select_now(p.receiver, 1, 1, 0) == 2); /* select counts set bits. */
    char byte;
    CHECK(recv(p.receiver, &byte, 1, 0) == 1 && byte == 'a');
    CHECK(select_now(p.receiver, 1, 0, 0) == 1);
    CHECK(recv(p.receiver, &byte, 1, 0) == 1 && byte == 'b');
    CHECK(select_now(p.receiver, 1, 0, 0) == 0);
    finish(p);
}
static void mixed_host_native(void)
{
    struct pair p = connected();
    int host[2];
    CHECK(pipe(host) == 0);
    CHECK(write(host[1], "h", 1) == 1 && send(p.sender, "n", 1, MSG_NOSIGNAL) == 1);
    queued(p.receiver, 1);
    struct pollfd events[] = {{host[0], POLLIN, 0}, {p.receiver, POLLIN, 0}, {-1, POLLIN, POLLIN}};
    CHECK(poll(events, 3, 0) == 2 && events[2].revents == 0);
    CHECK(events[0].revents & POLLIN); CHECK(events[1].revents & POLLIN);
    int maximum = host[0] > p.receiver ? host[0] : p.receiver;
    CHECK(maximum < FD_SETSIZE);
    fd_set reads; FD_ZERO(&reads); FD_SET(host[0], &reads); FD_SET(p.receiver, &reads);
    struct timespec timeout = {.tv_nsec = 20000000}, before = timeout;
    CHECK(pselect(maximum + 1, &reads, NULL, NULL, &timeout, NULL) == 2);
    CHECK(FD_ISSET(host[0], &reads) && FD_ISSET(p.receiver, &reads));
    CHECK(timeout.tv_sec == before.tv_sec && timeout.tv_nsec == before.tv_nsec);
    char byte;
    CHECK(read(host[0], &byte, 1) == 1 && byte == 'h');
    CHECK(recv(p.receiver, &byte, 1, 0) == 1 && byte == 'n');
    CHECK(close(host[0]) == 0 && close(host[1]) == 0);
    finish(p);
}
static void invalid_and_ignored(void)
{
    struct pair p = connected();
    int closed = dup(p.receiver);
    CHECK(closed >= 0 && closed < FD_SETSIZE && close(closed) == 0);
    struct pollfd events[] = {{closed, 0, 0}, {-1, POLLIN, POLLIN}, {p.receiver, POLLIN, POLLIN}};
    CHECK(poll(events, 3, 0) == 1);
    CHECK(events[0].revents == POLLNVAL && events[1].revents == 0 && events[2].revents == 0);
    ERROR(select_now(closed, 1, 0, 0), EBADF);
    /* A rejected operation must not poison a subsequent valid wait. */
    CHECK(select_now(p.receiver, 1, 1, 0) == 1);
    finish(p);
}
static void urgent_data(void)
{
    struct pair p = connected();
    CHECK(send(p.sender, "!", 1, MSG_OOB | MSG_NOSIGNAL) == 1);
    wait_for(p.receiver, POLLPRI);
    CHECK(select_now(p.receiver, 0, 0, 1) == 1);
    char byte;
    CHECK(recv(p.receiver, &byte, 1, MSG_OOB) == 1 && byte == '!');
    struct pollfd event = {p.receiver, POLLPRI, POLLPRI};
    CHECK(poll(&event, 1, 0) == 0 && event.revents == 0);
    CHECK(select_now(p.receiver, 0, 0, 1) == 0);
    CHECK(send(p.sender, "normal", 6, MSG_NOSIGNAL) == 6);
    wait_for(p.receiver, POLLIN);
    char buffer[6];
    CHECK(recv(p.receiver, buffer, sizeof(buffer), 0) == 6 && memcmp(buffer, "normal", 6) == 0);
    finish(p);
}
static void receive_low_watermark(void)
{
    struct pair p = connected();
    int minimum = 4;
    CHECK(setsockopt(p.receiver, SOL_SOCKET, SO_RCVLOWAT, &minimum, sizeof(minimum)) == 0);
    CHECK(send(p.sender, "abc", 3, MSG_NOSIGNAL) == 3);
    queued(p.receiver, 3);
    struct pollfd event = {p.receiver, POLLIN, 0};
    CHECK(poll(&event, 1, 0) == 0 && select_now(p.receiver, 1, 0, 0) == 0);
    CHECK(send(p.sender, "d", 1, MSG_NOSIGNAL) == 1);
    wait_for(p.receiver, POLLIN);
    CHECK(select_now(p.receiver, 1, 0, 0) == 1);
    char buffer[4];
    CHECK(recv(p.receiver, buffer, sizeof(buffer), 0) == 4 && memcmp(buffer, "abcd", 4) == 0);
    finish(p);
}
static void eof_readiness(void)
{
    struct pair p = connected();
    CHECK(send(p.sender, "end", 3, MSG_NOSIGNAL) == 3 && shutdown(p.sender, SHUT_WR) == 0);
    wait_for(p.receiver, POLLIN);
    queued(p.receiver, 3);
    CHECK(select_now(p.receiver, 1, 0, 0) == 1);
    char bytes[3];
    CHECK(recv(p.receiver, bytes, sizeof(bytes), 0) == 3 && memcmp(bytes, "end", 3) == 0);
    wait_for(p.receiver, POLLIN);
    CHECK(select_now(p.receiver, 1, 0, 0) == 1);
    CHECK(recv(p.receiver, bytes, sizeof(bytes), 0) == 0);
    finish(p);
}
static void zero_timeouts(void)
{
    struct pair p = connected();
    struct pollfd event = {p.receiver, POLLIN, POLLIN};
    const struct timespec zero = {0};
    CHECK(ppoll(&event, 1, &zero, NULL) == 0 && event.revents == 0);
    struct timespec invalid = {.tv_nsec = 1000000000};
    ERROR(ppoll(&event, 1, &invalid, NULL), EINVAL);
    CHECK(pselect(0, NULL, NULL, NULL, &zero, NULL) == 0);
    ERROR(pselect(0, NULL, NULL, NULL, &invalid, NULL), EINVAL);
    CHECK(poll(NULL, 0, 0) == 0);
    finish(p);
}
static void poll_memory_faults(void)
{
    struct pair p = connected(); int pipes[2]; CHECK(pipe(pipes) == 0);
    CHECK(write(p.sender, "n", 1) == 1 && write(pipes[1], "h", 1) == 1); queued(p.receiver, 1);
    long page = sysconf(_SC_PAGESIZE); CHECK(page >= (long)(2 * sizeof(struct pollfd)));
    char *memory = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && mprotect(memory + page, (size_t)page, PROT_NONE) == 0);
    struct pollfd fds[2] = {{p.receiver, POLLIN, 0x55}, {pipes[0], POLLIN, 0x55}};
    const struct timespec zero = {0}; void *bad = memory + page;
    fprintf(stderr, "poll fault probe: protected poll array\n");
    ERROR(poll(bad, 1, 0), EFAULT);
    ERROR(ppoll(bad, 1, &zero, NULL), EFAULT);
    if (ker_posix_kernel_release) ERROR(ppoll(fds, 2, bad, NULL), EFAULT);
    else ERROR(syscall(SYS_ppoll, fds, 2, bad, NULL, _NSIG / 8), EFAULT);
    CHECK(fds[0].revents == 0x55 && fds[1].revents == 0x55);
    /* libc may copy invalid timeout pointers itself; compare the kernel
     * contract directly on the host, and the public Ker entry when native. */
    if (ker_posix_kernel_release) ERROR(pselect(0, NULL, NULL, NULL, bad, NULL), EFAULT);
    else ERROR(syscall(SYS_pselect6, 0, NULL, NULL, NULL, bad, NULL), EFAULT);
    CHECK(poll(bad, 0, 0) == 0 && ppoll(bad, 0, &zero, NULL) == 0);
    memcpy(memory, fds, sizeof(fds)); CHECK(mprotect(memory, (size_t)page, PROT_READ) == 0);
    ERROR(poll((void *)memory, 2, 0), EFAULT);
    CHECK(mprotect(memory, (size_t)page * 2, PROT_READ | PROT_WRITE) == 0);
    struct pollfd *split = (void *)(memory + page - sizeof(struct pollfd));
    memcpy(split, fds, sizeof(fds)); CHECK(mprotect(memory + page, (size_t)page, PROT_READ) == 0);
    ERROR(ppoll(split, 2, &zero, NULL), EFAULT);
    CHECK(split[0].fd == p.receiver && split[0].events == POLLIN && split[0].revents == POLLIN);
    CHECK(split[1].fd == pipes[0] && split[1].events == POLLIN && split[1].revents == 0x55);
    CHECK(mprotect(memory + page, (size_t)page, PROT_READ | PROT_WRITE) == 0);
    CHECK(poll(split, 2, 0) == 2 && split[0].revents == POLLIN && split[1].revents == POLLIN);
    char byte; CHECK(read(p.receiver, &byte, 1) == 1 && byte == 'n');
    CHECK(read(pipes[0], &byte, 1) == 1 && byte == 'h');
    CHECK(munmap(memory, (size_t)page * 2) == 0 && close(pipes[0]) == 0 && close(pipes[1]) == 0);
    finish(p);
}
int main(void)
{
    const struct {const char *name; void (*run)(void);} cases[] = {
        {"listener-readiness-and-accept", accept_readiness},
        {"read-write-duplicate-entry-and-bit-counts", read_write_and_counts},
        {"mixed-host-native-and-pselect-timeout", mixed_host_native},
        {"invalid-and-negative-descriptors", invalid_and_ignored},
        {"urgent-data-exception-set", urgent_data},
        {"receive-low-watermark", receive_low_watermark},
        {"buffered-eof-is-readable", eof_readiness},
        {"zero-and-invalid-timeouts", zero_timeouts},
        {"poll-protected-input-output-and-timeout", poll_memory_faults},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cases[i].run();
        printf("PASS: fstack readiness %s\n", cases[i].name); fflush(stdout);
    }
    return 0;
}
