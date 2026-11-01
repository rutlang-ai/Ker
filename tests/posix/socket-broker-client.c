#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include "socket-broker-protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    dprintf(STDERR_FILENO, "broker client:%d: %s: %s\n", __LINE__, #condition, strerror(errno)); \
    return 1; } } while (0)

static int parse_fd(const char *text)
{
    char *end = NULL; long value = strtol(text, &end, 10);
    if (!text[0] || !end || *end || value < 0 || value > INT32_MAX) return -1;
    return (int)value;
}

static int wait_event(struct ker_socket_client *client, int epoll_cap, uint64_t token)
{
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (unsigned i = 0; i < 10000; ++i) {
        struct epoll_event events[4];
        int count = ker_socket_client_epoll_wait(client, epoll_cap, events, 4);
        if (count < 0) return -1;
        for (int j = 0; j < count; ++j) if (events[j].data.u64 == token) return 0;
        (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int read_until_eof(struct ker_socket_client *client, int cap)
{
    char buffer[64];
    for (unsigned i = 0; i < 10000; ++i) {
        ssize_t count = ker_socket_client_read(client, cap, buffer, sizeof(buffer));
        if (count == 0) return 0;
        if (count > 0) { errno = EPROTO; return -1; }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int read_exact(struct ker_socket_client *client, int cap, char *buffer, size_t length)
{
    size_t offset = 0;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (unsigned attempt = 0; offset < length && attempt < 10000; ++attempt) {
        size_t request = length - offset < KER_SOCKET_BROKER_IO_MAX ?
            length - offset : KER_SOCKET_BROKER_IO_MAX;
        ssize_t count = ker_socket_client_read(client, cap, buffer + offset, request);
        if (count > 0) { offset += (size_t)count; continue; }
        if (count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return -1;
        (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    if (offset != length) { errno = ETIMEDOUT; return -1; }
    return 0;
}

static int write_exact(struct ker_socket_client *client, int cap, const void *buffer, size_t length)
{
    size_t offset = 0;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (unsigned attempt = 0; offset < length && attempt < 10000; ++attempt) {
        size_t request = length - offset < KER_SOCKET_BROKER_IO_MAX ?
            length - offset : KER_SOCKET_BROKER_IO_MAX;
        ssize_t count = ker_socket_client_write(client, cap,
            (const char *)buffer + offset, request);
        if (count > 0) { offset += (size_t)count; continue; }
        if (count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return -1;
        (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    if (offset != length) { errno = ETIMEDOUT; return -1; }
    return 0;
}

static void fill_payload(char *buffer, size_t length)
{
    for (size_t i = 0; i < length; ++i) buffer[i] = (char)((i * 31u + 7u) & 0xffu);
}

static int inherited_rpc_is_rejected(struct ker_socket_client *client, int capability)
{
    struct ker_sb_header request = {.magic = KER_SB_MAGIC, .version = KER_SB_VERSION,
        .operation = KER_SB_GETSOCKNAME, .rights_count = 1,
        .sequence = client->sequence + 1};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &request, .iov_len = sizeof(request)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(capability));
    memcpy(CMSG_DATA(cmsg), &capability, sizeof(capability));
    if (syscall(SYS_sendmsg, client->session_fd, &message, MSG_NOSIGNAL) != sizeof(request)) return -1;
    struct pollfd event = {.fd = client->session_fd, .events = POLLIN | POLLHUP | POLLERR};
    if (syscall(SYS_poll, &event, 1, 5000) <= 0) { errno = ETIMEDOUT; return -1; }
    struct ker_sb_header reply;
    ssize_t amount = syscall(SYS_recvfrom, client->session_fd, &reply, sizeof(reply), MSG_TRUNC, NULL, NULL);
    if (amount != 0) { errno = EPROTO; return -1; }
    return 0;
}

static int wait_accept(struct ker_socket_client *client, int listener, int epoll,
    uint64_t token)
{
    if (wait_event(client, epoll, token)) return -1;
    return ker_socket_client_accept4(client, listener, NULL, NULL, SOCK_CLOEXEC);
}

static int child_mode(const char *path, int listener, int epoll, int accepted)
{
    struct ker_socket_client client;
    CHECK(ker_socket_client_open(&client, path) == 0);
    puts("CHILD_READY"); fflush(stdout);
    CHECK(wait_event(&client, epoll, UINT64_C(0x1234)) == 0);
    char first[4097] = {0}, expected[4097];
    fill_payload(expected, sizeof(expected));
    CHECK(read_exact(&client, accepted, first, sizeof(first)) == 0);
    CHECK(!memcmp(first, expected, sizeof(first)));
    CHECK(write_exact(&client, accepted, expected, sizeof(expected)) == 0);
    CHECK(read_until_eof(&client, accepted) == 0);
    puts("FIRST_STREAM_OK"); fflush(stdout);

    int second = wait_accept(&client, listener, epoll, UINT64_C(0x4097));
    CHECK(second >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x5678)};
    CHECK(ker_socket_client_epoll_ctl(&client, epoll, EPOLL_CTL_ADD, second, &event) == 0);
    puts("SECOND_ACCEPTED"); fflush(stdout);
    CHECK(wait_event(&client, epoll, UINT64_C(0x5678)) == 0);
    char second_data[12] = {0};
    CHECK(read_exact(&client, second, second_data, sizeof(second_data)) == 0);
    CHECK(!memcmp(second_data, "FRESH-ACCEPT", sizeof(second_data)));
    CHECK(ker_socket_client_write(&client, second, "REPLY-TWO", 9) == 9);
    CHECK(read_until_eof(&client, second) == 0);
    close(second);
    close(accepted);
    close(listener);
    close(epoll);
    ker_socket_client_close(&client);
    puts("CHILD_DONE"); fflush(stdout);
    return 0;
}

static int parent_mode(const char *self, const char *path, int listener, int epoll)
{
    struct ker_socket_client client;
    CHECK(ker_socket_client_open(&client, path) == 0);

    int alias = dup(listener);
    CHECK(alias >= 0);
    CHECK(close(alias) == 0);
    errno = 0;
    CHECK(shutdown(listener, SHUT_RDWR) == -1 && errno == ENOTSOCK);
    CHECK(write(listener, "x", 1) == 1);
    struct sockaddr_in bound = {0};
    socklen_t bound_length = sizeof(bound);
    CHECK(ker_socket_client_getsockname(&client, listener,
        (struct sockaddr *)&bound, &bound_length) == 0);
    CHECK(bound.sin_port == htons(4097));
    int option_value = 0;
    socklen_t option_length = sizeof(option_value);
    CHECK(ker_socket_client_getsockopt(&client, listener, SOL_SOCKET, SO_TYPE,
        &option_value, &option_length) == 0);
    CHECK(option_length == sizeof(option_value) && option_value == SOCK_STREAM);
    option_value = 1;
    CHECK(ker_socket_client_setsockopt(&client, listener, SOL_SOCKET, SO_KEEPALIVE,
        &option_value, sizeof(option_value)) == 0);
    option_value = 0; option_length = sizeof(option_value);
    CHECK(ker_socket_client_getsockopt(&client, listener, SOL_SOCKET, SO_KEEPALIVE,
        &option_value, &option_length) == 0);
    CHECK(option_length == sizeof(option_value) && option_value == 1);

    struct sock_fprog pointer_option = {.len = 1,
        .filter = (struct sock_filter *)(uintptr_t)1};
    errno = 0;
    CHECK(ker_socket_client_setsockopt(&client, listener, SOL_SOCKET, SO_ATTACH_FILTER,
        &pointer_option, sizeof(pointer_option)) == -1 && errno == EOPNOTSUPP);
#ifdef SO_ATTACH_REUSEPORT_EBPF
    int raw_fd_option = 0;
    errno = 0;
    CHECK(ker_socket_client_setsockopt(&client, listener, SOL_SOCKET,
        SO_ATTACH_REUSEPORT_EBPF, &raw_fd_option, sizeof(raw_fd_option)) == -1 &&
        errno == EOPNOTSUPP);
#endif
    option_value = 0; option_length = sizeof(option_value);
    errno = 0;
    CHECK(ker_socket_client_getsockopt(&client, listener, SOL_SOCKET, 0x7fff,
        &option_value, &option_length) == -1 && errno == EOPNOTSUPP);
    option_value = 0;
    CHECK(ker_socket_client_setsockopt(&client, listener, SOL_SOCKET, SO_KEEPALIVE,
        &option_value, sizeof(option_value)) == 0);

    errno = 0;
    int unsupported = ker_socket_client_socket(&client, AF_INET, SOCK_RAW, IPPROTO_RAW);
    CHECK(unsupported == -1 &&
        (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT));
    struct epoll_event listener_event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x4097)};
    CHECK(ker_socket_client_epoll_ctl(&client, epoll, EPOLL_CTL_DEL, listener, &listener_event) == 0);
    CHECK(ker_socket_client_epoll_ctl(&client, epoll, EPOLL_CTL_ADD, listener, &listener_event) == 0);

    int wrong[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, wrong) == 0);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, wrong[0], NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EBADF);
    close(wrong[0]); close(wrong[1]);
    int pipe_fds[2];
    CHECK(pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC) == 0);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, pipe_fds[0], NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EBADF);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, pipe_fds[1], NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EBADF);
    close(pipe_fds[0]); close(pipe_fds[1]);
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", listener);
    int read_alias = open(proc_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    CHECK(read_alias >= 0);
    struct stat write_identity = {0}, read_identity = {0};
    CHECK(fstat(listener, &write_identity) == 0 && fstat(read_alias, &read_identity) == 0);
    CHECK(write_identity.st_dev == read_identity.st_dev && write_identity.st_ino == read_identity.st_ino);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, read_alias, NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EBADF);
    close(read_alias);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, listener, NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EAGAIN);
    puts("WAIT_ACCEPT"); fflush(stdout);
    int accepted = -1;
    for (unsigned i = 0; i < 10000 && accepted < 0; ++i) {
        accepted = ker_socket_client_accept4(&client, listener, NULL, NULL, SOCK_CLOEXEC);
        if (accepted < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 1;
        if (accepted < 0) { struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)syscall(SYS_nanosleep, &pause, NULL); }
    }
    CHECK(accepted >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x1234)};
    CHECK(ker_socket_client_epoll_ctl(&client, epoll, EPOLL_CTL_ADD, accepted, &event) == 0);
    puts("PRE_FORK_WAIT"); fflush(stdout);
    CHECK(wait_event(&client, epoll, UINT64_C(0x1234)) == 0);
    char before[11] = {0};
    CHECK(read_exact(&client, accepted, before, sizeof(before)) == 0);
    CHECK(!memcmp(before, "BEFORE-FORK", sizeof(before)));
    CHECK(ker_socket_client_write(&client, accepted, "PRE-FORK-OK", 11) == 11);
    puts("PRE_FORK_OK"); fflush(stdout);
    for (int fd = 0; fd < 3; ++fd) {
        int value = fd == 0 ? listener : fd == 1 ? epoll : accepted;
        int flags = fcntl(value, F_GETFD);
        CHECK(flags >= 0 && fcntl(value, F_SETFD, flags & ~FD_CLOEXEC) == 0);
    }
    int child_ack[2];
    CHECK(pipe2(child_ack, O_CLOEXEC) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(child_ack[0]);
        puts("PREEXEC_BEGIN"); fflush(stdout);
        if (inherited_rpc_is_rejected(&client, listener)) {
            int error = errno;
            dprintf(STDOUT_FILENO, "PREEXEC_ERROR %d\n", error); fflush(stdout);
            _exit(121);
        }
        struct sockaddr_in inherited_name = {0};
        socklen_t inherited_length = sizeof(inherited_name);
        if (ker_socket_client_getsockname(&client, listener,
                (struct sockaddr *)&inherited_name, &inherited_length) ||
            inherited_name.sin_port != htons(4097)) {
            int error = errno;
            dprintf(STDOUT_FILENO, "PREEXEC_ERROR %d\n", error); fflush(stdout);
            _exit(120);
        }
        CHECK(write(child_ack[1], "A", 1) == 1);
        close(child_ack[1]);
        puts("PREEXEC_RECONNECTED"); fflush(stdout);
        char listener_text[24], epoll_text[24], accepted_text[24];
        snprintf(listener_text, sizeof(listener_text), "%d", listener);
        snprintf(epoll_text, sizeof(epoll_text), "%d", epoll);
        snprintf(accepted_text, sizeof(accepted_text), "%d", accepted);
        execl(self, self, "child", path, listener_text, epoll_text, accepted_text, (char *)NULL);
        _exit(127);
    }
    close(child_ack[1]);
    dprintf(STDOUT_FILENO, "CHILD_PID %ld\n", (long)child);
    struct pollfd child_ready = {.fd = child_ack[0], .events = POLLIN | POLLHUP | POLLERR};
    CHECK(syscall(SYS_poll, &child_ready, 1, 10000) > 0);
    char acknowledgement = 0;
    CHECK(read(child_ack[0], &acknowledgement, 1) == 1 && acknowledgement == 'A');
    close(child_ack[0]);
    ker_socket_client_close(&client);
    (void)syscall(SYS_close, listener); (void)syscall(SYS_close, epoll); (void)syscall(SYS_close, accepted);
    puts("PARENT_EXIT"); fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 6 && !strcmp(argv[1], "child")) {
        int listener = parse_fd(argv[3]), epoll = parse_fd(argv[4]), accepted = parse_fd(argv[5]);
        if (listener < 0 || epoll < 0 || accepted < 0) return 2;
        return child_mode(argv[2], listener, epoll, accepted);
    }
    if (argc == 5 && !strcmp(argv[1], "parent")) {
        int listener = parse_fd(argv[3]), epoll = parse_fd(argv[4]);
        if (listener < 0 || epoll < 0) return 2;
        return parent_mode(argv[0], argv[2], listener, epoll);
    }
    fprintf(stderr, "usage: client parent <rpc-path> <listener-fd> <epoll-fd> | child <rpc-path> <listener-fd> <epoll-fd> <accepted-fd>\n");
    return 2;
}
