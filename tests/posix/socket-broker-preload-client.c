#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define CHECK(test) do { if (!(test)) { \
    dprintf(STDERR_FILENO, "preload caller:%d: %s: %s\n", __LINE__, #test, strerror(errno)); \
    return 1; } } while (0)

static volatile sig_atomic_t signal_log_fd = -1;
static volatile sig_atomic_t caught_sigpipe_count = 0;
static volatile sig_atomic_t rpc_signal_close_fd = -1;
static volatile sig_atomic_t rpc_signal_seen = 0;
static volatile sig_atomic_t rpc_signal_close_result = -2;
static volatile sig_atomic_t rpc_signal_write_result = -2;
static int rpc_signal_pipe_write_fd = -1;
static void preload_signal_handler(int signal_number)
{
    (void)signal_number;
    const char marker = 'S';
    if (signal_log_fd >= 0) (void)write((int)signal_log_fd, &marker, sizeof(marker));
}
static void caught_sigpipe(int signal_number)
{
    (void)signal_number;
    ++caught_sigpipe_count;
}

static void rpc_signal_handler(int signal_number)
{
    (void)signal_number;
    const char marker = 'R';
    rpc_signal_close_result = close((int)rpc_signal_close_fd);
    rpc_signal_write_result = (sig_atomic_t)write(rpc_signal_pipe_write_fd,
        &marker, sizeof(marker));
    ++rpc_signal_seen;
}

struct wake_thread_args { pthread_t target; int event_fd; };
static void *wake_epoll_from_peer(void *opaque)
{
    struct wake_thread_args *args = opaque;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
    (void)nanosleep(&delay, NULL);
    (void)pthread_kill(args->target, SIGUSR1);
    (void)nanosleep(&delay, NULL);
    uint64_t one = 1; (void)write(args->event_fd, &one, sizeof(one));
    return NULL;
}

struct signal_thread_args { pthread_t target; int result; };
static void *signal_epoll_waiter(void *opaque)
{
    struct signal_thread_args *args = opaque;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
    (void)nanosleep(&delay, NULL);
    args->result = pthread_kill(args->target, SIGUSR1);
    return NULL;
}

struct close_wait_thread_args { int epoll_fd; int event_fd; int close_result; int write_result; };
static void *close_epoll_and_wake(void *opaque)
{
    struct close_wait_thread_args *args = opaque;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 50000000};
    (void)nanosleep(&delay, NULL);
    args->close_result = close(args->epoll_fd);
    uint64_t one = 1;
    args->write_result = (int)write(args->event_fd, &one, sizeof(one));
    return NULL;
}

static int parse_fd(const char *text)
{
    char *end = NULL; long value = strtol(text, &end, 10);
    return !text[0] || !end || *end || value < 0 || value > INT32_MAX ? -1 : (int)value;
}

static void fill(unsigned char *bytes, size_t length, unsigned seed)
{
    for (size_t i = 0; i < length; ++i) bytes[i] = (unsigned char)(i * 31u + seed);
}

static int wait_for(struct epoll_event *events, int epoll_fd, int wanted,
    uint64_t first, uint64_t second, uint64_t third)
{
    int seen = 0;
    for (unsigned attempt = 0; attempt < 10000 && seen != wanted; ++attempt) {
        int amount = epoll_wait(epoll_fd, events, 8, 1000);
        if (amount < 0) return -1;
        for (int i = 0; i < amount; ++i) {
            if (events[i].data.u64 == first) seen |= 1;
            if (events[i].data.u64 == second) seen |= 2;
            if (events[i].data.u64 == third) seen |= 4;
        }
    }
    if (seen != wanted) { errno = ETIMEDOUT; return -1; }
    return 0;
}

static int read_exact(int fd, unsigned char *buffer, size_t length)
{
    size_t offset = 0;
    for (unsigned attempt = 0; offset < length && attempt < 10000; ++attempt) {
        ssize_t amount = read(fd, buffer + offset, length - offset);
        if (amount > 0) { offset += (size_t)amount; continue; }
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)syscall(SYS_nanosleep, &delay, NULL); continue;
        }
        if (amount == 0) errno = ECONNRESET;
        return -1;
    }
    if (offset != length) { errno = ETIMEDOUT; return -1; }
    return 0;
}

static int write_exact(int fd, const unsigned char *buffer, size_t length)
{
    size_t offset = 0;
    for (unsigned attempt = 0; offset < length && attempt < 10000; ++attempt) {
        ssize_t amount = write(fd, buffer + offset, length - offset);
        if (amount > 0) { offset += (size_t)amount; continue; }
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)syscall(SYS_nanosleep, &delay, NULL); continue;
        }
        if (amount == 0) errno = EPIPE;
        return -1;
    }
    if (offset != length) { errno = ETIMEDOUT; return -1; }
    return 0;
}

static int common_checks(int listener, int inherited_epoll)
{
    struct sockaddr_in local = {0}; socklen_t local_length = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr *)&local, &local_length) == 0);
    CHECK(local.sin_family == AF_INET && local.sin_port == htons(4097));
    unsigned char short_name[4] = {0xaa, 0xaa, 0xaa, 0xaa}; socklen_t short_length = 2;
    CHECK(getsockname(listener, (struct sockaddr *)short_name, &short_length) == 0);
    CHECK(short_length == sizeof(struct sockaddr_in) && short_name[2] == 0xaa && short_name[3] == 0xaa);

    int host_pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, host_pair) == 0);
    int event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); CHECK(event_fd >= 0);
    int epoll_fd = epoll_create1(0); CHECK(epoll_fd >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x4097)};
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &event) == 0);
    event = (struct epoll_event){.events = EPOLLIN, .data.u64 = UINT64_C(0x484f5354)};
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, host_pair[0], &event) == 0);
    event = (struct epoll_event){.events = EPOLLIN, .data.u64 = UINT64_C(0x45564e54)};
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &event) == 0);
    const char host_message[] = "host-socketpair";
    CHECK(write(host_pair[1], host_message, sizeof(host_message)) == sizeof(host_message));
    uint64_t one = 1; CHECK(write(event_fd, &one, sizeof(one)) == sizeof(one));
    struct epoll_event ready[8];
    CHECK(wait_for(ready, epoll_fd, 6, UINT64_C(0x4097), UINT64_C(0x484f5354),
        UINT64_C(0x45564e54)) == 0);
    char host_result[sizeof(host_message)] = {0};
    CHECK(read(host_pair[0], host_result, sizeof(host_result)) == sizeof(host_result));
    CHECK(!memcmp(host_result, host_message, sizeof(host_message)));
    uint64_t event_result = 0; CHECK(read(event_fd, &event_result, sizeof(event_result)) == sizeof(event_result));
    CHECK(event_result == 1);

    char log_path[] = "/tmp/ker-preload-signal-log-XXXXXX";
    int log_fd = mkstemp(log_path); CHECK(log_fd >= 0);
    CHECK(unlink(log_path) == 0); signal_log_fd = log_fd;
    struct sigaction action = {.sa_handler = preload_signal_handler};
    struct sigaction previous; sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, &previous) == 0);

    int pending_epoll = epoll_create1(0); CHECK(pending_epoll >= 0);
    struct signal_thread_args signal_args = {.target = pthread_self(), .result = -1};
    pthread_t signal_thread; CHECK(pthread_create(&signal_thread, NULL,
        signal_epoll_waiter, &signal_args) == 0);
    errno = 0;
    CHECK(epoll_wait(pending_epoll, ready, 8, -1) == -1 && errno == EINTR);
    CHECK(pthread_join(signal_thread, NULL) == 0);
    CHECK(signal_args.result == 0);
    CHECK(close(pending_epoll) == 0);

    struct wake_thread_args wake = {.target = pthread_self(), .event_fd = event_fd};
    pthread_t wake_thread; CHECK(pthread_create(&wake_thread, NULL, wake_epoll_from_peer, &wake) == 0);
    errno = 0;
    int wait_result = epoll_wait(epoll_fd, ready, 8, 1000);
    if (wait_result < 0) CHECK(errno == EINTR);
    CHECK(pthread_join(wake_thread, NULL) == 0);
    CHECK(wait_for(ready, epoll_fd, 4, UINT64_C(0x4097), UINT64_C(0x484f5354),
        UINT64_C(0x45564e54)) == 0);
    char marker = 0; CHECK(pread(log_fd, &marker, 1, 0) == 1 && marker == 'S');

    int close_event = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); CHECK(close_event >= 0);
    int close_epoll = epoll_create1(0); CHECK(close_epoll >= 0);
    event = (struct epoll_event){.events = EPOLLIN, .data.u64 = UINT64_C(0x434c4f53)};
    CHECK(epoll_ctl(close_epoll, EPOLL_CTL_ADD, close_event, &event) == 0);
    struct close_wait_thread_args close_args = {
        .epoll_fd = close_epoll, .event_fd = close_event, .close_result = -2, .write_result = -2};
    pthread_t close_thread; CHECK(pthread_create(&close_thread, NULL,
        close_epoll_and_wake, &close_args) == 0);
    errno = 0;
    int close_count = epoll_wait(close_epoll, ready, 8, 1000);
    CHECK(close_count == 1 && ready[0].data.u64 == UINT64_C(0x434c4f53));
    CHECK(pthread_join(close_thread, NULL) == 0);
    CHECK(close_args.close_result == 0 && close_args.write_result == (int)sizeof(uint64_t));
    CHECK(close(close_event) == 0);

    signal_log_fd = -1; CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    CHECK(close(log_fd) == 0);

    int broken_pipe[2]; CHECK(pipe2(broken_pipe, O_CLOEXEC) == 0);
    CHECK(close(broken_pipe[0]) == 0);
    struct sigaction pipe_action = {.sa_handler = caught_sigpipe};
    struct sigaction previous_pipe_action; sigemptyset(&pipe_action.sa_mask);
    CHECK(sigaction(SIGPIPE, &pipe_action, &previous_pipe_action) == 0);
    caught_sigpipe_count = 0; errno = 0;
    CHECK(write(broken_pipe[1], "host", 4) == -1 && errno == EPIPE);
    CHECK(caught_sigpipe_count == 1);
    CHECK(sigaction(SIGPIPE, &previous_pipe_action, NULL) == 0);
    CHECK(close(broken_pipe[1]) == 0);

    char path[] = "/tmp/ker-preload-host-file-XXXXXX";
    int file_fd = mkstemp(path); CHECK(file_fd >= 0);
    const char file_data[] = "ordinary host file";
    CHECK(write(file_fd, file_data, sizeof(file_data)) == sizeof(file_data));
    CHECK(lseek(file_fd, 0, SEEK_SET) == 0);
    int copied_fd = dup(file_fd); CHECK(copied_fd >= 0);
    char file_result[sizeof(file_data)] = {0};
    CHECK(read(copied_fd, file_result, sizeof(file_result)) == sizeof(file_result));
    CHECK(!memcmp(file_result, file_data, sizeof(file_data)));
    int redirect_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    CHECK(redirect_fd >= 0 && dup2(redirect_fd, 30) == 30);
    CHECK(dup2(30, 30) == 30);
    CHECK(dup2(file_fd, 30) == 30);
    CHECK(close(30) == 0);
    CHECK(close(redirect_fd) == 0 && close(copied_fd) == 0 && close(file_fd) == 0);
    CHECK(unlink(path) == 0);

    int remote = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(remote >= 0);
    int type = 0; socklen_t type_length = sizeof(type);

    int host_fifo[2]; CHECK(pipe2(host_fifo, O_CLOEXEC) == 0);
    int close_in_handler = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(close_in_handler >= 0);
    int handler_pipe[2]; CHECK(pipe2(handler_pipe, O_CLOEXEC) == 0);
    rpc_signal_close_fd = close_in_handler;
    rpc_signal_pipe_write_fd = handler_pipe[1];
    rpc_signal_seen = 0;
    rpc_signal_close_result = -2;
    rpc_signal_write_result = -2;
    struct sigaction rpc_action = {.sa_handler = rpc_signal_handler};
    struct sigaction previous_rpc_action; sigemptyset(&rpc_action.sa_mask);
    CHECK(sigaction(SIGUSR2, &rpc_action, &previous_rpc_action) == 0);
    puts("BROKER_STOP_HOST_FIFO"); fflush(stdout);
    char gate = 0;
    CHECK(read(STDIN_FILENO, &gate, 1) == 1 && gate == 'H');
    CHECK(write(host_fifo[1], "F", 1) == 1);
    CHECK(read(host_fifo[0], &gate, 1) == 1 && gate == 'F');
    puts("HOST_FIFO_WRITE_OK"); fflush(stdout);

    puts("BROKER_STOP_SIGNAL_RPC"); fflush(stdout);
    CHECK(read(STDIN_FILENO, &gate, 1) == 1 && gate == 'R');
    CHECK(getsockopt(remote, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 && type == SOCK_STREAM);
    CHECK(rpc_signal_seen == 1 && rpc_signal_close_result == 0 &&
        rpc_signal_write_result == 1);
    char signal_marker = 0;
    CHECK(read(handler_pipe[0], &signal_marker, 1) == 1 && signal_marker == 'R');
    CHECK(sigaction(SIGUSR2, &previous_rpc_action, NULL) == 0);
    rpc_signal_close_fd = -1;
    rpc_signal_pipe_write_fd = -1;
    CHECK(close(handler_pipe[0]) == 0 && close(handler_pipe[1]) == 0);
    CHECK(close(host_fifo[0]) == 0 && close(host_fifo[1]) == 0);
    errno = 0; CHECK(dup2(remote, 17) == -1 && errno == EOPNOTSUPP);
    CHECK(close(remote) == 0);

    int epoll_alias = dup(epoll_fd); CHECK(epoll_alias >= 0);
    CHECK(close(epoll_alias) == 0);
    int inner_epoll = epoll_create1(EPOLL_CLOEXEC); CHECK(inner_epoll >= 0);
    int inner_alias = dup(inner_epoll); CHECK(inner_alias >= 0);
    int host_outer = (int)syscall(SYS_epoll_create1, EPOLL_CLOEXEC);
    CHECK(host_outer >= 0);
    struct epoll_event nested_event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x4e455354)};
    errno = 0;
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inner_epoll, &nested_event) == -1 &&
        errno == EOPNOTSUPP);
    errno = 0;
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inner_alias, &nested_event) == -1 &&
        errno == EOPNOTSUPP);
    errno = 0;
    CHECK(epoll_ctl(host_outer, EPOLL_CTL_ADD, inner_epoll, &nested_event) == -1 &&
        errno == EOPNOTSUPP);
    errno = 0;
    CHECK(epoll_ctl(host_outer, EPOLL_CTL_ADD, inner_alias, &nested_event) == -1 &&
        errno == EOPNOTSUPP);
    CHECK(close(host_outer) == 0 && close(inner_alias) == 0 && close(inner_epoll) == 0);
    CHECK(fcntl(epoll_fd, F_SETFD, 0) == 0);
    errno = 0;
    char *arguments[] = {(char *)"/bin/true", NULL};
    char *environment[] = {NULL};
    CHECK(execve(arguments[0], arguments, environment) == -1 && errno == EOPNOTSUPP);
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event_fd, NULL) == 0);
    CHECK(close(event_fd) == 0 && close(host_pair[0]) == 0 && close(host_pair[1]) == 0);
    CHECK(close(epoll_fd) == 0);
    (void)inherited_epoll;
    return 0;
}

static int exec_list_checks(void)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        typedef int (*execl_fn)(const char *, const char *, ...);
        execl_fn invoke_execl = execl;
        errno = 0;
        int result = invoke_execl("/ker/no-such-executable", (char *)NULL);
        _exit(result == -1 && errno == ENOENT ? 0 : 101);
    }
    int status = 0; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    child = fork(); CHECK(child >= 0);
    if (child == 0) {
        typedef int (*execle_fn)(const char *, const char *, ...);
        execle_fn invoke_execle = execle;
        char *const environment[] = {"KER_EXECLE_TEST=ok", NULL};
        errno = 0;
        int result = invoke_execle("/ker/no-such-executable", (char *)NULL,
            environment);
        _exit(result == -1 && errno == ENOENT ? 0 : 102);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    child = fork(); CHECK(child >= 0);
    if (child == 0) {
        char *const environment[] = {"KER_EXECLE_TEST=ok", NULL};
        execle("/bin/sh", "sh", "-c", "test \"$KER_EXECLE_TEST\" = ok",
            (char *)NULL, environment);
        _exit(103);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    child = fork(); CHECK(child >= 0);
    if (child == 0) {
        execlp("sh", "sh", "-c", "exit 0", (char *)NULL);
        _exit(104);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int exec_mode(int listener, int accepted)
{
    struct sockaddr_in local = {0}, peer = {0};
    socklen_t length = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr *)&local, &length) == 0 && local.sin_port == htons(4097));
    length = sizeof(peer);
    CHECK(getpeername(accepted, (struct sockaddr *)&peer, &length) == 0 && peer.sin_family == AF_INET);
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC); CHECK(epoll_fd >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x41434350)};
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accepted, &event) == 0);
    event = (struct epoll_event){.events = EPOLLIN, .data.u64 = UINT64_C(0x4c495354)};
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &event) == 0);
    puts("CHILD_READY"); fflush(stdout);
    struct epoll_event ready[8];
    CHECK(wait_for(ready, epoll_fd, 1, UINT64_C(0x41434350), 0, 0) == 0);
    unsigned char received[4097], expected[4097]; fill(expected, sizeof(expected), 93);
    CHECK(read_exact(accepted, received, sizeof(received)) == 0);
    CHECK(!memcmp(received, expected, sizeof(expected)));
    CHECK(write_exact(accepted, received, sizeof(received)) == 0);
    struct sigaction pipe_action = {.sa_handler = caught_sigpipe};
    struct sigaction previous_pipe_action; sigemptyset(&pipe_action.sa_mask);
    CHECK(sigaction(SIGPIPE, &pipe_action, &previous_pipe_action) == 0);
    caught_sigpipe_count = 0;
    CHECK(shutdown(accepted, SHUT_WR) == 0);
    errno = 0;
    CHECK(write(accepted, "closed", 6) == -1 && errno == EPIPE);
    CHECK(caught_sigpipe_count == 1);
    CHECK(sigaction(SIGPIPE, &previous_pipe_action, NULL) == 0);
    puts("STREAM_OK"); fflush(stdout);
    int second = -1;
    for (unsigned attempt = 0; attempt < 10000 && second < 0; ++attempt) {
        int amount = epoll_wait(epoll_fd, ready, 8, 1000);
        CHECK(amount >= 0);
        for (int i = 0; i < amount; ++i) if (ready[i].data.u64 == UINT64_C(0x4c495354)) {
            second = accept4(listener, NULL, NULL, SOCK_CLOEXEC); break;
        }
    }
    CHECK(second >= 0);
    puts("SECOND_ACCEPTED"); fflush(stdout);
    unsigned char request[12] = {0};
    CHECK(read_exact(second, request, sizeof(request)) == 0 && !memcmp(request, "FRESH-ACCEPT", 12));
    const unsigned char reply[] = "REPLY-TWO";
    CHECK(write_exact(second, reply, sizeof(reply) - 1) == 0);
    CHECK(close(second) == 0 && close(accepted) == 0 && close(listener) == 0 && close(epoll_fd) == 0);
    puts("CHILD_DONE"); fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "exec"))
        return exec_mode(parse_fd(argv[2]), parse_fd(argv[3]));
    if (argc != 3) { fprintf(stderr, "usage: preload-client <listener-fd> <epoll-fd>\n"); return 2; }
    int listener = parse_fd(argv[1]), inherited_epoll = parse_fd(argv[2]);
    CHECK(listener >= 0 && inherited_epoll >= 0);
    CHECK(common_checks(listener, inherited_epoll) == 0);
    CHECK(fcntl(inherited_epoll, F_SETFD, FD_CLOEXEC) == 0);
    CHECK(exec_list_checks() == 0);
    int accepted = -1;
    puts("PARENT_READY"); fflush(stdout);
    struct epoll_event ready[8];
    for (unsigned attempt = 0; attempt < 10000 && accepted < 0; ++attempt) {
        int amount = epoll_wait(inherited_epoll, ready, 8, 1000);
        CHECK(amount >= 0);
        for (int i = 0; i < amount; ++i) if (ready[i].data.u64 == UINT64_C(0x4097)) {
            unsigned char peer_name[4] = {0xaa, 0xaa, 0xaa, 0xaa}; socklen_t peer_length = 2;
            accepted = accept4(listener, (struct sockaddr *)peer_name, &peer_length, SOCK_NONBLOCK);
            if (accepted >= 0) CHECK(peer_length == sizeof(struct sockaddr_in) &&
                peer_name[2] == 0xaa && peer_name[3] == 0xaa);
            break;
        }
    }
    CHECK(accepted >= 0);
    int epoll_fd = epoll_create1(0); CHECK(epoll_fd >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x505245)};
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accepted, &event) == 0);
    event = (struct epoll_event){.events = EPOLLIN, .data.u64 = UINT64_C(0x4c495354)};
    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &event) == 0);
    CHECK(fcntl(epoll_fd, F_SETFD, FD_CLOEXEC) == 0);
    puts("ACCEPTED_FIRST"); fflush(stdout);
    CHECK(wait_for(ready, epoll_fd, 1, UINT64_C(0x505245), 0, 0) == 0);
    unsigned char first[24], first_expected[24]; fill(first_expected, sizeof(first_expected), 17);
    CHECK(read_exact(accepted, first, sizeof(first)) == 0 && !memcmp(first, first_expected, sizeof(first)));
    CHECK(write_exact(accepted, first, sizeof(first)) == 0);
    puts("PREFORK_STREAM_OK"); fflush(stdout);

    int ack[2]; CHECK(pipe2(ack, O_CLOEXEC) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        (void)syscall(SYS_close, ack[0]);
        struct sockaddr_in peer = {0}; socklen_t peer_length = sizeof(peer);
        if (getpeername(accepted, (struct sockaddr *)&peer, &peer_length) ||
            peer.sin_family != AF_INET || write(ack[1], "A", 1) != 1) {
            dprintf(STDERR_FILENO, "preload child reconnect failed: %s\n", strerror(errno)); _exit(121);
        }
        (void)syscall(SYS_close, ack[1]);
        char listener_text[24], accepted_text[24];
        snprintf(listener_text, sizeof(listener_text), "%d", listener);
        snprintf(accepted_text, sizeof(accepted_text), "%d", accepted);
        char *args[] = {argv[0], (char *)"exec", listener_text, accepted_text, NULL};
        execve(argv[0], args, environ);
        dprintf(STDERR_FILENO, "preload child exec failed: %s\n", strerror(errno));
        _exit(122);
    }
    (void)syscall(SYS_close, ack[1]);
    char acknowledgement = 0;
    CHECK(read(ack[0], &acknowledgement, 1) == 1 && acknowledgement == 'A');
    CHECK(close(ack[0]) == 0);
    CHECK(close(accepted) == 0 && close(listener) == 0 && close(epoll_fd) == 0 && close(inherited_epoll) == 0);
    int status = 0; pid_t waited = waitpid(child, &status, 0);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        dprintf(STDERR_FILENO, "preload child failed: waited=%ld status=%#x\n", (long)waited, status);
        return 1;
    }
    return 0;
}
