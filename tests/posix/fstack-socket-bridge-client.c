#define _GNU_SOURCE
#include <ff_api.h>
#include <ker/socket-broker.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t public_symbol_calls;
static volatile sig_atomic_t descriptor_interposition_guard;
static volatile sig_atomic_t descriptor_interposition_calls;
intptr_t ngx_max_sockets = 1024;
int is_fstack_fd(int fd) { return fd >= ngx_max_sockets; }

int socket(int domain, int type, int protocol)
{ (void)domain; (void)type; (void)protocol; ++public_symbol_calls; errno = EDEADLK; return -1; }
ssize_t read(int fd, void *buffer, size_t length)
{ (void)fd; (void)buffer; (void)length; ++public_symbol_calls; errno = EDEADLK; return -1; }
ssize_t write(int fd, const void *buffer, size_t length)
{ (void)fd; (void)buffer; (void)length; ++public_symbol_calls; errno = EDEADLK; return -1; }
int accept(int fd, struct sockaddr *address, socklen_t *length)
{ (void)fd; (void)address; (void)length; ++public_symbol_calls; errno = EDEADLK; return -1; }

static int (*next_dup_function(void))(int)
{
    static int (*function)(int);
    if (!function) function = (int (*)(int))dlsym(RTLD_NEXT, "dup");
    return function;
}

int dup(int old_fd)
{
    if (descriptor_interposition_guard) {
        ++descriptor_interposition_calls;
        errno = EDEADLK;
        return -1;
    }
    int (*next)(int) = next_dup_function();
    if (!next) { errno = ENOSYS; return -1; }
    return next(old_fd);
}

static int fcntl_command_has_no_argument(int command)
{
    switch (command) {
    case F_GETFD: case F_GETFL: case F_GETOWN:
#ifdef F_GETLEASE
    case F_GETLEASE:
#endif
#ifdef F_GETSIG
    case F_GETSIG:
#endif
#ifdef F_GETPIPE_SZ
    case F_GETPIPE_SZ:
#endif
#ifdef F_GET_SEALS
    case F_GET_SEALS:
#endif
        return 1;
    default: return 0;
    }
}

static int fcntl_command_has_pointer_argument(int command)
{
    switch (command) {
    case F_GETLK: case F_SETLK: case F_SETLKW:
#ifdef F_OFD_GETLK
    case F_OFD_GETLK: case F_OFD_SETLK: case F_OFD_SETLKW:
#endif
#ifdef F_GETOWN_EX
    case F_GETOWN_EX: case F_SETOWN_EX:
#endif
#ifdef F_GET_RW_HINT
    case F_GET_RW_HINT: case F_SET_RW_HINT:
#endif
#ifdef F_GET_FILE_RW_HINT
    case F_GET_FILE_RW_HINT: case F_SET_FILE_RW_HINT:
#endif
        return 1;
    default: return 0;
    }
}

int fcntl(int fd, int command, ...)
{
    if (descriptor_interposition_guard) {
        ++descriptor_interposition_calls;
        errno = EDEADLK;
        return -1;
    }
    static int (*next)(int, int, ...);
    if (!next) next = (int (*)(int, int, ...))dlsym(RTLD_NEXT, "fcntl");
    if (!next) { errno = ENOSYS; return -1; }
    if (fcntl_command_has_no_argument(command)) return next(fd, command);
    va_list arguments;
    va_start(arguments, command);
    int result;
    if (fcntl_command_has_pointer_argument(command))
        result = next(fd, command, va_arg(arguments, void *));
    else
        result = next(fd, command, va_arg(arguments, int));
    va_end(arguments);
    return result;
}

static int guarded_ff_dup(int fd)
{
    descriptor_interposition_guard = 1;
    int result = ff_dup(fd);
    descriptor_interposition_guard = 0;
    return result;
}

static int guarded_ff_fcntl(int fd, int command, int argument)
{
    descriptor_interposition_guard = 1;
    int result = ff_fcntl(fd, command, argument);
    descriptor_interposition_guard = 0;
    return result;
}

#define CHECK(expression) do { if (!(expression)) { \
    char line[256]; int size = snprintf(line, sizeof(line), "ff bridge:%d: %s errno=%d\n", \
        __LINE__, #expression, errno); \
    (void)syscall(SYS_write, STDERR_FILENO, line, (size_t)size); return 1; } } while (0)

static void output(const char *text)
{ (void)syscall(SYS_write, STDOUT_FILENO, text, strlen(text)); }

static int descriptor_count_below(unsigned limit);

static int capture_descriptor_set(unsigned limit, unsigned char *set)
{
    for (unsigned fd = 0; fd < limit; ++fd) {
        if (syscall(SYS_fcntl, (int)fd, F_GETFD) >= 0) set[fd] = 1;
        else if (errno != EBADF) return -1;
    }
    return 0;
}

static void make_bytes(unsigned char *bytes, size_t size)
{ for (size_t i = 0; i < size; ++i) bytes[i] = (unsigned char)(i * 31u + 17u); }

static int read_exact(int fd, unsigned char *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t result = ff_read(fd, bytes + offset, size - offset);
        if (result < 0 && (errno == EINTR || errno == EAGAIN)) {
            struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
            continue;
        }
        if (result <= 0) return -1;
        offset += (size_t)result;
    }
    return 0;
}

static int write_exact(int fd, const unsigned char *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t result = ff_write(fd, bytes + offset, size - offset);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return -1;
        offset += (size_t)result;
    }
    return 0;
}

static int verify_native_kqueue_readiness(int fd, int *queue_out,
    int expected_read_bytes, int *fin_seen, const unsigned char *baseline_fds)
{
    int queue = ff_kqueue();
    CHECK(queue >= 0);
    int read_tag = 101, write_tag = 202, user_add_tag = 303, user_trigger_tag = 404;
    struct kevent changes[4], results[4];
    EV_SET(&changes[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, &read_tag);
    EV_SET(&changes[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, &write_tag);
    EV_SET(&changes[2], 0, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, &user_add_tag);
    EV_SET(&changes[3], 0, EVFILT_USER, 0, NOTE_TRIGGER, 0, &user_trigger_tag);

    int have_read = 0, have_write = 0, have_user = 0;
    for (unsigned attempt = 0; attempt < 8 && !(have_read && have_write && have_user);
            ++attempt) {
        struct timespec timeout = {.tv_sec = 1};
        int count = ff_kevent(queue, attempt ? NULL : changes,
            attempt ? 0 : 4, results, 4, &timeout);
        CHECK(count >= 0);
        for (int i = 0; i < count; ++i) {
            if (results[i].filter == EVFILT_READ) {
                CHECK(results[i].udata == &read_tag && results[i].data == expected_read_bytes);
                CHECK(results[i].flags & EV_EOF);
                have_read = 1;
                if (results[i].flags & EV_EOF) *fin_seen = 1;
                CHECK(results[i].fflags == 0);
            } else if (results[i].filter == EVFILT_WRITE) {
                CHECK(results[i].udata == &write_tag && results[i].data > 0);
                CHECK(!(results[i].flags & EV_EOF));
                have_write = 1;
            } else if (results[i].filter == EVFILT_USER) {
                CHECK(results[i].ident == 0 && results[i].udata == &user_trigger_tag &&
                    results[i].fflags == NOTE_FFNOP);
                have_user = 1;
            } else {
                CHECK(0);
            }
        }
    }
    CHECK(have_read && have_write && have_user);

    int alias = dup(queue);
    CHECK(alias >= 0);
    void (*preload_lock)(void) = (void (*)(void))dlsym(RTLD_DEFAULT,
        "ker_sb_preload_lock");
    void (*preload_unlock)(void) = (void (*)(void))dlsym(RTLD_DEFAULT,
        "ker_sb_preload_unlock");
    int (*preload_epoll_mapping)(int, int *) = (int (*)(int, int *))
        dlsym(RTLD_DEFAULT, "ker_sb_preload_epoll_fd_locked");
    CHECK(preload_lock && preload_unlock && preload_epoll_mapping);
    int queue_broker_fd = -1, alias_broker_fd = -1;
    preload_lock();
    int queue_registered = preload_epoll_mapping(queue, &queue_broker_fd);
    int alias_registered = preload_epoll_mapping(alias, &alias_broker_fd);
    preload_unlock();
    CHECK(queue_registered == 1 && alias_registered == 1 &&
        queue_broker_fd >= 0 && alias_broker_fd >= 0 &&
        queue_broker_fd != alias_broker_fd);
    int hidden_fds[16];
    size_t hidden_count = 0;
    for (unsigned candidate = 0; candidate < 4096; ++candidate) {
        if (baseline_fds[candidate] || candidate == (unsigned)queue ||
                candidate == (unsigned)alias ||
                candidate == (unsigned)queue_broker_fd ||
                candidate == (unsigned)alias_broker_fd) continue;
        if (syscall(SYS_fcntl, (int)candidate, F_GETFD) >= 0) {
            CHECK(hidden_count < sizeof(hidden_fds) / sizeof(hidden_fds[0]));
            hidden_fds[hidden_count++] = (int)candidate;
        } else {
            CHECK(errno == EBADF);
        }
    }
    CHECK(hidden_count == 7);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        errno = 0;
        int result = ff_kevent(alias, NULL, 0, results, 1,
            &(struct timespec){.tv_nsec = 1000000});
        int kevent_error = errno;
        /* Child atfork cleanup closes read/write/user app+broker epoll pairs
         * and the private USER eventfd, while retaining public kqueue aliases. */
        int hidden_closed = 1;
        for (size_t i = 0; i < hidden_count; ++i) {
            errno = 0;
            if (syscall(SYS_fcntl, hidden_fds[i], F_GETFD) >= 0 || errno != EBADF)
                hidden_closed = 0;
        }
        if (syscall(SYS_fcntl, queue_broker_fd, F_GETFD) < 0 ||
                syscall(SYS_fcntl, alias_broker_fd, F_GETFD) < 0)
            hidden_closed = 0;
        _exit(result == -1 && kevent_error == EOPNOTSUPP && hidden_closed &&
            syscall(SYS_fcntl, alias, F_GETFD) >= 0 ? 0 : 91);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    CHECK(close(queue) == 0);
    errno = 0;
    CHECK(syscall(SYS_fcntl, queue_broker_fd, F_GETFD) < 0 && errno == EBADF);
    CHECK(syscall(SYS_fcntl, alias_broker_fd, F_GETFD) >= 0);
    *queue_out = alias;
    return 0;
}

static int wait_native_kqueue_reset(int queue, int fd)
{
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        struct kevent results[4];
        struct timespec timeout = {.tv_sec = 1};
        int count = ff_kevent(queue, NULL, 0, results, 4, &timeout);
        CHECK(count >= 0);
        for (int i = 0; i < count; ++i) {
            if (results[i].filter != EVFILT_READ || !(results[i].flags & EV_EOF)) continue;
            CHECK(results[i].fflags == ECONNRESET);
            int socket_error = 0;
            socklen_t length = sizeof(socket_error);
            CHECK(ff_getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) == 0);
            CHECK(length == sizeof(socket_error) && socket_error == ECONNRESET);
            return 0;
        }
    }
    CHECK(0);
    return 1;
}

static int wait_native_kqueue_fin(int queue)
{
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        struct kevent results[4];
        struct timespec timeout = {.tv_sec = 1};
        int count = ff_kevent(queue, NULL, 0, results, 4, &timeout);
        CHECK(count >= 0);
        for (int i = 0; i < count; ++i) {
            if (results[i].filter == EVFILT_READ && (results[i].flags & EV_EOF)) {
                CHECK(results[i].data == 0 && results[i].fflags == 0);
                return 0;
            }
        }
    }
    CHECK(0);
    return 1;
}

static int wait_native_kqueue_write_eof(int queue)
{
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        struct kevent results[4];
        struct timespec timeout = {.tv_sec = 1};
        int count = ff_kevent(queue, NULL, 0, results, 4, &timeout);
        CHECK(count >= 0);
        for (int i = 0; i < count; ++i) {
            if (results[i].filter != EVFILT_WRITE) continue;
            CHECK(results[i].flags & EV_EOF);
            CHECK(results[i].fflags == 0);
            return 0;
        }
    }
    CHECK(0);
    return 1;
}

static int verify_native_kqueue_reset_connection(const struct sockaddr_in *address)
{
    int fd = ff_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0 && ff_socket_drain_count() == 1);
    output("FF_RESET_CONNECTING\n");
    int result = ff_connect(fd, (const struct linux_sockaddr *)address,
        sizeof(*address));
    CHECK(result == 0 || (result == -1 &&
        (errno == EINPROGRESS || errno == EALREADY || errno == EINTR)));
    int connected = 0;
    struct linux_sockaddr peer = {0};
    socklen_t peer_length = sizeof(peer);
    for (unsigned attempt = 0; attempt < 2000; ++attempt) {
        peer_length = sizeof(peer);
        if (ff_getpeername(fd, &peer, &peer_length) == 0) { connected = 1; break; }
        if (errno != ENOTCONN && errno != EINVAL) return 1;
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    }
    CHECK(connected);
    output("FF_RESET_CONNECTED\n");

    int queue = ff_kqueue();
    CHECK(queue >= 0);
    int read_tag = 505;
    struct kevent change;
    EV_SET(&change,fd,EVFILT_READ,EV_ADD|EV_CLEAR,0,0,&read_tag);
    CHECK(ff_kevent(queue,&change,1,NULL,0,NULL)==0);
    CHECK(wait_native_kqueue_reset(queue,fd)==0);
    CHECK(close(queue)==0);
    CHECK(ff_close(fd)==0 && ff_socket_drain_count()==0);
    output("HARD_ERROR_NONCONSUMING_OK\n");
    return 0;
}

static int descriptor_count_below(unsigned limit)
{
    int count = 0;
    for (unsigned fd = 0; fd < limit; ++fd) {
        if (syscall(SYS_fcntl, (int)fd, F_GETFD) >= 0) {
            ++count;
        } else if (errno != EBADF) {
            return -1;
        }
    }
    return count;
}

static int ff_dup_emfile_child(int fd, int expected_count)
{
    if (ff_socket_drain_count() != expected_count) return 81;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0 || limit.rlim_max < 128) return 82;
    limit.rlim_cur = 128;
    if (setrlimit(RLIMIT_NOFILE, &limit) < 0) return 83;

    int fillers[128];
    size_t count = 0;
    for (; count < sizeof(fillers) / sizeof(fillers[0]); ++count) {
        fillers[count] = (int)syscall(SYS_eventfd2, 0, EFD_CLOEXEC);
        if (fillers[count] < 0) break;
    }
    if (count == 0 || count == sizeof(fillers) / sizeof(fillers[0]) || errno != EMFILE)
        return 84;
    int hole = fillers[count - 1];
    if (syscall(SYS_close, hole) < 0) return 85;
    int before = descriptor_count_below(128);
    if (before != 127) return 86;

    errno = 0;
    if (guarded_ff_dup(fd) != -1 || errno != EMFILE || descriptor_interposition_calls)
        return 87;
    int after = descriptor_count_below(128);
    if (after != before || syscall(SYS_fcntl, hole, F_GETFD) >= 0 || errno != EBADF)
        return 88;
    if (ff_socket_drain_count() != expected_count) return 89;
    int enabled = 0;
    socklen_t length = sizeof(enabled);
    if (ff_getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, &length) < 0 ||
            enabled != 1 || length != sizeof(enabled)) return 90;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--broker-death-census") == 0) {
        int fd = ff_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(fd >= 0 && ff_socket_drain_count() == 1);
        output("DRAIN_FAILURE_READY\n");
        char trigger = 0;
        CHECK(syscall(SYS_read, STDIN_FILENO, &trigger, 1) == 1 && trigger == 'F');
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) _exit(ff_socket_drain_count() < 0 ? 77 : 0);
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
            WTERMSIG(status) == SIGABRT);
        output("DRAIN_FAILURE_OK\n");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--failure-census") == 0) {
        (void)ff_socket_drain_count();
        return 75;
    }
    if (argc == 3 && strcmp(argv[1], "--exec-census") == 0) {
        CHECK(ff_socket_drain_count() == atoi(argv[2]));
        return 0;
    }
    CHECK(argc == 2);
    struct rlimit descriptor_limit;
    CHECK(getrlimit(RLIMIT_NOFILE, &descriptor_limit) == 0);
    if (descriptor_limit.rlim_cur <= (rlim_t)ngx_max_sockets) {
        descriptor_limit.rlim_cur = (rlim_t)ngx_max_sockets + 128;
        CHECK(descriptor_limit.rlim_cur <= descriptor_limit.rlim_max &&
            setrlimit(RLIMIT_NOFILE, &descriptor_limit) == 0);
    }
    CHECK(ff_socket_drain_count() == 0);
    int inherited_capability = atoi(argv[1]);
    CHECK(syscall(SYS_fcntl, inherited_capability, F_GETFD) >= 0);
    CHECK(guarded_ff_dup(inherited_capability) == -1 && errno == EOPNOTSUPP);
    CHECK(syscall(SYS_fcntl, inherited_capability, F_GETFD) >= 0);
    CHECK(ff_socket(AF_INET, SOCK_DGRAM, 0) == -1 && errno == EOPNOTSUPP);
    int host_socket = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(host_socket >= 0);
    CHECK(guarded_ff_dup(host_socket) == -1 && errno == EOPNOTSUPP);
    CHECK(syscall(SYS_fcntl, host_socket, F_GETFD) >= 0);
    int invalid_ff_fd = (int)syscall(SYS_fcntl, host_socket, F_DUPFD_CLOEXEC,
        (int)ngx_max_sockets);
    CHECK(invalid_ff_fd >= ngx_max_sockets && syscall(SYS_close, invalid_ff_fd) == 0);
    CHECK(guarded_ff_dup(invalid_ff_fd) == -1 && errno == EBADF);
    CHECK(ff_socket_drain_count() == 0);
    int host_udp = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(host_udp >= 0 && ff_socket_drain_count() == 0);
    CHECK(syscall(SYS_close, host_udp) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_port = htons(4097), .sin_addr.s_addr = htonl(0xc6120001u)};
    CHECK(ff_connect(host_socket, (const struct linux_sockaddr *)&address,
        sizeof(address)) == -1 && errno == EOPNOTSUPP);
    struct sockaddr_in observed_peer = {0}; socklen_t observed_length = sizeof(observed_peer);
    errno = 0;
    CHECK(syscall(SYS_getpeername, host_socket, &observed_peer, &observed_length) == -1 &&
        errno == ENOTCONN);
    CHECK(ff_write(host_socket, "x", 1) == -1 && errno == EOPNOTSUPP);
    CHECK(syscall(SYS_close, host_socket) == 0);
    int ipv6_socket = ff_socket(AF_INET6_LINUX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(ipv6_socket >= 0 && ff_socket_drain_count() == 1);
    CHECK(ff_close(ipv6_socket) == 0 && ff_socket_drain_count() == 0);
    int pipe_fds[2];
    CHECK(syscall(SYS_pipe2, pipe_fds, O_CLOEXEC) == 0);
    CHECK(guarded_ff_dup(pipe_fds[0]) == -1 && errno == EOPNOTSUPP);
    CHECK(ff_write(pipe_fds[1], "x", 1) == -1 && errno == EOPNOTSUPP);
    CHECK(ff_close(pipe_fds[0]) == -1 && errno == EOPNOTSUPP);
#ifdef FIOCLEX
    CHECK(ff_ioctl(pipe_fds[0], FIOCLEX) == -1 && errno == EOPNOTSUPP);
#endif
    CHECK(syscall(SYS_write, pipe_fds[1], "p", 1) == 1);
    char pipe_byte = 0;
    CHECK(syscall(SYS_read, pipe_fds[0], &pipe_byte, 1) == 1 && pipe_byte == 'p');
    CHECK(syscall(SYS_close, pipe_fds[0]) == 0 && syscall(SYS_close, pipe_fds[1]) == 0);
    int listener = ff_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0 && ff_socket_drain_count() == 1);
    struct sockaddr_in local = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(ff_bind(listener, (const struct linux_sockaddr *)&local, sizeof(local)) == 0);
    int signal_fds[2];
    CHECK(syscall(SYS_pipe2, signal_fds, O_CLOEXEC) == 0);
    pid_t listener_child = fork();
    CHECK(listener_child >= 0);
    if (listener_child == 0) {
        (void)syscall(SYS_close, signal_fds[0]);
        char ready = 'L';
        if (ff_listen(listener, 4) != 0 ||
            syscall(SYS_write, signal_fds[1], &ready, 1) != 1) _exit(72);
        _exit(0);
    }
    CHECK(syscall(SYS_close, signal_fds[1]) == 0);
    char listener_ready = 0;
    CHECK(syscall(SYS_read, signal_fds[0], &listener_ready, 1) == 1 && listener_ready == 'L');
    CHECK(syscall(SYS_close, signal_fds[0]) == 0);
    int listener_status = 0;
    CHECK(waitpid(listener_child, &listener_status, 0) == listener_child &&
        WIFEXITED(listener_status) && WEXITSTATUS(listener_status) == 0);
    CHECK(ff_socket_drain_count() == 0);
    int listener_alias = ff_fcntl(listener, F_DUPFD, (int)ngx_max_sockets);
    CHECK(listener_alias >= ngx_max_sockets && ff_socket_drain_count() == 0);
    CHECK(ff_close(listener) == 0 && ff_socket_drain_count() == 0);
    CHECK(ff_close(listener_alias) == 0 && ff_socket_drain_count() == 0);
    int stale = ff_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(stale >= 0 && ff_socket_drain_count() == 1);
    CHECK(syscall(SYS_close, stale) == 0);
    int replacement = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(replacement >= 0 && replacement == stale && ff_socket_drain_count() == 0);
    CHECK(syscall(SYS_close, replacement) == 0);
    int connection = ff_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(connection >= 0);
    CHECK(ff_socket_drain_count() == 1);
    int enabled = 1;
    CHECK(ff_setsockopt(connection, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) == 0);
    output("FF_CONNECTING\n");
    int connect_result = ff_connect(connection,
        (const struct linux_sockaddr *)&address, sizeof(address));
    CHECK(connect_result == 0 || (connect_result == -1 &&
        (errno == EINPROGRESS || errno == EALREADY || errno == EINTR)));
    struct linux_sockaddr peer = {0}; socklen_t peer_length = sizeof(peer);
    int connected = 0;
    for (unsigned attempt = 0; attempt < 2000; ++attempt) {
        peer_length = sizeof(peer);
        if (ff_getpeername(connection, &peer, &peer_length) == 0) { connected = 1; break; }
        if (errno != ENOTCONN && errno != EINVAL) return 1;
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    }
    CHECK(connected);
    CHECK(peer_length == sizeof(address));
    CHECK(ff_socket_drain_count() == 1);
    int hole = (int)syscall(SYS_dup, connection);
    CHECK(hole >= 0 && syscall(SYS_close, hole) == 0);
    int alias = guarded_ff_dup(connection);
    CHECK(alias == hole);
    CHECK(descriptor_interposition_calls == 0);
    CHECK((ff_fcntl(alias, F_GETFD) & FD_CLOEXEC) == 0);
    CHECK(ff_socket_drain_count() == 2);
    uint64_t connection_cookie = 0, alias_cookie = 0;
    socklen_t cookie_length = sizeof(connection_cookie);
    CHECK(ff_getsockopt(connection, SOL_SOCKET, SO_COOKIE, &connection_cookie,
        &cookie_length) == 0 && cookie_length == sizeof(connection_cookie));
    cookie_length = sizeof(alias_cookie);
    CHECK(ff_getsockopt(alias, SOL_SOCKET, SO_COOKIE, &alias_cookie,
        &cookie_length) == 0 && cookie_length == sizeof(alias_cookie));
    CHECK(connection_cookie != 0 && alias_cookie == connection_cookie);
    int keepalive = 0;
    socklen_t keepalive_length = sizeof(keepalive);
    CHECK(ff_getsockopt(alias, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
        &keepalive_length) == 0 && keepalive == 1);
    keepalive = 0;
    CHECK(ff_setsockopt(alias, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
        sizeof(keepalive)) == 0);
    keepalive = 1;
    keepalive_length = sizeof(keepalive);
    CHECK(ff_getsockopt(connection, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
        &keepalive_length) == 0 && keepalive == 0);
    keepalive = 1;
    CHECK(ff_setsockopt(connection, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
        sizeof(keepalive)) == 0);
    keepalive_length = sizeof(keepalive);
    CHECK(ff_getsockopt(alias, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
        &keepalive_length) == 0 && keepalive == 1);
    int nonblocking = 1;
    CHECK(ff_ioctl(alias, FIONBIO, &nonblocking) == 0);
    CHECK(ff_fcntl(connection, F_GETFL) & O_NONBLOCK);
    CHECK(ff_fcntl(alias, F_GETFL) & O_NONBLOCK);
#ifdef F_DUPFD_CLOEXEC
    int direct_cloexec = guarded_ff_fcntl(connection, F_DUPFD_CLOEXEC, 0);
    CHECK(direct_cloexec >= 0 && (ff_fcntl(direct_cloexec, F_GETFD) & FD_CLOEXEC));
    CHECK(ff_socket_drain_count() == 3);
    CHECK(ff_close(direct_cloexec) == 0 && ff_socket_drain_count() == 2);
    int relocated_cloexec = guarded_ff_fcntl(connection, F_DUPFD_CLOEXEC,
        (int)ngx_max_sockets);
    CHECK(relocated_cloexec >= ngx_max_sockets &&
        (ff_fcntl(relocated_cloexec, F_GETFD) & FD_CLOEXEC));
    CHECK(ff_socket_drain_count() == 3);
    CHECK(ff_close(relocated_cloexec) == 0 && ff_socket_drain_count() == 2);
#endif
    int high_alias = guarded_ff_fcntl(connection, F_DUPFD, (int)ngx_max_sockets);
    CHECK(high_alias >= ngx_max_sockets &&
        !(guarded_ff_fcntl(high_alias, F_GETFD, 0) & FD_CLOEXEC));
    CHECK(ff_socket_drain_count() == 3);
    CHECK(ff_close(high_alias) == 0 && ff_socket_drain_count() == 2);
    errno = 0;
    CHECK(guarded_ff_fcntl(connection, F_DUPFD, -1) == -1 && errno == EINVAL);
    errno = 0;
    CHECK((rlim_t)descriptor_limit.rlim_cur <= INT_MAX &&
        guarded_ff_fcntl(connection, F_DUPFD, (int)descriptor_limit.rlim_cur) == -1 &&
        errno == EINVAL);
    pid_t exhaustion_child = fork();
    CHECK(exhaustion_child >= 0);
    if (exhaustion_child == 0) _exit(ff_dup_emfile_child(connection, 2));
    int exhaustion_status = 0;
    CHECK(waitpid(exhaustion_child, &exhaustion_status, 0) == exhaustion_child &&
        WIFEXITED(exhaustion_status) && WEXITSTATUS(exhaustion_status) == 0);
    CHECK(ff_socket_drain_count() == 2);
    int duplicate = dup(alias);
    CHECK(duplicate >= 0);
    CHECK(ff_socket_drain_count() == 3);
    CHECK(close(duplicate) == 0 && ff_socket_drain_count() == 2);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(ff_socket_drain_count() == 2 ? 0 : 71);
    int child_status = 0;
    pid_t waited = waitpid(child, &child_status, 0);
    if (waited != child || !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        dprintf(STDERR_FILENO, "fork/exec census child failed: wait=%ld status=%#x\n",
            (long)waited, child_status);
        return 1;
    }
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (fcntl(atoi(argv[1]), F_SETFD, FD_CLOEXEC) < 0) _exit(75);
        execl("/proc/self/exe", "fstack-socket-bridge-client", "--exec-census", "1", NULL);
        dprintf(STDERR_FILENO, "exec census child exec failed: errno=%d\n", errno);
        _exit(73);
    }
    waited = waitpid(child, &child_status, 0);
    if (waited != child || !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        dprintf(STDERR_FILENO, "fork/exec census child failed: wait=%ld status=%#x\n",
            (long)waited, child_status);
        return 1;
    }
    CHECK(ff_close(connection) == 0);
    CHECK(ff_socket_drain_count() == 1);
    CHECK(ff_fcntl(alias, F_GETFL) >= 0);
    socklen_t invalid_length = sizeof(peer);
    CHECK(ff_getpeername(alias, (struct linux_sockaddr *)(uintptr_t)1,
        &invalid_length) == -1 && errno == EFAULT);
    CHECK(ff_fcntl(alias, F_SETFL, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(ff_poll(NULL, 0, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(ff_sendto(alias, "x", 1, 0, NULL, 0) == -1 && errno == EOPNOTSUPP);
    output("FF_CONNECTED\n");
    unsigned char input[4097], expected[4097], output_bytes[4097];
    make_bytes(expected, sizeof(expected));
    int queued = 0;
    for (unsigned attempt = 0; attempt < 5000; ++attempt) {
        if (ff_ioctl(alias, FIONREAD, &queued) == 0 && queued > 0) break;
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    }
    CHECK(queued == (int)sizeof(input));
    int descriptor_count_before_kqueue = descriptor_count_below(4096);
    CHECK(descriptor_count_before_kqueue > 0);
    unsigned char baseline_fds[4096] = {0};
    CHECK(capture_descriptor_set(4096, baseline_fds) == 0);
    int bridge_queue = -1, graceful_fin_seen = 0;
    CHECK(verify_native_kqueue_readiness(alias, &bridge_queue, queued,
        &graceful_fin_seen, baseline_fds) == 0);
    /* A bad write pointer must fail before changing the remote stream. */
    CHECK(ff_write(alias, (const void *)(uintptr_t)1, 1) == -1 && errno == EFAULT);
    CHECK(read_exact(alias, input, sizeof(input)) == 0);
    CHECK(memcmp(input, expected, sizeof(input)) == 0);
    if (!graceful_fin_seen) CHECK(wait_native_kqueue_fin(bridge_queue) == 0);
    memcpy(output_bytes, input, sizeof(input));
    CHECK(write_exact(alias, output_bytes, sizeof(output_bytes)) == 0);
    CHECK(ff_shutdown(alias, SHUT_WR) == 0);
    CHECK(wait_native_kqueue_write_eof(bridge_queue) == 0);
    CHECK(close(bridge_queue) == 0);
    CHECK(descriptor_count_below(4096) == descriptor_count_before_kqueue);
    CHECK(public_symbol_calls == 0);
    CHECK(ff_close(alias) == 0);
    CHECK(ff_socket_drain_count() == 0);
    CHECK(verify_native_kqueue_reset_connection(&address) == 0);
    const char *broker_path = getenv("KER_SOCKET_BROKER_PATH");
    CHECK(broker_path && *broker_path);
    struct ker_socket_client broker_client = {.session_fd = -1};
    CHECK(ker_socket_client_open(&broker_client, broker_path) == 0);
    int udp_capability = ker_socket_client_socket(&broker_client, AF_INET, SOCK_DGRAM, 0);
    CHECK(udp_capability >= 0);
    ker_socket_client_close(&broker_client);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (fcntl(atoi(argv[1]), F_SETFD, FD_CLOEXEC) < 0) _exit(76);
        execl("/proc/self/exe", "fstack-socket-bridge-client", "--exec-census", "1", NULL);
        dprintf(STDERR_FILENO, "UDP census child exec failed: errno=%d\n", errno);
        _exit(74);
    }
    CHECK(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status) &&
        WEXITSTATUS(child_status) == 0);
    CHECK(syscall(SYS_close, udp_capability) == 0);
    CHECK(ff_socket_drain_count() == 0);
    int composite_epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(composite_epoll >= 0);
    CHECK(guarded_ff_dup(composite_epoll) == -1 && errno == EOPNOTSUPP);
    CHECK(ff_close(composite_epoll) == -1 && errno == EOPNOTSUPP);
    CHECK(fcntl(composite_epoll, F_GETFD) >= 0);
    CHECK(close(composite_epoll) == 0);
    output("FF_STREAM_OK\n");
    return 0;
}
