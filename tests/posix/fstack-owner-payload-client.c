#define _GNU_SOURCE
#include <ff_api.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int ff_init(int argc, char * const argv[]);
int ff_syncache_count(void);

intptr_t ngx_max_sockets = 1024;
int is_fstack_fd(int fd) { return fd >= ngx_max_sockets; }

#define CHECK(condition) do { if (!(condition)) { \
    char message[256]; \
    int length = snprintf(message, sizeof(message), \
        "ff owner payload client:%d: %s errno=%d\n", __LINE__, #condition, errno); \
    if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message, (size_t)length); \
    return 1; \
} } while (0)

static void output(const char *message)
{
    (void)syscall(SYS_write, STDOUT_FILENO, message, strlen(message));
}

static int initialize_runtime(void)
{
    const char *broker = getenv("KER_SOCKET_BROKER_PATH");
    if (!broker || !*broker) { errno = ENOTCONN; return -1; }
    char path[128], conf_arg[160], contents[512];
    int n = snprintf(path, sizeof(path), "/tmp/ker-c12-owner-%ld.ini", (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return -1; }
    n = snprintf(contents, sizeof(contents),
        "[ker_socket_broker]\nversion=1\npath=%s\n[dpdk]\ngraceful_reload=0\n", broker);
    if (n <= 0 || (size_t)n >= sizeof(contents)) { errno = ENAMETOOLONG; return -1; }
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ssize_t written = syscall(SYS_write, fd, contents, (size_t)n);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    if (written != n) { (void)syscall(SYS_unlinkat, AT_FDCWD, path, 0); errno = written < 0 ? saved : EIO; return -1; }
    n = snprintf(conf_arg, sizeof(conf_arg), "--conf=%s", path);
    if (n <= 0 || (size_t)n >= sizeof(conf_arg)) {
        (void)syscall(SYS_unlinkat, AT_FDCWD, path, 0); errno = ENAMETOOLONG; return -1;
    }
    char *arguments[] = {"nginx", conf_arg, "--proc-id=0", "--proc-type=primary"};
    int result = ff_init(4, arguments);
    saved = errno;
    (void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
    errno = saved;
    return result;
}

static int write_payload(int fd, unsigned size, unsigned seed)
{
    unsigned char bytes[4096];
    if (size > sizeof(bytes)) { errno = EMSGSIZE; return -1; }
    for (unsigned i = 0; i < size; ++i)
        bytes[i] = (unsigned char)(i * 17u + seed * 29u + 3u);
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = ff_write(fd, bytes + offset, size - offset);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct timespec pause = {.tv_nsec = 1000000};
            (void)nanosleep(&pause, NULL);
            continue;
        }
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int owner_snapshot_loop(int listener)
{
    for (;;) {
        char command = 0;
        ssize_t count = syscall(SYS_read, STDIN_FILENO, &command, 1);
        if (count != 1) return 2;
        if (command == 'E') break;
        if (command != 'S' && command != 'Q' && command != 'A') { errno = EPROTO; return 3; }
        if (command == 'A') {
            if (listener < 0) { errno = EOPNOTSUPP; return 3; }
            int accepted = -1;
            for (unsigned attempt = 0; attempt < 5000; ++attempt) {
                accepted = ff_accept4(listener, NULL, NULL, SOCK_CLOEXEC);
                if (accepted >= 0) break;
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return 5;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            }
            if (accepted < 0) { errno = ETIMEDOUT; return 5; }
            if (ff_close(accepted)) return 5;
            output("OWNER_ACCEPTED\n");
            continue;
        }
        char line[96];
        int value = command == 'Q' ? ff_syncache_count() : ff_socket_snd_pending();
        int length = snprintf(line, sizeof(line), command == 'Q' ?
            "OWNER_REQUESTS %d\n" : "OWNER_SNAPSHOT %d\n", value);
        if (length <= 0 || (size_t)length >= sizeof(line)) return 4;
        output(line);
    }
    if (listener >= 0 && ff_close(listener)) return 5;
    if (listener >= 0 && ff_socket_drain_count() != 0) return 5;
    output("OWNER_DONE\n");
    return 0;
}

static int owner_payload_client(unsigned port, unsigned size, unsigned seed)
{
    CHECK(initialize_runtime() == 0);
    CHECK(ff_syncache_count() == 0);
    CHECK(ff_socket_snd_pending() == 0);
    int fd = ff_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    int send_buffer = 8192;
    CHECK(ff_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
        sizeof(send_buffer)) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(0xc6120001u)};
    int result = ff_connect(fd, (const struct linux_sockaddr *)&address, sizeof(address));
    CHECK(result == 0 || (result == -1 &&
        (errno == EINPROGRESS || errno == EALREADY || errno == EINTR)));
    int connected = 0;
    for (unsigned attempt = 0; attempt < 5000; ++attempt) {
        struct linux_sockaddr peer = {0};
        socklen_t peer_length = sizeof(peer);
        if (ff_getpeername(fd, &peer, &peer_length) == 0) { connected = 1; break; }
        CHECK(errno == ENOTCONN || errno == EINTR || errno == EAGAIN);
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    }
    CHECK(connected);
    CHECK(ff_syncache_count() == 0);
    CHECK(write_payload(fd, size, seed) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (ff_socket_drain_count() != 1) _exit(10);
        (void)ff_socket_snd_pending();
        _exit(11);
    }
    int child_status = 0;
    CHECK(waitpid(child, &child_status, 0) == child &&
        WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGABRT);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        (void)ff_syncache_count();
        _exit(12);
    }
    CHECK(waitpid(child, &child_status, 0) == child &&
        WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGABRT);
    int alias = ff_dup(fd);
    CHECK(alias >= 0 && ff_socket_drain_count() == 2);
    CHECK(ff_close(fd) == 0 && ff_socket_drain_count() == 1);
    CHECK(ff_shutdown(alias, SHUT_WR) == 0);
    CHECK(ff_close(alias) == 0 && ff_socket_drain_count() == 0);
    int listener = ff_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    struct sockaddr_in listen_address = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0xc6120002u)};
    CHECK(ff_bind(listener, (const struct linux_sockaddr *)&listen_address,
        sizeof(listen_address)) == 0);
    CHECK(ff_listen(listener, 16) == 0);
    struct linux_sockaddr bound = {0};
    socklen_t bound_length = sizeof(bound);
    CHECK(ff_getsockname(listener, &bound, &bound_length) == 0 &&
        bound_length == sizeof(struct sockaddr_in));
    unsigned listener_port = ntohs(((struct sockaddr_in *)&bound)->sin_port);
    CHECK(listener_port != 0);
    char listener_line[64];
    int listener_length = snprintf(listener_line, sizeof(listener_line),
        "OWNER_LISTENER %u\n", listener_port);
    CHECK(listener_length > 0 && (size_t)listener_length < sizeof(listener_line));
    output(listener_line);
    CHECK(ff_syncache_count() == 0);
    output("OWNER_READY\n");
    return owner_snapshot_loop(listener);
}

static int owner_reexec_start(unsigned port, unsigned size, unsigned seed,
    const char *executable)
{
    CHECK(initialize_runtime() == 0);
    int fd = ff_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(0xc6120001u)};
    int result = ff_connect(fd, (const struct linux_sockaddr *)&address, sizeof(address));
    CHECK(result == 0 || (result == -1 &&
        (errno == EINPROGRESS || errno == EALREADY || errno == EINTR)));
    int connected = 0;
    for (unsigned attempt = 0; attempt < 5000; ++attempt) {
        struct linux_sockaddr peer = {0}; socklen_t peer_length = sizeof(peer);
        if (ff_getpeername(fd, &peer, &peer_length) == 0) { connected = 1; break; }
        CHECK(errno == ENOTCONN || errno == EINTR || errno == EAGAIN);
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    }
    CHECK(connected && write_payload(fd, size, seed) == 0);
    CHECK(ff_close(fd) == 0);
    output("OWNER_EXEC_READY\n");
    char size_arg[16], seed_arg[16];
    snprintf(size_arg, sizeof(size_arg), "%u", size);
    snprintf(seed_arg, sizeof(seed_arg), "%u", seed);
    execl(executable, executable, "--owner-reexec-snapshot", size_arg,
        seed_arg, (char *)NULL);
    return 12;
}

static int legacy_payload_reexec(unsigned port, unsigned size, unsigned seed,
    const char *executable)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(0xc6120001u)};
    int connected_result = connect(fd, (const struct sockaddr *)&address, sizeof(address));
    CHECK(connected_result == 0 || (connected_result == -1 &&
        (errno == EINPROGRESS || errno == EALREADY || errno == EINTR)));
    int connected = 0;
    for (unsigned attempt = 0; attempt < 5000; ++attempt) {
        struct sockaddr_in peer = {0}; socklen_t peer_length = sizeof(peer);
        if (getpeername(fd, (struct sockaddr *)&peer, &peer_length) == 0) {
            connected = 1; break;
        }
        CHECK(errno == ENOTCONN || errno == EINTR || errno == EAGAIN);
        struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL);
    }
    CHECK(connected);
    unsigned char bytes[4096];
    CHECK(size <= sizeof(bytes));
    for (unsigned i = 0; i < size; ++i)
        bytes[i] = (unsigned char)(i * 17u + seed * 29u + 3u);
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = write(fd, bytes + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0);
        offset += (size_t)count;
    }
    CHECK(close(fd) == 0);
    output("OWNER_LEGACY_EXEC_READY\n");
    char size_arg[16], seed_arg[16];
    snprintf(size_arg, sizeof(size_arg), "%u", size);
    snprintf(seed_arg, sizeof(seed_arg), "%u", seed);
    execl(executable, executable, "--exec-rebegin-refused", size_arg,
        seed_arg, (char *)NULL);
    return 13;
}

static int owner_reexec_snapshot(unsigned size, unsigned seed)
{
    (void)size; (void)seed;
    CHECK(initialize_runtime() == 0);
    return owner_snapshot_loop(-1);
}

static int owner_history_probe(bool before_owner, const char *executable, bool exec_check)
{
    if (exec_check) {
        CHECK(initialize_runtime() != 0);
        output("OWNER_REBEGIN_REFUSED_AFTER_EXEC_HISTORY\n");
        return 0;
    }
    if (!before_owner) CHECK(initialize_runtime() == 0);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    if (before_owner) {
        CHECK(initialize_runtime() != 0);
        output("OWNER_BEGIN_REFUSED_AFTER_LEGACY_HISTORY\n");
        return 0;
    }
    if (executable) {
        execl(executable, executable, "--exec-rebegin-refused", (char *)NULL);
        return 12;
    }
    (void)ff_syncache_count();
    return 5;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--syncache-without-owner") == 0)
        return ff_syncache_count();
    if (argc == 2 && strcmp(argv[1], "--legacy-history") == 0)
        return owner_history_probe(true, NULL, false);
    if (argc == 2 && strcmp(argv[1], "--foreign-history") == 0)
        return owner_history_probe(false, NULL, false);
    if (argc == 2 && strcmp(argv[1], "--foreign-history-exec") == 0)
        return owner_history_probe(false, argv[0], false);
    if (argc == 2 && strcmp(argv[1], "--exec-rebegin-refused") == 0)
        return owner_history_probe(false, NULL, true);
    if (argc == 5 && strcmp(argv[1], "--owner-reexec") == 0) {
        unsigned port = (unsigned)strtoul(argv[2], NULL, 10);
        unsigned size = (unsigned)strtoul(argv[3], NULL, 10);
        unsigned seed = (unsigned)strtoul(argv[4], NULL, 10);
        return owner_reexec_start(port, size, seed, argv[0]);
    }
    if (argc == 4 && strcmp(argv[1], "--owner-reexec-snapshot") == 0) {
        unsigned size = (unsigned)strtoul(argv[2], NULL, 10);
        unsigned seed = (unsigned)strtoul(argv[3], NULL, 10);
        (void)seed;
        return owner_reexec_snapshot(size, seed);
    }
    if (argc == 5 && strcmp(argv[1], "--legacy-payload-reexec") == 0) {
        unsigned port = (unsigned)strtoul(argv[2], NULL, 10);
        unsigned size = (unsigned)strtoul(argv[3], NULL, 10);
        unsigned seed = (unsigned)strtoul(argv[4], NULL, 10);
        return legacy_payload_reexec(port, size, seed, argv[0]);
    }
    if (argc == 4 && strcmp(argv[1], "--exec-rebegin-refused") == 0) {
        unsigned size = (unsigned)strtoul(argv[2], NULL, 10);
        unsigned seed = (unsigned)strtoul(argv[3], NULL, 10);
        (void)size; (void)seed;
        return owner_history_probe(false, NULL, true);
    }
    if (argc != 5 || strcmp(argv[1], "--owner-payload") != 0) {
        fputs("usage: fstack-owner-payload-client --owner-payload PORT BYTES SEED\n", stderr);
        return 2;
    }
    char *end = NULL;
    unsigned long port = strtoul(argv[2], &end, 10);
    if (!end || *end || port < 1 || port > 65535) return 2;
    unsigned long size = strtoul(argv[3], &end, 10);
    if (!end || *end || size < 1 || size > 4096) return 2;
    unsigned long seed = strtoul(argv[4], &end, 10);
    if (!end || *end || seed > 255) return 2;
    return owner_payload_client((unsigned)port, (unsigned)size, (unsigned)seed);
}
