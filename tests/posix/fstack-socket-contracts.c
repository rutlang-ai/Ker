/* Ker-specific socket-contract extensions of pinned F-Stack host bridge cases.
 * Same public POSIX assertions on host Linux and the imported Linux stack. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define ERROR(call, code) do { errno = 0; CHECK((call) == -1); CHECK(errno == (code)); } while (0)
struct pair {int client, server;};
static struct sockaddr_in local(void)
{
    return (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
}
static int listen_at(struct sockaddr_in *address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0 && bind(fd, (void *)address, sizeof(*address)) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof(*address);
    CHECK(getsockname(fd, (void *)address, &length) == 0 && length == sizeof(*address));
    return fd;
}
static int connect_to(struct sockaddr_in address)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    CHECK(fd >= 0 && connect(fd, (void *)&address, sizeof(address)) == 0);
    return fd;
}
static void ready(int fd)
{
    struct pollfd event = {fd, POLLIN, 0};
    CHECK(poll(&event, 1, 2000) == 1 && (event.revents & POLLIN));
}
static struct pair connected(void)
{
    struct sockaddr_in address = local(); int listener = listen_at(&address);
    int client = connect_to(address); ready(listener);
    int server = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    CHECK(server >= 0 && close(listener) == 0);
    return (struct pair){client, server};
}
static void finish(struct pair p) {CHECK(close(p.client) == 0 && close(p.server) == 0);}
static int flags(int fd, int command)
{
    int value = fcntl(fd, command); CHECK(value >= 0); return value;
}
static int option(int fd, int level, int name)
{
    int value = -1; socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, level, name, &value, &length) == 0 && length == sizeof(value));
    return value;
}
static void set(int fd, int level, int name, int value)
{
    CHECK(setsockopt(fd, level, name, &value, sizeof(value)) == 0);
}
static void creation_flags(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    CHECK(fd >= 0 && (flags(fd, F_GETFL) & O_NONBLOCK) && (flags(fd, F_GETFD) & FD_CLOEXEC));
    CHECK(option(fd, SOL_SOCKET, SO_TYPE) == SOCK_STREAM);
    CHECK(option(fd, SOL_SOCKET, SO_DOMAIN) == AF_INET);
    CHECK(option(fd, SOL_SOCKET, SO_PROTOCOL) == IPPROTO_TCP);
    struct sockaddr_in peer; socklen_t length = sizeof(peer);
    ERROR(getpeername(fd, (void *)&peer, &length), ENOTCONN);
    CHECK(close(fd) == 0);
    struct pair p = connected(); finish(p);
}
static void accepted_flags(void)
{
    struct sockaddr_in address = local(); int listener = listen_at(&address);
    CHECK(flags(listener, F_GETFL) & O_NONBLOCK);
    CHECK(flags(listener, F_GETFD) & FD_CLOEXEC);
    ERROR(accept4(listener, NULL, NULL, SOCK_NONBLOCK), EAGAIN);
    for (int explicit = 0; explicit < 2; ++explicit) {
        int client = connect_to(address); ready(listener);
        int server = explicit ? accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC) :
            accept(listener, NULL, NULL);
        CHECK(server >= 0);
        CHECK(!!(flags(server, F_GETFL) & O_NONBLOCK) == explicit);
        CHECK(!!(flags(server, F_GETFD) & FD_CLOEXEC) == explicit);
        CHECK(write(client, "a", 1) == 1); ready(server);
        char byte; CHECK(read(server, &byte, 1) == 1 && byte == 'a');
        CHECK(close(server) == 0 && close(client) == 0);
    }
    CHECK(close(listener) == 0);
}
static void address_lengths(void)
{
    struct pair p = connected();
    for (int peer = 0; peer < 2; ++peer) {
        unsigned char bytes[32]; memset(bytes, 0xa5, sizeof(bytes));
        socklen_t length = 0;
        CHECK((peer ? getpeername(p.client, (void *)bytes, &length) :
            getsockname(p.client, (void *)bytes, &length)) == 0);
        CHECK(length == sizeof(struct sockaddr_in));
        for (size_t i = 0; i < sizeof(bytes); ++i) CHECK(bytes[i] == 0xa5);
        length = sizeof(sa_family_t);
        CHECK((peer ? getpeername(p.client, (void *)bytes, &length) :
            getsockname(p.client, (void *)bytes, &length)) == 0);
        CHECK(length == sizeof(struct sockaddr_in));
        sa_family_t family; memcpy(&family, bytes, sizeof(family)); CHECK(family == AF_INET);
        for (size_t i = sizeof(family); i < sizeof(bytes); ++i) CHECK(bytes[i] == 0xa5);
    }
    struct sockaddr_in client, server, peer; socklen_t length = sizeof(client);
    CHECK(getsockname(p.client, (void *)&client, &length) == 0);
    length = sizeof(server); CHECK(getsockname(p.server, (void *)&server, &length) == 0);
    length = sizeof(peer); CHECK(getpeername(p.client, (void *)&peer, &length) == 0);
    CHECK(peer.sin_port == server.sin_port && peer.sin_addr.s_addr == server.sin_addr.s_addr);
    length = sizeof(peer); CHECK(getpeername(p.server, (void *)&peer, &length) == 0);
    CHECK(peer.sin_port == client.sin_port && peer.sin_addr.s_addr == client.sin_addr.s_addr);
    finish(p);
}
static void option_roundtrip(void)
{
    struct pair p = connected();
    set(p.client, SOL_SOCKET, SO_KEEPALIVE, 1); CHECK(option(p.client, SOL_SOCKET, SO_KEEPALIVE) == 1);
    set(p.client, IPPROTO_TCP, TCP_NODELAY, 1); CHECK(option(p.client, IPPROTO_TCP, TCP_NODELAY) == 1);
    set(p.client, IPPROTO_TCP, TCP_KEEPIDLE, 123); CHECK(option(p.client, IPPROTO_TCP, TCP_KEEPIDLE) == 123);
    int invalid = 0;
    ERROR(setsockopt(p.client, IPPROTO_TCP, TCP_KEEPIDLE, &invalid, sizeof(invalid)), EINVAL);
    CHECK(option(p.client, IPPROTO_TCP, TCP_KEEPIDLE) == 123);
    set(p.client, IPPROTO_TCP, TCP_NODELAY, 0); CHECK(option(p.client, IPPROTO_TCP, TCP_NODELAY) == 0);
    int value; socklen_t length = sizeof(value);
    ERROR(getsockopt(p.client, SOL_SOCKET, 0x7fffffff, &value, &length), ENOPROTOOPT);
    length = sizeof(value); CHECK(getsockopt(p.client, SOL_SOCKET, SO_ERROR, &value, &length) == 0 && value == 0);
    CHECK(write(p.client, "ok", 2) == 2); ready(p.server);
    char bytes[2]; CHECK(recv(p.server, bytes, sizeof(bytes), MSG_WAITALL) == 2 && memcmp(bytes, "ok", 2) == 0);
    finish(p);
}
static void bind_collision(void)
{
    struct sockaddr_in address = local(); int listener = listen_at(&address);
    int other = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(other >= 0);
    ERROR(bind(other, (void *)&address, sizeof(address)), EADDRINUSE);
    CHECK(close(other) == 0);
    int client = connect_to(address); ready(listener);
    int server = accept(listener, NULL, NULL);
    CHECK(server >= 0 && close(listener) == 0);
    finish((struct pair){client, server});
}
static void duplicate_identity(void)
{
    struct pair p = connected();
    int alias = fcntl(p.client, F_DUPFD_CLOEXEC, 128);
    CHECK(alias >= 128 && (flags(alias, F_GETFD) & FD_CLOEXEC));
    struct stat original, duplicate;
    CHECK(fstat(p.client, &original) == 0 && fstat(alias, &duplicate) == 0);
    CHECK(S_ISSOCK(original.st_mode) && S_ISSOCK(duplicate.st_mode));
    CHECK(original.st_ino != 0 && original.st_ino == duplicate.st_ino && original.st_dev == duplicate.st_dev);
    CHECK(dup2(alias, alias) == alias && (flags(alias, F_GETFD) & FD_CLOEXEC));
    ERROR(dup3(alias, alias, O_CLOEXEC), EINVAL);
    CHECK(close(p.client) == 0);
    CHECK(write(alias, "alias", 5) == 5); ready(p.server);
    char bytes[5]; CHECK(recv(p.server, bytes, sizeof(bytes), MSG_WAITALL) == 5 && memcmp(bytes, "alias", 5) == 0);
    CHECK(close(alias) == 0 && close(p.server) == 0);
}
/* A raw syscall explicitly chooses host Linux. Subsequent ordinary POSIX fd
 * operations must dispatch by actual ownership, with no global mode toggle. */
static void datagram(int fd, struct sockaddr_in address, const char *payload)
{
    size_t size = strlen(payload) + 1;
    CHECK(sendto(fd, payload, size, MSG_DONTWAIT, (void *)&address, sizeof(address)) == (ssize_t)size);
}
static void received(int fd, struct sockaddr_in address, const char *payload)
{
    char data[64]; struct sockaddr_in peer = {0}; socklen_t length = sizeof(peer);
    CHECK(recvfrom(fd, data, sizeof(data), MSG_DONTWAIT, (void *)&peer, &length) == (ssize_t)strlen(payload) + 1);
    CHECK(!strcmp(data, payload) && length == sizeof(peer) && peer.sin_family == AF_INET);
    CHECK(peer.sin_addr.s_addr == address.sin_addr.s_addr && peer.sin_port == address.sin_port);
    ERROR(recv(fd, data, sizeof(data), MSG_DONTWAIT), EAGAIN);
}
static void host_native_same_tuple(void)
{
    uint64_t (*capabilities)(void) = (uint64_t (*)(void))dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    int native_instance = capabilities && capabilities();
    const uint64_t tags[2] = {UINT64_C(0x91a3000000000101), UINT64_C(0xb7f5000000000202)};
    for (int host_first = 0; host_first < 2; ++host_first) {
        int host = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(host >= 0);
        struct sockaddr_in address = local();
        CHECK(bind(host, (void *)&address, sizeof(address)) == 0);
        socklen_t length = sizeof(address);
        CHECK(getsockname(host, (void *)&address, &length) == 0 && length == sizeof(address));
        CHECK(address.sin_port != 0);
        int native = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(native >= 0 && native != host);
        if (!native_instance) {
            /* Host reference: a second same-kernel bind must collide. */
            ERROR(bind(native, (void *)&address, sizeof(address)), EADDRINUSE);
            CHECK(close(native) == 0);
            datagram(host, address, "host-reference"); ready(host);
            received(host, address, "host-reference"); CHECK(close(host) == 0);
            continue;
        }
        /* This can succeed only when the sockets belong to separate kernels. */
        CHECK(bind(native, (void *)&address, sizeof(address)) == 0);
        int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
        int sockets[2] = {host, native};
        const char *payloads[2] = {"HOST-only-identical-tuple", "NATIVE-only-identical-tuple"};
        for (int i = 0; i < 2; ++i) {
            CHECK((flags(sockets[i], F_GETFL) & O_NONBLOCK) && (flags(sockets[i], F_GETFD) & FD_CLOEXEC));
            struct epoll_event event = {.events = EPOLLIN, .data.u64 = tags[i]};
            CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, sockets[i], &event) == 0);
            datagram(sockets[i], address, payloads[i]);
        }
        unsigned seen = 0;
        for (int attempt = 0; seen != 3 && attempt < 4; ++attempt) {
            struct epoll_event events[2]; int count = epoll_wait(ep, events, 2, 2000);
            CHECK(count > 0 && count <= 2);
            for (int i = 0; i < count; ++i) {
                int index = events[i].data.u64 == tags[0] ? 0 : 1;
                CHECK(events[i].data.u64 == tags[index] && events[i].events == EPOLLIN);
                CHECK(!(seen & (1u << index)));
                received(sockets[index], address, payloads[index]); seen |= 1u << index;
            }
        }
        CHECK(seen == 3);
        int closed_index = host_first ? 0 : 1, survivor = 1 - closed_index;
        CHECK(close(sockets[closed_index]) == 0);
        datagram(sockets[survivor], address, payloads[survivor]);
        struct epoll_event event; CHECK(epoll_wait(ep, &event, 1, 2000) == 1);
        CHECK(event.data.u64 == tags[survivor] && event.events == EPOLLIN);
        received(sockets[survivor], address, payloads[survivor]);
        CHECK(close(sockets[survivor]) == 0 && epoll_wait(ep, &event, 1, 0) == 0 && close(ep) == 0);
    }
    puts(native_instance ? "PASS: independent host/native UDP same tuple, mixed epoll and both close orders" :
        "PASS: host reference same-kernel UDP tuple collision and survivor traffic");
}
static void select_error_preserves_sets(void)
{
    struct pair p = connected();
    int invalid = dup(p.server); CHECK(invalid >= 0 && invalid < FD_SETSIZE);
    CHECK(close(invalid) == 0);
    CHECK(write(p.client, "kept", 4) == 4);
    for (int variant = 0; variant < 2; ++variant) {
        fd_set reads, writes, errors;
        FD_ZERO(&reads); FD_ZERO(&writes); FD_ZERO(&errors);
        FD_SET(p.server, &reads); FD_SET(invalid, &reads);
        FD_SET(p.client, &writes); FD_SET(p.server, &errors);
        fd_set saved_reads = reads, saved_writes = writes, saved_errors = errors;
        int maximum = invalid > p.client ? invalid : p.client;
        if (p.server > maximum) maximum = p.server;
        struct timeval zero = {0}; struct timespec zero_ns = {0};
        if (variant) ERROR(pselect(maximum+1, &reads, &writes, &errors, &zero_ns, NULL), EBADF);
        else ERROR(select(maximum+1, &reads, &writes, &errors, &zero), EBADF);
        CHECK(!memcmp(&reads, &saved_reads, sizeof(reads)) &&
              !memcmp(&writes, &saved_writes, sizeof(writes)) &&
              !memcmp(&errors, &saved_errors, sizeof(errors)));
    }
    ready(p.server);
    char bytes[4]; CHECK(recv(p.server, bytes, sizeof(bytes), MSG_WAITALL) == 4 && !memcmp(bytes, "kept", 4));
    finish(p);
}

static void positioned_operations(void)
{
    struct pair p = connected();
    char byte = '?'; struct iovec vector = {&byte, 1};
    CHECK(write(p.client, "q", 1) == 1); ready(p.server);
    ERROR(lseek(p.server, 0, SEEK_SET), ESPIPE);
    ERROR(lseek64(p.server, 0, SEEK_CUR), ESPIPE);
    ERROR(pread(p.server, &byte, 1, 0), ESPIPE);
    ERROR(pread64(p.server, &byte, 1, 0), ESPIPE);
    ERROR(pwrite(p.server, &byte, 1, 0), ESPIPE);
    ERROR(pwrite64(p.server, &byte, 1, 0), ESPIPE);
    ERROR(preadv(p.server, &vector, 1, 0), ESPIPE);
    ERROR(preadv64(p.server, &vector, 1, 0), ESPIPE);
    ERROR(pwritev(p.server, &vector, 1, 0), ESPIPE);
    ERROR(pwritev64(p.server, &vector, 1, 0), ESPIPE);
    ERROR(preadv2(p.server, &vector, 1, 0, 0), ESPIPE);
    ERROR(preadv64v2(p.server, &vector, 1, 0, 0), ESPIPE);
    ERROR(pwritev2(p.server, &vector, 1, 0, 0), ESPIPE);
    ERROR(pwritev64v2(p.server, &vector, 1, 0, 0), ESPIPE);
    CHECK(read(p.server, &byte, 1) == 1 && byte == 'q');
    /* v2 offset -1 is a stream operation in Linux, rather than a seek. */
    CHECK(pwritev2(p.client, &vector, 1, -1, 0) == 1); ready(p.server);
    byte = '?'; CHECK(preadv2(p.server, &vector, 1, -1, 0) == 1 && byte == 'q');
    finish(p);
    char path[] = "/tmp/ker-positioned-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0);
    off_t far = ((off_t)1 << 33) + 19;
    CHECK(write(fd, "abc", 3) == 3 && lseek64(fd, 0, SEEK_CUR) == 3);
    CHECK(pwrite64(fd, "x", 1, far) == 1 && lseek(fd, 0, SEEK_CUR) == 3);
    CHECK(pread64(fd, &byte, 1, far) == 1 && byte == 'x');
    byte = 'y'; CHECK(pwritev64v2(fd, &vector, 1, far + 1, 0) == 1);
    byte = '?'; CHECK(preadv64(fd, &vector, 1, far + 1) == 1 && byte == 'y');
    CHECK(lseek(fd, 0, SEEK_CUR) == 3 && close(fd) == 0);
}
static volatile sig_atomic_t positioned_sigpipe_count;
static void positioned_sigpipe_handler(int signo)
{
    if (signo == SIGPIPE) ++positioned_sigpipe_count;
}
static void positioned_stream_sigpipe(void)
{
    struct sigaction action = {.sa_handler = positioned_sigpipe_handler}, original;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGPIPE, &action, &original) == 0);
    positioned_sigpipe_count = 0;
    struct pair p = connected(); char byte = 'p'; struct iovec vector = {&byte, 1};
    CHECK(pwritev2(p.client, &vector, 1, -1, 0) == 1); ready(p.server);
    CHECK(recv(p.server, &byte, 1, 0) == 1 && byte == 'p' && positioned_sigpipe_count == 0);
    ERROR(pwritev2(p.client, &vector, 1, -1, 0x40000000), EOPNOTSUPP);
    CHECK(positioned_sigpipe_count == 0);
    CHECK(shutdown(p.client, SHUT_WR) == 0);
    ERROR(pwritev2(p.client, &vector, 1, -1, 0), EPIPE);
    CHECK(positioned_sigpipe_count == 1);
    ERROR(pwritev64v2(p.client, &vector, 1, -1, 0), EPIPE);
    CHECK(positioned_sigpipe_count == 2);
    ERROR(pwritev2(p.client, &vector, 1, 0, 0), ESPIPE);
    CHECK(positioned_sigpipe_count == 2);
    finish(p);
    CHECK(sigaction(SIGPIPE, &original, NULL) == 0);
}
int main(void)
{
    const struct {const char *name; void (*run)(void);} cases[] = {
        {"positioned-io-and-seek-owner-routing", positioned_operations},
        {"positioned-stream-write-SIGPIPE-and-error-boundaries", positioned_stream_sigpipe},
        {"creation-flags-and-socket-type", creation_flags},
        {"select-ebadf-preserves-input-sets-and-data", select_error_preserves_sets},
        {"accept-flags-are-explicit-not-inherited", accepted_flags},
        {"address-length-truncation-and-peer-tuples", address_lengths},
        {"socket-options-errors-and-recovery", option_roundtrip},
        {"bind-collision-preserves-listener", bind_collision},
        {"duplicate-stat-identity-and-self-duplication", duplicate_identity},
        {"host-native-identical-udp-tuple", host_native_same_tuple},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cases[i].run(); printf("PASS: fstack socket contract %s\n", cases[i].name); fflush(stdout);
    }
    return 0;
}
