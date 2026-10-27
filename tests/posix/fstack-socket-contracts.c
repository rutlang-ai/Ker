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
#include <pthread.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <linux/sockios.h>
#include <linux/magic.h>
#include <linux/close_range.h>
#include <linux/limits.h>
#include <sys/time.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
extern ssize_t __read_chk(int, void *, size_t, size_t);
extern ssize_t __pread_chk(int, void *, size_t, off_t, size_t);
extern ssize_t __pread64_chk(int, void *, size_t, off64_t, size_t);
extern ssize_t __recv_chk(int, void *, size_t, size_t, int);
extern ssize_t __recvfrom_chk(int, void *, size_t, size_t, int, struct sockaddr *, socklen_t *);
extern int __poll_chk(struct pollfd *, nfds_t, int, size_t);
extern int __ppoll_chk(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *, size_t);
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

static void file_lifecycle_operations(void)
{
    struct pair p = connected();
    CHECK(write(p.client, "s", 1) == 1); ready(p.server);
    ERROR(ftruncate(p.server, 0), EINVAL);
    ERROR(ftruncate64(p.server, 0), EINVAL);
    ERROR(fsync(p.server), EINVAL); ERROR(fdatasync(p.server), EINVAL);
    char byte = '?'; CHECK(read(p.server, &byte, 1) == 1 && byte == 's');
    finish(p);
    char path[] = "/tmp/ker-file-lifecycle-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0);
    CHECK(write(fd, "abc", 3) == 3 && fsync(fd) == 0 && fdatasync(fd) == 0);
    CHECK(ftruncate64(fd, 1) == 0 && lseek(fd, 0, SEEK_CUR) == 3);
    struct stat st; CHECK(fstat(fd, &st) == 0 && st.st_size == 1);
    CHECK(ftruncate(fd, 5) == 0 && pread(fd, &byte, 1, 4) == 1 && byte == 0);
    CHECK(close(fd) == 0);
    ERROR(fsync(fd), EBADF); ERROR(fdatasync(fd), EBADF); ERROR(ftruncate(fd, 0), EBADF);
}

static void filesystem_statistics(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    int copy = dup(fd); CHECK(copy >= 0);
    struct statfs st; struct statfs64 wide;
    CHECK(fstatfs(fd, &st) == 0 && st.f_type == SOCKFS_MAGIC && st.f_bsize > 0);
    CHECK(fstatfs64(copy, &wide) == 0 && wide.f_type == st.f_type);
    CHECK(wide.f_bsize == st.f_bsize && wide.f_namelen == st.f_namelen);
    CHECK(memcmp(&wide.f_fsid, &st.f_fsid, sizeof(st.f_fsid)) == 0);
    int (*query)(int, void *) = dlsym(RTLD_DEFAULT, "fstatfs"); CHECK(query);
    ERROR(query(fd, NULL), EFAULT);
    CHECK(close(fd) == 0 && fstatfs(copy, &st) == 0 && st.f_type == SOCKFS_MAGIC);
    ERROR(query(fd, NULL), EBADF); CHECK(close(copy) == 0);
    char path[] = "/tmp/ker-filesystem-XXXXXX";
    fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0);
    struct statfs host; CHECK(syscall(SYS_fstatfs, fd, &host) == 0);
    CHECK(fstatfs(fd, &st) == 0 && st.f_type == host.f_type && st.f_bsize == host.f_bsize);
    CHECK(memcmp(&st.f_fsid, &host.f_fsid, sizeof(st.f_fsid)) == 0 && close(fd) == 0);
}
static void descriptor_permissions(void)
{
    struct pair p = connected();
    int copy = dup(p.server); CHECK(copy >= 0);
    struct stat before, after; CHECK(fstat(p.server, &before) == 0);
    CHECK(fchmod(copy, 0600) == 0 && fchown(copy, (uid_t)-1, (gid_t)-1) == 0);
    CHECK(fstat(p.server, &after) == 0 && (after.st_mode & 0777) == 0600);
    CHECK(after.st_ino == before.st_ino && after.st_uid == before.st_uid && after.st_gid == before.st_gid);
    CHECK(fchmod(p.server, 0640) == 0 && fstat(copy, &after) == 0 && (after.st_mode & 0777) == 0640);
    CHECK(write(p.client, "p", 1) == 1); ready(p.server);
    char byte; CHECK(read(copy, &byte, 1) == 1 && byte == 'p');
    CHECK(close(copy) == 0); finish(p);
    char path[] = "/tmp/ker-permissions-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0);
    CHECK(fstat(fd, &before) == 0 && fchmod(fd, 0640) == 0);
    CHECK(fchown(fd, (uid_t)-1, (gid_t)-1) == 0 && fstat(fd, &after) == 0);
    CHECK((after.st_mode & 0777) == 0640 && after.st_uid == before.st_uid && after.st_gid == before.st_gid);
    CHECK(close(fd) == 0); ERROR(fchmod(fd, 0600), EBADF); ERROR(fchown(fd, (uid_t)-1, (gid_t)-1), EBADF);
}

static void descriptor_timestamps(void)
{
    int socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(socket_fd >= 0);
    char path[] = "/tmp/ker-timestamps-XXXXXX";
    int file_fd = mkstemp(path); CHECK(file_fd >= 0 && unlink(path) == 0);
    int descriptors[] = {socket_fd, file_fd};
    for (unsigned i = 0; i < 2; ++i) {
        int fd = descriptors[i];
        struct timespec times[2] = {{1234567890, 123456789}, {1234567891, 987654321}};
        CHECK(futimens(fd, times) == 0);
        struct stat st; CHECK(fstat(fd, &st) == 0);
        CHECK(st.st_atim.tv_sec == times[0].tv_sec && st.st_atim.tv_nsec == times[0].tv_nsec);
        CHECK(st.st_mtim.tv_sec == times[1].tv_sec && st.st_mtim.tv_nsec == times[1].tv_nsec);
        times[0].tv_nsec = UTIME_OMIT; times[1].tv_nsec = 1000000000;
        ERROR(futimens(fd, times), EINVAL);
        times[1].tv_nsec = UTIME_OMIT; CHECK(futimens(fd, times) == 0);
        CHECK(fstat(fd, &st) == 0 && st.st_mtim.tv_nsec == 987654321);
        struct timeval micros[2] = {{1234567892, 123456}, {1234567893, 654321}};
        CHECK(futimes(fd, micros) == 0 && fstat(fd, &st) == 0);
        CHECK(st.st_atim.tv_sec == micros[0].tv_sec && st.st_atim.tv_nsec == 123456000);
        CHECK(st.st_mtim.tv_sec == micros[1].tv_sec && st.st_mtim.tv_nsec == 654321000);
        micros[1].tv_usec = 1000000; ERROR(futimes(fd, micros), EINVAL);
        CHECK(futimens(fd, NULL) == 0 && fstat(fd, &st) == 0 && st.st_mtim.tv_sec > 1234567893);
        CHECK(close(fd) == 0); ERROR(futimens(fd, NULL), EBADF);
    }
}

static void file_allocation(void)
{
    struct pair p = connected();
    CHECK(write(p.client, "a", 1) == 1); ready(p.server);
    ERROR(fallocate(p.server, 0, 0, 4096), ENODEV);
    ERROR(fallocate64(p.server, 0, 0, 4096), ENODEV);
    CHECK(posix_fallocate(p.server, 0, 4096) == ENODEV);
    CHECK(posix_fallocate64(p.server, 0, 4096) == ENODEV);
    char byte; CHECK(read(p.server, &byte, 1) == 1 && byte == 'a'); finish(p);
    char path[] = "/tmp/ker-allocation-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0);
    struct stat st;
    CHECK(fallocate64(fd, FALLOC_FL_KEEP_SIZE, 0, 4096) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 0);
    CHECK(fallocate(fd, 0, 0, 4096) == 0 && fstat(fd, &st) == 0 && st.st_size == 4096);
    CHECK(pwrite(fd, "b", 1, 0) == 1);
    CHECK(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 4096) == 0);
    CHECK(pread(fd, &byte, 1, 0) == 1 && byte == 0);
    CHECK(posix_fallocate(fd, 4096, 4096) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 8192);
    CHECK(pread(fd, &byte, 1, 4096) == 1 && byte == 0);
    CHECK(posix_fallocate64(fd, 8192, 4096) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 12288);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 12288 && close(fd) == 0);
    ERROR(fallocate(fd, 0, 0, 4096), EBADF);
}

static void file_cache_operations(void)
{
    struct pair p = connected();
    CHECK(write(p.client, "c", 1) == 1); ready(p.server);
    ERROR(readahead(p.server, 0, 4096), EINVAL);
    ERROR(sync_file_range(p.server, 0, 4096, 0), ESPIPE);
    int advice_result = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release") ? ENOSYS : 0;
    errno = EINPROGRESS; CHECK(posix_fadvise(p.server, 0, 0, POSIX_FADV_NORMAL) == advice_result);
    CHECK(errno == EINPROGRESS);
    CHECK(posix_fadvise64(p.server, 0, 0, POSIX_FADV_NORMAL) == advice_result && errno == EINPROGRESS);
    char byte; CHECK(read(p.server, &byte, 1) == 1 && byte == 'c'); finish(p);
    char path[] = "/tmp/ker-file-cache-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0 && write(fd, "c", 1) == 1);
    errno = EINPROGRESS; CHECK(posix_fadvise64(fd, 0, 0, POSIX_FADV_NORMAL) == 0 && errno == EINPROGRESS);
    CHECK(posix_fadvise(fd, 0, 0, -1) == EINVAL && errno == EINPROGRESS);
    CHECK(readahead(fd, 0, 4096) == 0 && sync_file_range(fd, 0, 4096, 0) == 0);
    CHECK(lseek(fd, 0, SEEK_CUR) == 1 && close(fd) == 0);
    errno = EINPROGRESS; CHECK(posix_fadvise(fd, 0, 0, POSIX_FADV_NORMAL) == EBADF && errno == EINPROGRESS);
    ERROR(readahead(fd, 0, 4096), EBADF); ERROR(sync_file_range(fd, 0, 4096, 0), EBADF);
}

static void file_transfer_boundaries(void)
{
    char path[] = "/tmp/ker-transfer-XXXXXX", second[] = "/tmp/ker-copy-XXXXXX";
    int fd = mkstemp(path), output = mkstemp(second);
    CHECK(fd >= 0 && output >= 0 && unlink(path) == 0 && unlink(second) == 0);
    CHECK(write(fd, "transfer", 8) == 8);
    int sockets[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    off_t offset = 0; CHECK(sendfile64(sockets[0], fd, &offset, 8) == 8 && offset == 8);
    char bytes[8]; CHECK(read(sockets[1], bytes, sizeof(bytes)) == 8 && memcmp(bytes, "transfer", 8) == 0);
    off64_t in_offset = 0, out_offset = 0;
    CHECK(copy_file_range(fd, &in_offset, output, &out_offset, 8, 0) == 8 && in_offset == 8 && out_offset == 8);
    CHECK(pread(output, bytes, 8, 0) == 8 && memcmp(bytes, "transfer", 8) == 0);
    int pipes[2], copies[2]; CHECK(pipe(pipes) == 0 && pipe(copies) == 0);
    offset = 0; CHECK(splice(fd, &offset, pipes[1], NULL, 8, 0) == 8 && offset == 8);
    CHECK(tee(pipes[0], copies[1], 8, 0) == 8);
    CHECK(read(pipes[0], bytes, 8) == 8 && memcmp(bytes, "transfer", 8) == 0);
    CHECK(read(copies[0], bytes, 8) == 8 && memcmp(bytes, "transfer", 8) == 0);
    struct iovec vector = {(void *)"v", 1}; CHECK(vmsplice(pipes[1], &vector, 1, 0) == 1);
    CHECK(read(pipes[0], bytes, 1) == 1 && bytes[0] == 'v');
    if (dlsym(RTLD_DEFAULT, "ker_posix_kernel_release")) {
        struct pair p = connected(); offset = 0;
        ERROR(sendfile(p.client, -1, NULL, 1), EBADF);
        ERROR(splice(-1, NULL, p.client, NULL, 1, 0), EBADF);
        ERROR(sendfile(p.client, fd, &offset, 1), EOPNOTSUPP); CHECK(offset == 0);
        ERROR(sendfile64(output, p.server, &offset, 1), EOPNOTSUPP); CHECK(offset == 0);
        ERROR(splice(p.server, NULL, pipes[1], NULL, 1, 0), EOPNOTSUPP);
        ERROR(tee(p.server, pipes[1], 1, 0), EOPNOTSUPP);
        ERROR(copy_file_range(fd, NULL, p.client, NULL, 1, 0), EOPNOTSUPP);
        ERROR(sendfile(p.client, p.server, &offset, 1), ESPIPE);
        ERROR(vmsplice(p.client, &vector, 1, 0), EBADF);

        size_t page = (size_t)sysconf(_SC_PAGESIZE); CHECK(page >= 4096);
        char *user = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(user != MAP_FAILED);
        loff_t value = 19, observed;
        loff_t *cross_offset = (loff_t *)(user + page - sizeof(value) / 2);
        memcpy(cross_offset, &value, sizeof(value));
        ERROR(sendfile(p.client, p.server, (off_t *)cross_offset, 1), ESPIPE);
        memcpy(&observed, cross_offset, sizeof(observed)); CHECK(observed == value);
        ERROR(sendfile(p.client, p.server, NULL, 1), EINVAL);
        ERROR(splice(p.server, cross_offset, p.client, NULL, 1, 0), EINVAL);
        ERROR(copy_file_range(p.server, (off64_t *)cross_offset, p.client, NULL, 1, 0), EINVAL);
        memcpy(&observed, cross_offset, sizeof(observed)); CHECK(observed == value);

        loff_t *readonly_offset = (loff_t *)(user + 32);
        memcpy(readonly_offset, &value, sizeof(value));
        CHECK(mprotect(user, page, PROT_READ) == 0);
        /* Linux sends the unchanged position back even when sendfile fails. */
        ERROR(sendfile(p.client, p.server, (off_t *)readonly_offset, 1), EFAULT);
        CHECK(mprotect(user, page, PROT_READ | PROT_WRITE) == 0);

        struct iovec *cross_vectors = (struct iovec *)(user + page - sizeof(struct iovec) / 2);
        struct iovec data_vector = {user + page + 64, 1};
        memcpy(cross_vectors, &data_vector, sizeof(data_vector));
        ERROR(vmsplice(p.client, cross_vectors, 1, 0), EBADF);
        CHECK(mprotect(user + page, page, PROT_NONE) == 0);

        CHECK(splice(p.server, (loff_t *)(user + page), p.client,
            (loff_t *)(user + page), 0, 0) == 0);
        ERROR(splice(p.server, (loff_t *)(user + page), p.client,
            (loff_t *)(user + page), 1, 0x80000000u), EINVAL);
        ERROR(sendfile(p.client, p.server, (off_t *)(user + page), 1), EFAULT);
        ERROR(sendfile(p.client, p.server, (off_t *)cross_offset, 1), EFAULT);
        ERROR(splice(p.server, (loff_t *)(user + page), p.client, NULL, 1, 0), EFAULT);
        ERROR(splice(p.server, NULL, p.client, (loff_t *)(user + page), 1, 0), EFAULT);
        ERROR(copy_file_range(p.server, (off64_t *)(user + page), p.client, NULL, 1, 0), EFAULT);
        ERROR(copy_file_range(p.server, NULL, p.client, (off64_t *)(user + page), 1, 0), EFAULT);
        ERROR(copy_file_range(-1, (off64_t *)(user + page), p.client, NULL, 1, 0), EBADF);
        ERROR(vmsplice(p.client, (struct iovec *)(user + page), 1, 0), EFAULT);
        ERROR(vmsplice(p.client, cross_vectors, 1, 0), EFAULT);
        ERROR(vmsplice(p.client, (struct iovec *)(user + page), 1, 0x80000000u), EINVAL);
        void *near_max = (void *)(uintptr_t)(UINTPTR_MAX - sizeof(loff_t) / 2);
        ERROR(sendfile(p.client, p.server, (off_t *)near_max, 1), EFAULT);
        ERROR(splice(p.server, (loff_t *)near_max, p.client, NULL, 1, 0), EFAULT);
        ERROR(splice(p.server, NULL, p.client, (loff_t *)near_max, 1, 0), EFAULT);
        ERROR(copy_file_range(p.server, (off64_t *)near_max, p.client, NULL, 1, 0), EFAULT);
        ERROR(copy_file_range(p.server, NULL, p.client, (off64_t *)near_max, 1, 0), EFAULT);
        ERROR(vmsplice(p.client, (struct iovec *)near_max, 1, 0), EFAULT);
        /* The native socket is not a pipe, so upstream rejects it before
         * touching the user payload address; do not stage/free vmsplice data. */
        struct iovec protected_data = {user + page, 1};
        ERROR(vmsplice(p.client, &protected_data, 1, 0), EBADF);
        CHECK(munmap(user, page * 2) == 0);

        ERROR(splice(p.server, NULL, p.client, NULL, 1, 0), EINVAL);
        ERROR(copy_file_range(p.server, NULL, p.client, NULL, 1, 0), EINVAL);
        CHECK(write(p.client, "t", 1) == 1); ready(p.server);
        CHECK(read(p.server, bytes, 1) == 1 && bytes[0] == 't'); finish(p);
    }
    CHECK(lseek(fd, 0, SEEK_CUR) == 8 && close(fd) == 0 && close(output) == 0);
    CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0 && close(copies[0]) == 0 && close(copies[1]) == 0);
}

enum blocked_transfer_kind { BLOCKED_SPLICE, BLOCKED_TEE, BLOCKED_VMSPLICE };
struct blocked_transfer {
    enum blocked_transfer_kind kind;
    int input[2];
    int output[2];
    atomic_int entered;
    ssize_t result;
    char byte;
};

static void *blocked_transfer_call(void *opaque)
{
    struct blocked_transfer *call = opaque;
    atomic_store_explicit(&call->entered, 1, memory_order_release);
    if (call->kind == BLOCKED_SPLICE)
        call->result = splice(call->input[0], NULL, call->output[1], NULL, 1, 0);
    else if (call->kind == BLOCKED_TEE)
        call->result = tee(call->input[0], call->output[1], 1, 0);
    else {
        struct iovec vector = {&call->byte, 1};
        call->result = vmsplice(call->output[1], &vector, 1, 0);
    }
    return NULL;
}

static int timed_join(pthread_t thread, void **result, long milliseconds)
{
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += milliseconds / 1000;
    deadline.tv_nsec += (milliseconds % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000L; }
    return pthread_timedjoin_np(thread, result, &deadline);
}

static void blocked_host_transfer_is_cancellable(enum blocked_transfer_kind kind)
{
    struct blocked_transfer call = {.kind = kind, .byte = 'c'};
    CHECK(pipe(call.input) == 0 && pipe(call.output) == 0);
    if (kind == BLOCKED_VMSPLICE) {
        int capacity = fcntl(call.output[1], F_GETPIPE_SZ); CHECK(capacity > 0);
        char *fill = calloc((size_t)capacity, 1); CHECK(fill);
        size_t written = 0;
        while (written < (size_t)capacity) {
            ssize_t result = write(call.output[1], fill + written, (size_t)capacity - written);
            CHECK(result > 0); written += (size_t)result;
        }
        free(fill);
    }

    atomic_init(&call.entered, 0);
    pthread_t thread; CHECK(pthread_create(&thread, NULL, blocked_transfer_call, &call) == 0);
    for (unsigned i = 0; i < 1000 && !atomic_load_explicit(&call.entered, memory_order_acquire); ++i) {
        struct timespec pause = {.tv_nsec = 1000000L}; nanosleep(&pause, NULL);
    }
    CHECK(atomic_load_explicit(&call.entered, memory_order_acquire));
    struct timespec settle = {.tv_nsec = 20000000L}; nanosleep(&settle, NULL);
    CHECK(pthread_cancel(thread) == 0);
    void *result = NULL;
    int joined = timed_join(thread, &result, 2000);
    if (joined == ETIMEDOUT) {
        /* Release a raw-syscall regression before failing, so the test never
         * strands a worker or hangs the test runner. */
        if (kind == BLOCKED_VMSPLICE) {
            char byte; CHECK(read(call.output[0], &byte, 1) == 1);
        } else CHECK(write(call.input[1], "x", 1) == 1);
        CHECK(timed_join(thread, &result, 2000) == 0);
        CHECK(result == PTHREAD_CANCELED);
    } else CHECK(joined == 0 && result == PTHREAD_CANCELED);
    CHECK(close(call.input[0]) == 0 && close(call.input[1]) == 0);
    CHECK(close(call.output[0]) == 0 && close(call.output[1]) == 0);
}

static void host_transfer_cancellation(void)
{
    blocked_host_transfer_is_cancellable(BLOCKED_SPLICE);
    blocked_host_transfer_is_cancellable(BLOCKED_TEE);
    blocked_host_transfer_is_cancellable(BLOCKED_VMSPLICE);
}

static void close_range_boundary(void)
{
    struct pair p = connected();
    int copy = dup(p.server); CHECK(copy >= 0 && !(fcntl(copy, F_GETFD) & FD_CLOEXEC));
    CHECK(close_range(copy, copy, CLOSE_RANGE_CLOEXEC) == 0);
    CHECK(fcntl(copy, F_GETFD) & FD_CLOEXEC);
    ERROR(close_range(2, 1, 0), EINVAL); ERROR(close_range(copy, copy, 1), EINVAL);
    int native = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release") != NULL;
    if (native) {
        ERROR(close_range(copy, copy, 0), EOPNOTSUPP);
        ERROR(close_range(copy, copy, CLOSE_RANGE_UNSHARE), EOPNOTSUPP);
        CHECK(write(p.client, "r", 1) == 1); ready(copy);
        char byte; CHECK(read(copy, &byte, 1) == 1 && byte == 'r');
        CHECK(close(copy) == 0);
    } else {
        CHECK(close_range(copy, copy, 0) == 0); ERROR(fcntl(copy, F_GETFD), EBADF);
    }
    int pipefd[2]; CHECK(pipe(pipefd) == 0);
    CHECK(close_range(pipefd[0], pipefd[0], CLOSE_RANGE_CLOEXEC) == 0);
    CHECK(fcntl(pipefd[0], F_GETFD) & FD_CLOEXEC);
    if (native) {
        ERROR(close_range(pipefd[0], pipefd[0], 0), EOPNOTSUPP);
        CHECK(close(pipefd[0]) == 0);
    } else CHECK(close_range(pipefd[0], pipefd[0], 0) == 0);
    CHECK(close(pipefd[1]) == 0); finish(p);
}
static void descriptor_xattrs(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    int copy = dup(fd); CHECK(copy >= 0);
    char value[128];
    CHECK(fgetxattr(fd, "system.sockprotoname", NULL, 0) == 4);
    CHECK(fgetxattr(copy, "system.sockprotoname", value, sizeof(value)) == 4 && memcmp(value, "TCP", 4) == 0);
    ERROR(fgetxattr(fd, "system.sockprotoname", value, 1), ERANGE);
    ssize_t length = flistxattr(fd, value, sizeof(value)); CHECK(length > 0);
    int found = 0;
    for (ssize_t at = 0; at < length; at += strlen(value + at) + 1)
        if (strcmp(value + at, "system.sockprotoname") == 0) found = 1;
    CHECK(found); ERROR(flistxattr(fd, value, 1), ERANGE);
    ssize_t (*get_attribute)(int, const char *, void *, size_t) = fgetxattr;
    ssize_t (*list_attributes)(int, char *, size_t) = flistxattr;
    int (*set_attribute)(int, const char *, const void *, size_t, int) = fsetxattr;
    int native = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release") != NULL;
    if (native) {
        ERROR(get_attribute(fd, NULL, value, sizeof(value)), EFAULT);
        ERROR(fremovexattr(fd, NULL), EFAULT);
        ERROR(set_attribute(fd, NULL, "a", 1, 0), EFAULT);
        long page_size = sysconf(_SC_PAGESIZE); CHECK(page_size > 0);
        char *inaccessible_name = mmap(NULL, (size_t)page_size, PROT_NONE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(inaccessible_name != MAP_FAILED);
        ERROR(get_attribute(fd, inaccessible_name, value, sizeof(value)), EFAULT);
        ERROR(fremovexattr(fd, inaccessible_name), EFAULT);
        ERROR(set_attribute(fd, inaccessible_name, "a", 1, 0), EFAULT);
        ERROR(set_attribute(fd, inaccessible_name, "a", 1, ~0), EINVAL);
        ERROR(get_attribute(fd, "system.sockprotoname", inaccessible_name, 4), EFAULT);
        ERROR(list_attributes(fd, inaccessible_name, (size_t)page_size), EFAULT);
        char *readonly_output = mmap(NULL, (size_t)page_size, PROT_READ,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(readonly_output != MAP_FAILED);
        ERROR(get_attribute(fd, "system.sockprotoname", readonly_output, 4), EFAULT);
        ERROR(list_attributes(fd, readonly_output, (size_t)page_size), EFAULT);
        CHECK(munmap(readonly_output, (size_t)page_size) == 0);
        char *partial_input = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(partial_input != MAP_FAILED);
        CHECK(mprotect(partial_input + page_size, (size_t)page_size, PROT_NONE) == 0);
        partial_input[page_size - 1] = 'x';
        ERROR(set_attribute(fd, "user.partial", inaccessible_name, 1, 0), EFAULT);
        ERROR(set_attribute(fd, "user.partial", partial_input + page_size - 1, 2, 0), EFAULT);
        CHECK(munmap(partial_input, (size_t)page_size * 2) == 0);
        CHECK(get_attribute(fd, "system.sockprotoname", value, sizeof(value)) == 4 &&
              memcmp(value, "TCP", 4) == 0);
        CHECK(list_attributes(fd, value, sizeof(value)) == length);
        CHECK(fgetxattr(fd, "system.sockprotoname", NULL, 0) == 4);
        CHECK(munmap(inaccessible_name, (size_t)page_size) == 0);
        ERROR(get_attribute(fd, "system.sockprotoname", NULL, 4), EFAULT);
        ERROR(list_attributes(fd, NULL, 128), EFAULT);
        ERROR(set_attribute(fd, "user.ker", NULL, 1, 0), EFAULT);
        ERROR(set_attribute(fd, "user.ker", NULL, 0, 0), EPERM);
        ERROR(set_attribute(fd, "user.ker", NULL, 1, ~0), EINVAL);
        ERROR(set_attribute(fd, "", NULL, 1, 0), ERANGE);
        const char *near_max_name = (const char *)(UINTPTR_MAX - 1u);
        ERROR(set_attribute(fd, near_max_name, NULL, 1, 0), EFAULT);
        ERROR(set_attribute(fd, near_max_name, NULL, 1, ~0), EINVAL);
        ERROR(set_attribute(fd, "user.ker", NULL, XATTR_SIZE_MAX + 1u, 0), E2BIG);
        CHECK(fgetxattr(fd, "system.sockprotoname", NULL, 0) == 4);
        CHECK(flistxattr(fd, NULL, 0) == length);
        ERROR(fsetxattr(fd, "user.ker", "a", 1, 0), EPERM);
        ERROR(fremovexattr(fd, "system.sockprotoname"), EOPNOTSUPP);
    }
    CHECK(close(fd) == 0 && fgetxattr(copy, "system.sockprotoname", value, sizeof(value)) == 4);
    CHECK(close(copy) == 0); ERROR(flistxattr(copy, value, sizeof(value)), EBADF);
    ERROR(get_attribute(copy, "system.sockprotoname", NULL, 4), EBADF);
    ERROR(list_attributes(copy, NULL, 128), EBADF);
    ERROR(set_attribute(copy, "user.ker", "a", 1, 0), EBADF);
    char path[] = "/tmp/ker-xattrs-XXXXXX";
    fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0);
    ERROR(get_attribute(fd, NULL, value, sizeof(value)), EFAULT);
    ERROR(set_attribute(fd, NULL, "a", 1, 0), EFAULT);
    ERROR(fremovexattr(fd, NULL), EFAULT);
    ERROR(set_attribute(fd, "user.ker", NULL, 1, 0), EFAULT);
    CHECK(fsetxattr(fd, "user.empty", NULL, 0, XATTR_CREATE) == 0);
    CHECK(get_attribute(fd, "user.empty", NULL, 0) == 0);
    CHECK(fremovexattr(fd, "user.empty") == 0);
    CHECK(fsetxattr(fd, "user.ker", "a", 1, XATTR_CREATE) == 0);
    ERROR(get_attribute(fd, "user.ker", NULL, 1), EFAULT);
    ERROR(list_attributes(fd, NULL, 128), EFAULT);
    CHECK(get_attribute(fd, "user.ker", NULL, 0) == 1);
    CHECK(list_attributes(fd, NULL, 0) > 0);
    ERROR(fsetxattr(fd, "user.ker", "b", 1, XATTR_CREATE), EEXIST);
    CHECK(fsetxattr(fd, "user.ker", "b", 1, XATTR_REPLACE) == 0);
    CHECK(fgetxattr(fd, "user.ker", value, sizeof(value)) == 1 && value[0] == 'b');
    CHECK(fremovexattr(fd, "user.ker") == 0); ERROR(fgetxattr(fd, "user.ker", value, sizeof(value)), ENODATA);
    CHECK(close(fd) == 0);
}

static void null_queue_ioctl(void)
{
    struct pair p = connected();
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(udp >= 0);
    int pipefd[2]; CHECK(pipe2(pipefd, O_CLOEXEC) == 0);
    CHECK(write(p.client, "i", 1) == 1); ready(p.server);
    CHECK(write(pipefd[1], "h", 1) == 1);
    int descriptors[] = {p.server, udp, pipefd[0]};
    for (unsigned i = 0; i < 3; ++i) {
        ERROR(ioctl(descriptors[i], FIONREAD, (void *)NULL), EFAULT);
        ERROR(ioctl(descriptors[i], FIONBIO, (void *)NULL), EFAULT);
        if (i < 2) ERROR(ioctl(descriptors[i], SIOCOUTQ, (void *)NULL), EFAULT);
        int count = -1; CHECK(ioctl(descriptors[i], FIONREAD, &count) == 0);
        CHECK(count == (i == 1 ? 0 : 1));
        CHECK(!(fcntl(descriptors[i], F_GETFL) & O_NONBLOCK));
    }
    ERROR(ioctl(-1, FIONREAD, (void *)NULL), EBADF);
    char byte; CHECK(read(p.server, &byte, 1) == 1 && byte == 'i');
    CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'h');
    CHECK(close(udp) == 0 && close(pipefd[0]) == 0 && close(pipefd[1]) == 0); finish(p);
}

static void mapping_owner_boundary(void)
{
    int descriptors[] = {socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0),
        socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), epoll_create1(EPOLL_CLOEXEC)};
    for (unsigned i = 0; i < 3; ++i) {
        int fd = descriptors[i]; CHECK(fd >= 0);
        int native = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release") != NULL;
        int expected = native && i < 2 ? EINVAL : ENODEV;
        errno = 0; void *mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (!native && i == 0) CHECK(mapping != MAP_FAILED && munmap(mapping, 4096) == 0);
        else CHECK(mapping == MAP_FAILED && errno == expected);
        errno = 0; mapping = mmap64(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (!native && i == 0) CHECK(mapping != MAP_FAILED && munmap(mapping, 4096) == 0);
        else CHECK(mapping == MAP_FAILED && errno == expected);
        errno = 0; CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 1) == MAP_FAILED && errno == EINVAL);
        char *anonymous = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, fd, 0);
        CHECK(anonymous != MAP_FAILED); anonymous[0] = 'm'; CHECK(anonymous[0] == 'm' && munmap(anonymous, 4096) == 0);
        CHECK(close(fd) == 0);
    }
    char path[] = "/tmp/ker-file-map-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0 && unlink(path) == 0);
    CHECK(pwrite(fd, "x", 1, 4095) == 1);
    char *mapped = mmap64(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(mapped != MAP_FAILED && mapped[4095] == 'x'); mapped[0] = 'y';
    CHECK(msync(mapped, 4096, MS_SYNC) == 0 && munmap(mapped, 4096) == 0);
    char byte; CHECK(pread(fd, &byte, 1, 0) == 1 && byte == 'y' && close(fd) == 0);
}

enum checked_block_kind { CHECKED_READ, CHECKED_PREAD_PENDING, CHECKED_RECV, CHECKED_RECVFROM, CHECKED_POLL, CHECKED_PPOLL };
struct checked_block_call {
    enum checked_block_kind kind;
    int fd, peer;
    struct pollfd event;
    struct timespec timeout;
    atomic_int entered, release;
    ssize_t result;
};
static void *checked_blocked_call(void *opaque)
{
    struct checked_block_call *call = opaque;
    char byte = 0;
    if (call->kind == CHECKED_PREAD_PENDING) {
        int previous;
        if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return (void *)1;
        atomic_store_explicit(&call->entered, 1, memory_order_release);
        while (!atomic_load_explicit(&call->release, memory_order_acquire)) sched_yield();
        call->result = __pread_chk(call->fd, &byte, 1, 0, sizeof byte);
        pthread_setcancelstate(previous, NULL);
        pthread_testcancel();
        return (void *)(intptr_t)call->result;
    }
    atomic_store_explicit(&call->entered, 1, memory_order_release);
    switch (call->kind) {
    case CHECKED_READ: call->result = __read_chk(call->fd, &byte, 1, sizeof byte); break;
    case CHECKED_RECV: call->result = __recv_chk(call->fd, &byte, 1, sizeof byte, 0); break;
    case CHECKED_RECVFROM: call->result = __recvfrom_chk(call->fd, &byte, 1, sizeof byte, 0, NULL, NULL); break;
    case CHECKED_POLL: call->result = __poll_chk(&call->event, 1, -1, sizeof call->event); break;
    case CHECKED_PPOLL: call->result = __ppoll_chk(&call->event, 1, NULL, NULL, sizeof call->event); break;
    case CHECKED_PREAD_PENDING: return NULL;
    }
    return (void *)(intptr_t)call->result;
}
static int checked_timed_join(pthread_t thread, void **result)
{
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 2;
    return pthread_timedjoin_np(thread, result, &deadline);
}
static void checked_host_cancellation(enum checked_block_kind kind)
{
    struct checked_block_call call = {.kind = kind, .fd = -1, .peer = -1};
    if (kind == CHECKED_PREAD_PENDING) {
        char path[] = "/tmp/ker-checked-pread-XXXXXX";
        call.fd = mkstemp(path); CHECK(call.fd >= 0 && unlink(path) == 0);
        CHECK(write(call.fd, "p", 1) == 1);
    } else if (kind == CHECKED_READ || kind == CHECKED_POLL || kind == CHECKED_PPOLL) {
        int pipefd[2]; CHECK(pipe(pipefd) == 0); call.fd = pipefd[0]; call.peer = pipefd[1];
        call.event = (struct pollfd){call.fd, POLLIN, 0};
    } else {
        int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
        call.fd = pair[0]; call.peer = pair[1];
    }
    atomic_init(&call.entered, 0); atomic_init(&call.release, 0);
    pthread_t thread; CHECK(pthread_create(&thread, NULL, checked_blocked_call, &call) == 0);
    for (unsigned i = 0; i < 1000 && !atomic_load_explicit(&call.entered, memory_order_acquire); ++i) {
        struct timespec pause = {.tv_nsec = 1000000L}; nanosleep(&pause, NULL);
    }
    CHECK(atomic_load_explicit(&call.entered, memory_order_acquire));
    if (kind == CHECKED_PREAD_PENDING) {
        CHECK(pthread_cancel(thread) == 0);
        atomic_store_explicit(&call.release, 1, memory_order_release);
    } else {
        struct timespec settle = {.tv_nsec = 20000000L}; nanosleep(&settle, NULL);
        CHECK(pthread_cancel(thread) == 0);
    }
    void *result = NULL;
    int joined = checked_timed_join(thread, &result);
    if (joined == ETIMEDOUT) {
        /* Wake a raw-syscall regression before reporting it, avoiding leaked
         * threads or a hung test runner. */
        if (kind == CHECKED_READ || kind == CHECKED_POLL || kind == CHECKED_PPOLL)
            CHECK(write(call.peer, "x", 1) == 1);
        else CHECK(write(call.peer, "x", 1) == 1);
        CHECK(checked_timed_join(thread, &result) == 0);
        CHECK(result == PTHREAD_CANCELED);
    } else CHECK(joined == 0 && result == PTHREAD_CANCELED);
    if (kind == CHECKED_PREAD_PENDING) CHECK(close(call.fd) == 0);
    else { CHECK(close(call.fd) == 0); CHECK(close(call.peer) == 0); }
}
static void checked_entry_cancellation(void)
{
    checked_host_cancellation(CHECKED_READ);
    checked_host_cancellation(CHECKED_PREAD_PENDING);
    checked_host_cancellation(CHECKED_RECV);
    checked_host_cancellation(CHECKED_RECVFROM);
    checked_host_cancellation(CHECKED_POLL);
    checked_host_cancellation(CHECKED_PPOLL);
}
static void fortified_io(void)
{
    struct pair p = connected(); char bytes[8];
    volatile size_t count = 1; volatile nfds_t descriptors = 1;
    CHECK(write(p.client, "f", 1) == 1); ready(p.server);
    struct pollfd event = {p.server, POLLIN, 0};
    CHECK(__poll_chk(&event, descriptors, 0, sizeof event) == 1 && (event.revents & POLLIN));
    struct timespec timeout = {0, 0};
    CHECK(__ppoll_chk(&event, descriptors, &timeout, NULL, sizeof event) == 1 && (event.revents & POLLIN));
    CHECK(__recv_chk(p.server, bytes, count, sizeof bytes, MSG_PEEK) == 1 && bytes[0] == 'f');
    CHECK(__recvfrom_chk(p.server, bytes, count, sizeof bytes, MSG_PEEK, NULL, NULL) == 1 && bytes[0] == 'f');
    ERROR(__pread_chk(p.server, bytes, count, 0, sizeof bytes), ESPIPE);
    ERROR(__pread64_chk(p.server, bytes, count, 0, sizeof bytes), ESPIPE);
    CHECK(__read_chk(p.server, bytes, count, sizeof bytes) == 1 && bytes[0] == 'f');

    int hostpipe[2]; CHECK(pipe(hostpipe) == 0);
    CHECK(write(p.client, "m", 1) == 1 && write(hostpipe[1], "h", 1) == 1); ready(p.server);
    struct pollfd mixed[2] = {{p.server, POLLIN, 0}, {hostpipe[0], POLLIN, 0}};
    CHECK(__poll_chk(mixed, 2, 0, sizeof mixed) == 2);
    CHECK((mixed[0].revents & POLLIN) && (mixed[1].revents & POLLIN));
    CHECK(__read_chk(p.server, bytes, 1, sizeof bytes) == 1 && bytes[0] == 'm');
    CHECK(read(hostpipe[0], bytes, 1) == 1 && bytes[0] == 'h');
    CHECK(write(p.client, "n", 1) == 1 && write(hostpipe[1], "g", 1) == 1); ready(p.server);
    mixed[0].revents = mixed[1].revents = 0;
    CHECK(__ppoll_chk(mixed, 2, &timeout, NULL, sizeof mixed) == 2);
    CHECK((mixed[0].revents & POLLIN) && (mixed[1].revents & POLLIN));
    CHECK(__read_chk(p.server, bytes, 1, sizeof bytes) == 1 && bytes[0] == 'n');
    CHECK(read(hostpipe[0], bytes, 1) == 1 && bytes[0] == 'g');
    CHECK(close(hostpipe[0]) == 0 && close(hostpipe[1]) == 0);
    void *bad = mmap(NULL, (size_t)sysconf(_SC_PAGESIZE), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(bad != MAP_FAILED);
    ERROR(__poll_chk(bad, 1, 0, sizeof event), EFAULT);
    ERROR(__ppoll_chk(bad, 1, &timeout, NULL, sizeof event), EFAULT);
    CHECK(munmap(bad, (size_t)sysconf(_SC_PAGESIZE)) == 0);
    finish(p);
    checked_entry_cancellation();
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
        {"file-lifecycle-owner-routing", file_lifecycle_operations},
        {"filesystem-statistics-owner-routing", filesystem_statistics},
        {"descriptor-permissions-owner-routing", descriptor_permissions},
        {"descriptor-timestamp-owner-routing", descriptor_timestamps},
        {"file-allocation-owner-routing", file_allocation},
        {"file-cache-owner-routing", file_cache_operations},
        {"cross-kernel-file-transfer-boundaries", file_transfer_boundaries},
        {"host-transfer-cancellation-points", host_transfer_cancellation},
        {"close-range-explicit-native-boundary", close_range_boundary},
        {"descriptor-xattr-owner-routing", descriptor_xattrs},
        {"null-queue-ioctl-errors-preserve-state", null_queue_ioctl},
        {"mapping-owner-and-anonymous-fd-boundaries", mapping_owner_boundary},
        {"fortified-io-retains-owner-and-bounds", fortified_io},
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
