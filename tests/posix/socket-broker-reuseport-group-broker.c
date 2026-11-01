#define _GNU_SOURCE
#include <ker/socket-broker-server.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

struct bootstrap_record { uint32_t magic; uint16_t version; uint16_t count; };

static int check_server_singleton_lease(const char *path)
{
    char probe_path[KER_SOCKET_BROKER_PATH_MAX + 1];
    int length = snprintf(probe_path, sizeof(probe_path), "%s.lease-probe", path);
    if (length < 0 || (size_t)length >= sizeof(probe_path)) { errno = ENAMETOOLONG; return -1; }

    int blocker = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (blocker < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (syscall(SYS_bind, blocker, &address, sizeof(address))) {
        int error = errno; (void)syscall(SYS_close, blocker); errno = error; return -1;
    }
    errno = 0;
    struct ker_socket_broker_server *failed = ker_socket_broker_server_create(path);
    bool rolled_back = !failed && errno == EADDRINUSE;
    (void)syscall(SYS_close, blocker);
    (void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
    if (!rolled_back) {
        if (failed) ker_socket_broker_server_destroy(failed);
        errno = EPROTO;
        return -1;
    }

    struct ker_socket_broker_server *first = ker_socket_broker_server_create(probe_path);
    if (!first) return -1;
    errno = 0;
    struct ker_socket_broker_server *second = ker_socket_broker_server_create(path);
    struct stat identity;
    bool excluded = !second && errno == EBUSY && lstat(path, &identity) < 0 && errno == ENOENT;
    if (second) ker_socket_broker_server_destroy(second);
    ker_socket_broker_server_destroy(first);
    if (!excluded) { errno = EPROTO; return -1; }

    struct ker_socket_broker_server *released = ker_socket_broker_server_create(path);
    if (!released) return -1;
    ker_socket_broker_server_destroy(released);
    return 0;
}

static int send_group_capability(const char *path, int capability)
{
    int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (!length || length > sizeof(address.sun_path) - 1) {
        (void)syscall(SYS_close, fd); errno = ENAMETOOLONG; return -1;
    }
    memcpy(address.sun_path, path, length + 1);
    if (syscall(SYS_connect, fd, &address, sizeof(address))) {
        int error = errno; (void)syscall(SYS_close, fd); errno = error; return -1;
    }
    struct bootstrap_record record = {.magic = UINT32_C(0x4b534243), .version = 1, .count = 1};
    char control[CMSG_SPACE(sizeof(capability))] = {0};
    struct iovec iov = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(capability));
    memcpy(CMSG_DATA(cmsg), &capability, sizeof(capability));
    ssize_t sent = syscall(SYS_sendmsg, fd, &message, MSG_NOSIGNAL);
    int error = sent == sizeof(record) ? 0 : (sent < 0 ? errno : EIO);
    (void)syscall(SYS_close, fd);
    if (error) { errno = error; return -1; }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: broker <rpc-path> <bootstrap-path>\n"); return 2; }
    if (check_server_singleton_lease(argv[1])) {
        perror("broker runtime singleton lease");
        return 1;
    }
    struct ker_socket_broker_server *server = ker_socket_broker_server_create(argv[1]);
    if (!server) { perror("create broker"); return 1; }
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4098)};
    if (inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1) return 1;
    int denied = ker_socket_broker_server_reuseport_group_create(server, &address, 16,
        KER_SOCKET_BROKER_READ);
    if (denied < 0) { perror("create read-only group"); ker_socket_broker_server_destroy(server); return 1; }
    if (send_group_capability(argv[2], denied)) {
        perror("send group capability"); close(denied); ker_socket_broker_server_destroy(server); return 1;
    }
    close(denied);
    puts("BROKER_READY"); fflush(stdout);
    int result = ker_socket_broker_server_run(server, 1);
    if (result) perror("ker_socket_broker_server_run");
    ker_socket_broker_server_destroy(server);
    if (result) return 1;
    puts("BROKER_DONE"); fflush(stdout);
    return 0;
}
