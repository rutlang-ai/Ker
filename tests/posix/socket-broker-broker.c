#define _GNU_SOURCE
#include <ker/socket-broker-server.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "broker fixture:%d: %s: %s\n", __LINE__, #condition, strerror(errno)); \
    return 1; } } while (0)

struct bootstrap_record { uint32_t magic; uint16_t version; uint16_t count; };

static int send_capabilities(struct ker_socket_broker_server *server, const char *path,
    int listener, int epoll)
{
    int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (!length || length > sizeof(address.sun_path) - 1) { (void)syscall(SYS_close, fd); errno = ENAMETOOLONG; return -1; }
    memcpy(address.sun_path, path, length + 1);
    if (syscall(SYS_connect, fd, &address, sizeof(address))) { int e = errno; (void)syscall(SYS_close, fd); errno = e; return -1; }
    struct bootstrap_record record = {.magic = UINT32_C(0x4b534243), .version = 1, .count = 2};
    int fds[2] = {listener, epoll};
    char control[CMSG_SPACE(sizeof(fds))] = {0};
    struct iovec iov = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));
    ssize_t sent = syscall(SYS_sendmsg, fd, &message, MSG_NOSIGNAL);
    if (sent != sizeof(record)) {
        int error = sent < 0 ? errno : EIO;
        (void)syscall(SYS_close, fd); errno = error; return -1;
    }
    struct bootstrap_record host_record = {0};
    int host_fd = -1;
    char receive_control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec receive_iov = {.iov_base = &host_record, .iov_len = sizeof(host_record)};
    struct msghdr receive_message = {.msg_iov = &receive_iov, .msg_iovlen = 1,
        .msg_control = receive_control, .msg_controllen = sizeof(receive_control)};
    ssize_t received = syscall(SYS_recvmsg, fd, &receive_message, MSG_CMSG_CLOEXEC | MSG_TRUNC);
    struct cmsghdr *received_control = CMSG_FIRSTHDR(&receive_message);
    if (received != sizeof(host_record) || (receive_message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        !received_control || received_control->cmsg_level != SOL_SOCKET ||
        received_control->cmsg_type != SCM_RIGHTS ||
        received_control->cmsg_len != CMSG_LEN(sizeof(int))) {
        int error = received < 0 ? errno : EPROTO;
        (void)syscall(SYS_close, fd); errno = error; return -1;
    }
    memcpy(&host_fd, CMSG_DATA(received_control), sizeof(host_fd));
    if (host_record.magic != UINT32_C(0x4b534248) || host_record.version != 1 || host_record.count != 1) {
        (void)syscall(SYS_close, host_fd); (void)syscall(SYS_close, fd); errno = EPROTO; return -1;
    }
    errno = 0;
    if (ker_socket_broker_server_adopt(server, host_fd, KER_SOCKET_BROKER_SOCKET,
            KER_SOCKET_BROKER_ALL) != -1 || errno != EBADF) {
        int error = errno ? errno : EPROTO;
        (void)syscall(SYS_close, host_fd); (void)syscall(SYS_close, fd); errno = error; return -1;
    }
    const char reply[] = "OKAY";
    int error = syscall(SYS_sendto, fd, reply, sizeof(reply) - 1, MSG_NOSIGNAL, NULL, 0) == sizeof(reply) - 1 ? 0 : EIO;
    (void)syscall(SYS_close, fd);
    (void)syscall(SYS_close, host_fd);
    if (error) { errno = error; return -1; }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: broker <rpc-path> <bootstrap-path>\n"); return 2; }
    struct ker_socket_broker_server *server = ker_socket_broker_server_create(argv[1]);
    CHECK(server != NULL);
    int host_epoll = (int)syscall(SYS_epoll_create1, EPOLL_CLOEXEC);
    CHECK(host_epoll >= 0);
    errno = 0;
    CHECK(ker_socket_broker_server_adopt(server, host_epoll, KER_SOCKET_BROKER_EPOLL,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_WAIT) == -1 && errno == EBADF);
    (void)syscall(SYS_close, host_epoll);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    int one = 1;
    CHECK(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4097)};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) == 1);
    CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(listen(listener, 8) == 0);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x4097)};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, listener, &event) == 0);
    int listener_cap = ker_socket_broker_server_adopt(server, listener,
        KER_SOCKET_BROKER_SOCKET, KER_SOCKET_BROKER_ALL);
    CHECK(listener_cap >= 0);
    errno = 0;
    CHECK(ker_socket_broker_server_adopt(server, listener, KER_SOCKET_BROKER_SOCKET,
        KER_SOCKET_BROKER_ALL) == -1 && errno == EALREADY);
    int epoll_cap = ker_socket_broker_server_adopt(server, epoll,
        KER_SOCKET_BROKER_EPOLL, KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_WAIT);
    CHECK(epoll_cap >= 0);
    CHECK(send_capabilities(server, argv[2], listener_cap, epoll_cap) == 0);
    (void)syscall(SYS_close, listener_cap);
    (void)syscall(SYS_close, epoll_cap);
    puts("BROKER_READY"); fflush(stdout);
    int result = ker_socket_broker_server_run(server, 1);
    if (result) perror("ker_socket_broker_server_run");
    ker_socket_broker_server_destroy(server);
    if (result) return 1;
    puts("BROKER_DONE"); fflush(stdout);
    return 0;
}
