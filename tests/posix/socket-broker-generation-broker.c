#define _GNU_SOURCE
#include <ker/socket-broker-server.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

struct bootstrap_record { uint32_t magic; uint16_t version; uint16_t count; };

static int send_capability(const char *path, int capability)
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
    if (argc != 3) { fprintf(stderr, "usage: generation-broker <rpc-path> <bootstrap-path>\n"); return 2; }
    struct ker_socket_broker_server *server = ker_socket_broker_server_create(argv[1]);
    if (!server) { perror("create generation broker"); return 1; }
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4097)};
    if (inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1) return 1;
    int group = ker_socket_broker_server_reuseport_group_create(server, &address, 64,
        KER_SOCKET_BROKER_CONTROL);
    if (group < 0) { perror("create generation group"); ker_socket_broker_server_destroy(server); return 1; }
    if (send_capability(argv[2], group)) {
        perror("send generation group"); close(group); ker_socket_broker_server_destroy(server); return 1;
    }
    close(group);
    puts("BROKER_READY"); fflush(stdout);
    int result = ker_socket_broker_server_run(server, 1);
    if (result) perror("ker_socket_broker_server_run");
    ker_socket_broker_server_destroy(server);
    if (result) return 1;
    puts("BROKER_DONE"); fflush(stdout);
    return 0;
}
