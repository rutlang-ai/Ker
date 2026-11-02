#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int send_watch(int fd, int watch_fd, uint16_t port)
{
    struct { uint32_t magic; uint32_t pid; uint16_t port; uint16_t reserved; } record = {
        .magic = UINT32_C(0x57415443), .pid = (uint32_t)getpid(), .port = port};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = {.iov_base = &record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &watch_fd, sizeof(watch_fd));
    return sendmsg(fd, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(record) ? 0 : -1;
}

static int connect_control(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (!length || length >= sizeof(address.sun_path)) { close(fd); errno = ENAMETOOLONG; return -1; }
    memcpy(address.sun_path, path, length + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        int error = errno; close(fd); errno = error; return -1;
    }
    return fd;
}

static int describe_watch_actor(const char *rpc_path, const char *control_path)
{
    int control = connect_control(control_path);
    if (control < 0) return 1;
    char payload[8] = {0};
    char ancillary[CMSG_SPACE(sizeof(int) * 4)] = {0};
    struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ancillary, .msg_controllen = sizeof(ancillary)};
    ssize_t received = recvmsg(control, &message, MSG_CMSG_CLOEXEC);
    int fds[4];
    size_t fd_count = 0;
    bool malformed = received != 1 || payload[0] != 'W' ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
            cmsg->cmsg_len < CMSG_LEN(0)) {
            malformed = true;
            continue;
        }
        size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int)) malformed = true;
        size_t count = bytes / sizeof(int);
        const int *installed = (const int *)CMSG_DATA(cmsg);
        for (size_t i = 0; i < count; ++i) {
            if (fd_count < sizeof(fds) / sizeof(fds[0])) fds[fd_count++] = installed[i];
            else { close(installed[i]); malformed = true; }
        }
    }
    struct ker_socket_client client = {.session_fd = -1};
    int result = 1;
    if (!malformed && fd_count == 1 && ker_socket_client_open(&client, rpc_path) == 0) {
        enum ker_socket_broker_kind kind = 0;
        int flags = 0;
        int described = ker_socket_client_describe(&client, fds[0], &kind, &flags);
        if (described == 0 &&
            kind == KER_SOCKET_BROKER_FF_OWNER_GENERATION_WATCH &&
            flags == 0 &&
            ker_socket_client_describe(&client, fds[0], &kind, &flags) == 0 &&
            kind == KER_SOCKET_BROKER_FF_OWNER_GENERATION_WATCH &&
            flags == 0) {
            result = send(control, "D", 1, MSG_NOSIGNAL) == 1 ? 0 : 1;
        } else {
            fprintf(stderr, "describe watch failed: rc=%d kind=%d flags=%d errno=%s\n",
                described, kind, flags, strerror(errno));
        }
    }
    if (result) (void)send(control, "X", 1, MSG_NOSIGNAL);
    for (size_t i = 0; i < fd_count; ++i) close(fds[i]);
    ker_socket_client_close(&client);
    close(control);
    return result;
}

static int same_port_owner_actor(const char *rpc_path, const char *control_path,
    uint16_t port)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) return 2;
    struct ker_socket_client client;
    int owner = -1, plan = -1, slot = -1, activated = -1, control = -1;
    int result = 1;
    if (ker_socket_client_open(&client, rpc_path)) goto done;
    owner = ker_socket_client_ff_owner_create(&client);
    if (owner < 0) goto close_client;
    plan = ker_socket_client_owner_group_staged_plan(&client, &address, 8,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    if (plan < 0) goto close_client;
    slot = ker_socket_client_owner_group_slot(&client, plan, 0);
    if (slot < 0 || ker_socket_client_ff_owner_group_claim(&client, owner, slot))
        goto close_client;
    activated = ker_socket_client_owner_group_activate_initial(&client, owner, slot);
    if (activated < 0 || ker_socket_client_bind(&client, activated,
            (const struct sockaddr *)&address, sizeof(address)) ||
        ker_socket_client_listen(&client, activated, 8)) goto close_client;
    control = connect_control(control_path);
    if (control < 0 || send(control, "R", 1, MSG_NOSIGNAL) != 1) goto close_client;
    char command = 0;
    if (recv(control, &command, 1, 0) != 1 || command != 'C') goto close_client;
    result = 0;

close_client:
    if (control >= 0) close(control);
    if (activated >= 0) close(activated);
    if (slot >= 0) close(slot);
    if (plan >= 0) close(plan);
    if (owner >= 0) close(owner);
    ker_socket_client_close(&client);
done:
    return result;
}

static int expect_port_reserved_actor(const char *rpc_path, uint16_t port)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) return 2;
    struct ker_socket_client client;
    if (ker_socket_client_open(&client, rpc_path)) return 1;
    int owner = ker_socket_client_ff_owner_create(&client);
    if (owner < 0) { ker_socket_client_close(&client); return 1; }
    errno = 0;
    int plan = ker_socket_client_owner_group_staged_plan(&client, &address, 8,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    int result = plan < 0 && errno == EADDRINUSE ? 0 : 1;
    if (plan >= 0) close(plan);
    close(owner);
    ker_socket_client_close(&client);
    return result;
}

#define REQUIRE(call) do { if (!(call)) { \
    fprintf(stderr, "generation watch actor:%d: %s: %s\n", __LINE__, #call, strerror(errno)); \
    goto fail; } } while (0)

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "--describe-watch") == 0)
        return describe_watch_actor(argv[2], argv[3]);
    if (argc == 5 && strcmp(argv[1], "--same-port-owner") == 0) {
        char *end = NULL;
        unsigned long port = strtoul(argv[4], &end, 10);
        if (!end || *end || !port || port > UINT16_MAX) return 2;
        return same_port_owner_actor(argv[2], argv[3], (uint16_t)port);
    }
    if (argc == 4 && strcmp(argv[1], "--expect-port-reserved") == 0) {
        char *end = NULL;
        unsigned long port = strtoul(argv[3], &end, 10);
        if (!end || *end || !port || port > UINT16_MAX) return 2;
        return expect_port_reserved_actor(argv[2], (uint16_t)port);
    }
    if (argc != 3) { fprintf(stderr, "usage: generation-watch-actor <rpc-path> <control-path>\n"); return 2; }
    const uint16_t port = 4127;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) return 2;
    struct ker_socket_client client;
    int owner = -1, plan = -1, slot = -1, watch = -1, activated = -1, control = -1;
    REQUIRE(ker_socket_client_open(&client, argv[1]) == 0);
    owner = ker_socket_client_ff_owner_create(&client);
    REQUIRE(owner >= 0);
    plan = ker_socket_client_owner_group_staged_plan(&client, &address, 8,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    REQUIRE(plan >= 0);
    slot = ker_socket_client_owner_group_slot(&client, plan, 0);
    REQUIRE(slot >= 0);
    watch = ker_socket_client_owner_generation_watch_create(&client, plan);
    REQUIRE(watch >= 0);
    REQUIRE(ker_socket_client_ff_owner_group_claim(&client, owner, slot) == 0);
    activated = ker_socket_client_owner_group_activate_initial(&client, owner, slot);
    REQUIRE(activated >= 0);
    REQUIRE(ker_socket_client_bind(&client, activated,
        (const struct sockaddr *)&address, sizeof(address)) == 0);
    REQUIRE(ker_socket_client_listen(&client, activated, 8) == 0);
    control = connect_control(argv[2]);
    REQUIRE(control >= 0);
    REQUIRE(send_watch(control, watch, port) == 0);
    char command = 0;
    REQUIRE(recv(control, &command, 1, 0) == 1 && command == 'C');
    close(activated); activated = -1;
    close(slot); slot = -1;
    close(plan); plan = -1;
    /* Keep the owner actor alive after every listener and plan capability is
     * closed. The watch capability belongs to the controller connection. */
    close(watch); watch = -1;
    REQUIRE(send(control, "C", 1, MSG_NOSIGNAL) == 1);
    for (;;) pause();

fail:
    if (activated >= 0) close(activated);
    if (watch >= 0) close(watch);
    if (slot >= 0) close(slot);
    if (plan >= 0) close(plan);
    if (owner >= 0) close(owner);
    if (control >= 0) close(control);
    ker_socket_client_close(&client);
    return 1;
}
