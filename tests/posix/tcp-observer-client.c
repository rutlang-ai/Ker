#define _GNU_SOURCE
#include <ker/socket-broker.h>
#ifdef KER_TCP_OBSERVER_PRIVATE_TEST
#include "socket-broker-protocol.h"
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    dprintf(STDERR_FILENO, "tcp observer:%d: %s: %s\n", __LINE__, #test, strerror(errno)); \
    return 1; } } while (0)

static int parse_fd(const char *text)
{
    char *end = NULL;
    long value = strtol(text, &end, 10);
    return text[0] && end && !*end && value >= 0 && value <= INT32_MAX ? (int)value : -1;
}

static int read_exact(struct ker_socket_client *client, int cap, void *buffer, size_t size)
{
    size_t offset = 0;
    struct timespec pause = {.tv_nsec = 1000000};
    for (unsigned tries = 0; offset < size && tries < 10000; ++tries) {
        size_t request = size - offset < KER_SOCKET_BROKER_IO_MAX ?
            size - offset : KER_SOCKET_BROKER_IO_MAX;
        ssize_t amount = ker_socket_client_read(client, cap,
            (char *)buffer + offset, request);
        if (amount > 0) { offset += (size_t)amount; continue; }
        if (!amount || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return -1;
        (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    if (offset != size) { errno = ETIMEDOUT; return -1; }
    return 0;
}

static int wait_observer(struct ker_socket_client *client, int observer,
    struct ker_socket_tcp_observer_snapshot *snapshot, uint32_t receive_queue)
{
    struct timespec pause = {.tv_nsec = 1000000};
    for (unsigned tries = 0; tries < 10000; ++tries) {
        if (ker_socket_client_tcp_observer_snapshot(client, observer, snapshot)) return -1;
        if ((receive_queue == UINT32_MAX || snapshot->receive_queue == receive_queue) &&
            snapshot->present) return 0;
        (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

#ifdef KER_TCP_OBSERVER_PRIVATE_TEST
static int malformed_snapshot_is_rejected(struct ker_socket_client *client, int observer)
{
    unsigned char invalid_payload = 1;
    struct ker_sb_header request = {.magic = KER_SB_MAGIC, .version = KER_SB_VERSION,
        .operation = KER_SB_TCP_OBSERVER_SNAPSHOT, .payload_length = 1,
        .rights_count = 1, .sequence = client->sequence + 1};
    struct iovec vectors[2] = {{&request, sizeof(request)}, {&invalid_payload, 1}};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *entry = CMSG_FIRSTHDR(&message);
    entry->cmsg_level = SOL_SOCKET; entry->cmsg_type = SCM_RIGHTS;
    entry->cmsg_len = CMSG_LEN(sizeof(observer));
    memcpy(CMSG_DATA(entry), &observer, sizeof(observer));
    if (syscall(SYS_sendmsg, client->session_fd, &message, MSG_NOSIGNAL) !=
            (ssize_t)(sizeof(request) + sizeof(invalid_payload))) return -1;
    struct ker_sb_header reply = {0};
    ssize_t received = syscall(SYS_recvfrom, client->session_fd, &reply,
        sizeof(reply), MSG_TRUNC, NULL, NULL);
    if (received != sizeof(reply) || reply.magic != KER_SB_MAGIC ||
        reply.version != KER_SB_VERSION || reply.operation != KER_SB_TCP_OBSERVER_SNAPSHOT ||
        reply.sequence != request.sequence || reply.payload_length || reply.rights_count ||
        reply.result != -EPROTO) { errno = EPROTO; return -1; }
    client->sequence = request.sequence;
    return 0;
}
#endif

int main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "--inherited-observer")) {
        int inherited = parse_fd(argv[3]);
        char *end = NULL;
        uint64_t expected_cookie = strtoull(argv[4], &end, 10);
        CHECK(inherited >= 0 && end && !*end && expected_cookie != 0);
        CHECK((fcntl(inherited, F_GETFL) & O_ACCMODE) == O_WRONLY);
        struct ker_socket_client inherited_client;
        CHECK(ker_socket_client_open(&inherited_client, argv[2]) == 0);
        enum ker_socket_broker_kind inherited_kind = 0;
        int inherited_flags = -1;
        CHECK(ker_socket_client_describe(&inherited_client, inherited,
            &inherited_kind, &inherited_flags) == 0 &&
            inherited_kind == KER_SOCKET_BROKER_TCP_OBSERVER && inherited_flags == 0);
        struct ker_socket_tcp_observer_snapshot inherited_snapshot = {0};
        CHECK(ker_socket_client_tcp_observer_snapshot(&inherited_client, inherited,
            &inherited_snapshot) == 0 && inherited_snapshot.present &&
            inherited_snapshot.cookie == expected_cookie);
        ker_socket_client_close(&inherited_client);
        return 0;
    }
    if (argc != 7) {
        fprintf(stderr, "usage: tcp-observer-client <rpc-path> <listener-cap> <epoll-cap> <restricted-cap> <ack-fd> <preload-library>\n");
        return 2;
    }
    int listener = parse_fd(argv[2]), epoll = parse_fd(argv[3]);
    int restricted = parse_fd(argv[4]), ack = parse_fd(argv[5]);
    CHECK(listener >= 0 && epoll >= 0 && restricted >= 0 && ack >= 0);
    struct ker_socket_client client;
    CHECK(ker_socket_client_open(&client, argv[1]) == 0);
    int udp = ker_socket_client_socket(&client, AF_INET, SOCK_DGRAM, 0);
    CHECK(udp >= 0);
    errno = 0;
    CHECK(ker_socket_client_tcp_observer_create(&client, udp) == -1 && errno == EPROTOTYPE);
    CHECK(close(udp) == 0);
    int ipv6 = ker_socket_client_socket(&client, AF_INET6, SOCK_STREAM, 0);
    if (ipv6 >= 0) {
        errno = 0;
        CHECK(ker_socket_client_tcp_observer_create(&client, ipv6) == -1 && errno == EAFNOSUPPORT);
        CHECK(close(ipv6) == 0);
    } else CHECK(errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT);
    errno = 0;
    CHECK(ker_socket_client_tcp_observer_create(&client, listener) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(ker_socket_client_tcp_observer_create(&client, epoll) == -1 && errno == ENOTSOCK);
    errno = 0;
    CHECK(ker_socket_client_tcp_observer_create(&client, restricted) == -1 && errno == EACCES);
    puts("OBSERVER_WAIT_ACCEPT"); fflush(stdout);
    int accepted = -1;
    struct timespec pause = {.tv_nsec = 1000000};
    for (unsigned tries = 0; tries < 10000 && accepted < 0; ++tries) {
        accepted = ker_socket_client_accept4(&client, listener, NULL, NULL, SOCK_CLOEXEC);
        if (accepted < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 1;
        if (accepted < 0) (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    CHECK(accepted >= 0);
    puts("OBSERVER_ACCEPTED"); fflush(stdout);
    int duplicate = ker_socket_client_dup(&client, accepted);
    CHECK(duplicate >= 0);
    uint64_t cookie = 0;
    socklen_t length = sizeof(cookie);
    CHECK(ker_socket_client_getsockopt(&client, accepted, SOL_SOCKET, SO_COOKIE,
        &cookie, &length) == 0 && length == sizeof(cookie) && cookie != 0);
    uint32_t short_cookie = 0;
    length = sizeof(short_cookie);
    errno = 0;
    CHECK(ker_socket_client_getsockopt(&client, accepted, SOL_SOCKET, SO_COOKIE,
        &short_cookie, &length) == -1 && errno == EINVAL);
    uint64_t alias_cookie = 0;
    length = sizeof(alias_cookie);
    CHECK(ker_socket_client_getsockopt(&client, duplicate, SOL_SOCKET, SO_COOKIE,
        &alias_cookie, &length) == 0 && alias_cookie == cookie);
    errno = 0;
    CHECK(ker_socket_client_setsockopt(&client, accepted, SOL_SOCKET, SO_COOKIE,
        &cookie, sizeof(cookie)) == -1 && errno == EOPNOTSUPP);
    int observer = ker_socket_client_tcp_observer_create(&client, accepted);
    CHECK(observer >= 0);
    enum ker_socket_broker_kind kind;
    int status_flags = -1;
    CHECK(ker_socket_client_describe(&client, observer, &kind, &status_flags) == 0 &&
        kind == KER_SOCKET_BROKER_TCP_OBSERVER && status_flags == 0);
    errno = 0;
    CHECK(ker_socket_client_dup(&client, observer) == -1 && errno == EOPNOTSUPP);
    struct ker_socket_tcp_observer_snapshot snapshot = {0};
    CHECK(wait_observer(&client, observer, &snapshot, 16384) == 0);
    CHECK(snapshot.cookie == cookie && snapshot.receive_queue > 0);
    int descriptor_flags = fcntl(observer, F_GETFD);
    CHECK(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC));
    CHECK(fcntl(observer, F_SETFD, descriptor_flags & ~FD_CLOEXEC) == 0);
    CHECK(setenv("KER_SOCKET_BROKER_PATH", argv[1], 1) == 0);
    CHECK(setenv("LD_PRELOAD", argv[6], 1) == 0);
    pid_t exec_child = fork();
    CHECK(exec_child >= 0);
    if (exec_child == 0) {
        char observer_text[32], cookie_text[32];
        (void)syscall(SYS_close, accepted);
        (void)syscall(SYS_close, duplicate);
        (void)snprintf(observer_text, sizeof(observer_text), "%d", observer);
        (void)snprintf(cookie_text, sizeof(cookie_text), "%" PRIu64, cookie);
        execl(argv[0], argv[0], "--inherited-observer", argv[1], observer_text,
            cookie_text, (char *)NULL);
        _exit(127);
    }
    int exec_status = 0;
    CHECK(waitpid(exec_child, &exec_status, 0) == exec_child &&
        WIFEXITED(exec_status) && WEXITSTATUS(exec_status) == 0);
    puts("OBSERVER_EXEC_SNAPSHOT_OK"); fflush(stdout);
    CHECK(fcntl(observer, F_SETFD, descriptor_flags) == 0);
    CHECK(unsetenv("KER_SOCKET_BROKER_PATH") == 0);
    CHECK(unsetenv("LD_PRELOAD") == 0);
    CHECK(wait_observer(&client, observer, &snapshot, 16384) == 0 &&
        snapshot.cookie == cookie && snapshot.receive_queue > 0);
    puts("OBSERVER_EXEC_CAP_RETAINED"); fflush(stdout);
    errno = 0;
    CHECK(ker_socket_client_tcp_observer_snapshot(&client, accepted, &snapshot) == -1 &&
        errno == ENOTSOCK);
#ifdef KER_TCP_OBSERVER_PRIVATE_TEST
    CHECK(malformed_snapshot_is_rejected(&client, observer) == 0);
#endif
    CHECK(wait_observer(&client, observer, &snapshot, 16384) == 0 &&
        snapshot.cookie == cookie && snapshot.receive_queue > 0);
    char inbound[16384];
    CHECK(read_exact(&client, accepted, inbound, sizeof(inbound)) == 0);
    for (size_t i = 0; i < sizeof(inbound); ++i)
        CHECK((unsigned char)inbound[i] == (unsigned char)((i * 17u + 5u) & 0xffu));
    CHECK(wait_observer(&client, observer, &snapshot, 0) == 0 && snapshot.cookie == cookie);
    puts("OBSERVER_RX_DRAINED"); fflush(stdout);

    int send_buffer = 4096;
    CHECK(ker_socket_client_setsockopt(&client, accepted, SOL_SOCKET, SO_SNDBUF,
        &send_buffer, sizeof(send_buffer)) == 0);
    char payload[KER_SOCKET_BROKER_IO_MAX];
    uint64_t sent_total = 0;
    bool blocked = false;
    for (unsigned tries = 0; tries < 8192; ++tries) {
        for (size_t i = 0; i < sizeof(payload); ++i)
            payload[i] = (char)(((sent_total + i) * 29u + 3u) & 0xffu);
        ssize_t amount = ker_socket_client_write(&client, accepted, payload, sizeof(payload));
        if (amount > 0) { sent_total += (uint64_t)amount; continue; }
        if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { blocked = true; break; }
        if (amount < 0 && errno == EINTR) continue;
        CHECK(false);
    }
    CHECK(blocked && sent_total > 0);
    CHECK(wait_observer(&client, observer, &snapshot, UINT32_MAX) == 0);
    CHECK(snapshot.cookie == cookie && snapshot.send_queue > 0);
    CHECK(close(accepted) == 0);
    CHECK(close(duplicate) == 0);
    CHECK(wait_observer(&client, observer, &snapshot, UINT32_MAX) == 0);
    CHECK(snapshot.cookie == cookie);
    dprintf(STDOUT_FILENO, "OBSERVER_CAPS_CLOSED %" PRIu64 "\n", sent_total);
    char acknowledgement = 0;
    CHECK(read(ack, &acknowledgement, 1) == 1 && acknowledgement == 'A');
    close(ack);
    int final_found = 0;
    for (unsigned tries = 0; tries < 10000; ++tries) {
        CHECK(ker_socket_client_tcp_observer_snapshot(&client, observer, &snapshot) == 0);
        CHECK(snapshot.cookie == cookie);
        if (!snapshot.present || snapshot.state == TCP_TIME_WAIT) { final_found = 1; break; }
        (void)syscall(SYS_nanosleep, &pause, NULL);
    }
    CHECK(final_found);
    printf("OBSERVER_FINAL present=%u state=%u cookie=%" PRIu64 "\n",
        snapshot.present, snapshot.state, snapshot.cookie); fflush(stdout);
    close(observer);
    close(restricted);
    close(listener);
    close(epoll);
    ker_socket_client_close(&client);
    return 0;
}
