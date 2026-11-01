#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CENSUS_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "member census client:%d: %s: %s\n", __LINE__, #x, strerror(errno)); \
    return 1; } } while (0)

static int snapshot(struct ker_socket_client *client, int cap,
    struct ker_socket_member_census_snapshot *result)
{
    memset(result, 0, sizeof(*result));
    return ker_socket_client_member_census_snapshot(client, cap, result);
}

static int send_census_caps(int control_fd, const int census[2])
{
    static const char ready = 'C';
    char control[CMSG_SPACE(sizeof(int) * 2)] = {0};
    struct iovec iov = {.iov_base = (void *)&ready, .iov_len = sizeof(ready)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 2);
    memcpy(CMSG_DATA(cmsg), census, sizeof(int) * 2);
    return sendmsg(control_fd, &message, MSG_NOSIGNAL) == 1 ? 0 : -1;
}

static int send_observer_cap(int control_fd, unsigned index, int observer)
{
    unsigned char tag[2] = {'O', (unsigned char)index};
    char control[CMSG_SPACE(sizeof(observer))] = {0};
    struct iovec iov = {.iov_base = tag, .iov_len = sizeof(tag)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(observer));
    memcpy(CMSG_DATA(cmsg), &observer, sizeof(observer));
    return sendmsg(control_fd, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(tag) ? 0 : -1;
}

static int print_snapshot(struct ker_socket_client *client, int cap, unsigned index)
{
    struct ker_socket_member_census_snapshot value;
    if (snapshot(client, cap, &value)) return -1;
    printf("SNAP %u total=%llu listen=%llu synrecv=%llu established=%llu \
        finwait1=%llu closing=%llu lastack=%llu timewait=%llu cookie=%llu\n",
        index, (unsigned long long)value.total,
        (unsigned long long)value.state_counts[KER_SOCKET_TCP_STATE_LISTEN],
        (unsigned long long)value.state_counts[KER_SOCKET_TCP_STATE_SYN_RECV],
        (unsigned long long)value.state_counts[KER_SOCKET_TCP_STATE_ESTABLISHED],
        (unsigned long long)value.state_counts[KER_SOCKET_TCP_STATE_FIN_WAIT1],
        (unsigned long long)value.state_counts[KER_SOCKET_TCP_STATE_CLOSING],
        (unsigned long long)value.state_counts[KER_SOCKET_TCP_STATE_LAST_ACK],
        (unsigned long long)value.state_counts[KER_SOCKET_TCP_STATE_TIME_WAIT],
        (unsigned long long)value.listener_cookie);
    return 0;
}

static int read_exact(struct ker_socket_client *client, int fd, size_t offset, size_t length)
{
    unsigned char buffer[4096];
    size_t received = 0;
    while (received < length) {
        size_t wanted = length - received;
        if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
        ssize_t amount = ker_socket_client_read(client, fd, buffer, wanted);
        if (amount > 0) {
            for (ssize_t i = 0; i < amount; ++i) {
                unsigned char expected = (unsigned char)((offset + received + (size_t)i) * 31u + 7u);
                if (buffer[i] != expected) { errno = EBADMSG; return -1; }
            }
            received += (size_t)amount;
            continue;
        }
        if (amount < 0 && (errno == EAGAIN || errno == EINTR)) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)nanosleep(&pause, NULL);
            continue;
        }
        if (!amount) errno = ECONNRESET;
        return -1;
    }
    return 0;
}

static int write_reply(struct ker_socket_client *client, int fd, const char *text)
{
    size_t length = strlen(text), written = 0;
    while (written < length) {
        ssize_t amount = ker_socket_client_write(client, fd, text + written, length - written);
        if (amount > 0) { written += (size_t)amount; continue; }
        if (amount < 0 && (errno == EAGAIN || errno == EINTR)) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)nanosleep(&pause, NULL);
            continue;
        }
        if (!amount) errno = EPIPE;
        return -1;
    }
    return 0;
}

static int fill_send_queue(struct ker_socket_client *client, int fd, size_t *sent)
{
    int send_buffer = 262144;
    if (ker_socket_client_setsockopt(client, fd, SOL_SOCKET, SO_SNDBUF,
            &send_buffer, sizeof(send_buffer))) return -1;
    unsigned char payload[4096];
    *sent = 0;
    bool pressure = false;
    while (*sent < 4 * 1024 * 1024) {
        size_t amount = sizeof(payload);
        if (amount > 4 * 1024 * 1024 - *sent) amount = 4 * 1024 * 1024 - *sent;
        for (size_t i = 0; i < amount; ++i)
            payload[i] = (unsigned char)(((*sent + i) * 17u + 3u) & 0xffu);
        ssize_t result = ker_socket_client_write(client, fd, payload, amount);
        if (result > 0) { *sent += (size_t)result; continue; }
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pressure = true;
            break;
        }
        if (!result) errno = EPIPE;
        return -1;
    }
    if (!pressure) { errno = ENOBUFS; return -1; }
    return 0;
}

static uint64_t monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return (uint64_t)value.tv_sec * 1000u + (uint64_t)value.tv_nsec / 1000000u;
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--tcp-observe")) {
        char *end = NULL;
        long observer_fd = strtol(argv[3], &end, 10);
        if (!end || *end || observer_fd < 0 || observer_fd > INT32_MAX) return 2;
        struct ker_socket_client observer;
        if (ker_socket_client_open(&observer, argv[2])) return 1;
        struct ker_socket_tcp_observer_snapshot value;
        int result = ker_socket_client_tcp_observer_snapshot(&observer,
            (int)observer_fd, &value);
        if (!result) printf("TCP_OBSERVER present=%u state=%u send_queue=%u cookie=%llu\n",
            value.present, value.state, value.send_queue, (unsigned long long)value.cookie);
        ker_socket_client_close(&observer);
        fflush(stdout);
        return result ? 1 : 0;
    }
    if (argc == 5 && !strcmp(argv[1], "--observe")) {
        char *first_end = NULL, *second_end = NULL;
        long first = strtol(argv[3], &first_end, 10), second = strtol(argv[4], &second_end, 10);
        if (!first_end || *first_end || !second_end || *second_end || first < 0 || second < 0) return 2;
        struct ker_socket_client observer;
        if (ker_socket_client_open(&observer, argv[2])) return 1;
        int status = print_snapshot(&observer, (int)first, 0) ||
            print_snapshot(&observer, (int)second, 1);
        ker_socket_client_close(&observer);
        fflush(stdout);
        return status ? 1 : 0;
    }
    if (argc != 4) {
        fprintf(stderr, "usage: member-census-client <rpc-path> <group-cap> <control-fd>\n"); return 2;
    }
    char *end = NULL;
    long parsed_fd = strtol(argv[2], &end, 10);
    if (!end || *end || parsed_fd < 0 || parsed_fd > INT32_MAX) return 2;
    int bootstrap_group = (int)parsed_fd;
    long parsed_control = strtol(argv[3], &end, 10);
    if (!end || *end || parsed_control < 0 || parsed_control > INT32_MAX) return 2;
    int control_fd = (int)parsed_control;
    struct ker_socket_client client;
    CENSUS_CHECK(ker_socket_client_open(&client, argv[1]) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4097)};
    CENSUS_CHECK(inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) == 1);
    int group = ker_socket_client_reuseport_group_create(&client, &address, 16);
    CENSUS_CHECK(group >= 0);
    close(bootstrap_group);
    int member[2] = {-1, -1}, census[2] = {-1, -1}, accepted[8];
    for (size_t i = 0; i < 8; ++i) accepted[i] = -1;
    for (unsigned i = 0; i < 2; ++i) {
        member[i] = ker_socket_client_reuseport_group_member(&client, group, i);
        CENSUS_CHECK(member[i] >= 0);
        census[i] = ker_socket_client_member_census_create(&client, group, i);
        CENSUS_CHECK(census[i] >= 0);
    }
    CENSUS_CHECK(send_census_caps(control_fd, census) == 0);
    CENSUS_CHECK(ker_socket_client_reuseport_group_select(&client, group, 0) == 0);
    puts("CENSUS_CLIENT_READY"); fflush(stdout);

    char command[256];
    while (fgets(command, sizeof(command), stdin)) {
        unsigned index = 0, slot = 0, state = 0, milliseconds = 0;
        size_t count = 0;
        if (!strncmp(command, "SNAP", 4)) {
            for (unsigned i = 0; i < 2; ++i) {
                if (print_snapshot(&client, census[i], i)) {
                    printf("ERROR snapshot %d\n", errno); fflush(stdout); continue;
                }
            }
            fflush(stdout);
        } else if (sscanf(command, "SELECT %u", &index) == 1) {
            int result = ker_socket_client_reuseport_group_select(&client, group, index);
            printf("SELECT %u %d %d\n", index, result, result < 0 ? errno : 0); fflush(stdout);
        } else if (sscanf(command, "WAIT %u %zu %u", &state, &count, &milliseconds) == 3) {
            if (state >= KER_SOCKET_BROKER_TCP_STATES || milliseconds > 10000) return 3;
            uint64_t now = monotonic_ms();
            if (!now) return 3;
            uint64_t deadline = now + milliseconds;
            bool observed = false;
            bool query_failed = false;
            do {
                struct ker_socket_member_census_snapshot value;
                if (snapshot(&client, census[0], &value)) {
                    printf("WAIT %u ERROR %d\n", state, errno); fflush(stdout);
                    query_failed = true;
                    break;
                }
                if (value.state_counts[state] >= count) { observed = true; break; }
                struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
                (void)nanosleep(&pause, NULL);
            } while (monotonic_ms() && monotonic_ms() <= deadline);
            if (observed) printf("WAIT %u FOUND\n", state);
            else if (!query_failed) printf("WAIT %u TIMEOUT\n", state);
            fflush(stdout);
        } else if (sscanf(command, "ACCEPT %u %u", &index, &slot) == 2) {
            if (index > 1 || slot >= 8 || accepted[slot] >= 0) return 3;
            accepted[slot] = ker_socket_client_accept4(&client, member[index], NULL, NULL,
                SOCK_NONBLOCK | SOCK_CLOEXEC);
            printf("ACCEPT %u %u %d %d\n", index, slot, accepted[slot],
                accepted[slot] < 0 ? errno : 0); fflush(stdout);
        } else if (sscanf(command, "READ %u %u %zu", &slot, &index, &count) == 3) {
            if (slot >= 8 || accepted[slot] < 0 || count > 1024 * 1024) return 3;
            int result = read_exact(&client, accepted[slot], index, count);
            printf("READ %u %u %zu %d %d\n", slot, index, count, result, result ? errno : 0); fflush(stdout);
        } else if (sscanf(command, "FILL %u", &slot) == 1) {
            if (slot >= 8 || accepted[slot] < 0) return 3;
            size_t sent = 0;
            int result = fill_send_queue(&client, accepted[slot], &sent);
            uint32_t send_queue = 0;
            int observer = -1;
            if (!result) {
                observer = ker_socket_client_tcp_observer_create(&client, accepted[slot]);
                if (observer < 0) result = -1;
            }
            if (!result) {
                struct ker_socket_tcp_observer_snapshot value;
                if (ker_socket_client_tcp_observer_snapshot(&client, observer, &value)) {
                    result = -1;
                } else if (!value.present || !value.send_queue) {
                    errno = ENODATA;
                    result = -1;
                } else {
                    send_queue = value.send_queue;
                    if (send_observer_cap(control_fd, slot, observer)) result = -1;
                }
            }
            int saved = errno;
            if (observer >= 0) close(observer);
            printf("FILL %u %zu %u %d %d\n", slot, sent, send_queue, result, result ? saved : 0);
            fflush(stdout);
        } else if (!strncmp(command, "WRITE ", 6)) {
            char payload[64];
            if (sscanf(command, "WRITE %u %63s", &slot, payload) != 2) return 3;
            if (slot >= 8 || accepted[slot] < 0) return 3;
            int result = write_reply(&client, accepted[slot], payload);
            printf("WRITE %u %d %d\n", slot, result, result ? errno : 0); fflush(stdout);
        } else if (sscanf(command, "CLOSE %u", &slot) == 1) {
            if (slot >= 8 || accepted[slot] < 0) return 3;
            int result = close(accepted[slot]); accepted[slot] = -1;
            printf("CLOSE %u %d %d\n", slot, result, result ? errno : 0); fflush(stdout);
        } else if (!strncmp(command, "CLOSE_GROUP", 11)) {
            for (unsigned i = 0; i < 2; ++i) {
                if (member[i] >= 0) close(member[i]);
                member[i] = -1;
            }
            if (group >= 0) close(group);
            group = -1;
            puts("GROUP_CLOSED"); fflush(stdout);
        } else if (!strncmp(command, "QUIT", 4)) {
            for (unsigned i = 0; i < 2; ++i) if (census[i] >= 0) close(census[i]);
            for (size_t i = 0; i < 8; ++i) if (accepted[i] >= 0) close(accepted[i]);
            if (group >= 0) close(group);
            for (unsigned i = 0; i < 2; ++i) if (member[i] >= 0) close(member[i]);
            close(control_fd);
            ker_socket_client_close(&client);
            puts("CENSUS_CLIENT_DONE"); fflush(stdout);
            return 0;
        } else {
            puts("ERROR command"); fflush(stdout);
            return 3;
        }
    }
    return 4;
}
