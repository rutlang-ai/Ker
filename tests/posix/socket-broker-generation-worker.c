#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include "socket-broker-generation-protocol.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define STREAM_LIMIT 64
#define REQUEST_MAGIC UINT32_C(0x4b455257)
#define RESPONSE_MAGIC UINT32_C(0x4b455252)
#define REQUEST_LENGTH 12
#define RESPONSE_LENGTH 24

_Static_assert(sizeof(struct ker_test_generation_message) == 24,
    "generation control record must have a fixed local ABI");

struct generation_stream {
    int fd;
    uint8_t request[REQUEST_LENGTH];
    size_t request_length;
    uint8_t output[RESPONSE_LENGTH + KER_SOCKET_BROKER_IO_MAX];
    size_t output_length;
    size_t output_offset;
    int response_sent;
};

static uint64_t to_be64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static uint64_t from_be64(uint64_t value) { return to_be64(value); }

static int parse_number(const char *text, long minimum, long maximum, long *value)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (!text[0] || errno || !end || *end || parsed < minimum || parsed > maximum) return -1;
    *value = parsed;
    return 0;
}

static int send_control(int fd, const struct ker_test_generation_message *message, int right)
{
    struct iovec vector = {.iov_base = (void *)message, .iov_len = sizeof(*message)};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr packet = {.msg_iov = &vector, .msg_iovlen = 1};
    if (right >= 0) {
        packet.msg_control = control;
        packet.msg_controllen = sizeof(control);
        struct cmsghdr *entry = CMSG_FIRSTHDR(&packet);
        entry->cmsg_level = SOL_SOCKET; entry->cmsg_type = SCM_RIGHTS;
        entry->cmsg_len = CMSG_LEN(sizeof(right));
        memcpy(CMSG_DATA(entry), &right, sizeof(right));
    }
    ssize_t sent = sendmsg(fd, &packet, MSG_NOSIGNAL);
    return sent == (ssize_t)sizeof(*message) ? 0 : -1;
}

static int receive_command(int fd, struct ker_test_generation_message *command)
{
    struct iovec vector = {.iov_base = command, .iov_len = sizeof(*command)};
    struct msghdr packet = {.msg_iov = &vector, .msg_iovlen = 1};
    ssize_t amount = recvmsg(fd, &packet, MSG_CMSG_CLOEXEC);
    if (amount != (ssize_t)sizeof(*command) ||
        packet.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int update_stream_interest(struct ker_socket_client *client, int epoll_fd,
    const struct generation_stream *stream, size_t slot)
{
    struct epoll_event event = {.events = EPOLLRDHUP, .data.u64 = slot + 1};
    if (stream->output_offset < stream->output_length) event.events |= EPOLLOUT;
    else event.events |= EPOLLIN;
    return ker_socket_client_epoll_ctl(client, epoll_fd, EPOLL_CTL_MOD, stream->fd, &event);
}

static void close_stream(struct ker_socket_client *client, int epoll_fd,
    struct generation_stream *stream)
{
    struct epoll_event event = {0};
    (void)ker_socket_client_epoll_ctl(client, epoll_fd, EPOLL_CTL_DEL, stream->fd, &event);
    (void)close(stream->fd);
    memset(stream, 0, sizeof(*stream));
    stream->fd = -1;
}

static int notify_accepted(struct ker_socket_client *client, int control_fd,
    struct generation_stream *stream, uint32_t generation, uint32_t worker,
    uint32_t process_id, uint64_t nonce)
{
    int observer = ker_socket_client_tcp_observer_create(client, stream->fd);
    if (observer < 0) return -1;
    struct ker_test_generation_message notification = {
        .type = KER_TEST_GENERATION_ACCEPTED, .generation = generation,
        .worker = worker, .process_id = process_id, .nonce = nonce
    };
    int result = send_control(control_fd, &notification, observer);
    int error = errno;
    close(observer);
    errno = error;
    return result;
}

static int process_stream_read(struct ker_socket_client *client, int control_fd,
    int epoll_fd, struct generation_stream *stream, size_t slot,
    uint32_t generation, uint32_t worker, uint32_t process_id)
{
    if (stream->output_offset < stream->output_length) return 0;
    stream->output_length = stream->output_offset = 0;
    if (!stream->response_sent) {
        ssize_t amount = ker_socket_client_read(client, stream->fd,
            stream->request + stream->request_length, REQUEST_LENGTH - stream->request_length);
        if (amount == 0) { close_stream(client, epoll_fd, stream); return 0; }
        if (amount < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
            return -1;
        }
        stream->request_length += (size_t)amount;
        if (stream->request_length < REQUEST_LENGTH) return 0;
        uint32_t magic = 0;
        uint64_t wire_nonce = 0;
        memcpy(&magic, stream->request, sizeof(magic));
        memcpy(&wire_nonce, stream->request + sizeof(magic), sizeof(wire_nonce));
        if (ntohl(magic) != REQUEST_MAGIC) { errno = EPROTO; return -1; }
        uint64_t nonce = from_be64(wire_nonce);
        uint32_t fields[4] = {htonl(RESPONSE_MAGIC), htonl(generation),
            htonl(worker), htonl(process_id)};
        memcpy(stream->output, fields, sizeof(fields));
        uint64_t response_nonce = to_be64(nonce);
        memcpy(stream->output + sizeof(fields), &response_nonce, sizeof(response_nonce));
        stream->output_length = RESPONSE_LENGTH;
        stream->response_sent = 1;
        if (notify_accepted(client, control_fd, stream, generation, worker,
                process_id, nonce)) return -1;
    } else {
        ssize_t amount = ker_socket_client_read(client, stream->fd,
            stream->output, KER_SOCKET_BROKER_IO_MAX);
        if (amount == 0) { close_stream(client, epoll_fd, stream); return 0; }
        if (amount < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
            return -1;
        }
        stream->output_length = (size_t)amount;
    }
    return update_stream_interest(client, epoll_fd, stream, slot);
}

static int process_stream_write(struct ker_socket_client *client, int epoll_fd,
    struct generation_stream *stream, size_t slot)
{
    if (stream->output_offset >= stream->output_length) return 0;
    ssize_t amount = ker_socket_client_write(client, stream->fd,
        stream->output + stream->output_offset,
        stream->output_length - stream->output_offset);
    if (amount < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return -1;
    }
    if (!amount) { errno = EPIPE; return -1; }
    stream->output_offset += (size_t)amount;
    if (stream->output_offset == stream->output_length) {
        stream->output_offset = stream->output_length = 0;
    }
    return update_stream_interest(client, epoll_fd, stream, slot);
}

static int accept_ready(struct ker_socket_client *client, int epoll_fd,
    int member_fd, struct generation_stream *streams)
{
    for (unsigned accepted_count = 0; accepted_count < 16; ++accepted_count) {
        int accepted = ker_socket_client_accept4(client, member_fd, NULL, NULL,
            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (accepted < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
            return -1;
        }
        size_t slot = STREAM_LIMIT;
        for (size_t i = 0; i < STREAM_LIMIT; ++i)
            if (streams[i].fd < 0) { slot = i; break; }
        if (slot == STREAM_LIMIT) { close(accepted); errno = EMFILE; return -1; }
        streams[slot].fd = accepted;
        struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.u64 = slot + 1};
        if (ker_socket_client_epoll_ctl(client, epoll_fd, EPOLL_CTL_ADD, accepted, &event)) {
            int error = errno; close(accepted); streams[slot].fd = -1; errno = error; return -1;
        }
    }
    return 0;
}

static int live_streams(const struct generation_stream *streams)
{
    int live = 0;
    for (size_t i = 0; i < STREAM_LIMIT; ++i) if (streams[i].fd >= 0) live++;
    return live;
}

int main(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "usage: generation-worker <rpc-path> <member-cap> <control-fd> <generation> <worker> <paused>\n");
        return 2;
    }
    long member, control, generation, worker, paused;
    if (parse_number(argv[2], 0, INT32_MAX, &member) ||
        parse_number(argv[3], 0, INT32_MAX, &control) ||
        parse_number(argv[4], 0, 1, &generation) ||
        parse_number(argv[5], 0, 1, &worker) || parse_number(argv[6], 0, 1, &paused)) return 2;

    struct ker_socket_client client;
    if (ker_socket_client_open(&client, argv[1])) { perror("worker client open"); return 1; }
    enum ker_socket_broker_kind kind = 0; int status_flags = -1;
    if (ker_socket_client_describe(&client, (int)member, &kind, &status_flags) ||
        kind != KER_SOCKET_BROKER_SOCKET || status_flags < 0) {
        perror("worker member describe"); ker_socket_client_close(&client); return 1;
    }
    int epoll_fd = ker_socket_client_epoll_create1(&client, EPOLL_CLOEXEC);
    if (epoll_fd < 0) { perror("worker epoll create"); ker_socket_client_close(&client); return 1; }
    struct epoll_event listener_event = {.events = EPOLLIN, .data.u64 = 0};
    if (ker_socket_client_epoll_ctl(&client, epoll_fd, EPOLL_CTL_ADD, (int)member,
            &listener_event)) {
        perror("worker epoll add listener"); close(epoll_fd); ker_socket_client_close(&client); return 1;
    }
    uint32_t process_id = (uint32_t)getpid();
    struct ker_test_generation_message ready = {
        .type = KER_TEST_GENERATION_READY, .generation = (uint32_t)generation,
        .worker = (uint32_t)worker, .process_id = process_id
    };
    if (send_control((int)control, &ready, -1)) {
        perror("worker ready message"); close(epoll_fd); ker_socket_client_close(&client); return 1;
    }

    struct generation_stream streams[STREAM_LIMIT];
    memset(streams, 0, sizeof(streams));
    for (size_t i = 0; i < STREAM_LIMIT; ++i) streams[i].fd = -1;
    int accepting_paused = (int)paused, retiring = 0, failed = 0;
    struct pollfd host = {.fd = (int)control, .events = POLLIN | POLLHUP};
    for (;;) {
        host.revents = 0;
        int host_ready = poll(&host, 1, 10);
        if (host_ready < 0 && errno != EINTR) { perror("worker control poll"); failed = 1; break; }
        if (host.revents & POLLIN) {
            struct ker_test_generation_message command = {0};
            if (receive_command((int)control, &command) ||
                command.generation != (uint32_t)generation || command.worker != (uint32_t)worker ||
                command.process_id != process_id || !command.nonce) {
                perror("worker invalid control command"); failed = 1; break;
            }
            if (command.type == KER_TEST_GENERATION_PAUSE_ACCEPT) accepting_paused = 1;
            else if (command.type == KER_TEST_GENERATION_RESUME_ACCEPT) accepting_paused = 0;
            else if (command.type == KER_TEST_GENERATION_RETIRE) { accepting_paused = 1; retiring = 1; }
            else { errno = EPROTO; perror("worker unsupported control operation"); failed = 1; break; }
            struct ker_test_generation_message ack = command;
            ack.type = KER_TEST_GENERATION_ACK;
            if (send_control((int)control, &ack, -1)) { perror("worker control ACK"); failed = 1; break; }
        }
        if (host.revents & (POLLHUP | POLLERR | POLLNVAL)) {
            errno = EPIPE; perror("worker supervisor disconnected"); failed = 1; break;
        }

        struct epoll_event events[16];
        int count = ker_socket_client_epoll_wait(&client, epoll_fd, events, 16);
        if (count < 0) { perror("worker original epoll wait"); failed = 1; break; }
        for (int event_index = 0; event_index < count; ++event_index) {
            uint64_t token = events[event_index].data.u64;
            if (token == 0) {
                if (!accepting_paused && accept_ready(&client, epoll_fd, (int)member, streams)) {
                    perror("worker original accept"); failed = 1; break;
                }
                continue;
            }
            size_t slot = (size_t)(token - 1);
            if (slot >= STREAM_LIMIT || streams[slot].fd < 0) { errno = EPROTO; failed = 1; break; }
            struct generation_stream *stream = &streams[slot];
            if ((events[event_index].events & EPOLLOUT) &&
                process_stream_write(&client, epoll_fd, stream, slot)) {
                perror("worker original write"); failed = 1; break;
            }
            if (stream->fd >= 0 && (events[event_index].events & (EPOLLIN | EPOLLRDHUP)) &&
                process_stream_read(&client, (int)control, epoll_fd, stream, slot,
                    (uint32_t)generation, (uint32_t)worker, process_id)) {
                perror("worker original read"); failed = 1; break;
            }
        }
        if (failed) break;
        if (retiring && !live_streams(streams)) break;
    }

    for (size_t i = 0; i < STREAM_LIMIT; ++i)
        if (streams[i].fd >= 0) close_stream(&client, epoll_fd, &streams[i]);
    if (!failed && retiring) {
        struct ker_test_generation_message exited = {
            .type = KER_TEST_GENERATION_EXITED, .generation = (uint32_t)generation,
            .worker = (uint32_t)worker, .process_id = process_id
        };
        if (send_control((int)control, &exited, -1)) { perror("worker exit message"); failed = 1; }
    } else if (!failed) {
        errno = EPROTO; perror("worker stopped without RETIRE"); failed = 1;
    }
    close((int)member); close(epoll_fd); close((int)control);
    ker_socket_client_close(&client);
    return failed ? 1 : 0;
}
