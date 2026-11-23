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
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define HANDOFF_MAGIC UINT32_C(0x314f574b)
#define HANDOFF_VERSION 1
#define HANDOFF_OWNER_WATCH 1
#define REQUEST_BYTES 16
#define RESPONSE_BYTES 20

static void put16le(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
}

static void put32le(uint8_t *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) out[i] = (uint8_t)(value >> (i * 8));
}

static void put64le(uint8_t *out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) out[i] = (uint8_t)(value >> (i * 8));
}

static uint64_t process_start_ticks(void)
{
    char text[4096];
    FILE *file = fopen("/proc/self/stat", "re");
    if (!file) return 0;
    if (!fgets(text, sizeof(text), file)) { fclose(file); return 0; }
    fclose(file);
    char *close = strrchr(text, ')');
    if (!close) return 0;
    char *save = NULL;
    char *field = strtok_r(close + 2, " ", &save);
    for (unsigned index = 0; field; ++index, field = strtok_r(NULL, " ", &save)) {
        if (index == 19) {
            char *end = NULL;
            errno = 0;
            unsigned long long value = strtoull(field, &end, 10);
            if (errno || !end || (*end && *end != '\n') || !value) return 0;
            return (uint64_t)value;
        }
    }
    return 0;
}

static int connect_handoff(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (!length || length >= sizeof(address.sun_path)) {
        close(fd); errno = ENAMETOOLONG; return -1;
    }
    memcpy(address.sun_path, path, length + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        int error = errno; close(fd); errno = error; return -1;
    }
    return fd;
}

static int send_watch(int control, int watch, uint16_t port,
    const uint8_t address[4])
{
    uint8_t record[64] = {0};
    put32le(record + 0, HANDOFF_MAGIC);
    put16le(record + 4, HANDOFF_VERSION);
    put16le(record + 6, HANDOFF_OWNER_WATCH);
    put32le(record + 8, sizeof(record));
    put32le(record + 16, (uint32_t)getpid());
    put32le(record + 20, (uint32_t)getuid());
    put32le(record + 24, (uint32_t)getgid());
    put64le(record + 32, process_start_ticks());
    put16le(record + 40, AF_INET);
    put16le(record + 42, port);
    put16le(record + 44, 4);
    memcpy(record + 48, address, 4);
    if (!process_start_ticks()) { errno = EPROTO; return -1; }

    char ancillary[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec vector = {.iov_base = record, .iov_len = sizeof(record)};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = ancillary, .msg_controllen = sizeof(ancillary)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(watch));
    memcpy(CMSG_DATA(cmsg), &watch, sizeof(watch));
    return sendmsg(control, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(record) ? 0 : -1;
}

static int wait_retry(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    if (now.tv_sec > deadline->tv_sec ||
        (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) {
        errno = ETIMEDOUT;
        return -1;
    }
    struct timespec pause = {.tv_nsec = 1000000};
    while (nanosleep(&pause, &pause) && errno == EINTR) { }
    return 0;
}

static int read_exact(struct ker_socket_client *client, int fd, uint8_t *data,
    size_t size, const struct timespec *deadline)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = ker_socket_client_read(client, fd, data + offset, size - offset);
        if (amount <= 0) {
            if (amount < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (wait_retry(deadline)) return -1;
                continue;
            }
            if (!amount) errno = ECONNRESET;
            return -1;
        }
        offset += (size_t)amount;
    }
    return 0;
}

static int write_exact(struct ker_socket_client *client, int fd,
    const uint8_t *data, size_t size, const struct timespec *deadline)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = ker_socket_client_write(client, fd, data + offset, size - offset);
        if (amount <= 0) {
            if (amount < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (wait_retry(deadline)) return -1;
                continue;
            }
            if (!amount) errno = EPIPE;
            return -1;
        }
        offset += (size_t)amount;
    }
    return 0;
}

static int wait_control(int fd, short events, const struct timespec *deadline)
{
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
        int64_t left_ms = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000 +
            (deadline->tv_nsec - now.tv_nsec + 999999) / 1000000;
        if (left_ms <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd descriptor = {.fd = fd, .events = events};
        int rc = poll(&descriptor, 1, left_ms > INT32_MAX ? INT32_MAX : (int)left_ms);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return -1;
        if (!rc) continue;
        if (descriptor.revents & (POLLERR | POLLNVAL)) { errno = EIO; return -1; }
        if (descriptor.revents & events) return 0;
        if (descriptor.revents & POLLHUP) { errno = ECONNRESET; return -1; }
    }
}

static int control_deadline(struct timespec *deadline, long seconds)
{
    if (clock_gettime(CLOCK_MONOTONIC, deadline)) return -1;
    deadline->tv_sec += seconds;
    return 0;
}

static int send_control_byte(int fd, char value, const struct timespec *deadline)
{
    for (;;) {
        ssize_t sent = send(fd, &value, 1, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent == 1) return 0;
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (wait_control(fd, POLLOUT, deadline)) return -1;
            continue;
        }
        if (sent == 0) errno = EPIPE;
        return -1;
    }
}

static int receive_control_byte(int fd, char *value, const struct timespec *deadline)
{
    for (;;) {
        if (wait_control(fd, POLLIN, deadline)) return -1;
        ssize_t received = recv(fd, value, 1, MSG_DONTWAIT);
        if (received == 1) return 0;
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (received == 0) errno = ECONNRESET;
        return -1;
    }
}

static int serial_service(const char *rpc_path, const char *handoff_path,
    const char *port_text, const char *tag_text)
{
    char *end = NULL;
    errno = 0;
    unsigned long parsed_port = strtoul(port_text, &end, 10);
    if (errno || !end || *end || !parsed_port || parsed_port > UINT16_MAX ||
        strlen(tag_text) != 1 || (tag_text[0] != 'A' && tag_text[0] != 'B')) return 2;
    uint16_t port = (uint16_t)parsed_port;
    struct sockaddr_in bind_address = {.sin_family = AF_INET,
        .sin_port = htons(port)};
    uint8_t address_bytes[4];
    if (inet_pton(AF_INET, "198.18.0.2", &bind_address.sin_addr) != 1) return 2;
    memcpy(address_bytes, &bind_address.sin_addr, sizeof(address_bytes));

    struct ker_socket_client client = {.session_fd = -1};
    int owner = -1, plan = -1, slot = -1, watch = -1, listener = -1;
    int control = -1, accepted = -1, result = 1;
    if (ker_socket_client_open(&client, rpc_path)) goto done;
    owner = ker_socket_client_ff_owner_create(&client);
    if (owner < 0) goto done;
    plan = ker_socket_client_owner_group_staged_plan(&client, &bind_address, 8,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    if (plan < 0) goto done;
    slot = ker_socket_client_owner_group_slot(&client, plan, 0);
    if (slot < 0) goto done;
    watch = ker_socket_client_owner_generation_watch_create(&client, plan);
    if (watch < 0 || ker_socket_client_ff_owner_group_claim(&client, owner, slot))
        goto done;
    listener = ker_socket_client_owner_group_activate_initial(&client, owner, slot);
    if (listener < 0 || ker_socket_client_bind(&client, listener,
            (const struct sockaddr *)&bind_address, sizeof(bind_address)) ||
        ker_socket_client_listen(&client, listener, 8)) goto done;
    control = connect_handoff(handoff_path);
    if (control < 0 || send_watch(control, watch, port, address_bytes)) goto done;
    close(watch); watch = -1;

    struct timespec application_deadline;
    if (control_deadline(&application_deadline, 20)) goto done;
    do {
        accepted = ker_socket_client_accept4(&client, listener, NULL, NULL, SOCK_CLOEXEC);
        if (accepted >= 0) break;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) goto done;
        if (wait_retry(&application_deadline)) goto done;
    } while (accepted < 0);
    uint8_t request[REQUEST_BYTES], response[RESPONSE_BYTES] = {0};
    if (read_exact(&client, accepted, request, sizeof(request), &application_deadline)) goto done;
    uint32_t request_magic = 0, request_generation = 0;
    memcpy(&request_magic, request, 4);
    memcpy(&request_generation, request + 4, 4);
    if (ntohl(request_magic) != UINT32_C(0x4b534731) ||
        ntohl(request_generation) != (uint32_t)(tag_text[0] - 'A' + 1)) {
        errno = EPROTO; goto done;
    }
    uint64_t request_nonce = 0;
    memcpy(&request_nonce, request + 8, 8);
    if (!request_nonce) { errno = EPROTO; goto done; }
    uint32_t response_fields[2] = {htonl(UINT32_C(0x4b535231)), request_generation};
    memcpy(response, response_fields, sizeof(response_fields));
    memcpy(response + 8, request + 8, 8);
    response[16] = (uint8_t)tag_text[0];
    memcpy(response + 17, "ACK", 3);
    if (write_exact(&client, accepted, response, sizeof(response), &application_deadline)) goto done;
    close(accepted); accepted = -1;
    struct timespec deadline;
    if (control_deadline(&deadline, 5) || send_control_byte(control, 'P', &deadline)) goto done;

    char command = 0;
    if (control_deadline(&deadline, 5) || receive_control_byte(control, &command, &deadline))
        goto done;
    if (command != 'C') { errno = EPROTO; goto done; }
    close(listener); listener = -1;
    close(slot); slot = -1;
    close(plan); plan = -1;
    if (control_deadline(&deadline, 5) || send_control_byte(control, 'C', &deadline)) goto done;
    if (control_deadline(&deadline, 5) || receive_control_byte(control, &command, &deadline))
        goto done;
    if (command != 'X') { errno = EPROTO; goto done; }
    result = 0;

done:
    if (result && errno)
        fprintf(stderr, "serial generation actor failed: %s\n", strerror(errno));
    if (accepted >= 0) close(accepted);
    if (listener >= 0) close(listener);
    if (watch >= 0) close(watch);
    if (slot >= 0) close(slot);
    if (plan >= 0) close(plan);
    if (owner >= 0) close(owner);
    if (control >= 0) close(control);
    ker_socket_client_close(&client);
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 6 || strcmp(argv[1], "--serial-service") != 0) {
        fprintf(stderr, "usage: serial-generation-actor --serial-service <rpc> <handoff> <port> <A|B>\n");
        return 2;
    }
    return serial_service(argv[2], argv[3], argv[4], argv[5]);
}
