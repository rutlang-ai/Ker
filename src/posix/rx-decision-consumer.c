#define _GNU_SOURCE
#include "rx-decision-consumer.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_PEERCRED
#define SO_PEERCRED 17
#endif
#ifndef SO_PASSCRED
#define SO_PASSCRED 16
#endif

#define RX_STARTUP_TIMEOUT_NS UINT64_C(5000000000)
#define RX_SHUTDOWN_TIMEOUT_NS UINT64_C(1000000000)
#define RX_CONTROL_BUFFER_BYTES (CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(2 * sizeof(int)))

enum consumer_state {
    CONSUMER_EMPTY,
    CONSUMER_REGISTERED,
    CONSUMER_READY,
    CONSUMER_STOPPING,
    CONSUMER_SETTLED,
    CONSUMER_FAILED,
    CONSUMER_DEAD,
};

struct received_message {
    unsigned char bytes[KER_RX_DECISION_MAX_MESSAGE];
    size_t length;
    struct ucred credentials;
    bool have_credentials;
    int descriptors[2];
    size_t descriptor_count;
};

struct consumer {
    enum consumer_state state;
    int fd;
    int worker_pidfd;
    int supervisor_pidfd;
    struct ucred peer;
    pid_t worker_pid;
    uid_t worker_uid;
    gid_t worker_gid;
    uint64_t worker_start_ticks;
    pid_t supervisor_pid;
    uint64_t supervisor_start_ticks;
    uint8_t run_nonce[KER_RX_DECISION_NONCE_BYTES];
    uint64_t worker_epoch;
    uint64_t last_packet_id;
    uint64_t last_result_id;
    ker_rx_decision_handler handler;
    void *context;
    pthread_t owner_thread;
    bool owner_valid;
    bool stop_sent;
    int transport_error;
};

static pthread_mutex_t consumer_lock = PTHREAD_MUTEX_INITIALIZER;
static struct consumer consumer = {.state = CONSUMER_EMPTY, .fd = -1,
    .worker_pidfd = -1, .supervisor_pidfd = -1};

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int wait_event(int fd, short requested, uint64_t deadline_ns)
{
    for (;;) {
        uint64_t now = monotonic_ns();
        if (!now) return -errno;
        if (now >= deadline_ns) return -ETIMEDOUT;
        uint64_t remaining = deadline_ns - now;
        int timeout = remaining / UINT64_C(1000000) > INT32_MAX ? INT32_MAX :
            (int)((remaining + UINT64_C(999999)) / UINT64_C(1000000));
        struct pollfd event = {.fd = fd, .events = requested | POLLHUP | POLLERR};
        int result = (int)syscall(SYS_poll, &event, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -errno;
        if (!result) continue;
        if (event.revents & POLLNVAL) return -EBADF;
        if (event.revents & (requested | POLLHUP | POLLERR)) return 0;
    }
}

static int read_exact_file(const char *path, char *buffer, size_t capacity)
{
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -errno;
    ssize_t length = (ssize_t)syscall(SYS_read, fd, buffer, capacity - 1);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    if (length < 0) return -saved;
    if ((size_t)length >= capacity - 1) return -EOVERFLOW;
    buffer[length] = '\0';
    return 0;
}

static int proc_start_ticks(pid_t pid, uint64_t *ticks)
{
    if (pid <= 0 || !ticks) return -EINVAL;
    char path[64], stat_line[4096];
    int count = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (count <= 0 || (size_t)count >= sizeof(path)) return -EOVERFLOW;
    int result = read_exact_file(path, stat_line, sizeof(stat_line));
    if (result) return result;
    char *end_comm = strrchr(stat_line, ')');
    if (!end_comm || end_comm[1] != ' ') return -EPROTO;
    char *cursor = end_comm + 2;
    /* The first token after comm is field 3; starttime is field 22. */
    for (unsigned field = 3; field < 22; ++field) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) return -EPROTO;
        while (*cursor && *cursor != ' ') ++cursor;
    }
    while (*cursor == ' ') ++cursor;
    if (!*cursor) return -EPROTO;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(cursor, &end, 10);
    if (errno || end == cursor || (*end && *end != ' ')) return -EPROTO;
    *ticks = (uint64_t)value;
    return 0;
}

static int pidfd_pid(int fd, pid_t *pid)
{
    if (fd < 0 || !pid) return -EINVAL;
    char path[64], contents[1024];
    int count = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    if (count <= 0 || (size_t)count >= sizeof(path)) return -EOVERFLOW;
    int result = read_exact_file(path, contents, sizeof(contents));
    if (result) return result;
    char *line = contents;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next++ = '\0';
        if (!strncmp(line, "Pid:\t", 5) || !strncmp(line, "Pid: ", 5)) {
            errno = 0;
            char *end = NULL;
            long value = strtol(line + 5, &end, 10);
            if (errno || end == line + 5 || *end || value <= 0 || value > INT32_MAX)
                return -EPROTO;
            *pid = (pid_t)value;
            return 0;
        }
        line = next;
    }
    return -EINVAL;
}

static int pidfd_alive(int fd)
{
    struct pollfd event = {.fd = fd, .events = POLLIN};
    int result = (int)syscall(SYS_poll, &event, 1, 0);
    if (result < 0) return -errno;
    if (!result) return 1;
    if (event.revents & (POLLNVAL | POLLERR)) return -EBADF;
    if (event.revents & POLLIN) return 0;
    return -EIO;
}

static int validate_pidfd(int fd, pid_t expected_pid, uint64_t expected_start)
{
    pid_t actual_pid = -1;
    int result = pidfd_pid(fd, &actual_pid);
    if (result) return result;
    if (actual_pid != expected_pid) return -ESTALE;
    uint64_t actual_start = 0;
    result = proc_start_ticks(actual_pid, &actual_start);
    if (result) return result;
    if (actual_start != expected_start) return -ESTALE;
    result = pidfd_alive(fd);
    return result == 1 ? 0 : (result == 0 ? -ESRCH : result);
}

static void close_message_fds(struct received_message *message)
{
    for (size_t i = 0; i < message->descriptor_count; ++i)
        if (message->descriptors[i] >= 0)
            (void)syscall(SYS_close, message->descriptors[i]);
    message->descriptor_count = 0;
}

static int receive_message(int fd, bool nonblocking, struct received_message *message)
{
    memset(message, 0, sizeof(*message));
    message->descriptors[0] = message->descriptors[1] = -1;
    union {
        struct cmsghdr alignment;
        char bytes[RX_CONTROL_BUFFER_BYTES];
    } control;
    struct iovec vector = {.iov_base = message->bytes, .iov_len = sizeof(message->bytes)};
    struct msghdr header = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    int flags = MSG_CMSG_CLOEXEC | MSG_TRUNC;
    if (nonblocking) flags |= MSG_DONTWAIT;
    ssize_t received = (ssize_t)syscall(SYS_recvmsg, fd, &header, flags);
    if (received < 0) return -errno;
    if (received == 0) return -EPIPE;
    if ((header.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        (size_t)received > sizeof(message->bytes)) {
        for (struct cmsghdr *item = CMSG_FIRSTHDR(&header); item;
             item = CMSG_NXTHDR(&header, item)) {
            if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_RIGHTS &&
                item->cmsg_len >= CMSG_LEN(0) &&
                (item->cmsg_len - CMSG_LEN(0)) % sizeof(int) == 0) {
                int *fds = (int *)CMSG_DATA(item);
                size_t count = (item->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t i = 0; i < count; ++i) (void)syscall(SYS_close, fds[i]);
            }
        }
        return -EMSGSIZE;
    }
    message->length = (size_t)received;
    for (struct cmsghdr *item = CMSG_FIRSTHDR(&header); item;
         item = CMSG_NXTHDR(&header, item)) {
        if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_CREDENTIALS &&
            item->cmsg_len == CMSG_LEN(sizeof(struct ucred)) && !message->have_credentials) {
            memcpy(&message->credentials, CMSG_DATA(item), sizeof(message->credentials));
            message->have_credentials = true;
        } else if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_RIGHTS &&
            item->cmsg_len >= CMSG_LEN(0) &&
            (item->cmsg_len - CMSG_LEN(0)) % sizeof(int) == 0) {
            size_t count = (item->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            if (count > 2 || message->descriptor_count + count > 2) {
                int *received_fds = (int *)CMSG_DATA(item);
                for (size_t i = 0; i < count; ++i)
                    (void)syscall(SYS_close, received_fds[i]);
                close_message_fds(message);
                return -EMSGSIZE;
            }
            memcpy(&message->descriptors[message->descriptor_count], CMSG_DATA(item),
                count * sizeof(int));
            message->descriptor_count += count;
        } else {
            close_message_fds(message);
            return -EPROTO;
        }
    }
    if (!message->have_credentials) {
        close_message_fds(message);
        return -EPROTO;
    }
    return 0;
}

static int validate_header(const struct received_message *message,
    struct ker_rx_decision_header *decoded, uint16_t expected_type,
    uint64_t expected_control_id, uint64_t expected_packet_id)
{
    if (message->length < sizeof(*decoded)) return -EPROTO;
    memcpy(decoded, message->bytes, sizeof(*decoded));
    if (decoded->magic != KER_RX_DECISION_MAGIC ||
        decoded->version != KER_RX_DECISION_VERSION ||
        decoded->type != expected_type || decoded->header_bytes != sizeof(*decoded) ||
        decoded->message_bytes != message->length ||
        decoded->worker_epoch != consumer.worker_epoch ||
        memcmp(decoded->run_nonce, consumer.run_nonce, sizeof(consumer.run_nonce)) ||
        decoded->control_id != expected_control_id ||
        decoded->packet_id != expected_packet_id ||
        decoded->message_bytes > KER_RX_DECISION_MAX_MESSAGE ||
        message->descriptor_count != 0) return -EPROTO;
    return 0;
}

static int validate_worker_credentials(const struct ucred *credentials)
{
    if (!credentials || credentials->pid != consumer.worker_pid ||
        credentials->uid != consumer.worker_uid || credentials->gid != consumer.worker_gid)
        return -EACCES;
    int result = validate_pidfd(consumer.worker_pidfd, consumer.worker_pid,
        consumer.worker_start_ticks);
    if (result) return result;
    return validate_pidfd(consumer.supervisor_pidfd, consumer.supervisor_pid,
        consumer.supervisor_start_ticks);
}

static int send_message(int fd, const struct ker_rx_decision_header *header,
    const void *body, size_t body_bytes, uint64_t deadline_ns)
{
    size_t total = sizeof(*header) + body_bytes;
    if (total > KER_RX_DECISION_MAX_MESSAGE || total != header->message_bytes)
        return -EMSGSIZE;
    struct iovec vectors[2] = {
        {.iov_base = (void *)header, .iov_len = sizeof(*header)},
        {.iov_base = (void *)body, .iov_len = body_bytes},
    };
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = body_bytes ? 2 : 1};
    for (;;) {
        ssize_t sent = (ssize_t)syscall(SYS_sendmsg, fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent == (ssize_t)total) return 0;
        if (sent >= 0) return -EIO;
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -errno;
        int ready = wait_event(fd, POLLOUT, deadline_ns);
        if (ready) return ready;
        struct pollfd event = {.fd = fd, .events = POLLOUT | POLLERR | POLLHUP};
        int polled = (int)syscall(SYS_poll, &event, 1, 0);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) return -errno;
        if (event.revents & (POLLERR | POLLHUP | POLLNVAL)) return -EPIPE;
        if (!(event.revents & POLLOUT)) continue;
    }
}

static struct ker_rx_decision_header make_header(uint16_t type,
    uint64_t packet_id, uint64_t control_id, uint64_t deadline_ns,
    uint32_t total_bytes)
{
    struct ker_rx_decision_header header = {
        .magic = KER_RX_DECISION_MAGIC,
        .version = KER_RX_DECISION_VERSION,
        .type = type,
        .header_bytes = sizeof(header),
        .message_bytes = total_bytes,
        .worker_epoch = consumer.worker_epoch,
        .packet_id = packet_id,
        .control_id = control_id,
        .deadline_ns = deadline_ns,
    };
    memcpy(header.run_nonce, consumer.run_nonce, sizeof(header.run_nonce));
    return header;
}

static void close_registered_fds(void)
{
    if (consumer.fd >= 0) (void)syscall(SYS_close, consumer.fd);
    if (consumer.worker_pidfd >= 0) (void)syscall(SYS_close, consumer.worker_pidfd);
    if (consumer.supervisor_pidfd >= 0) (void)syscall(SYS_close, consumer.supervisor_pidfd);
    consumer.fd = consumer.worker_pidfd = consumer.supervisor_pidfd = -1;
}

int ker_posix_rx_decision_register(int fd,
    ker_rx_decision_handler handler, void *context)
{
    if (fd < 0 || !handler) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&consumer_lock);
    if (consumer.state != CONSUMER_EMPTY) {
        pthread_mutex_unlock(&consumer_lock);
        errno = EBUSY;
        return -1;
    }
    int type = 0;
    socklen_t type_size = sizeof(type);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &type_size) ||
        type != SOCK_SEQPACKET) {
        int error = errno ? errno : EPROTOTYPE;
        pthread_mutex_unlock(&consumer_lock);
        errno = error;
        return -1;
    }
    struct ucred peer = {0};
    socklen_t peer_size = sizeof(peer);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) ||
        peer_size != sizeof(peer) || peer.pid <= 0) {
        int error = errno ? errno : EPROTO;
        pthread_mutex_unlock(&consumer_lock);
        errno = error;
        return -1;
    }
    int pass_credentials = 1;
    if (syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_PASSCRED,
            &pass_credentials, sizeof(pass_credentials))) {
        int error = errno;
        pthread_mutex_unlock(&consumer_lock);
        errno = error;
        return -1;
    }
    int flags = (int)syscall(SYS_fcntl, fd, F_GETFL, 0);
    if (flags < 0 || syscall(SYS_fcntl, fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC) < 0) {
        int error = errno;
        pthread_mutex_unlock(&consumer_lock);
        errno = error;
        return -1;
    }

    uint64_t deadline = monotonic_ns() + RX_STARTUP_TIMEOUT_NS;
    int wait = wait_event(fd, POLLIN, deadline);
    struct received_message message = {0};
    int result = wait ? wait : receive_message(fd, true, &message);
    struct ker_rx_decision_header header = {0};
    struct ker_rx_decision_bootstrap bootstrap;
    if (!result && message.length >= sizeof(header))
        memcpy(&header, message.bytes, sizeof(header));
    else if (!result) result = -EPROTO;
    if (!result && (message.length != sizeof(header) + sizeof(bootstrap) ||
            message.descriptor_count != 2 || !message.have_credentials ||
            header.magic != KER_RX_DECISION_MAGIC ||
            header.version != KER_RX_DECISION_VERSION ||
            header.type != KER_RX_DECISION_BOOTSTRAP ||
            header.header_bytes != sizeof(header) || header.message_bytes != message.length ||
            header.packet_id || header.control_id != KER_RX_DECISION_BOOTSTRAP_CONTROL_ID ||
            header.deadline_ns || !header.worker_epoch)) result = -EPROTO;
    if (!result) {
        memcpy(&bootstrap, message.bytes + sizeof(header), sizeof(bootstrap));
        if (message.credentials.pid != peer.pid || message.credentials.uid != peer.uid ||
            message.credentials.gid != peer.gid || bootstrap.target_role != KER_RX_DECISION_TARGET_WORKER ||
            bootstrap.target_pid <= 0 || bootstrap.supervisor_pid != (uint32_t)peer.pid ||
            bootstrap.supervisor_uid != (uint32_t)peer.uid ||
            bootstrap.supervisor_gid != (uint32_t)peer.gid || bootstrap.reserved ||
            !header.worker_epoch || header.deadline_ns) result = -EACCES;
    }
    int worker_pidfd = -1, supervisor_pidfd = -1;
    if (!result) {
        worker_pidfd = message.descriptors[0];
        supervisor_pidfd = message.descriptors[1];
        message.descriptors[0] = message.descriptors[1] = -1;
        message.descriptor_count = 0;
        uint64_t supervisor_start = 0;
        result = validate_pidfd(worker_pidfd, (pid_t)bootstrap.target_pid,
            bootstrap.target_start_ticks);
        if (!result) result = proc_start_ticks(peer.pid, &supervisor_start);
        if (!result && bootstrap.supervisor_start_ticks != supervisor_start) result = -ESTALE;
        if (!result) result = validate_pidfd(supervisor_pidfd, peer.pid, supervisor_start);
    }
    close_message_fds(&message);
    if (result) {
        if (worker_pidfd >= 0) (void)syscall(SYS_close, worker_pidfd);
        if (supervisor_pidfd >= 0) (void)syscall(SYS_close, supervisor_pidfd);
        pthread_mutex_unlock(&consumer_lock);
        errno = -result;
        return -1;
    }
    consumer.fd = fd;
    consumer.worker_pidfd = worker_pidfd;
    consumer.supervisor_pidfd = supervisor_pidfd;
    consumer.peer = peer;
    consumer.worker_pid = (pid_t)bootstrap.target_pid;
    consumer.worker_uid = (uid_t)bootstrap.target_uid;
    consumer.worker_gid = (gid_t)bootstrap.target_gid;
    consumer.worker_start_ticks = bootstrap.target_start_ticks;
    consumer.supervisor_pid = peer.pid;
    consumer.supervisor_start_ticks = bootstrap.supervisor_start_ticks;
    memcpy(consumer.run_nonce, header.run_nonce, sizeof(consumer.run_nonce));
    consumer.worker_epoch = header.worker_epoch;
    consumer.handler = handler;
    consumer.context = context;
    consumer.owner_thread = pthread_self();
    consumer.owner_valid = true;
    consumer.state = CONSUMER_REGISTERED;
    pthread_mutex_unlock(&consumer_lock);
    return 0;
}

int ker_posix_rx_decision_is_ready(void)
{
    pthread_mutex_lock(&consumer_lock);
    int ready = consumer.state == CONSUMER_READY;
    pthread_mutex_unlock(&consumer_lock);
    return ready;
}

static int check_owner_thread(void)
{
    return consumer.owner_valid && pthread_equal(consumer.owner_thread, pthread_self()) ?
        0 : -EPERM;
}

int ker_rx_decision_consumer_start(void)
{
    pthread_mutex_lock(&consumer_lock);
    if (consumer.state == CONSUMER_EMPTY) {
        pthread_mutex_unlock(&consumer_lock);
        return 0;
    }
    if (check_owner_thread()) {
        pthread_mutex_unlock(&consumer_lock);
        return -EPERM;
    }
    if (consumer.state != CONSUMER_REGISTERED) {
        pthread_mutex_unlock(&consumer_lock);
        return -EBUSY;
    }
    struct ker_rx_decision_header hello = make_header(KER_RX_DECISION_HELLO,
        0, KER_RX_DECISION_HELLO_CONTROL_ID, 0, sizeof(hello));
    int result = send_message(consumer.fd, &hello, NULL, 0,
        monotonic_ns() + RX_STARTUP_TIMEOUT_NS);
    if (result) {
        consumer.state = CONSUMER_FAILED;
        consumer.transport_error = result;
        pthread_mutex_unlock(&consumer_lock);
        return result;
    }
    uint64_t deadline = monotonic_ns() + RX_STARTUP_TIMEOUT_NS;
    pthread_mutex_unlock(&consumer_lock);
    result = wait_event(consumer.fd, POLLIN, deadline);
    struct received_message message = {0};
    if (!result) result = receive_message(consumer.fd, true, &message);
    if (!result) result = validate_worker_credentials(&message.credentials);
    struct ker_rx_decision_header ready;
    if (!result) result = validate_header(&message, &ready,
        KER_RX_DECISION_READY, KER_RX_DECISION_HELLO_CONTROL_ID, 0);
    if (!result && (message.length != sizeof(ready) || message.descriptor_count ||
            ready.deadline_ns)) result = -EPROTO;
    close_message_fds(&message);
    pthread_mutex_lock(&consumer_lock);
    if (result) {
        consumer.state = CONSUMER_FAILED;
        consumer.transport_error = result;
    } else if (consumer.state != CONSUMER_REGISTERED) {
        result = -ECANCELED;
    } else {
        consumer.state = CONSUMER_READY;
    }
    pthread_mutex_unlock(&consumer_lock);
    return result;
}

static int validate_data_message(const struct received_message *message,
    struct ker_rx_decision_header *header, struct ker_rx_decision_data *data)
{
    if (message->length < sizeof(*header) + sizeof(*data)) return -EPROTO;
    memcpy(header, message->bytes, sizeof(*header));
    if (header->magic != KER_RX_DECISION_MAGIC ||
        header->version != KER_RX_DECISION_VERSION || header->type != KER_RX_DECISION_DATA ||
        header->header_bytes != sizeof(*header) ||
        header->message_bytes != message->length || header->control_id ||
        header->packet_id == 0 || header->packet_id != consumer.last_packet_id + 1 ||
        header->worker_epoch != consumer.worker_epoch ||
        memcmp(header->run_nonce, consumer.run_nonce, sizeof(consumer.run_nonce)) ||
        message->descriptor_count || message->length > KER_RX_DECISION_MAX_MESSAGE)
        return -EPROTO;
    memcpy(data, message->bytes + sizeof(*header), sizeof(*data));
    if (data->packet_bytes < 14 || data->packet_bytes > KER_RX_DECISION_MAX_FRAME ||
        !data->first_segment_bytes || data->first_segment_bytes > data->packet_bytes ||
        data->segment_count == 0 || data->queue_count == 0 ||
        data->queue_id >= data->queue_count || data->flags || data->vlan_tci ||
        (data->rx_offload_flags & ~KER_RX_DECISION_RX_KNOWN_CKSUM_MASK) ||
        ((data->rx_offload_flags & KER_RX_DECISION_RX_IP_CKSUM_MASK) &&
         (data->rx_offload_flags & KER_RX_DECISION_RX_IP_CKSUM_MASK) !=
             KER_RX_DECISION_RX_IP_CKSUM_GOOD) ||
        ((data->rx_offload_flags & KER_RX_DECISION_RX_L4_CKSUM_MASK) &&
         (data->rx_offload_flags & KER_RX_DECISION_RX_L4_CKSUM_MASK) !=
             KER_RX_DECISION_RX_L4_CKSUM_GOOD) || !data->data_room_bytes ||
        data->data_offset > data->data_room_bytes ||
        data->first_segment_bytes > data->data_room_bytes - data->data_offset ||
        message->length != sizeof(*header) + sizeof(*data) + data->first_segment_bytes)
        return -EOPNOTSUPP;
    uint64_t now = monotonic_ns();
    if (!header->deadline_ns || !now || now >= header->deadline_ns) return -ETIMEDOUT;
    uint64_t max_deadline = now + KER_RX_DECISION_DEADLINE_NS + UINT64_C(1000000);
    if (header->deadline_ns > max_deadline) return -EPROTO;
    return 0;
}

int ker_rx_decision_consumer_pump(void)
{
    pthread_mutex_lock(&consumer_lock);
    if (consumer.state == CONSUMER_EMPTY) {
        pthread_mutex_unlock(&consumer_lock);
        return 0;
    }
    if (check_owner_thread()) {
        pthread_mutex_unlock(&consumer_lock);
        return -EPERM;
    }
    if (consumer.state != CONSUMER_READY) {
        int result = consumer.state == CONSUMER_STOPPING ||
            consumer.state == CONSUMER_SETTLED ? 0 : -EIO;
        pthread_mutex_unlock(&consumer_lock);
        return result;
    }
    int fd = consumer.fd;
    pthread_mutex_unlock(&consumer_lock);

    struct received_message message;
    int result = receive_message(fd, true, &message);
    if (result == -EAGAIN || result == -EWOULDBLOCK) return 0;
    if (result) goto failed;
    result = validate_worker_credentials(&message.credentials);
    struct ker_rx_decision_header header;
    struct ker_rx_decision_data data;
    if (!result) result = validate_data_message(&message, &header, &data);
    if (result) { close_message_fds(&message); goto failed; }

    struct ker_rx_decision_packet packet = {
        .packet_id = header.packet_id,
        .deadline_ns = header.deadline_ns,
        .packet_bytes = data.packet_bytes,
        .first_segment_bytes = data.first_segment_bytes,
        .data_room_bytes = data.data_room_bytes,
        .data_offset = data.data_offset,
        .segment_count = data.segment_count,
        .queue_id = data.queue_id,
        .queue_count = data.queue_count,
        .vlan_tci = data.vlan_tci,
        .flags = data.flags,
        .rx_offload_flags = data.rx_offload_flags,
        .first_segment = message.bytes + sizeof(header) + sizeof(data),
    };
    int action = consumer.handler(&packet, consumer.context);
    uint64_t after_callback = monotonic_ns();
    if (!after_callback || after_callback >= header.deadline_ns) result = -ETIMEDOUT;
    else if (action != KER_RX_DECISION_LOCAL && action != KER_RX_DECISION_DROP)
        result = -EPROTO;
    if (!result) {
        struct ker_rx_decision_result decision = {.action = (uint32_t)action};
        struct ker_rx_decision_header response = make_header(KER_RX_DECISION_RESULT,
            header.packet_id, 0, 0, sizeof(response) + sizeof(decision));
        result = send_message(fd, &response, &decision, sizeof(decision), header.deadline_ns);
    }
    close_message_fds(&message);
    if (result) goto failed;
    pthread_mutex_lock(&consumer_lock);
    consumer.last_packet_id = header.packet_id;
    consumer.last_result_id = header.packet_id;
    pthread_mutex_unlock(&consumer_lock);
    return 0;

failed:
    pthread_mutex_lock(&consumer_lock);
    consumer.state = CONSUMER_FAILED;
    consumer.transport_error = result;
    pthread_mutex_unlock(&consumer_lock);
    return result;
}

static int worker_definitively_dead(void)
{
    int alive = pidfd_alive(consumer.worker_pidfd);
    return alive == 0;
}

int ker_rx_decision_consumer_registered(void)
{
    pthread_mutex_lock(&consumer_lock);
    int registered = consumer.state != CONSUMER_EMPTY &&
        consumer.state != CONSUMER_SETTLED && consumer.state != CONSUMER_DEAD;
    pthread_mutex_unlock(&consumer_lock);
    return registered;
}

int ker_rx_decision_consumer_error(void)
{
    pthread_mutex_lock(&consumer_lock);
    int error = consumer.transport_error;
    pthread_mutex_unlock(&consumer_lock);
    return error;
}

static int shutdown_receive(uint64_t deadline, struct received_message *message)
{
    int result = wait_event(consumer.fd, POLLIN, deadline);
    if (result) return result;
    result = receive_message(consumer.fd, true, message);
    if (result == -EPIPE && worker_definitively_dead()) return -ESRCH;
    return result;
}

int ker_rx_decision_consumer_prepare_runtime_shutdown(void)
{
    int result = -EPROTO;
    pthread_mutex_lock(&consumer_lock);
    if (consumer.state == CONSUMER_EMPTY || consumer.state == CONSUMER_SETTLED ||
        consumer.state == CONSUMER_DEAD) {
        pthread_mutex_unlock(&consumer_lock);
        return 0;
    }
    if (check_owner_thread()) {
        pthread_mutex_unlock(&consumer_lock);
        return -EPERM;
    }
    if (consumer.state == CONSUMER_REGISTERED) {
        /* The run loop did not complete HELLO; never claim a settled worker. */
        pthread_mutex_unlock(&consumer_lock);
        return -EBUSY;
    }
    if (consumer.state == CONSUMER_STOPPING) {
        pthread_mutex_unlock(&consumer_lock);
    } else {
        if (consumer.state == CONSUMER_READY || consumer.state == CONSUMER_FAILED) {
            struct ker_rx_decision_header header = make_header(KER_RX_DECISION_STOP,
                0, KER_RX_DECISION_STOP_CONTROL_ID, 0, sizeof(header));
            int sent = send_message(consumer.fd, &header, NULL, 0,
                monotonic_ns() + RX_SHUTDOWN_TIMEOUT_NS);
            if (sent) {
                consumer.state = CONSUMER_FAILED;
                consumer.transport_error = sent;
                pthread_mutex_unlock(&consumer_lock);
                if (!worker_definitively_dead()) return -EBUSY;
                /* A dead pidfd alone is insufficient: wait for EOF too, so
                 * inherited duplicate endpoints cannot hide another sender. */
                pthread_mutex_lock(&consumer_lock);
                consumer.state = CONSUMER_STOPPING;
                pthread_mutex_unlock(&consumer_lock);
                goto wait_for_settlement;
            }
            consumer.stop_sent = true;
            consumer.state = CONSUMER_STOPPING;
        }
        pthread_mutex_unlock(&consumer_lock);
    }

wait_for_settlement:
    uint64_t deadline = monotonic_ns() + RX_SHUTDOWN_TIMEOUT_NS;
    for (;;) {
        struct received_message message;
        result = shutdown_receive(deadline, &message);
        if (result == -ESRCH) {
            close_registered_fds();
            pthread_mutex_lock(&consumer_lock);
            consumer.state = CONSUMER_DEAD;
            consumer.transport_error = -EPIPE;
            consumer.handler = NULL;
            consumer.context = NULL;
            pthread_mutex_unlock(&consumer_lock);
            return 1;
        }
        if (result) {
            pthread_mutex_lock(&consumer_lock);
            consumer.state = CONSUMER_STOPPING;
            consumer.transport_error = result;
            pthread_mutex_unlock(&consumer_lock);
            return -EBUSY;
        }
        result = validate_worker_credentials(&message.credentials);
        struct ker_rx_decision_header header;
        if (!result && message.length >= sizeof(header))
            memcpy(&header, message.bytes, sizeof(header));
        else if (!result) result = -EPROTO;
        if (!result && header.type == KER_RX_DECISION_DATA) {
            struct ker_rx_decision_data data;
            result = validate_data_message(&message, &header, &data);
            if (!result) {
                struct ker_rx_decision_result decision = {.action = KER_RX_DECISION_DROP};
                struct ker_rx_decision_header response = make_header(KER_RX_DECISION_RESULT,
                    header.packet_id, 0, 0, sizeof(response) + sizeof(decision));
                result = send_message(consumer.fd, &response, &decision, sizeof(decision),
                    header.deadline_ns);
                if (!result) {
                    pthread_mutex_lock(&consumer_lock);
                    consumer.last_packet_id = header.packet_id;
                    consumer.last_result_id = header.packet_id;
                    pthread_mutex_unlock(&consumer_lock);
                }
            }
        } else if (!result && header.type == KER_RX_DECISION_SETTLED) {
            struct ker_rx_decision_settled settled;
            result = validate_header(&message, &header, KER_RX_DECISION_SETTLED,
                KER_RX_DECISION_STOP_CONTROL_ID, 0);
            if (!result && (message.length != sizeof(header) + sizeof(settled) ||
                    header.deadline_ns)) result = -EPROTO;
            if (!result) {
                memcpy(&settled, message.bytes + sizeof(header), sizeof(settled));
                if (settled.reserved || settled.outstanding_count ||
                    settled.last_packet_id != consumer.last_result_id) result = -EPROTO;
            }
            close_message_fds(&message);
            if (result) break;
            close_registered_fds();
            pthread_mutex_lock(&consumer_lock);
            consumer.state = CONSUMER_SETTLED;
            consumer.handler = NULL;
            consumer.context = NULL;
            pthread_mutex_unlock(&consumer_lock);
            return 0;
        } else if (!result) result = -EPROTO;
        close_message_fds(&message);
        if (result) break;
    }
    pthread_mutex_lock(&consumer_lock);
    consumer.state = CONSUMER_STOPPING;
    consumer.transport_error = result;
    pthread_mutex_unlock(&consumer_lock);
    if (worker_definitively_dead()) {
        close_registered_fds();
        pthread_mutex_lock(&consumer_lock);
        consumer.state = CONSUMER_DEAD;
        consumer.handler = NULL;
        consumer.context = NULL;
        pthread_mutex_unlock(&consumer_lock);
        return 1;
    }
    return -EBUSY;
}
