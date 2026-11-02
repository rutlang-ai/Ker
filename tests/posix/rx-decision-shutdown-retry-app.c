#define _GNU_SOURCE
#include "rx-decision-consumer.h"
#include <ker/posix.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct retry_context {
    int socket_fd;
    int mode;
    FILE *buffered_stream;
    char *stdio_buffer;
    bool connect_started;
    bool connected;
    bool ready_reported;
    bool pending_proven;
    bool failed;
    uint64_t loop_calls;
    uint64_t decision_calls;
    uint64_t decision_calls_at_stop;
    uint64_t bytes_sent;
    uint32_t notsent_bytes;
};

struct wrong_thread_result {
    struct retry_context *context;
    int result;
    int error;
};

static int retry_loop(void *opaque);

static void *wrong_thread_retry(void *opaque)
{
    struct wrong_thread_result *result = opaque;
    errno = 0;
    result->result = ker_posix_run(retry_loop, result->context);
    result->error = errno;
    return NULL;
}

static int decision_handler(const struct ker_rx_decision_packet *packet,
    void *opaque)
{
    struct retry_context *context = opaque;
    if (!packet || !packet->packet_bytes || !packet->first_segment ||
        packet->deadline_ns <= 0) return -1;
    context->decision_calls++;
    return KER_RX_DECISION_LOCAL;
}

static int report_ready(struct retry_context *context)
{
    if (context->ready_reported || !ker_posix_rx_decision_is_ready()) return 0;
    const char *value = getenv("KER_STARTUP_FD");
    char *end = NULL;
    errno = 0;
    long fd = value ? strtol(value, &end, 10) : -1;
    if (!value || errno || end == value || *end || fd < 0 || fd > INT32_MAX)
        return -EINVAL;
    static const char marker[] = "KER_RX_DECISION_READY\n";
    long count = syscall(SYS_write, (int)fd, marker, sizeof(marker) - 1);
    if (count != (long)(sizeof(marker) - 1)) return count < 0 ? -errno : -EIO;
    static const char started[] = "C31_RETRY_APP_READY\n";
    (void)syscall(SYS_write, STDOUT_FILENO, started, sizeof(started) - 1);
    context->ready_reported = true;
    return 0;
}

static int socket_error(int fd, int *error)
{
    socklen_t length = sizeof(*error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, error, &length)) return -errno;
    return 0;
}

static bool has_unsent_bytes(struct retry_context *context)
{
    struct tcp_info info = {0};
    socklen_t length = sizeof(info);
    if (getsockopt(context->socket_fd, IPPROTO_TCP, TCP_INFO, &info, &length)) {
        context->failed = true;
        return false;
    }
    context->notsent_bytes = info.tcpi_notsent_bytes;
    return info.tcpi_notsent_bytes > 0;
}

static int retry_loop(void *opaque)
{
    struct retry_context *context = opaque;
    context->loop_calls++;
    int ready = report_ready(context);
    if (ready) {
        context->failed = true;
        ker_posix_stop_run();
        return 0;
    }
    if (!context->ready_reported) return 0;

    if (!context->connect_started) {
        context->socket_fd = socket(AF_INET,
            SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
        if (context->socket_fd < 0) {
            context->failed = true;
            ker_posix_stop_run();
            return 0;
        }
        int send_buffer = 262144;
        (void)setsockopt(context->socket_fd, SOL_SOCKET, SO_SNDBUF,
            &send_buffer, sizeof(send_buffer));
        struct sockaddr_in address = {
            .sin_family = AF_INET, .sin_port = htons(9090)
        };
        if (inet_pton(AF_INET, "198.18.0.1", &address.sin_addr) != 1) {
            context->failed = true;
            ker_posix_stop_run();
            return 0;
        }
        int connected = connect(context->socket_fd,
            (struct sockaddr *)&address, sizeof(address));
        if (connected && errno != EINPROGRESS) {
            context->failed = true;
            ker_posix_stop_run();
            return 0;
        }
        context->connect_started = true;
        context->connected = connected == 0;
        return 0;
    }

    if (!context->connected) {
        struct pollfd event = {.fd = context->socket_fd, .events = POLLOUT};
        int polled = poll(&event, 1, 0);
        if (polled < 0 && errno != EINTR) {
            context->failed = true;
            ker_posix_stop_run();
            return 0;
        }
        if (!polled) return 0;
        int error = 0;
        if (socket_error(context->socket_fd, &error) || error) {
            context->failed = true;
            ker_posix_stop_run();
            return 0;
        }
        context->connected = true;
    }

    unsigned char bytes[65536];
    memset(bytes, 0x5a, sizeof(bytes));
    size_t budget = 1024 * 1024;
    while (budget) {
        size_t amount = budget < sizeof(bytes) ? budget : sizeof(bytes);
        ssize_t sent = send(context->socket_fd, bytes, amount, MSG_NOSIGNAL);
        if (sent > 0) {
            context->bytes_sent += (uint64_t)sent;
            budget -= (size_t)sent;
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            break;
        context->failed = true;
        ker_posix_stop_run();
        return 0;
    }
    if (has_unsent_bytes(context)) {
        context->pending_proven = true;
        if (context->mode == 1) {
            struct linger linger = {.l_onoff = 1, .l_linger = 5};
            if (setsockopt(context->socket_fd, SOL_SOCKET, SO_LINGER,
                    &linger, sizeof(linger))) context->failed = true;
        } else if (context->mode == 2) {
            context->stdio_buffer = malloc(2 * 1024 * 1024);
            if (!context->stdio_buffer) context->failed = true;
            else {
                context->buffered_stream = fdopen(context->socket_fd, "w");
                if (!context->buffered_stream || setvbuf(context->buffered_stream,
                        context->stdio_buffer, _IOFBF, 2 * 1024 * 1024)) {
                    context->failed = true;
                } else {
                    unsigned char block[65536];
                    memset(block, 0x6b, sizeof(block));
                    for (unsigned i = 0; i < 16; ++i)
                        if (fwrite(block, 1, sizeof(block), context->buffered_stream) != sizeof(block)) {
                            context->failed = true;
                            break;
                        }
                }
            }
        }
        int flags = fcntl(context->socket_fd, F_GETFL);
        if (flags < 0 || fcntl(context->socket_fd, F_SETFL, flags & ~O_NONBLOCK) < 0)
            context->failed = true;
        if (context->failed) {
            ker_posix_stop_run();
            return 0;
        }
        context->decision_calls_at_stop = context->decision_calls;
        ker_posix_stop_run();
        return 0;
    }
    if (context->failed || context->bytes_sent > UINT64_C(32) * 1024 * 1024) {
        context->failed = true;
        ker_posix_stop_run();
        return 0;
    }
    struct timespec delay = {.tv_nsec = 1000000};
    nanosleep(&delay, NULL);
    return 0;
}

static void report(const char *marker, uint64_t first_calls,
    const struct retry_context *context, int error)
{
    char line[256];
    int length = snprintf(line, sizeof(line),
        "%s loop_calls=%llu first_calls=%llu pending=%u notsent=%u bytes=%llu decisions=%llu decisions_at_stop=%llu error=%d wrong_context_rejected=1\n",
        marker, (unsigned long long)context->loop_calls,
        (unsigned long long)first_calls, context->pending_proven ? 1U : 0U,
        context->notsent_bytes, (unsigned long long)context->bytes_sent,
        (unsigned long long)context->decision_calls,
        (unsigned long long)context->decision_calls_at_stop, error);
    if (length > 0 && (size_t)length < sizeof(line))
        (void)syscall(SYS_write, STDOUT_FILENO, line, (size_t)length);
}

int main(int argc, char **argv)
{
    int mode = 0;
    if (argc == 2 && !strcmp(argv[1], "linger")) mode = 1;
    else if (argc == 2 && !strcmp(argv[1], "stdio")) mode = 2;
    else if (argc != 1) return 2;
    const char *value = getenv("KER_RX_DECISION_FD");
    char *end = NULL;
    errno = 0;
    long fd = value ? strtol(value, &end, 10) : -1;
    if (!value || errno || end == value || *end || fd < 0 || fd > INT32_MAX)
        return 2;
    struct retry_context context = {.socket_fd = -1, .mode = mode};
    if (ker_posix_rx_decision_register((int)fd, decision_handler, &context)) return 3;
    if (!mode) ker_posix_rx_decision_test_shutdown_ebusy_once();

    int first = ker_posix_run(retry_loop, &context);
    int first_error = errno;
    uint64_t first_calls = context.loop_calls;
    if (first != -1 || first_error != EBUSY || context.failed ||
        !context.pending_proven) {
        report("C31_RETRY_FIRST_FAILED", first_calls, &context, first_error);
        return 4;
    }

    struct wrong_thread_result wrong_thread = {.context = &context};
    uint64_t calls_before_wrong_thread = context.loop_calls;
    pthread_t wrong_thread_id;
    if (pthread_create(&wrong_thread_id, NULL, wrong_thread_retry, &wrong_thread) ||
        pthread_join(wrong_thread_id, NULL) || wrong_thread.result != -1 ||
        wrong_thread.error != EBUSY ||
        context.loop_calls != calls_before_wrong_thread) {
        report("C31_RETRY_WRONG_THREAD_FAILED", first_calls, &context,
            wrong_thread.error);
        return 5;
    }

    struct retry_context wrong_context = context;
    uint64_t calls_before_wrong_context = context.loop_calls;
    errno = 0;
    int wrong = ker_posix_run(retry_loop, &wrong_context);
    int wrong_error = errno;
    if (wrong != -1 || wrong_error != EBUSY ||
        wrong_context.loop_calls != calls_before_wrong_context ||
        context.loop_calls != calls_before_wrong_context) {
        report("C31_RETRY_WRONG_CONTEXT_FAILED", first_calls, &context, wrong_error);
        return 5;
    }

    if (mode) report("C31_BLOCKING_CLOSE_WAIT", first_calls, &context, first_error);
    int second = ker_posix_run(retry_loop, &context);
    int second_error = errno;
    report("C31_RETRY_PROOF", first_calls, &context, second_error);
    if (mode) report("C31_BLOCKING_CLOSE_DONE", first_calls, &context, second_error);
    if (mode)
        return second == 0 && !context.failed && context.pending_proven &&
            context.loop_calls == first_calls ? 0 : 5;
    return second == -1 && second_error == ETIMEDOUT && !context.failed &&
        context.pending_proven && context.loop_calls == first_calls ? 0 : 5;
}
