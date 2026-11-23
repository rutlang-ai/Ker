#define _GNU_SOURCE
#include "rx-decision-consumer.h"
#include "run-loop.h"
#include <ker/posix.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct app_context {
    int listener;
    int accepted;
    const char *mode;
    uint64_t callbacks;
    uint64_t callbacks_at_peer_closed;
    uint64_t callbacks_at_stop;
    uint64_t local;
    uint64_t drop;
    uint64_t deferred;
    uint64_t deferred_completed;
    uint64_t deferred_packet_id;
    uint64_t deferred_deadline_ns;
    uint64_t deferred_complete_at_ns;
    uint32_t deferred_bytes;
    unsigned char deferred_snapshot[KER_RX_DECISION_MAX_FRAME];
    uint64_t stop_at_ns;
    size_t reply_length;
    size_t reply_offset;
    char reply[256];
    bool decision_enabled;
    bool ready_reported;
    bool completed;
    bool peer_closed;
    bool shutdown_requested;
    bool draining;
    int error;
};

static uint64_t monotonic_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static int decision_handler(const struct ker_rx_decision_packet *packet, void *opaque)
{
    struct app_context *context = opaque;
    if (!packet || !packet->full_frame || !packet->first_segment ||
        packet->full_frame != packet->first_segment ||
        packet->full_frame_bytes != packet->packet_bytes || !packet->packet_bytes ||
        packet->deadline_ns <= monotonic_ns()) return -1;
    context->callbacks++;
    if (!strcmp(context->mode, "drop")) {
        context->drop++;
        return KER_RX_DECISION_DROP;
    }
    if (!strcmp(context->mode, "defer") && !context->draining) {
        if (context->deferred_packet_id ||
            packet->full_frame_bytes > sizeof(context->deferred_snapshot)) return -1;
        memcpy(context->deferred_snapshot, packet->full_frame,
            packet->full_frame_bytes);
        context->deferred_bytes = packet->full_frame_bytes;
        context->deferred_packet_id = packet->packet_id;
        context->deferred_deadline_ns = packet->deadline_ns;
        context->deferred_complete_at_ns = monotonic_ns() + UINT64_C(5000000);
        context->deferred++;
        return KER_RX_DECISION_DEFER;
    }
    context->local++;
    return KER_RX_DECISION_LOCAL;
}

static int report_ready(struct app_context *context)
{
    if (context->ready_reported) return 0;
    if (context->decision_enabled && !ker_posix_rx_decision_is_ready()) return -EAGAIN;
    if (!strcmp(context->mode, "drop") || !strcmp(context->mode, "legacy"))
        context->stop_at_ns = monotonic_ns() + UINT64_C(1500000000);
    const char *startup = getenv("KER_STARTUP_FD");
    if (!startup) return -EINVAL;
    char *end = NULL;
    errno = 0;
    long fd = strtol(startup, &end, 10);
    if (errno || end == startup || *end || fd < 0 || fd > INT32_MAX) return -EINVAL;
    static const char marker[] = "KER_RX_DECISION_READY\n";
    if (context->decision_enabled) {
        ssize_t written = (ssize_t)syscall(SYS_write, (int)fd, marker, sizeof(marker) - 1);
        if (written != (ssize_t)(sizeof(marker) - 1)) return written < 0 ? -errno : -EIO;
    }
    context->ready_reported = true;
    const char *mac = getenv("LKL_HIJACK_NET_MAC");
    printf("RX_DECISION_APP_READY mode=%s mac=%s\n", context->mode, mac ? mac : "missing");
    fflush(stdout);
    return 0;
}

static void stop_with_error(struct app_context *context, int error)
{
    if (!context->error) context->error = error ? error : EIO;
    context->completed = true;
    ker_posix_stop_run();
}

static int app_loop(void *opaque)
{
    struct app_context *context = opaque;
    int ready = report_ready(context);
    if (ready && ready != -EAGAIN) {
        stop_with_error(context, -ready);
        return 0;
    }
    if (!context->ready_reported) return 0;

    if (!strcmp(context->mode, "defer") && context->deferred_packet_id) {
        uint64_t now = monotonic_ns();
        if (!now || now >= context->deferred_deadline_ns) {
            stop_with_error(context, ETIMEDOUT);
            return 0;
        }
        if (now >= context->deferred_complete_at_ns) {
            if (!context->deferred_bytes || ker_posix_rx_decision_complete(
                    context->deferred_packet_id, KER_RX_DECISION_LOCAL)) {
                stop_with_error(context, errno ? errno : EPROTO);
                return 0;
            }
            context->local++;
            context->deferred_completed++;
            context->deferred_packet_id = 0;
            context->deferred_deadline_ns = 0;
            context->deferred_bytes = 0;
        }
    }

    if (((!strcmp(context->mode, "drop") || !strcmp(context->mode, "legacy")) &&
            monotonic_ns() >= context->stop_at_ns) ||
        (!strcmp(context->mode, "queued-drop") && !context->shutdown_requested) ||
        (context->peer_closed && (!context->decision_enabled ||
            (context->callbacks > context->callbacks_at_peer_closed &&
             (strcmp(context->mode, "defer") || !context->deferred_packet_id))))) {
        context->completed = true;
        context->shutdown_requested = true;
        context->callbacks_at_stop = context->callbacks;
        context->draining = true;
        if (!strcmp(context->mode, "queued-drop")) {
            puts("RX_DECISION_APP_STOPPING mode=queued-drop");
            fflush(stdout);
        }
        ker_posix_stop_run();
        return 0;
    }
    if (!strcmp(context->mode, "local") || !strcmp(context->mode, "defer") ||
            !strcmp(context->mode, "eagain") ||
            !strcmp(context->mode, "immediate") ||
            !strcmp(context->mode, "legacy")) {
        if (context->accepted < 0) {
            context->accepted = accept4(context->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (context->accepted < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                stop_with_error(context, errno);
                return 0;
            }
        }
        if (context->accepted >= 0 && context->reply_offset < context->reply_length) {
            ssize_t sent = send(context->accepted, context->reply + context->reply_offset,
                context->reply_length - context->reply_offset, MSG_NOSIGNAL);
            if (sent > 0) context->reply_offset += (size_t)sent;
            else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                stop_with_error(context, errno);
                return 0;
            }
            if (context->reply_offset == context->reply_length) {
                context->reply_offset = context->reply_length = 0;
                if (!strcmp(context->mode, "immediate")) {
                    /* Leave the accepted socket registered. Native prepare
                     * closes it and must pump the peer's final ACK. */
                    context->callbacks_at_stop = context->callbacks;
                    context->completed = true;
                    context->shutdown_requested = true;
                    context->accepted = -1;
                    ker_posix_stop_run();
                    return 0;
                }
            }
        }
        if (context->accepted >= 0 && context->reply_length == 0) {
            char bytes[sizeof(context->reply)];
            ssize_t received = recv(context->accepted, bytes, sizeof(bytes), MSG_DONTWAIT);
            if (received > 0) {
                memcpy(context->reply, bytes, (size_t)received);
                context->reply_length = (size_t)received;
                context->reply_offset = 0;
            } else if (received == 0) {
                close(context->accepted);
                context->accepted = -1;
                /* Keep RX active until the test peer has observed and ACKed
                 * the server FIN. This is an explicit wire barrier, not a
                 * guessed delay before native shutdown. */
                context->peer_closed = true;
                context->callbacks_at_peer_closed = context->callbacks;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                stop_with_error(context, errno);
                return 0;
            }
        }
    }
    usleep(1000);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "local") && strcmp(argv[1], "defer") &&
            strcmp(argv[1], "eagain") &&
            strcmp(argv[1], "immediate") &&
            strcmp(argv[1], "queued-drop") && strcmp(argv[1], "drop") &&
            strcmp(argv[1], "legacy"))) {
        fprintf(stderr, "usage: rx-decision-forward-app local|eagain|immediate|queued-drop|drop|legacy\n");
        return 2;
    }
    struct app_context context = {.listener = -1, .accepted = -1, .mode = argv[1]};
    context.decision_enabled = strcmp(context.mode, "legacy") != 0;
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (listener < 0) { perror("socket"); return 1; }
    int reuse = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        perror("SO_REUSEADDR"); close(listener); return 1;
    }
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(8080)};
    if (inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 8)) {
        perror("bind/listen"); close(listener); return 1;
    }
    int flags = fcntl(listener, F_GETFL);
    if (flags < 0 || fcntl(listener, F_SETFL, flags | O_NONBLOCK)) {
        perror("listener nonblock"); close(listener); return 1;
    }
    context.listener = listener;
    if (context.decision_enabled) {
        const char *value = getenv("KER_RX_DECISION_FD");
        char *end = NULL;
        errno = 0;
        long fd = value ? strtol(value, &end, 10) : -1;
        if (!value || errno || end == value || *end || fd < 0 || fd > INT32_MAX) {
            fprintf(stderr, "missing/invalid RX decision descriptor\n");
            close(listener);
            return 1;
        }
        if (ker_posix_rx_decision_register((int)fd, decision_handler, &context)) {
            perror("ker_posix_rx_decision_register");
            close((int)fd);
            close(listener);
            return 1;
        }
    }
    const char *barrier_ready_path = getenv("KER_RX_DECISION_TEST_READY_PATH");
    const char *barrier_release_path = getenv("KER_RX_DECISION_TEST_RELEASE_PATH");
    if (barrier_ready_path || barrier_release_path) {
        if (!barrier_ready_path || !barrier_release_path) {
            fprintf(stderr, "incomplete shutdown barrier paths\n");
            close(listener);
            return 1;
        }
        int barrier_ready_fd = open(barrier_ready_path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        int barrier_release_fd = open(barrier_release_path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (barrier_ready_fd < 0 || barrier_release_fd < 0) {
            perror("shutdown barrier open");
            if (barrier_ready_fd >= 0) close(barrier_ready_fd);
            if (barrier_release_fd >= 0) close(barrier_release_fd);
            close(listener);
            return 1;
        }
        if (ker_posix_run_test_set_shutdown_barrier(barrier_ready_fd, barrier_release_fd)) {
            perror("ker_posix_run_test_set_shutdown_barrier");
            close(barrier_ready_fd);
            close(barrier_release_fd);
            close(listener);
            return 1;
        }
        close(barrier_ready_fd);
        close(barrier_release_fd);
    }
    int result = ker_posix_run(app_loop, &context);
    if (result) { perror("ker_posix_run"); context.error = context.error ? context.error : errno; }
    if (context.accepted >= 0) close(context.accepted);
    close(listener);
    printf("RX_DECISION_APP_DONE mode=%s callbacks=%llu callbacks_at_stop=%llu local=%llu drop=%llu deferred=%llu deferred_completed=%llu completed=%u error=%d\n",
        context.mode, (unsigned long long)context.callbacks,
        (unsigned long long)context.callbacks_at_stop, (unsigned long long)context.local,
        (unsigned long long)context.drop, (unsigned long long)context.deferred,
        (unsigned long long)context.deferred_completed,
        context.completed ? 1U : 0U, context.error);
    fflush(stdout);
    return result || context.error || !context.completed ? 1 : 0;
}
