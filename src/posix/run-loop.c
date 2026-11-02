#define _GNU_SOURCE
#include "run-loop.h"
#include "lifecycle.h"
#include "fd-table.h"
#include "ff-admission-task.h"
#include "ff-ingress-controller.h"
#include "rx-decision-consumer.h"
#include <ker/posix.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool running, stopping;
static bool cleanup_pending;
static ker_posix_loop_func pending_loop;
static void *pending_argument;
static int pending_error;
static int control_fd = -1;

int ker_run_control_init(int fd)
{
    int type;
    socklen_t size = sizeof(type);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_SEQPACKET)
        return -EINVAL;
    if (syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC) < 0) return -errno;
    control_fd = fd;
    return 0;
}
void ker_run_control_close(void)
{
    if (control_fd >= 0) syscall(SYS_close, control_fd);
    control_fd = -1;
}

void ker_posix_stop_run(void)
{
    pthread_mutex_lock(&lock);
    if (running) {
        stopping = true;
        pthread_cond_broadcast(&changed);
    }
    pthread_mutex_unlock(&lock);
}

/* Reap EAL workers in their owning launcher, after original Linux has drained
 * and removed all devices. A successful local kernel halt is not an EAL ack. */
static int stop_workers(void)
{
    static const char request[] = "KER_RUN_STOP\n";
    if (syscall(SYS_sendto, control_fd, request, sizeof(request) - 1,
            MSG_NOSIGNAL, NULL, 0) != sizeof(request) - 1) return -EIO;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -errno;
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + 30000;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return -errno;
        int64_t remaining = deadline - ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
        if (remaining <= 0) return -ETIMEDOUT;
        struct pollfd event = {.fd = control_fd, .events = POLLIN};
        int result = (int)syscall(SYS_poll, &event, 1, (int)remaining);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -errno;
        if (!result) return -ETIMEDOUT;
        char reply[16];
        long count = syscall(SYS_recvfrom, control_fd, reply, sizeof(reply), MSG_TRUNC, NULL, NULL);
        return count == 3 && !memcmp(reply, "OK\n", 3) ? 0 : -EIO;
    }
}

int ker_posix_run(ker_posix_loop_func loop, void *argument)
{
    pthread_mutex_lock(&lock);
    if (running || !ker_native_ready() || control_fd < 0 ||
        (!loop && ker_rx_decision_consumer_registered()) ||
        (cleanup_pending && (loop != pending_loop || argument != pending_argument))) {
        int error = running ? EBUSY : (!ker_native_ready() ? ENETDOWN : EOPNOTSUPP);
        if (cleanup_pending) error = EBUSY;
        pthread_mutex_unlock(&lock);
        errno = error;
        return -1;
    }
    bool cleanup_only = cleanup_pending;
    int run_error = cleanup_only ? pending_error : 0;
    running = true;
    if (!cleanup_only) {
        pending_loop = loop;
        pending_argument = argument;
        stopping = false;
        pthread_mutex_unlock(&lock);
        int start_error = ker_rx_decision_consumer_start();
        if (start_error == -EPERM) {
            pthread_mutex_lock(&lock);
            running = false;
            pending_loop = NULL;
            pending_argument = NULL;
            pthread_mutex_unlock(&lock);
            errno = EPERM;
            return -1;
        }
        if (start_error) run_error = start_error;
        pthread_mutex_lock(&lock);
        for (;;) {
            if (stopping) break;
            if (run_error) break;
            if (!loop) {
                pthread_cond_wait(&changed, &lock);
                continue;
            }
            pthread_mutex_unlock(&lock);
            int pump = ker_rx_decision_consumer_pump();
            if (pump) run_error = pump;
            if (run_error) {
                pthread_mutex_lock(&lock);
                break;
            }
            (void)loop(argument); /* Same ignored return-value contract as ff_run. */
            pump = ker_rx_decision_consumer_pump();
            if (pump) run_error = pump;
            pthread_mutex_lock(&lock);
        }
    }
    pthread_mutex_unlock(&lock);
    int rx = ker_rx_decision_consumer_prepare_runtime_shutdown();
    if (rx < 0) {
        pthread_mutex_lock(&lock);
        cleanup_pending = true;
        pending_error = run_error;
        running = false;
        pthread_mutex_unlock(&lock);
        errno = EBUSY;
        return -1;
    }
    if (rx > 0 && !run_error) {
        run_error = ker_rx_decision_consumer_error();
        if (!run_error) run_error = -EPIPE;
    }
    int ingress = ker_posix_ff_ingress_controller_prepare_runtime_shutdown();
    if (ingress) {
        pthread_mutex_lock(&lock);
        cleanup_pending = true;
        pending_error = run_error;
        running = false;
        pthread_mutex_unlock(&lock);
        /* Preserve the live runtime for a cleanup-only continuation. The
         * underlying controller error remains in its terminal receipt; EBUSY
         * tells callers teardown has not completed. */
        errno = EBUSY;
        return -1;
    }
    ker_ff_admission_task_runtime_shutdown();
    int result = ker_native_finalize();
    int workers = stop_workers();
    ker_run_control_close();
    if (!result) result = workers;
    if (!result && run_error) result = run_error;
    pthread_mutex_lock(&lock);
    running = false;
    cleanup_pending = false;
    pending_loop = NULL;
    pending_argument = NULL;
    pending_error = 0;
    pthread_mutex_unlock(&lock);
    if (result) { errno = -result; return -1; }
    return 0;
}
