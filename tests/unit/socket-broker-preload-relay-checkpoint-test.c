#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ker/socket-broker.h>
#include "socket-broker-preload-internal.h"

void ker_sb_preload_test_owner_setup(void);
int ker_sb_preload_test_runtime_init(void);
int ker_sb_preload_test_registry_add(int app_fd, int private_fd);
int ker_sb_preload_test_registry_remove(int app_fd);
int ker_sb_preload_test_lock_available(void);

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "preload relay checkpoint:%d: %s errno=%d\n", \
        __LINE__, #test, errno); return 1; } } while (0)

struct callback_state {
    int calls;
    int lock_free;
    int mode;
    int remove_fd;
    int nested_status;
};

static int relay_callback(void *opaque)
{
    struct callback_state *state = opaque;
    ++state->calls;
    state->lock_free = ker_sb_preload_test_lock_available();
    if (state->mode == 1) {
        state->nested_status = ker_sb_preload_rx_relay_checkpoint();
        return 0;
    }
    if (state->mode == 2) {
        if (ker_sb_preload_test_registry_remove(state->remove_fd)) return -EIO;
        return 0;
    }
    if (state->mode == 3) {
        errno = ECHILD;
        return -EIO;
    }
    if (state->mode == 4) return -EAGAIN;
    errno = EINTR;
    return 0;
}

int __wrap_ker_socket_client_getsockopt(struct ker_socket_client *client, int cap_fd,
    int level, int option, void *value, socklen_t *length)
{
    (void)client;
    if (level != SOL_SOCKET || !value || !length || *length != sizeof(int)) {
        errno = EPROTO;
        return -1;
    }
    int result;
    if (option == SO_DOMAIN) {
        result = cap_fd == 101 ? AF_INET : cap_fd == 102 ? AF_INET6 : AF_UNIX;
    } else if (option == SO_ACCEPTCONN) {
        result = cap_fd == 102;
    } else {
        errno = EINVAL;
        return -1;
    }
    *(int *)value = result;
    *length = sizeof(result);
    return 0;
}

struct other_thread_result { int status; int error; };
static void *other_thread_checkpoint(void *opaque)
{
    struct other_thread_result *result = opaque;
    errno = ERANGE;
    result->status = ker_sb_preload_rx_relay_checkpoint();
    result->error = errno;
    return NULL;
}

static int open_test_fd(void)
{
    return (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY | O_CLOEXEC, 0);
}

struct child_checkpoint_result {
    int loop_active;
    int status;
    int saved_errno;
    int callback_calls;
};

static int fork_cleanup_control(struct callback_state *state, int expected_calls)
{
    int pipes[2];
    if (syscall(SYS_pipe2, pipes, O_CLOEXEC)) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        (void)syscall(SYS_close, pipes[0]);
        struct child_checkpoint_result result = {0};
        result.loop_active = ker_sb_preload_owner_loop_active();
        errno = EDOM;
        result.status = ker_sb_preload_rx_relay_checkpoint();
        result.saved_errno = errno;
        result.callback_calls = state->calls;
        (void)syscall(SYS_write, pipes[1], &result, sizeof(result));
        _exit(0);
    }
    (void)syscall(SYS_close, pipes[1]);
    struct child_checkpoint_result result = {0};
    ssize_t got = syscall(SYS_read, pipes[0], &result, sizeof(result));
    (void)syscall(SYS_close, pipes[0]);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) || got != (ssize_t)sizeof(result)) return -1;
    return !result.loop_active && result.status == 0 &&
        result.saved_errno == EDOM && result.callback_calls == expected_calls ? 0 : -1;
}

static int arm_loop(struct callback_state *state)
{
    ker_sb_preload_test_owner_setup();
    if (ker_sb_preload_owner_loop_enter()) return -1;
    if (ker_sb_preload_rx_relay_pump_register(relay_callback, state)) return -1;
    return 0;
}

int main(void)
{
    CHECK(ker_sb_preload_test_runtime_init() == 0);
    int first = open_test_fd(), second = open_test_fd(), third = open_test_fd();
    CHECK(first >= 0 && second >= 0 && third >= 0);
    CHECK(ker_sb_preload_test_registry_add(first, 101) == 0);
    CHECK(ker_sb_preload_test_registry_add(second, 102) == 0);
    CHECK(ker_sb_preload_test_registry_add(third, 103) == 0);

    struct callback_state state = {0};
    CHECK(arm_loop(&state) == 0);
    errno = E2BIG;
    CHECK(ker_sb_preload_rx_relay_checkpoint() == 0 && errno == E2BIG);
    CHECK(state.calls == 1 && state.lock_free);

    state.mode = 1;
    state.nested_status = -999;
    errno = EDOM;
    CHECK(ker_sb_preload_rx_relay_checkpoint() == 0 && errno == EDOM);
    CHECK(state.calls == 2 && state.nested_status == 0 && state.lock_free);

    struct other_thread_result thread_result = {0};
    pthread_t thread;
    int calls_before_thread = state.calls;
    CHECK(pthread_create(&thread, NULL, other_thread_checkpoint, &thread_result) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(thread_result.status == 0 && thread_result.error == ERANGE);
    CHECK(state.calls == calls_before_thread);

    int calls_before_fork = state.calls;
    CHECK(fork_cleanup_control(&state, calls_before_fork) == 0);
    CHECK(state.calls == calls_before_fork);

    ker_sb_preload_lock();
    errno = E2BIG;
    CHECK(ker_sb_preload_rx_relay_checkpoint() == -EDEADLK && errno == E2BIG);
    ker_sb_preload_unlock();
    CHECK(state.calls == calls_before_fork);

    state.mode = 4;
    errno = EILSEQ;
    CHECK(ker_sb_preload_rx_relay_checkpoint() == 0 && errno == EILSEQ);

    state.mode = 0;
    state.calls = 0;
    errno = EBUSY;
    CHECK(ker_sb_preload_socket_drain_count() == 1 && errno == EBUSY);
    CHECK(state.calls == 3 && state.lock_free);

    state.mode = 2;
    state.calls = 0;
    state.remove_fd = third;
    errno = 0;
    CHECK(ker_sb_preload_socket_drain_count() == -1 && errno == EAGAIN);
    CHECK(state.calls == 1 && state.lock_free);
    CHECK(ker_sb_preload_test_registry_add(third, 103) == 0);

    state.mode = 3;
    state.calls = 0;
    errno = 0;
    CHECK(ker_sb_preload_rx_relay_checkpoint() == -EIO && errno == 0);
    CHECK(state.calls == 1 && state.lock_free);
    CHECK(ker_sb_preload_rx_relay_checkpoint() == -EIO && state.calls == 1);
    CHECK(ker_sb_preload_owner_pump() == -EIO && state.calls == 1);

    ker_sb_preload_owner_loop_leave();
    errno = EFAULT;
    CHECK(ker_sb_preload_rx_relay_checkpoint() == 0 && errno == EFAULT);
    (void)syscall(SYS_close, first);
    (void)syscall(SYS_close, second);
    (void)syscall(SYS_close, third);
    puts("preload relay checkpoint model controls passed");
    return 0;
}
