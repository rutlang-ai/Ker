#define _GNU_SOURCE
#include "runtime-service-client.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void fail(const char *what)
{
    fprintf(stderr, "runtime-service delegation actor: %s: %s\n", what,
        strerror(errno));
    exit(2);
}

static int parse_u64(const char *name, uint64_t *out)
{
    const char *text = getenv(name);
    if (!text || !*text || !out) { errno = EINVAL; return -1; }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || end == text || *end || !value) { errno = EINVAL; return -1; }
    *out = (uint64_t)value;
    return 0;
}

static int parse_i32(const char *name, int32_t *out)
{
    uint64_t value;
    if (parse_u64(name, &value) || value > INT32_MAX) { errno = EINVAL; return -1; }
    *out = (int32_t)value;
    return 0;
}

static int parse_hex(const char *name, uint8_t *out, size_t length)
{
    const char *text = getenv(name);
    if (!text || strlen(text) != length * 2) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < length; ++i) {
        char byte[3] = {text[i * 2], text[i * 2 + 1], '\0'};
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(byte, &end, 16);
        if (errno || end == byte || *end || value > UINT8_MAX) {
            errno = EINVAL; return -1;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

struct settings {
    const char *path;
    uint8_t nonce[KER_RUNTIME_SERVICE_NONCE_BYTES];
    uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES];
    uint8_t profile[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t worker_profile[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t supervisor_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint64_t epoch;
    uint64_t supervisor_start;
    int32_t supervisor_pid;
};

static int read_settings(struct settings *s)
{
    s->path = getenv("KER_RUNTIME_SERVICE_PATH");
    if (!s->path || !*s->path ||
        parse_hex("KER_RUNTIME_SERVICE_NONCE", s->nonce, sizeof(s->nonce)) ||
        parse_hex("KER_RUNTIME_SERVICE_TICKET", s->ticket, sizeof(s->ticket)) ||
        parse_hex("KER_RUNTIME_SERVICE_PROFILE", s->profile, sizeof(s->profile)) ||
        parse_hex("KER_RUNTIME_SERVICE_WORKER_PROFILE", s->worker_profile,
            sizeof(s->worker_profile)) ||
        parse_hex("KER_RUNTIME_SERVICE_SUPERVISOR_EXE_SHA256", s->supervisor_hash,
            sizeof(s->supervisor_hash)) ||
        parse_u64("KER_RUNTIME_SERVICE_EPOCH", &s->epoch) ||
        parse_u64("KER_RUNTIME_SERVICE_SUPERVISOR_START_TICKS", &s->supervisor_start) ||
        parse_i32("KER_RUNTIME_SERVICE_SUPERVISOR_PID", &s->supervisor_pid)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int read_full(int fd, void *buffer, size_t length)
{
    uint8_t *bytes = buffer;
    size_t done = 0;
    while (done < length) {
        ssize_t count = read(fd, bytes + done, length - done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { if (!count) errno = EPIPE; return -1; }
        done += (size_t)count;
    }
    return 0;
}

static int write_full(int fd, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(fd, bytes + done, length - done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { if (!count) errno = EPIPE; return -1; }
        done += (size_t)count;
    }
    return 0;
}

struct grant {
    uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES];
    uint32_t role;
};

static int read_grant(struct grant *grant)
{
    if (read_full(3, grant, sizeof(*grant))) return -1;
    close(3);
    if (!grant->role || grant->role > KER_RUNTIME_SERVICE_ROLE_SLIM_PRIMARY) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int claim_grant(struct ker_runtime_service_client *client,
    struct settings *settings, const struct grant *grant)
{
    return ker_runtime_service_claim_delegated(client, settings->path,
        settings->nonce, settings->epoch, grant->ticket, grant->role,
        settings->profile, settings->worker_profile, settings->supervisor_pid,
        settings->supervisor_start, settings->supervisor_hash);
}

static int marker(const char *name, const char *text)
{
    const char *path = getenv(name);
    if (!path || !*path) { errno = EINVAL; return -1; }
    char temporary[PATH_MAX];
    int length = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", path);
    if (length < 0 || (size_t)length >= sizeof(temporary)) { errno = ENAMETOOLONG; return -1; }
    int fd = mkostemp(temporary, O_CLOEXEC);
    if (fd < 0) return -1;
    int result = write_full(fd, text, strlen(text));
    if (!result && fsync(fd)) result = -1;
    int error = errno;
    if (close(fd) && !result) { result = -1; error = errno; }
    if (!result && link(temporary, path)) { result = -1; error = errno; }
    if (unlink(temporary) && !result) { result = -1; error = errno; }
    errno = error;
    return result;
}

static int wait_for_release(void)
{
    const char *path = getenv("KER_TEST_FINAL_RELEASE");
    if (!path || !*path) { errno = EINVAL; return -1; }
    for (unsigned i = 0; i < 1500; ++i) {
        if (!access(path, F_OK)) return 0;
        if (errno != ENOENT) return -1;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        while (syscall(SYS_nanosleep, &pause, &pause) && errno == EINTR) {}
    }
    errno = ETIMEDOUT;
    return -1;
}

static int delegated_main(uint32_t expected_role)
{
    struct settings settings = {0};
    if (read_settings(&settings)) fail("environment");
    struct grant grant;
    if (read_grant(&grant)) fail("delegation grant");
    if (grant.role != expected_role) { errno = EPROTO; fail("grant role"); }
    int stage_pipe[2] = {-1, -1};
    if (expected_role == KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1 &&
        pipe2(stage_pipe, O_CLOEXEC)) fail("primary grant pipe");
    if (stage_pipe[0] >= 0 && stage_pipe[0] != 3) {
        errno = EBUSY;
        fail("fd-3 grant pipe fixture setup");
    }

    if (expected_role == KER_RUNTIME_SERVICE_ROLE_SLIM_PRIMARY) {
        uint64_t old_parent;
        if (parse_u64("KER_TEST_EXPECTED_PARENT_PID", &old_parent))
            fail("expected stage parent");
        for (unsigned i = 0; i < 500; ++i) {
            if ((uint64_t)getppid() != old_parent) break;
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
            while (syscall(SYS_nanosleep, &pause, &pause) && errno == EINTR) {}
            if (i == 499) { errno = ETIMEDOUT; fail("stage parent did not exit"); }
        }
        const char *delay_text = getenv("KER_TEST_DELAY_FINAL_CLAIM_MS");
        if (delay_text && *delay_text) {
            char *end = NULL;
            errno = 0;
            unsigned long delay_ms = strtoul(delay_text, &end, 10);
            if (errno || end == delay_text || *end || delay_ms > 15000) {
                errno = EINVAL;
                fail("final claim delay");
            }
            struct timespec delay = {
                .tv_sec = (time_t)(delay_ms / 1000),
                .tv_nsec = (long)(delay_ms % 1000) * 1000000L
            };
            while (syscall(SYS_nanosleep, &delay, &delay) && errno == EINTR) {}
        }
    }

    struct ker_runtime_service_client client;
    ker_runtime_service_client_init(&client);
    if (claim_grant(&client, &settings, &grant)) {
        int claim_error = errno;
        if (expected_role == KER_RUNTIME_SERVICE_ROLE_SLIM_PRIMARY &&
            getenv("KER_TEST_EXPECT_FINAL_CLAIM_FAILURE") && claim_error == ESTALE) {
            char pid_text[32];
            int count = snprintf(pid_text, sizeof(pid_text), "%ld", (long)getpid());
            if (count <= 0 || (size_t)count >= sizeof(pid_text) ||
                marker("KER_TEST_FINAL_CLAIM_FAILED", pid_text))
                fail("expired grant marker");
            return 0;
        }
        errno = claim_error;
        fail("delegated CLAIM");
    }
    if (ker_runtime_service_check(&client)) fail("delegated CHECK");
    if (expected_role == KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1) {
        char parent_pid[32];
        int count = snprintf(parent_pid, sizeof(parent_pid), "%ld", (long)getpid());
        if (count <= 0 || (size_t)count >= sizeof(parent_pid) ||
            setenv("KER_TEST_EXPECTED_PARENT_PID", parent_pid, 1))
            fail("stage parent identity");
        uint8_t intent[KER_RUNTIME_SERVICE_INTENT_BYTES];
        if (ker_runtime_service_delegate_intent(&client,
                KER_RUNTIME_SERVICE_ROLE_SLIM_PRIMARY, intent)) fail("primary INTENT");
        pid_t child = fork();
        if (child < 0) fail("primary fork");
        if (child == 0) {
            close(stage_pipe[1]);
            if (stage_pipe[0] != 3 && dup2(stage_pipe[0], 3) < 0) _exit(126);
            if (stage_pipe[0] != 3) close(stage_pipe[0]);
            if (fcntl(3, F_SETFD, 0) < 0) _exit(126);
            char *const args[] = {(char *)"runtime-service-delegation-actor",
                (char *)"--primary", NULL};
            execve("/proc/self/exe", args, environ);
            _exit(127);
        }
        char child_pid_text[32];
        int child_pid_length = snprintf(child_pid_text, sizeof(child_pid_text),
            "%ld", (long)child);
        if (child_pid_length <= 0 || (size_t)child_pid_length >= sizeof(child_pid_text) ||
            (getenv("KER_TEST_PRIMARY_PID") &&
                marker("KER_TEST_PRIMARY_PID", child_pid_text)))
            fail("primary PID marker");
        close(stage_pipe[0]);
        int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
        if (pidfd < 0) fail("primary pidfd");
        struct grant next = {0};
        next.role = KER_RUNTIME_SERVICE_ROLE_SLIM_PRIMARY;
        uint32_t bound_role = 0;
        if (ker_runtime_service_delegate_bind(&client, intent, pidfd,
                next.ticket, &bound_role)) fail("primary BIND");
        close(pidfd);
        if (bound_role != next.role || write_full(stage_pipe[1], &next, sizeof(next)))
            fail("send primary grant");
        close(stage_pipe[1]);
        if (ker_runtime_service_release(&client)) fail("stage RELEASE");
        ker_runtime_service_client_close(&client);
        return 0;
    }

    char pid_text[32];
    int count = snprintf(pid_text, sizeof(pid_text), "%ld", (long)getpid());
    if (count <= 0 || (size_t)count >= sizeof(pid_text) ||
        marker("KER_TEST_FINAL_CLAIMED", pid_text)) fail("final claim marker");
    if (wait_for_release()) fail("final release wait");
    if (ker_runtime_service_check(&client)) fail("final CHECK");
    if (ker_runtime_service_release(&client)) fail("final RELEASE");
    ker_runtime_service_client_close(&client);
    if (getenv("KER_TEST_FINAL_RELEASED") &&
        marker("KER_TEST_FINAL_RELEASED", pid_text)) fail("final release marker");
    return 0;
}

static int spawn_stage1(void)
{
    struct settings settings = {0};
    if (read_settings(&settings)) fail("environment");
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC)) fail("stage grant pipe");
    if (pipefd[0] != 3) { errno = EBUSY; fail("fd-3 grant pipe fixture setup"); }
    struct ker_runtime_service_client client;
    ker_runtime_service_client_init(&client);
    if (ker_runtime_service_claim(&client, settings.path, settings.nonce,
            settings.epoch, settings.ticket, settings.profile,
            settings.worker_profile, settings.supervisor_pid,
            settings.supervisor_start, settings.supervisor_hash))
        fail("direct CLAIM");
    uint8_t intent[KER_RUNTIME_SERVICE_INTENT_BYTES];
    if (ker_runtime_service_delegate_intent(&client,
            KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1, intent)) fail("stage INTENT");
    pid_t child = fork();
    if (child < 0) fail("stage fork");
    if (child == 0) {
        close(pipefd[1]);
        if (pipefd[0] != 3 && dup2(pipefd[0], 3) < 0) _exit(126);
        if (pipefd[0] != 3) close(pipefd[0]);
        if (fcntl(3, F_SETFD, 0) < 0) _exit(126);
        char *const args[] = {(char *)"runtime-service-delegation-actor",
            (char *)"--stage1", NULL};
        execve("/proc/self/exe", args, environ);
        _exit(127);
    }
    char child_pid_text[32];
    int child_pid_length = snprintf(child_pid_text, sizeof(child_pid_text),
        "%ld", (long)child);
    if (child_pid_length <= 0 || (size_t)child_pid_length >= sizeof(child_pid_text) ||
        (getenv("KER_TEST_STAGE1_PID") &&
            marker("KER_TEST_STAGE1_PID", child_pid_text)))
        fail("stage1 PID marker");
    close(pipefd[0]);
    int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    if (pidfd < 0) fail("stage pidfd");
    struct grant next = {0};
    next.role = KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1;
    uint32_t bound_role = 0;
    if (ker_runtime_service_delegate_bind(&client, intent, pidfd,
            next.ticket, &bound_role)) fail("stage BIND");
    close(pidfd);
    if (bound_role != next.role || write_full(pipefd[1], &next, sizeof(next)))
        fail("send stage grant");
    close(pipefd[1]);
    if (ker_runtime_service_release(&client)) fail("direct RELEASE");
    ker_runtime_service_client_close(&client);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
        errno = ECHILD;
        fail("stage child");
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1) return spawn_stage1();
    if (argc == 2 && !strcmp(argv[1], "--stage1"))
        return delegated_main(KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1);
    if (argc == 2 && !strcmp(argv[1], "--primary"))
        return delegated_main(KER_RUNTIME_SERVICE_ROLE_SLIM_PRIMARY);
    fprintf(stderr, "usage: %s [--stage1|--primary]\n", argv[0]);
    return 2;
}
