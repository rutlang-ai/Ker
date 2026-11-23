#define _GNU_SOURCE
/* Production origin APIs with explicit predicate/snapshot fixtures and real
 * process, pidfd, credential, and seqpacket behavior; not genuine Nginx. */
#include "nginx-source-origin.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum fixture_mode { MODE_VALID, MODE_BAD_PROOF, MODE_OLD_120, MODE_BAD_VERSION,
    MODE_EXTRA_FD, MODE_WRONG_SENDER, MODE_EOF, MODE_DELAY, MODE_CHILD_CHANGED,
    MODE_UNSUPPORTED, MODE_WRONG_ABI };

/* These exported symbols model only the narrow preconditions queried by the
 * production prepare callback. They do not model Nginx config parsing/state. */
uintptr_t ngx_process = 1; /* NGX_PROCESS_MASTER */
void *ngx_ff_reload_shm = NULL;
static pid_t fixture_master_pid;
static enum fixture_mode fixture_mode_value;
static uint64_t fixture_ini_serial = 10;

int ker_fstack_nginx_source_shell_daemon_prepared(void) { return 1; }
int ker_fstack_nginx_owner_activation_abi_matches(void) { return 0; }

int ker_nginx_source_native_ini_snapshot_read(
    struct ker_source_native_ini_cycle_snapshot *snapshot)
{
    if (fixture_mode_value == MODE_UNSUPPORTED) return -ENOTSUP;
    memset(snapshot->config_sha256, 0x27, sizeof(snapshot->config_sha256));
    memset(snapshot->ini_sha256, 0x91, sizeof(snapshot->ini_sha256));
    snapshot->version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION;
    snapshot->size = sizeof(*snapshot);
    snapshot->adapter_cycle_serial = fixture_ini_serial;
    snapshot->cycle_identity = (uintptr_t)0x56789000;
    if (fixture_mode_value == MODE_WRONG_ABI) snapshot->size--;
    if (fixture_mode_value == MODE_CHILD_CHANGED && getpid() != fixture_master_pid)
        snapshot->ini_sha256[3] ^= 0x5a;
    return 0;
}

struct fixture {
    enum fixture_mode mode;
    char path[100];
    int control_read;
};

struct child_report { int result; int error; int fds_after; };

static uint64_t mono_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static int start_ticks(pid_t pid, uint64_t *ticks)
{
    char path[64], buf[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    if (!p || p[1] != ' ') return -1;
    p += 2;
    for (int field = 3; field < 22; field++) {
        while (*p == ' ') p++;
        while (*p && *p != ' ') p++;
    }
    while (*p == ' ') p++;
    char *end = NULL;
    unsigned long long value = strtoull(p, &end, 10);
    if (end == p || !value) return -1;
    *ticks = (uint64_t)value;
    return 0;
}

static int fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int own = dirfd(d), count = 0;
    struct dirent *entry;
    while ((entry = readdir(d))) {
        char *end = NULL;
        long value = strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && !*end && value != own) count++;
    }
    closedir(d);
    return count;
}

static int send_record(int fd, const void *data, size_t bytes,
    const int *fds, size_t fd_count_value)
{
    struct iovec iov = {.iov_base = (void *)data, .iov_len = bytes};
    char control[CMSG_SPACE(4 * sizeof(int))] = {0};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    if (fd_count_value) {
        msg.msg_control = control;
        msg.msg_controllen = CMSG_SPACE(fd_count_value * sizeof(int));
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(fd_count_value * sizeof(int));
        memcpy(CMSG_DATA(c), fds, fd_count_value * sizeof(int));
    }
    return sendmsg(fd, &msg, MSG_NOSIGNAL) == (ssize_t)bytes ? 0 : -1;
}

static void supervisor(const struct fixture *f, int ready_write, int control_read)
{
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (listener < 0) _exit(10);
    int enabled = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) _exit(11);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", f->path);
    unlink(f->path);
    if (bind(listener, (struct sockaddr *)&addr,
            offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1) ||
        listen(listener, 1)) _exit(12);
    char ready = 'R';
    if (write(ready_write, &ready, 1) != 1) _exit(13);
    close(ready_write);
    struct pollfd pfds[] = {{.fd = listener, .events = POLLIN},
        {.fd = control_read, .events = POLLIN}};
    int result = poll(pfds, 2, 3000);
    if (result <= 0 || pfds[1].revents) {
        if (pfds[1].revents & POLLIN) { (void)read(control_read, &ready, 1); _exit(0); }
        _exit(14);
    }
    if (!(pfds[0].revents & POLLIN)) _exit(14);
    int channel = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    close(listener);
    if (channel < 0) _exit(15);
    if (setsockopt(channel, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) _exit(16);

    struct ker_nginx_source_origin_record request;
    char recv_control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(4 * sizeof(int))] = {0};
    struct iovec riov = {.iov_base = &request, .iov_len = sizeof(request)};
    struct msghdr rmsg = {.msg_iov = &riov, .msg_iovlen = 1,
        .msg_control = recv_control, .msg_controllen = sizeof(recv_control)};
    ssize_t received = recvmsg(channel, &rmsg, MSG_TRUNC | MSG_CMSG_CLOEXEC);
    struct ucred sender = {0};
    int credential_count = 0, rights[4], right_count = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&rmsg); c; c = CMSG_NXTHDR(&rmsg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
            c->cmsg_len == CMSG_LEN(sizeof(sender))) {
            memcpy(&sender, CMSG_DATA(c), sizeof(sender)); credential_count++;
        } else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
            c->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes = c->cmsg_len - CMSG_LEN(0);
            for (size_t i = 0; i + sizeof(int) <= bytes; i += sizeof(int)) {
                memcpy(&rights[right_count++], (char *)CMSG_DATA(c) + i, sizeof(int));
            }
        }
    }
    if (received != sizeof(request) || (rmsg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        credential_count != 1 || sender.pid != (pid_t)request.child_pid ||
        right_count != 2 || request.magic != KER_NGINX_SOURCE_ORIGIN_MAGIC ||
        request.version != KER_NGINX_SOURCE_ORIGIN_VERSION ||
        request.record_bytes != sizeof(request) ||
        request.type != KER_NGINX_SOURCE_ORIGIN_REQUEST ||
        request.proof_version != KER_NGINX_SOURCE_ORIGIN_PROOF_VERSION ||
        request.proof_flags != 0 || request.adapter_cycle_serial != fixture_ini_serial ||
        request.opaque_cycle_token != UINT64_C(0x56789000) ||
        request.config_sha256[0] != 0x27 || request.ini_sha256[0] != 0x91 ||
        request.origin_pid != (uint32_t)getppid()) _exit(17);
    for (int i = 0; i < right_count; i++) close(rights[i]);
    if (f->mode == MODE_EOF) {
        close(channel);
        if (read(control_read, &ready, 1) != 1) _exit(22);
        _exit(0);
    }
    if (f->mode == MODE_DELAY) {
        struct pollfd delayed = {.fd = control_read, .events = POLLIN};
        int ready_result = poll(&delayed, 1, 650);
        if (ready_result > 0) { (void)read(control_read, &ready, 1); close(channel); _exit(0); }
        close(channel);
        _exit(0);
    }
    struct ker_nginx_source_origin_record reply = request;
    reply.type = KER_NGINX_SOURCE_ORIGIN_ACK;
    if (f->mode == MODE_BAD_PROOF) reply.config_sha256[0] ^= 1;
    if (f->mode == MODE_BAD_VERSION) reply.version = 1;
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0) _exit(18);
    int passed[2] = {pidfd, -1}, count = 1;
    if (f->mode == MODE_EXTRA_FD) {
        passed[1] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (passed[1] < 0) _exit(19);
        count = 2;
    }
    size_t reply_bytes = f->mode == MODE_OLD_120 ? 120 : sizeof(reply);
    if (f->mode == MODE_WRONG_SENDER) {
        pid_t messenger = fork();
        if (messenger == 0) {
            (void)send_record(channel, &reply, reply_bytes, passed, count);
            _exit(0);
        }
        int child_status;
        waitpid(messenger, &child_status, 0);
    } else if (send_record(channel, &reply, reply_bytes, passed, count)) _exit(20);
    close(pidfd);
    if (passed[1] >= 0) close(passed[1]);
    char command;
    if (read(control_read, &command, 1) != 1) _exit(21);
    close(control_read);
    close(channel);
    _exit(0);
}

static int set_env(const char *key, const char *value)
{
    return setenv(key, value, 1);
}

static int run_one(enum fixture_mode mode)
{
    fixture_mode_value = mode;
    fixture_master_pid = getpid();
    struct fixture f = {.mode = mode};
    char fixture_dir[80] = "/tmp/ker-origin-v2-XXXXXX";
    if (!mkdtemp(fixture_dir)) return 1;
    snprintf(f.path, sizeof(f.path), "%s/origin.sock", fixture_dir);
    int ready[2], control[2];
    if (pipe(ready) || pipe(control)) return 1;
    pid_t supervisor_pid = fork();
    if (supervisor_pid == 0) {
        close(ready[0]); close(control[1]);
        supervisor(&f, ready[1], control[0]);
    }
    close(ready[1]); close(control[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    close(ready[0]);
    uint64_t supervisor_start = 0;
    if (start_ticks(supervisor_pid, &supervisor_start)) return 1;
    uint64_t deadline = mono_ns() + (mode == MODE_DELAY ? UINT64_C(450000000) :
        UINT64_C(2500000000));
    char text[32];
    snprintf(text, sizeof(text), "%ld", (long)supervisor_pid);
    if (set_env("KER_NGINX_SOURCE_SHELL_ENABLE", "1") ||
        set_env("KER_NGINX_SOURCE_BOOTSTRAP_PATH", f.path) ||
        set_env("KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID", text)) return 1;
    snprintf(text, sizeof(text), "%llu", (unsigned long long)supervisor_start);
    if (set_env("KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START", text)) return 1;
    set_env("KER_NGINX_SOURCE_BOOTSTRAP_EPOCH", "1");
    snprintf(text, sizeof(text), "%llu", (unsigned long long)deadline);
    set_env("KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS", text);
    set_env("KER_NGINX_SOURCE_BOOTSTRAP_NONCE", "112233445566778899aabbccddeeff00");
    int baseline_fds = fd_count();

    if (mode == MODE_UNSUPPORTED || mode == MODE_WRONG_ABI) {
        int result = ker_nginx_source_daemon_fork_prepare();
        int expected_errno = mode == MODE_UNSUPPORTED ? ENOTSUP : EPROTO;
        int ok = result < 0 && errno == expected_errno && fd_count() == baseline_fds;
        byte = 'Q'; write(control[1], &byte, 1); close(control[1]);
        int status; waitpid(supervisor_pid, &status, 0);
        unlink(f.path);
        rmdir(fixture_dir);
        if (!ok || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "origin mode %d preflight failed result=%d errno=%d fds=%d/%d server=%d\n",
                mode, result, errno, baseline_fds, fd_count(), status);
            return 1;
        }
        return 0;
    }

    int prepared = ker_nginx_source_daemon_fork_prepare();
    if (prepared != 0 || fd_count() != baseline_fds + 5) {
        fprintf(stderr, "origin mode %d prepare failed result=%d errno=%d fds=%d/%d\n",
            mode, prepared, errno, baseline_fds, fd_count());
        return 1;
    }
    int child_report[2];
    if (pipe(child_report)) return 1;
    pid_t child = fork();
    if (child == 0) {
        close(child_report[0]);
        int result = ker_nginx_source_daemon_fork_child();
        struct child_report report = {.result = result, .error = errno,
            .fds_after = fd_count()};
        (void)write(child_report[1], &report, sizeof(report));
        _exit(0);
    }
    close(child_report[1]);
    struct child_report report = {.result = -999, .error = 0, .fds_after = -1};
    int parent_result, parent_error, child_status = 0;
    if (mode != MODE_VALID) {
        (void)read(child_report[0], &report, sizeof(report));
        parent_result = ker_nginx_source_daemon_fork_parent(child);
        parent_error = errno;
        waitpid(child, &child_status, 0);
    } else {
        parent_result = ker_nginx_source_daemon_fork_parent(child);
        parent_error = errno;
        waitpid(child, &child_status, 0);
        (void)read(child_report[0], &report, sizeof(report));
    }
    close(child_report[0]);
    int expected_success = mode == MODE_VALID;
    int ok = expected_success ? parent_result == 0 && report.result == 0 :
        parent_result < 0 && report.result < 0;
    if (mode == MODE_CHILD_CHANGED) ok &= report.error == ESTALE;
    if (mode == MODE_DELAY) ok &= report.error == ETIMEDOUT;
    ok &= WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
    ok &= report.fds_after == baseline_fds + 1;
    ok &= fd_count() == baseline_fds;
    byte = 'Q'; (void)write(control[1], &byte, 1); close(control[1]);
    int supervisor_status = 0;
    waitpid(supervisor_pid, &supervisor_status, 0);
    unlink(f.path);
    rmdir(fixture_dir);
    if (!ok || !WIFEXITED(supervisor_status) || WEXITSTATUS(supervisor_status) != 0) {
        fprintf(stderr, "origin mode %d failed parent=%d/%d child=%d/%d childfds=%d baseline=%d server=%d\n",
            mode, parent_result, parent_error, report.result, report.error,
            report.fds_after, baseline_fds, supervisor_status);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--case")) {
        int mode = atoi(argv[2]);
        if (mode < MODE_VALID || mode > MODE_WRONG_ABI) return 2;
        return run_one((enum fixture_mode)mode);
    }
    int failures = 0;
    for (int mode = MODE_VALID; mode <= MODE_WRONG_ABI; mode++) {
        pid_t child = fork();
        if (child == 0) {
            char text[16]; snprintf(text, sizeof(text), "%d", mode);
            execl("/proc/self/exe", "origin-driver", "--case", text, (char *)NULL);
            _exit(127);
        }
        int status = 0;
        waitpid(child, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "origin fixture case %d exit=%d\n", mode, status);
            failures++;
        }
    }
    if (!failures) puts("origin v2 fork/ACK transport controls passed");
    return failures ? 1 : 0;
}
