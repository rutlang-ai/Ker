#define _GNU_SOURCE
/* Real bootstrap transport with contained model actors. This is not Nginx,
 * native TCP, DPDK, or a source owner/readiness qualification. */
#include "nginx-source-bootstrap.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
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

enum mode { LEGACY_OK, SHELL_SLIM_OK, SHELL_WORKER_OK, BAD_PROOF, BAD_VERSION,
    BAD_SIZE, OLD_176, EXTRA_FD, WRONG_CRED, EOF_REPLY, EXPIRED_MASTER,
    CLOSED_MASTER_ACK, CLOSED_MASTER_BAD_PROOF, WORKER_PREEXIT_OK,
    WORKER_PREEXIT_BAD_ACK, WORKER_PREEXIT_NO_EOF };

static const uint64_t preexit_cookie = UINT64_C(0x9911);
static const uint64_t preexit_operation = 901;
static const uint32_t preexit_slot = 4;

struct run {
    enum mode mode;
    char socket_path[100];
    char fifo_path[100];
    pid_t runtime_pid, io_pid, master_pid;
    int finish_read;
};

static char fixture_dir[80];

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
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (!n) return -1;
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

static pid_t keeper(void)
{
    pid_t p = fork();
    if (p == 0) {
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        for (;;) pause();
    }
    return p;
}

static int fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int count = 0;
    int own = dirfd(d);
    struct dirent *entry;
    while ((entry = readdir(d))) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && !*end && fd != own) count++;
    }
    closedir(d);
    return count;
}

static int send_record(int fd, const void *record, size_t bytes,
    const int *fds, size_t fd_count_value)
{
    struct iovec iov = {.iov_base = (void *)record, .iov_len = bytes};
    char control[CMSG_SPACE(8 * sizeof(int))] = {0};
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

static int wait_master_stopped(pid_t master, uint64_t deadline)
{
    char path[64], info[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)master);
    while (mono_ns() < deadline) {
        FILE *stream = fopen(path, "r");
        if (!stream) return -1;
        size_t length = fread(info, 1, sizeof(info) - 1, stream);
        fclose(stream);
        info[length] = '\0';
        const char *end = strrchr(info, ')');
        if (end && end[1] == ' ' && end[2] == 'T') return 0;
        usleep(100);
    }
    return -1;
}

static int serve_worker_preexit(int channel, int relay_peer, enum mode mode,
    const struct ker_nginx_source_bootstrap_record_v4 *grant)
{
    int enabled = 1;
    if (setsockopt(channel, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))) return -1;
    struct ker_nginx_source_commit_evidence_record evidence = {
        .magic = KER_NGINX_SOURCE_BOOTSTRAP_MAGIC,
        .version = KER_NGINX_SOURCE_PREEXIT_VERSION,
        .type = KER_NGINX_SOURCE_WORKER_COMMIT_EVIDENCE,
        .record_bytes = sizeof(evidence),
        .identity = *grant,
        .native_current_cookie = preexit_cookie,
    };
    evidence.identity.record.type = KER_NGINX_SOURCE_WORKER_COMMIT_EVIDENCE;
    if (send_record(channel, &evidence, sizeof(evidence), NULL, 0)) return -1;

    struct ker_nginx_source_preexit_record request;
    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec iov = {.iov_base = &request, .iov_len = sizeof(request)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    if (recvmsg(channel, &message, MSG_TRUNC | MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(request) ||
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_CREDENTIALS ||
            cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred)) ||
            CMSG_NXTHDR(&message, cmsg)) return -1;
    struct ucred creds;
    memcpy(&creds, CMSG_DATA(cmsg), sizeof(creds));
    struct ker_nginx_source_bootstrap_record expected = grant->record;
    expected.type = KER_NGINX_SOURCE_WORKER_PREEXIT;
    uint64_t now = mono_ns();
    if (creds.pid != (pid_t)expected.actor_pid || creds.uid != getuid() || creds.gid != getgid() ||
            request.magic != KER_NGINX_SOURCE_BOOTSTRAP_MAGIC ||
            request.version != KER_NGINX_SOURCE_PREEXIT_VERSION ||
            request.type != KER_NGINX_SOURCE_WORKER_PREEXIT ||
            request.record_bytes != sizeof(request) || request.reserved ||
            !ker_nginx_source_bootstrap_v4_matches(&expected, &grant->proof, &request.identity) ||
            request.worker_slot != preexit_slot ||
            request.worker_role != KER_NGINX_SOURCE_WORKER_CANDIDATE ||
            request.operation_id != preexit_operation ||
            request.native_commit_cookie != preexit_cookie ||
            request.operation_deadline_ns <= now ||
            request.operation_deadline_ns > expected.deadline_ns ||
            request.operation_deadline_ns - now > KER_NGINX_SOURCE_PREEXIT_BUDGET_NS) return -1;

    struct ker_nginx_source_settled_record settled = {
        .magic = KER_NGINX_SOURCE_BOOTSTRAP_MAGIC,
        .version = KER_NGINX_SOURCE_PREEXIT_VERSION,
        .type = KER_NGINX_SOURCE_WORKER_SETTLED,
        .record_bytes = sizeof(settled),
        .request = request,
        .c31_last_packet_id = 4,
        .native_settled = 1,
    };
    if (mode == WORKER_PREEXIT_BAD_ACK) settled.request.native_commit_cookie ^= 1;
    if (send_record(channel, &settled, sizeof(settled), NULL, 0)) return -1;
    if (mode != WORKER_PREEXIT_NO_EOF) close(relay_peer);
    return 0;
}

static void supervisor_child(struct run *r, int ready_fd, int finish_read)
{
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (listener < 0) _exit(10);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", r->socket_path);
    unlink(r->socket_path);
    if (bind(listener, (struct sockaddr *)&addr,
            offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1) ||
        listen(listener, 1)) _exit(11);
    char ready = 'R';
    if (write(ready_fd, &ready, 1) != 1) _exit(12);
    close(ready_fd);
    int channel = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    close(listener);
    if (channel < 0) _exit(13);

    union {
        struct ker_nginx_source_bootstrap_record legacy;
        struct ker_nginx_source_bootstrap_record_v4 shell;
    } request;
    char recv_control[CMSG_SPACE(sizeof(struct ucred))] = {0};
    struct iovec riov = {.iov_base = &request, .iov_len = sizeof(request)};
    struct msghdr rmsg = {.msg_iov = &riov, .msg_iovlen = 1,
        .msg_control = recv_control, .msg_controllen = sizeof(recv_control)};
    ssize_t received = recvmsg(channel, &rmsg, MSG_TRUNC);
    size_t expected = (r->mode == LEGACY_OK) ? sizeof(request.legacy) : sizeof(request.shell);
    if (received != (ssize_t)expected || (rmsg.msg_flags & MSG_TRUNC)) _exit(14);
    struct ker_nginx_source_bootstrap_record *req = r->mode == LEGACY_OK ?
        &request.legacy : &request.shell.record;
    if (req->magic != KER_NGINX_SOURCE_BOOTSTRAP_MAGIC) _exit(15);
    if (r->mode == LEGACY_OK) {
        if (req->version != KER_NGINX_SOURCE_BOOTSTRAP_VERSION ||
            req->record_bytes != sizeof(*req)) _exit(27);
    } else if (req->version != KER_NGINX_SOURCE_BOOTSTRAP_SHELL_VERSION ||
        req->record_bytes != sizeof(request.shell) ||
        request.shell.proof.version != 1 || request.shell.proof.flags != 0 ||
        request.shell.proof.adapter_cycle_serial != 5 ||
        request.shell.proof.opaque_cycle_token != UINT64_C(0x12345000) ||
        request.shell.proof.config_sha256[0] != 0x43 ||
        request.shell.proof.ini_sha256[0] != 0x76) _exit(28);
    if (r->mode == EOF_REPLY) { close(channel); _exit(0); }
    if (r->mode == EXPIRED_MASTER) {
        struct timespec delay = {.tv_nsec = 250000000};
        nanosleep(&delay, NULL);
        close(channel);
        _exit(0);
    }

    union {
        struct ker_nginx_source_bootstrap_record legacy;
        struct ker_nginx_source_bootstrap_record_v4 shell;
    } reply;
    memset(&reply, 0, sizeof(reply));
    struct ker_nginx_source_bootstrap_record *out = r->mode == LEGACY_OK ?
        &reply.legacy : &reply.shell.record;
    *out = *req;
    if (r->mode != LEGACY_OK) reply.shell.proof = request.shell.proof;
    out->type = req->role == KER_NGINX_SOURCE_ROLE_MASTER ? req->type + 2 :
        KER_NGINX_SOURCE_BOOTSTRAP_REPLY;
    out->supervisor_pid = (uint32_t)getpid();
    (void)start_ticks(getpid(), &out->supervisor_start_ticks);
    out->runtime_pid = (uint32_t)r->runtime_pid;
    out->io_pid = (uint32_t)r->io_pid;
    (void)start_ticks(r->runtime_pid, &out->runtime_start_ticks);
    (void)start_ticks(r->io_pid, &out->io_start_ticks);
    if (req->role == KER_NGINX_SOURCE_ROLE_SLIM)
        out->flags = KER_NGINX_SOURCE_SLIM_CONTROL_ONLY;
    if (req->role == KER_NGINX_SOURCE_ROLE_WORKER) {
        out->flags = KER_NGINX_SOURCE_WORKER_CANDIDATE;
        struct stat st;
        if (stat(r->fifo_path, &st)) _exit(16);
        out->slot_device = (uint64_t)st.st_dev;
        out->slot_inode = (uint64_t)st.st_ino;
        out->relay_cookie = 0;
        out->ready_cookie = 0;
    }

    int passed[8], count = 0, relay_peer = -1;
    passed[count] = (int)syscall(SYS_pidfd_open, r->runtime_pid, 0); if (passed[count++] < 0) _exit(17);
    passed[count] = (int)syscall(SYS_pidfd_open, r->io_pid, 0); if (passed[count++] < 0) _exit(18);
    if (req->role == KER_NGINX_SOURCE_ROLE_WORKER) {
        int reader = open(r->fifo_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        int writer = open(r->fifo_path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (reader < 0 || writer < 0) _exit(19);
        passed[count++] = writer;
        int relay[2], ready[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, relay) ||
            socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, ready)) _exit(20);
        socklen_t n = sizeof(uint64_t);
        if (getsockopt(relay[0], SOL_SOCKET, SO_COOKIE, &out->relay_cookie, &n) ||
            getsockopt(ready[0], SOL_SOCKET, SO_COOKIE, &out->ready_cookie, &n)) _exit(21);
        passed[count++] = relay[0]; passed[count++] = ready[0];
        /* Keep the counterpart endpoints and FIFO reader alive through validation. */
        relay_peer = relay[1];
        (void)reader; (void)ready[1];
    }
    if (r->mode == BAD_PROOF) reply.shell.proof.config_sha256[0] ^= 1;
    if (r->mode == BAD_VERSION) reply.shell.record.version = 3;
    if (r->mode == BAD_SIZE) reply.shell.record.record_bytes--;
    size_t send_bytes = r->mode == OLD_176 ? sizeof(reply.legacy) : expected;
    if (r->mode == EXTRA_FD) passed[count++] = open("/dev/null", O_RDONLY | O_CLOEXEC);

    if (r->mode == WRONG_CRED) {
        pid_t messenger = fork();
        if (messenger == 0) {
            (void)send_record(channel, &reply, send_bytes, passed, count);
            _exit(0);
        }
        int status;
        waitpid(messenger, &status, 0);
    } else if (r->mode == CLOSED_MASTER_ACK || r->mode == CLOSED_MASTER_BAD_PROOF) {
        /* Force the master to observe the queued reply and peer closure in
         * the same poll, while keeping the supervisor identity live. */
        pid_t master = getppid();
        if (req->actor_pid != (uint32_t)master || kill(master, SIGSTOP)) _exit(29);
        if (r->mode == CLOSED_MASTER_BAD_PROOF) reply.shell.proof.config_sha256[0] ^= 1;
        int failed = wait_master_stopped(master, req->control_deadline_ns) ||
            send_record(channel, &reply, send_bytes, passed, count);
        close(channel);
        if (kill(master, SIGCONT)) _exit(30);
        char command;
        if (read(finish_read, &command, 1) != 1 || failed) _exit(31);
        _exit(0);
    } else if (send_record(channel, &reply, send_bytes, passed, count)) _exit(22);

    if (r->mode == LEGACY_OK || r->mode == SHELL_SLIM_OK ||
            req->role == KER_NGINX_SOURCE_ROLE_WORKER) {
        char command;
        if (read(finish_read, &command, 1) != 1) _exit(23);
        if (command == 'S' || command == 'A') {
            if (r->mode == LEGACY_OK) reply.legacy.type = command == 'S' ?
                KER_NGINX_SOURCE_BOOTSTRAP_STOP : KER_NGINX_SOURCE_BOOTSTRAP_ACTIVATE;
            else reply.shell.record.type = command == 'S' ?
                KER_NGINX_SOURCE_BOOTSTRAP_STOP : KER_NGINX_SOURCE_BOOTSTRAP_ACTIVATE;
            if (send_record(channel, &reply, expected, NULL, 0)) _exit(24);
            int preexit_result = 0;
            if (r->mode >= WORKER_PREEXIT_OK) {
                reply.shell.record.type = KER_NGINX_SOURCE_BOOTSTRAP_REPLY;
                preexit_result = serve_worker_preexit(channel, relay_peer, r->mode, &reply.shell);
            }
            if (read(finish_read, &command, 1) != 1) _exit(25);
            if (preexit_result) _exit(32);
        }
    } else {
        char command;
        if (read(finish_read, &command, 1) != 1) _exit(26);
    }
    for (int i = 0; i < count; i++) close(passed[i]);
    close(channel);
    _exit(0);
}

static void make_snapshot(struct ker_source_native_ini_cycle_snapshot *s)
{
    memset(s, 0, sizeof(*s));
    s->version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION;
    s->size = sizeof(*s);
    s->adapter_cycle_serial = 5;
    s->cycle_identity = (uintptr_t)0x12345000;
    memset(s->config_sha256, 0x43, sizeof(s->config_sha256));
    memset(s->ini_sha256, 0x76, sizeof(s->ini_sha256));
}

static int preexit_relay_fd;
static int preexit_relay_eof;

static int pump_preexit_relay(void)
{
    char byte;
    ssize_t count = recv(preexit_relay_fd, &byte, 1, MSG_DONTWAIT);
    if (count < 0) return errno == EAGAIN || errno == EINTR ? 0 : -errno;
    if (count) return -EPROTO;
    preexit_relay_eof = 1;
    return KER_NGINX_SOURCE_PREEXIT_PUMP_RELAY_EOF;
}

static int run_worker_preexit(struct ker_nginx_source_bootstrap *binding, enum mode mode)
{
    uint64_t cookie = 0;
    uint64_t limit = mono_ns() + UINT64_C(1000000000);
    int status;
    do {
        /* The final worker can reach TERM before its ordinary owner-loop
         * poll has consumed the queued COMMIT evidence. */
        status = ker_nginx_source_bootstrap_worker_commit_cookie(
            &binding->record, &binding->source_shell_proof, &cookie);
        if (status == -EPERM) usleep(100);
    } while (status == -EPERM && mono_ns() < limit);
    if (status || cookie != preexit_cookie) {
        fprintf(stderr, "PREEXIT commit cookie failed: status=%d cookie=%llu\n",
            status, (unsigned long long)cookie);
        return 1;
    }
    preexit_relay_fd = binding->relay_fd;
    int widened = ker_nginx_source_bootstrap_worker_preexit(&binding->record,
        &binding->source_shell_proof, preexit_slot, KER_NGINX_SOURCE_WORKER_CANDIDATE,
        preexit_operation + 1, cookie, binding->record.deadline_ns + 1, pump_preexit_relay);
    int settled = ker_nginx_source_bootstrap_worker_preexit(&binding->record,
        &binding->source_shell_proof, preexit_slot, KER_NGINX_SOURCE_WORKER_CANDIDATE,
        preexit_operation, cookie, binding->record.deadline_ns, pump_preexit_relay);
    int replay = ker_nginx_source_bootstrap_worker_preexit(&binding->record,
        &binding->source_shell_proof, preexit_slot, KER_NGINX_SOURCE_WORKER_CANDIDATE,
        preexit_operation, cookie, binding->record.deadline_ns, pump_preexit_relay);
    int expected = mode == WORKER_PREEXIT_OK ? 0 :
        mode == WORKER_PREEXIT_BAD_ACK ? -EPROTO : -ETIMEDOUT;
    if (widened != -EPERM || settled != expected || replay != -EALREADY ||
            (mode == WORKER_PREEXIT_OK && !preexit_relay_eof) ||
            (mode == WORKER_PREEXIT_NO_EOF && preexit_relay_eof)) {
        fprintf(stderr, "PREEXIT mode %d failed: widened=%d settled=%d expected=%d replay=%d eof=%d\n",
            mode, widened, settled, expected, replay, preexit_relay_eof);
        return 1;
    }
    return 0;
}

static int run_case(enum mode mode)
{
    struct run r = {.mode = mode};
    r.runtime_pid = keeper(); r.io_pid = keeper(); r.master_pid = keeper();
    if (r.runtime_pid < 0 || r.io_pid < 0 || r.master_pid < 0) return 1;
    snprintf(r.socket_path, sizeof(r.socket_path), "%s/s%d.sock", fixture_dir, mode);
    snprintf(r.fifo_path, sizeof(r.fifo_path), "%s/s%d.fifo", fixture_dir, mode);
    int worker_case = mode == SHELL_WORKER_OK || mode >= WORKER_PREEXIT_OK;
    if (worker_case && mkfifo(r.fifo_path, 0600)) return 1;
    int ready[2], finish[2];
    if (pipe(ready) || pipe(finish)) return 1;
    pid_t supervisor = fork();
    if (supervisor == 0) {
        close(ready[0]); close(finish[1]);
        r.finish_read = finish[0];
        supervisor_child(&r, ready[1], finish[0]);
    }
    close(ready[1]); close(finish[0]);
    char signal_byte;
    if (read(ready[0], &signal_byte, 1) != 1) return 1;
    close(ready[0]);
    int master_case = mode == EXPIRED_MASTER || mode == CLOSED_MASTER_ACK ||
        mode == CLOSED_MASTER_BAD_PROOF;
    uint64_t sup_start, actor_start, master_start, now = mono_ns();
    if (start_ticks(supervisor, &sup_start) || start_ticks(getpid(), &actor_start) ||
        start_ticks(master_case ? getpid() : r.master_pid, &master_start)) return 1;
    struct ker_nginx_source_bootstrap_record req = {
        .magic = KER_NGINX_SOURCE_BOOTSTRAP_MAGIC,
        .version = KER_NGINX_SOURCE_BOOTSTRAP_VERSION,
        .type = master_case ? KER_NGINX_SOURCE_MASTER_PARK :
            KER_NGINX_SOURCE_BOOTSTRAP_REQUEST,
        .record_bytes = sizeof(req),
        .role = worker_case ? KER_NGINX_SOURCE_ROLE_WORKER :
            master_case ? KER_NGINX_SOURCE_ROLE_MASTER : KER_NGINX_SOURCE_ROLE_SLIM,
        .actor_pid = (uint32_t)getpid(), .actor_tid = (uint32_t)syscall(SYS_gettid),
        .master_pid = (uint32_t)(master_case ? getpid() : r.master_pid),
        .generation = worker_case ? 1 : 0,
        .source_epoch = worker_case ? 1 : 0,
        .actor_start_ticks = actor_start, .master_start_ticks = master_start,
        .source_block_address = 0x12340000,
        .launch_epoch = 8, .deadline_ns = now + UINT64_C(2000000000),
    };
    memset(req.run_nonce, 0x58, sizeof(req.run_nonce));
    if (master_case) req.control_deadline_ns = now + UINT64_C(95000000);
    struct ker_source_native_ini_cycle_snapshot snapshot;
    make_snapshot(&snapshot);
    if (mode == LEGACY_OK) unsetenv("KER_NGINX_SOURCE_SHELL_ENABLE");
    else setenv("KER_NGINX_SOURCE_SHELL_ENABLE", "1", 1);
    struct ker_nginx_source_bootstrap binding;
    int before = fd_count();
    uint64_t began = mono_ns();
    int status = mode == LEGACY_OK ?
        ker_nginx_source_bootstrap_connect(r.socket_path, &req,
            (uint32_t)supervisor, sup_start, &binding) :
        ker_nginx_source_bootstrap_connect_source_shell(r.socket_path, &req,
            &snapshot, (uint32_t)supervisor, sup_start, &binding);
    uint64_t elapsed = mono_ns() - began;
    int expect_success = mode == LEGACY_OK || mode == SHELL_SLIM_OK ||
        worker_case || mode == CLOSED_MASTER_ACK;
    int ok = expect_success ? status == 0 : status < 0;
    if (mode == BAD_PROOF || mode == BAD_VERSION || mode == BAD_SIZE || mode == OLD_176 ||
        mode == EXTRA_FD || mode == WRONG_CRED || mode == CLOSED_MASTER_BAD_PROOF)
        ok &= status == -EPROTO;
    if (mode == EOF_REPLY) ok &= status < 0;
    if (mode == EXPIRED_MASTER) ok &= status == -ETIMEDOUT && elapsed < UINT64_C(500000000);
    if (expect_success) {
        ok &= status == 0;
        if (!master_case) ok &= ker_nginx_source_bootstrap_live(&binding) == 0;
        int want_shell = mode != LEGACY_OK;
        ok &= !!binding.source_shell_proof_enabled == want_shell;
        ok &= binding.record.record_bytes == (want_shell ? 264u : 176u);
        if (mode == CLOSED_MASTER_ACK) {
            ok &= binding.record.type == KER_NGINX_SOURCE_MASTER_PARK + 2 &&
                binding.record.control_deadline_ns == req.control_deadline_ns;
            char command = 'Q'; write(finish[1], &command, 1);
        } else if (mode == SHELL_SLIM_OK || mode == LEGACY_OK) {
            ok &= ker_nginx_source_bootstrap_poll_stop(&binding) == 0;
            char command = 'S'; write(finish[1], &command, 1);
            int stop = 0;
            uint64_t deadline = mono_ns() + UINT64_C(1000000000);
            while (mono_ns() < deadline && stop == 0) {
                stop = ker_nginx_source_bootstrap_poll_stop(&binding);
                if (stop == 0) usleep(1000);
            }
            ok &= stop == 1;
            command = 'Q'; write(finish[1], &command, 1);
        } else {
            char command = 'A'; write(finish[1], &command, 1);
            int activate = 0;
            uint64_t deadline = mono_ns() + UINT64_C(1000000000);
            while (mono_ns() < deadline && activate == 0) {
                activate = ker_nginx_source_bootstrap_poll_activate(&binding);
                if (activate == 0) usleep(1000);
            }
            ok &= activate == 1;
            if (activate == 1 && mode >= WORKER_PREEXIT_OK)
                ok &= run_worker_preexit(&binding, mode) == 0;
            command = 'Q'; write(finish[1], &command, 1);
        }
        ker_nginx_source_bootstrap_close(&binding);
    } else {
        if (mode != EOF_REPLY && mode != EXPIRED_MASTER) {
            char command = 'Q';
            (void)write(finish[1], &command, 1);
        }
    }
    close(finish[1]);
    ok &= fd_count() == before - 1;
    int child_status = 0;
    waitpid(supervisor, &child_status, 0);
    ok &= WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
    kill(r.runtime_pid, SIGKILL); kill(r.io_pid, SIGKILL); kill(r.master_pid, SIGKILL);
    waitpid(r.runtime_pid, NULL, 0); waitpid(r.io_pid, NULL, 0); waitpid(r.master_pid, NULL, 0);
    unlink(r.socket_path); unlink(r.fifo_path);
    if (!ok) fprintf(stderr, "transport case %d failed: connect=%d elapsed_ns=%llu fds=%d->%d server=%d\n",
        mode, status, (unsigned long long)elapsed, before, fd_count(), child_status);
    return ok ? 0 : 1;
}

static int connect_activation(const char *path)
{
    struct sockaddr_un endpoint = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(endpoint.sun_path)) return -1;
    memcpy(endpoint.sun_path, path, strlen(path) + 1);
    int channel = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (channel < 0) return -1;
    if (connect(channel, (struct sockaddr *)&endpoint, sizeof(endpoint))) {
        close(channel);
        return -1;
    }
    return channel;
}

enum commit_expectation { NO_COMMIT, ACCEPT_COMMIT, REJECT_COMMIT };

static int receive_activation(int channel, int expect_mismatch,
    enum commit_expectation commit)
{
    /* The fixture supplies a contained grant. The worker receives the SDK
     * command through the production ACTIVATE receiver. */
    struct ker_nginx_source_bootstrap_record_v4 grant;
    struct ker_nginx_source_bootstrap binding = {
        .channel = channel, .supervisor_pidfd = -1, .runtime_pidfd = -1,
        .io_pidfd = -1, .slot_fd = -1, .relay_fd = -1, .ready_fd = -1,
    };
    int result = 1;
    int enabled = 1;
    if (binding.channel < 0 ||
            setsockopt(binding.channel, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) ||
            fread(&grant, sizeof(grant), 1, stdin) != 1)
        goto close;
    binding.record = grant.record;
    binding.source_shell_proof = grant.proof;
    binding.source_shell_proof_enabled = 1;
    if (expect_mismatch) binding.source_shell_proof.config_sha256[0] ^= 1;
    binding.supervisor_pidfd = (int)syscall(SYS_pidfd_open, grant.record.supervisor_pid, 0);
    binding.runtime_pidfd = (int)syscall(SYS_pidfd_open, grant.record.runtime_pid, 0);
    binding.io_pidfd = (int)syscall(SYS_pidfd_open, grant.record.io_pid, 0);
    if (ker_nginx_source_bootstrap_live(&binding)) goto close;
    puts("RECEIVER_READY");
    fflush(stdout);
    uint64_t limit = mono_ns() + UINT64_C(2000000000);
    int status = 0;
    while (mono_ns() < limit && status == 0) {
        status = ker_nginx_source_bootstrap_poll_activate(&binding);
        if (!status) usleep(1000);
    }
    printf("ACTIVATE status=%d accepted=%u\n", status, binding.source_candidate_activated);
    result = expect_mismatch ? !(status == -EPROTO && !binding.source_candidate_activated)
        : !(status == 1 && binding.source_candidate_activated);
    if (result == 0 && commit != NO_COMMIT) {
        limit = mono_ns() + UINT64_C(2000000000);
        status = 0;
        while (mono_ns() < limit && status == 0 && !binding.source_commit_evidence_received) {
            status = ker_nginx_source_bootstrap_poll_stop(&binding);
            if (!status && !binding.source_commit_evidence_received) usleep(1000);
        }
        printf("COMMIT_EVIDENCE status=%d accepted=%u cookie=%llu\n",
            status, binding.source_commit_evidence_received,
            (unsigned long long)binding.native_commit_cookie);
        result = commit == ACCEPT_COMMIT
            ? !(status == 0 && binding.source_commit_evidence_received && binding.native_commit_cookie)
            : !(status == -EPROTO && !binding.source_commit_evidence_received && !binding.native_commit_cookie);
    }
close:
    ker_nginx_source_bootstrap_close(&binding);
    return result;
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--receive-activate") &&
            (!strcmp(argv[3], "accept") || !strcmp(argv[3], "reject")))
        return receive_activation(connect_activation(argv[2]), !strcmp(argv[3], "reject"), NO_COMMIT);
    if (argc == 4 && !strcmp(argv[1], "--receive-activate-fd")) {
        char *end;
        errno = 0;
        long channel = strtol(argv[2], &end, 10);
        if (errno || end == argv[2] || *end || channel < 3 || channel > INT_MAX)
            return 2;
        if (!strcmp(argv[3], "activate"))
            return receive_activation((int)channel, 0, NO_COMMIT);
        if (!strcmp(argv[3], "commit"))
            return receive_activation((int)channel, 0, ACCEPT_COMMIT);
        if (!strcmp(argv[3], "reject-commit"))
            return receive_activation((int)channel, 0, REJECT_COMMIT);
        return 2;
    }
    if (argc != 1) return 2;
    int failed = 0;
    snprintf(fixture_dir, sizeof(fixture_dir), "/tmp/ker-source-v4-XXXXXX");
    if (!mkdtemp(fixture_dir)) return 2;
    struct ker_source_native_ini_cycle_snapshot snapshot;
    make_snapshot(&snapshot);
    struct ker_nginx_source_bootstrap_record request = {
        .magic = KER_NGINX_SOURCE_BOOTSTRAP_MAGIC,
        .version = KER_NGINX_SOURCE_BOOTSTRAP_VERSION,
        .record_bytes = sizeof(request),
    };
    struct ker_nginx_source_bootstrap binding;
    setenv("KER_NGINX_SOURCE_SHELL_ENABLE", "1", 1);
    int before = fd_count();
    int missing_proof = ker_nginx_source_bootstrap_connect_source_shell("/tmp/no-source.sock",
        &request, NULL, 1, 1, &binding);
    failed += missing_proof != -ENOTSUP || fd_count() != before;
    int legacy_fallback = ker_nginx_source_bootstrap_connect("/tmp/no-source.sock",
        &request, 1, 1, &binding);
    failed += legacy_fallback != -ENOTSUP || fd_count() != before;
    for (enum mode mode = LEGACY_OK; mode <= CLOSED_MASTER_BAD_PROOF; mode++)
        failed += run_case(mode);
    for (enum mode mode = WORKER_PREEXIT_OK; mode <= WORKER_PREEXIT_NO_EOF; mode++) {
        /* The production worker has one process-lifetime PREEXIT attempt. */
        pid_t worker = fork();
        if (!worker) _exit(run_case(mode));
        int status;
        failed += worker < 0 || waitpid(worker, &status, 0) != worker ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    }
    if (!failed) puts("source bootstrap transport controls passed");
    rmdir(fixture_dir);
    return failed ? 1 : 0;
}
