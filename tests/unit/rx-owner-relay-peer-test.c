#define _GNU_SOURCE
#include "rx-owner-relay-peer.h"
#include "rx-decision-wire.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); abort(); } } while (0)

enum mode { LOCAL, PEER, ERROR, RESPONSE, WRONG_QUEUE, WRONG_FRAME, WRONG_HASH,
    WRONG_NONCE, WRONG_EPOCH, WRONG_PACKET, WRONG_DEADLINE, WRONG_TID,
    WRONG_LENGTH, RIGHTS, FOREIGN_CREDENTIALS, SLOW, EXPIRED, WRONG_PIDFD,
    WRONG_CONTEXT, SAME_OWNER, REPLAY, CLOSED, WRONG_START, PRIMARY_LOCAL,
    FAR_DEADLINE, WRONG_UID, DIES_ON_REQUEST, UNBOUND };

static uint64_t now_ns(void)
{
    struct timespec t;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}

static uint32_t hash(const unsigned char *frame, size_t bytes)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < bytes; ++i) h = (h ^ frame[i]) * 16777619u;
    return h;
}

static unsigned fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); CHECK(d);
    unsigned count = 0;
    while (readdir(d)) ++count;
    closedir(d);
    return count;
}

static uint64_t start_ticks(pid_t pid)
{
    char path[64], data[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r"); CHECK(f && fgets(data, sizeof(data), f)); fclose(f);
    char *p = strrchr(data, ')'); CHECK(p); p += 2;
    for (unsigned field = 3; field < 22; ++field) {
        while (*p == ' ') ++p;
        while (*p && *p != ' ') ++p;
        CHECK(*p);
    }
    return strtoull(p, NULL, 10);
}

static void old_owner(int fd, enum mode mode)
{
    unsigned char packet[sizeof(struct ker_rx_owner_relay_header) + 64];
    struct ker_rx_owner_relay_header header;
    long n = recv(fd, packet, sizeof(packet), 0);
    CHECK(n == (long)sizeof(packet));
    memcpy(&header, packet, sizeof(header));
    CHECK(header.type == KER_RX_OWNER_RELAY_REQUEST && header.owner_pid == (uint32_t)getpid());
    CHECK(header.owner_tid == (uint32_t)syscall(SYS_gettid) && header.packet_id == 17);
    CHECK(header.frame_bytes == 64 && header.queue_id == 0 && header.queue_count == 2);
    CHECK(!header.dispatcher_result && !header.frame_hash32 && !header.frame_unchanged);
    for (unsigned i = 0; i < 64; ++i) CHECK(packet[sizeof(header) + i] == (unsigned char)i);
    if (mode == DIES_ON_REQUEST) _exit(0);
    if (mode == SLOW) {
        struct timespec delay = {.tv_nsec = 200000000};
        nanosleep(&delay, NULL);
    }
    header.type = KER_RX_OWNER_RELAY_REPLY;
    header.dispatcher_result = mode == PEER ? -3 : mode == ERROR ? -1 :
        mode == RESPONSE ? -2 : mode == WRONG_QUEUE ? 1 : 0;
    header.frame_hash32 = hash(packet + sizeof(header), 64);
    header.frame_unchanged = 1;
    if (mode == WRONG_FRAME) packet[sizeof(header) + 9] ^= 1;
    if (mode == WRONG_HASH) header.frame_hash32 ^= 1;
    if (mode == WRONG_NONCE) header.run_nonce[0] ^= 1;
    if (mode == WRONG_EPOCH) ++header.worker_epoch;
    if (mode == WRONG_PACKET) ++header.packet_id;
    if (mode == WRONG_DEADLINE) ++header.deadline_ns;
    if (mode == WRONG_TID) ++header.owner_tid;
    memcpy(packet, &header, sizeof(header));
    struct iovec iov = {.iov_base = packet, .iov_len = sizeof(packet) - (mode == WRONG_LENGTH)};
    unsigned char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    int extra = -1;
    if (mode == RIGHTS) {
        extra = open("/dev/null", O_RDONLY | O_CLOEXEC); CHECK(extra >= 0);
        message.msg_control = control; message.msg_controllen = sizeof(control);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &extra, sizeof(extra));
    }
    if (mode == FOREIGN_CREDENTIALS) {
        pid_t sender = fork(); CHECK(sender >= 0);
        if (!sender) { CHECK(sendmsg(fd, &message, MSG_NOSIGNAL) == (long)iov.iov_len); _exit(0); }
        int status; CHECK(waitpid(sender, &status, 0) == sender && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    } else CHECK(sendmsg(fd, &message, MSG_NOSIGNAL) == (long)iov.iov_len);
    if (extra >= 0) close(extra);
    /* Keep the exact owner alive until the parent has checked the pidfd after
     * receiving the reply. Socket EOF also releases negative-test workers. */
    unsigned char done;
    (void)recv(fd, &done, 1, 0);
    _exit(0);
}

static void run_case(enum mode mode)
{
    unsigned before = fd_count();
    int channel[2]; CHECK(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel));
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) { close(channel[0]); old_owner(channel[1], mode); }
    close(channel[1]);
    int pidfd = (int)syscall(SYS_pidfd_open, child, 0); CHECK(pidfd >= 0);
    struct ker_rx_owner_relay_header source = {
        .magic = KER_RX_OWNER_RELAY_MAGIC, .version = KER_RX_OWNER_RELAY_VERSION,
        .type = KER_RX_OWNER_RELAY_REPLY, .packet_id = 17,
        .deadline_ns = now_ns() + 80000000, .worker_epoch = 7,
        .app_start_ticks = 1, .owner_start_ticks = 2, .supervisor_start_ticks = 3,
        .app_pid = (uint32_t)getpid(), .owner_pid = (uint32_t)getpid(),
        .owner_tid = (uint32_t)syscall(SYS_gettid), .supervisor_pid = (uint32_t)getpid(),
        .frame_bytes = 64, .queue_count = 2, .dispatcher_result = -3,
        .frame_unchanged = 1,
    };
    memset(source.run_nonce, 0x5a, sizeof(source.run_nonce));
    unsigned char frame[64], original[64];
    for (unsigned i = 0; i < sizeof(frame); ++i) frame[i] = (unsigned char)i;
    memcpy(original, frame, sizeof(frame)); source.frame_hash32 = hash(frame, sizeof(frame));
    struct ker_rx_owner_relay_peer peer = {.fd = channel[0], .pidfd = pidfd,
        .uid = getuid(), .gid = getgid(), .identity = source};
    peer.identity.owner_pid = (uint32_t)child;
    peer.identity.owner_tid = (uint32_t)child;
    peer.identity.owner_start_ticks = start_ticks(child);
    int other_pidfd = -1;
    if (mode == EXPIRED) source.deadline_ns = now_ns() - 1;
    if (mode == WRONG_PIDFD) {
        other_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0); CHECK(other_pidfd >= 0);
        peer.pidfd = other_pidfd;
    }
    if (mode == WRONG_CONTEXT) ++peer.identity.worker_epoch;
    if (mode == SAME_OWNER) peer.identity.owner_pid = source.owner_pid;
    if (mode == REPLAY) peer.last_packet_id = source.packet_id;
    if (mode == CLOSED) { close(channel[0]); peer.fd = -1; }
    if (mode == UNBOUND) peer.pidfd = -1;
    if (mode == WRONG_START) ++peer.identity.owner_start_ticks;
    if (mode == PRIMARY_LOCAL) source.dispatcher_result = 0;
    if (mode == FAR_DEADLINE) source.deadline_ns = now_ns() + 200000000;
    if (mode == WRONG_UID) ++peer.uid;
    struct ker_rx_owner_relay_header saved = source;
    int action = 71;
    int result = ker_rx_owner_relay_peer_forward(&peer, &source, frame, sizeof(frame), &action);
    if (mode <= WRONG_QUEUE) {
        CHECK(!result && action == (mode == LOCAL ? KER_RX_DECISION_LOCAL : KER_RX_DECISION_DROP));
        CHECK(peer.last_packet_id == source.packet_id);
        action = 71;
        CHECK(ker_rx_owner_relay_peer_forward(&peer, &source, frame, sizeof(frame), &action) == -EALREADY && action == 71);
    } else {
        CHECK(result < 0 && action == 71);
        if (mode == EXPIRED || mode == SLOW) CHECK(result == -ETIMEDOUT);
    }
    CHECK(!memcmp(frame, original, sizeof(frame)) && !memcmp(&source, &saved, sizeof(source)));
    if (mode != CLOSED) close(channel[0]);
    close(pidfd);
    if (other_pidfd >= 0) close(other_pidfd);
    /* Negative controls may leave the peer waiting for a request or sleeping.
     * Terminate only this test-owned child; never leave a helper behind. */
    CHECK(!kill(child, SIGKILL) || errno == ESRCH);
    int status; CHECK(waitpid(child, &status, 0) == child);
    /* Reap the foreign-sender control even if its owner was killed before it
     * finished waitpid. The standalone test is a subreaper for its own helpers. */
    while (waitpid(-1, &status, 0) > 0) {}
    CHECK(errno == ECHILD);
    CHECK(fd_count() == before);
    printf("PASS peer-relay control %d\n", mode);
}

int main(void)
{
    CHECK(!prctl(PR_SET_CHILD_SUBREAPER, 1));
    for (int mode = LOCAL; mode <= UNBOUND; ++mode) run_case((enum mode)mode);
    puts("PASS: bounded old-owner frame relay, credentials/pidfd, exact lease, no loops, no FD leaks");
    return 0;
}
