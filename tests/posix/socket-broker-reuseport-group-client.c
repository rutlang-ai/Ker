#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "reuseport client:%d: %s: %s\n", __LINE__, #condition, strerror(errno)); \
    return 1; } } while (0)

static int wait_token(struct ker_socket_client *client, int epoll, uint64_t expected,
    uint64_t forbidden)
{
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (unsigned attempt = 0; attempt < 10000; ++attempt) {
        struct epoll_event events[4];
        int count = ker_socket_client_epoll_wait(client, epoll, events, 4);
        if (count < 0) return -1;
        for (int i = 0; i < count; ++i) {
            if (events[i].data.u64 == forbidden) { errno = EPROTO; return -1; }
            if (events[i].data.u64 == expected) return 0;
        }
        (void)nanosleep(&pause, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int read_exact(struct ker_socket_client *client, int fd, void *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t amount = ker_socket_client_read(client, fd, (char *)bytes + done, length - done);
        if (amount > 0) { done += (size_t)amount; continue; }
        if (amount < 0 && (errno == EAGAIN || errno == EINTR)) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)nanosleep(&pause, NULL); continue;
        }
        if (!amount) errno = ECONNRESET;
        return -1;
    }
    return 0;
}

static int write_exact(struct ker_socket_client *client, int fd, const void *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t amount = ker_socket_client_write(client, fd, (const char *)bytes + done, length - done);
        if (amount > 0) { done += (size_t)amount; continue; }
        if (amount < 0 && (errno == EAGAIN || errno == EINTR)) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)nanosleep(&pause, NULL); continue;
        }
        if (!amount) errno = EPIPE;
        return -1;
    }
    return 0;
}

static int exec_inherited_group_probe(const char *rpc_path, const char *helper,
    const char *preload, int capability, bool duplicate, const char *kind)
{
    int inherited = capability;
    if (duplicate) {
        inherited = dup(capability);
        if (inherited < 0) return -1;
    } else {
        int flags = fcntl(inherited, F_GETFD);
        if (flags < 0 || fcntl(inherited, F_SETFD, flags & ~FD_CLOEXEC)) return -1;
    }
    pid_t child = fork();
    if (child == 0) {
        char descriptor[32];
        snprintf(descriptor, sizeof(descriptor), "%d", inherited);
        if (setenv("KER_SOCKET_BROKER_PATH", rpc_path, 1) ||
            setenv("LD_PRELOAD", preload, 1)) _exit(120);
        execl(helper, helper, rpc_path, descriptor, duplicate ? "0" : "1", kind, (char *)NULL);
        _exit(121);
    }
    int saved = errno;
    if (duplicate) (void)close(inherited);
    else {
        int flags = fcntl(inherited, F_GETFD);
        if (flags >= 0) (void)fcntl(inherited, F_SETFD, flags | FD_CLOEXEC);
    }
    if (child < 0) { errno = saved; return -1; }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "inherited capability probe failed: wait_status=%d\n", status);
        errno = ECHILD; return -1;
    }
    return 0;
}

static int snapshot_live_member(struct ker_socket_client *client, int census,
    int member, uint64_t expected_cookie)
{
    struct ker_socket_member_census_snapshot snapshot = {0};
    int option = 0;
    socklen_t option_length = sizeof(option);
    uint64_t cookie = 0;
    socklen_t cookie_length = sizeof(cookie);
    if (ker_socket_client_getsockopt(client, member, SOL_SOCKET, SO_COOKIE,
            &cookie, &cookie_length) || cookie_length != sizeof(cookie) ||
        ker_socket_client_getsockopt(client, member, SOL_SOCKET, SO_ACCEPTCONN,
            &option, &option_length) || option_length != sizeof(option) || !option ||
        ker_socket_client_member_census_snapshot(client, census, &snapshot)) return -1;
    if (snapshot.total != 1 ||
        snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1 ||
        snapshot.listener_cookie != expected_cookie || snapshot.listener_cookie != cookie) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int owner_wait_fd(struct ker_socket_client *client, int fd, uint32_t events)
{
    int epoll = ker_socket_client_epoll_create1(client, EPOLL_CLOEXEC);
    if (epoll < 0) return -1;
    struct epoll_event event = {.events = events, .data.u64 = 1};
    int result = ker_socket_client_epoll_ctl(client, epoll, EPOLL_CTL_ADD, fd, &event);
    if (!result) result = wait_token(client, epoll, 1, 0);
    int error = errno;
    close(epoll);
    errno = error;
    return result;
}

static int owner_accept_exchange(struct ker_socket_client *client, int owner,
    int listener, const char *request, const char *reply, int *held_out)
{
    if (owner_wait_fd(client, listener, EPOLLIN)) return -1;
    int accepted = ker_socket_client_accept4(client, listener, NULL, NULL, SOCK_CLOEXEC);
    if (accepted < 0) return -1;
    if (ker_socket_client_ff_owner_match(client, owner, accepted) != 1) {
        int error = errno ? errno : EPROTO; close(accepted); errno = error; return -1;
    }
    int accepted_alias = ker_socket_client_dup(client, accepted);
    if (accepted_alias < 0 ||
        ker_socket_client_ff_owner_match(client, owner, accepted_alias) != 1) {
        int error = errno ? errno : EPROTO;
        if (accepted_alias >= 0) close(accepted_alias);
        close(accepted); errno = error; return -1;
    }
    close(accepted_alias);
    char actual[8];
    int result = read_exact(client, accepted, actual, sizeof(actual));
    if (!result && memcmp(actual, request, 8)) { errno = EPROTO; result = -1; }
    if (!result) result = write_exact(client, accepted, reply, 8);
    int error = errno;
    if (!result && held_out) *held_out = accepted;
    else close(accepted);
    errno = error;
    return result;
}

static int owner_echo_held(struct ker_socket_client *client, int fd,
    const char *request, const char *reply)
{
    char actual[8];
    if (read_exact(client, fd, actual, sizeof(actual))) return -1;
    if (memcmp(actual, request, sizeof(actual))) { errno = EPROTO; return -1; }
    return write_exact(client, fd, reply, 8);
}

static int owner_group_orphan_payload(struct ker_socket_client *client,
    int owner, int census, int held_fd)
{
    struct ker_socket_member_payload_snapshot owner_snapshot = {0}, member_snapshot = {0};
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    bool baseline = false;
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
        if (ker_socket_client_ff_owner_payload_snapshot(client, owner,
                &owner_snapshot) ||
            ker_socket_client_member_payload_snapshot(client, census, &member_snapshot))
            return -1;
        if (!owner_snapshot.payload_bytes && !member_snapshot.payload_bytes &&
            owner_snapshot.sampled_sockets == 1 && member_snapshot.sampled_sockets == 1) {
            baseline = true;
            break;
        }
        (void)nanosleep(&pause, NULL);
    }
    if (!baseline) { errno = EPROTO; return -1; }
    puts("OWNER_GROUP_WAIT_PAYLOAD"); fflush(stdout);
    char command[32] = {0};
    if (!fgets(command, sizeof(command), stdin) || strcmp(command, "SEND\n")) {
        fprintf(stderr, "C18 payload: bad SEND command %s\n", command);
        errno = EPROTO; return -1;
    }
    unsigned char payload[1200];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (unsigned char)((i * 17 + 3) & 0xff);
    if (write_exact(client, held_fd, payload, sizeof(payload)) || close(held_fd)) return -1;

    bool pending = false;
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
        if (ker_socket_client_ff_owner_payload_snapshot(client, owner,
                &owner_snapshot) ||
            ker_socket_client_member_payload_snapshot(client, census, &member_snapshot))
            { fprintf(stderr, "C18 payload: query failed errno=%d\n", errno); return -1; }
        if (owner_snapshot.payload_bytes == sizeof(payload) &&
            member_snapshot.payload_bytes == sizeof(payload) &&
            owner_snapshot.sampled_sockets == 1 && member_snapshot.sampled_sockets == 1) {
            pending = true;
            break;
        }
        (void)nanosleep(&pause, NULL);
    }
    if (!pending) {
        fprintf(stderr, "C18 payload: snapshots owner=%llu/%llu member=%llu/%llu\n",
            (unsigned long long)owner_snapshot.payload_bytes,
            (unsigned long long)owner_snapshot.sampled_sockets,
            (unsigned long long)member_snapshot.payload_bytes,
            (unsigned long long)member_snapshot.sampled_sockets);
        errno = EPROTO; return -1;
    }
    printf("OWNER_GROUP_DESCRIPTORLESS_PENDING bytes=%llu owner_sockets=%llu member_sockets=%llu\n",
        (unsigned long long)owner_snapshot.payload_bytes,
        (unsigned long long)owner_snapshot.sampled_sockets,
        (unsigned long long)member_snapshot.sampled_sockets);
    fflush(stdout);
    memset(command, 0, sizeof(command));
    if (!fgets(command, sizeof(command), stdin) || strcmp(command, "DRAIN\n")) {
        fprintf(stderr, "C18 payload: bad DRAIN command %s\n", command);
        errno = EPROTO; return -1;
    }
    bool drained = false;
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        if (ker_socket_client_ff_owner_payload_snapshot(client, owner,
                &owner_snapshot) ||
            ker_socket_client_member_payload_snapshot(client, census, &member_snapshot))
            return -1;
        if (!owner_snapshot.payload_bytes && !member_snapshot.payload_bytes) {
            drained = true;
            break;
        }
        (void)nanosleep(&pause, NULL);
    }
    if (!drained) { errno = ETIMEDOUT; return -1; }
    puts("OWNER_GROUP_DESCRIPTORLESS_DRAINED bytes=0"); fflush(stdout);
    return 0;
}

static int owner_group_child(struct ker_socket_client *inherited_client,
    const char *rpc_path, int foreign_owner, int slot, int control)
{
    ker_socket_client_close(inherited_client);
    struct ker_socket_client client;
    if (ker_socket_client_open(&client, rpc_path)) return 20;
    errno = 0;
    if (ker_socket_client_ff_owner_group_claim(&client, foreign_owner, slot) != -1 ||
        errno != EXDEV) return 21;
    close(foreign_owner);
    int owner = ker_socket_client_ff_owner_create(&client);
    if (owner < 0 || ker_socket_client_ff_owner_group_claim(&client, owner, slot)) return 22;
    errno = 0;
    if (ker_socket_client_ff_owner_group_claim(&client, owner, slot) != -1 ||
        errno != EALREADY) return 23;
    char token = 'C';
    if (send(control, &token, 1, MSG_NOSIGNAL) != 1 || recv(control, &token, 1, 0) != 1 ||
        token != 'P') return 24;
    enum ker_socket_broker_kind slot_kind = 0;
    int slot_flags = -1;
    if (ker_socket_client_describe(&client, slot, &slot_kind, &slot_flags) ||
        slot_kind != KER_SOCKET_BROKER_FF_OWNER_GROUP_SLOT || slot_flags != 0) return 25;
    errno = 0;
    if (ker_socket_client_reuseport_group_select(&client, slot, 0) != -1 ||
        errno != ENOTSOCK) return 25;
    int member = ker_socket_client_owner_group_member(&client, owner, slot);
    int alias = ker_socket_client_owner_group_member(&client, owner, slot);
    if (member < 0 || alias < 0 ||
        ker_socket_client_ff_owner_match(&client, owner, member) != 1) return 25;
    int member_duplicate = ker_socket_client_dup(&client, member);
    if (member_duplicate < 0 ||
        ker_socket_client_ff_owner_match(&client, owner, member_duplicate) != 1) return 25;
    close(member_duplicate);
    uint64_t first_cookie = 0, second_cookie = 0;
    socklen_t length = sizeof(first_cookie);
    if (ker_socket_client_getsockopt(&client, member, SOL_SOCKET, SO_COOKIE,
            &first_cookie, &length) || length != sizeof(first_cookie)) return 26;
    length = sizeof(second_cookie);
    if (ker_socket_client_getsockopt(&client, alias, SOL_SOCKET, SO_COOKIE,
            &second_cookie, &length) || length != sizeof(second_cookie) ||
        first_cookie != second_cookie) return 27;
    token = 'R';
    if (send(control, &token, 1, MSG_NOSIGNAL) != 1 || recv(control, &token, 1, 0) != 1 ||
        token != 'A') return 28;
    int result = owner_accept_exchange(&client, owner, member, "OWNER-01", "WORKER-1", NULL);
    close(alias); close(member); close(slot); close(owner);
    ker_socket_client_close(&client);
    if (result) return 29;
    token = 'D';
    return send(control, &token, 1, MSG_NOSIGNAL) == 1 ? 0 : 30;
}

static int owner_group_smoke(struct ker_socket_client *client, const char *rpc_path,
    int foreign_group)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4100)};
    if (inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1) return -1;
    int owner = ker_socket_client_ff_owner_create(client);
    if (owner < 0) return -1;
    int plan = ker_socket_client_owner_group_plan(client, &address, 16,
        KER_SOCKET_BROKER_CONTROL);
    if (plan < 0) return -1;
    int slot0 = ker_socket_client_owner_group_slot(client, plan, 0);
    int slot1 = ker_socket_client_owner_group_slot(client, plan, 1);
    if (slot0 < 0 || slot1 < 0) return -1;
    errno = 0;
    if (ker_socket_client_owner_group_slot(client, plan, 0) != -1 || errno != EALREADY)
        { errno = EPROTO; return -1; }
    if (ker_socket_client_ff_owner_group_claim(client, owner, slot0)) return -1;
    errno = 0;
    if (ker_socket_client_ff_owner_group_claim(client, owner, slot0) != -1 ||
        errno != EALREADY) { errno = EPROTO; return -1; }
    errno = 0;
    if (ker_socket_client_ff_owner_socket(client, owner, AF_INET,
            SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP) != -1 || errno != EBUSY)
        { errno = EPROTO; return -1; }

    int control[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control)) return -1;
    struct timeval timeout = {.tv_sec = 15};
    if (setsockopt(control[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(control[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(control[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(control[1], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) return -1;
    pid_t child = fork();
    if (child < 0) { int error = errno; close(control[0]); close(control[1]); errno = error; return -1; }
    if (child == 0) {
        close(control[0]);
        close(STDOUT_FILENO);
        close(foreign_group); close(plan); close(slot0);
        int result = owner_group_child(client, rpc_path, owner, slot1, control[1]);
        _exit(result);
    }
    close(control[1]);
    char token = 0;
    if (recv(control[0], &token, 1, 0) != 1 || token != 'C')
        { errno = EPROTO; return -1; }
    int group = ker_socket_client_owner_group_publish(client, plan);
    if (group < 0) return -1;
    errno = 0;
    if (ker_socket_client_owner_group_publish(client, plan) != -1 || errno != EALREADY)
        { errno = EPROTO; return -1; }
    int member0 = ker_socket_client_owner_group_member(client, owner, slot0);
    int alias0 = ker_socket_client_owner_group_member(client, owner, slot0);
    if (member0 < 0 || alias0 < 0) return -1;
    errno = 0;
    if (ker_socket_client_ff_owner_socket(client, owner, AF_INET,
            SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP) != -1 || errno != EBUSY) {
        errno = EPROTO; return -1;
    }
    uint64_t cookie0 = 0;
    socklen_t cookie_length = sizeof(cookie0);
    if (ker_socket_client_getsockopt(client, member0, SOL_SOCKET, SO_COOKIE,
            &cookie0, &cookie_length) || cookie_length != sizeof(cookie0)) return -1;
    int census0 = ker_socket_client_member_census_create(client, group, 0);
    int census1 = ker_socket_client_member_census_create(client, group, 1);
    if (census0 < 0 || census1 < 0) return -1;
    struct ker_socket_member_census_snapshot snap0 = {0}, snap1 = {0};
    if (ker_socket_client_member_census_snapshot(client, census0, &snap0) ||
        ker_socket_client_member_census_snapshot(client, census1, &snap1) ||
        snap0.total != 1 || snap1.total != 1 ||
        snap0.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1 ||
        snap1.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1 ||
        !snap0.listener_cookie || snap0.listener_cookie != cookie0 ||
        snap0.listener_cookie == snap1.listener_cookie) { errno = EPROTO; return -1; }
    if (send(control[0], "P", 1, MSG_NOSIGNAL) != 1 ||
        recv(control[0], &token, 1, 0) != 1 || token != 'R')
        { errno = EPROTO; return -1; }

    if (ker_socket_client_reuseport_group_select(client, group, 0)) return -1;
    puts("OWNER_GROUP_READY_0"); fflush(stdout);
    int held_fd = -1;
    if (owner_accept_exchange(client, owner, member0, "OWNER-00", "WORKER-0", &held_fd))
        return -1;
    puts("OWNER_GROUP_ACCEPTED_0"); fflush(stdout);
    if (ker_socket_client_reuseport_group_select(client, group, 1) ||
        send(control[0], "A", 1, MSG_NOSIGNAL) != 1) return -1;
    puts("OWNER_GROUP_READY_1"); fflush(stdout);
    if (
        recv(control[0], &token, 1, 0) != 1 || token != 'D')
        { errno = EPROTO; return -1; }
    if (owner_echo_held(client, held_fd, "OLD-0001", "OLD-ACK1")) return -1;
    puts("OWNER_GROUP_ACCEPTED_1"); fflush(stdout);
    if (owner_group_orphan_payload(client, owner, census0, held_fd)) {
        return -1;
    }
    close(control[0]);
    int child_status = 0;
    while (waitpid(child, &child_status, 0) < 0) if (errno != EINTR) return -1;
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        errno = ECHILD; return -1;
    }
    errno = 0;
    if (ker_socket_client_owner_group_publish(client, plan) != -1 || errno != EALREADY)
        { errno = EPROTO; return -1; }
    close(census0); close(census1); close(alias0); close(member0);
    close(slot0); close(slot1); close(group); close(plan); close(owner);
    puts("OWNER_GROUP_TWO_ACTOR_TCP_OK"); fflush(stdout);
    return 0;
}

static int owner_group_poison_actor(struct ker_socket_client *inherited_client,
    const char *rpc_path, int slot, int control, bool poison)
{
    ker_socket_client_close(inherited_client);
    struct ker_socket_client client;
    if (ker_socket_client_open(&client, rpc_path)) return 30;
    int owner = ker_socket_client_ff_owner_create(&client);
    if (owner < 0 || ker_socket_client_ff_owner_group_claim(&client, owner, slot)) return 31;
    if (poison) {
        int ordinary = ker_socket_client_socket(&client, AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ordinary < 0 || close(ordinary)) return 32;
    }
    char token = 'C';
    if (send(control, &token, 1, MSG_NOSIGNAL) != 1 || recv(control, &token, 1, 0) != 1 ||
        token != 'R') return 33;
    close(owner); close(slot); ker_socket_client_close(&client);
    return 0;
}

static int owner_group_history_rejection(struct ker_socket_client *client,
    const char *rpc_path, int foreign_group)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4101)};
    if (inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1) return -1;
    int plan = ker_socket_client_owner_group_plan(client, &address, 8,
        KER_SOCKET_BROKER_CONTROL);
    if (plan < 0) return -1;
    int slot0 = ker_socket_client_owner_group_slot(client, plan, 0);
    int slot1 = ker_socket_client_owner_group_slot(client, plan, 1);
    if (slot0 < 0 || slot1 < 0) return -1;
    int controls[2][2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, controls[0]) ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, controls[1])) return -1;
    struct timeval timeout = {.tv_sec = 15};
    for (unsigned i = 0; i < 2; ++i) {
        if (setsockopt(controls[i][0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(controls[i][0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(controls[i][1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(controls[i][1], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
            return -1;
    }
    pid_t actors[2] = {-1, -1};
    for (unsigned i = 0; i < 2; ++i) {
        actors[i] = fork();
        if (actors[i] < 0) return -1;
        if (!actors[i]) {
            close(controls[i][0]);
            close(foreign_group); close(plan);
            close(i ? slot0 : slot1);
            int result = owner_group_poison_actor(client, rpc_path,
                i ? slot1 : slot0, controls[i][1], i == 0);
            _exit(result);
        }
        close(controls[i][1]);
    }
    for (unsigned i = 0; i < 2; ++i) {
        char token = 0;
        if (recv(controls[i][0], &token, 1, 0) != 1 || token != 'C')
            { errno = EPROTO; return -1; }
    }
    errno = 0;
    if (ker_socket_client_owner_group_publish(client, plan) != -1 || errno != EOPNOTSUPP)
        { errno = EPROTO; return -1; }
    for (unsigned i = 0; i < 2; ++i) {
        (void)send(controls[i][0], "R", 1, MSG_NOSIGNAL);
        close(controls[i][0]);
        int status = 0;
        while (waitpid(actors[i], &status, 0) < 0) if (errno != EINTR) return -1;
        if (!WIFEXITED(status) || WEXITSTATUS(status)) { errno = ECHILD; return -1; }
    }
    close(slot0); close(slot1); close(plan);
    puts("OWNER_GROUP_HISTORY_FAIL_CLOSED_OK"); fflush(stdout);
    return 0;
}

static int owner_group_dead_actor(struct ker_socket_client *inherited_client,
    const char *rpc_path, int slot, int control, bool wait_release)
{
    ker_socket_client_close(inherited_client);
    struct ker_socket_client client;
    if (ker_socket_client_open(&client, rpc_path)) return 40;
    int owner = ker_socket_client_ff_owner_create(&client);
    if (owner < 0 || ker_socket_client_ff_owner_group_claim(&client, owner, slot)) return 41;
    char token = 'C';
    if (send(control, &token, 1, MSG_NOSIGNAL) != 1) return 42;
    if (wait_release && (recv(control, &token, 1, 0) != 1 || token != 'R')) return 43;
    close(owner); close(slot); ker_socket_client_close(&client);
    return 0;
}

static int owner_group_dead_owner_rejection(struct ker_socket_client *client,
    const char *rpc_path, int foreign_group)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4102)};
    if (inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1) return -1;
    int plan = ker_socket_client_owner_group_plan(client, &address, 8,
        KER_SOCKET_BROKER_CONTROL);
    if (plan < 0) return -1;
    int slot0 = ker_socket_client_owner_group_slot(client, plan, 0);
    int slot1 = ker_socket_client_owner_group_slot(client, plan, 1);
    if (slot0 < 0 || slot1 < 0) return -1;
    int controls[2][2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, controls[0]) ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, controls[1])) return -1;
    struct timeval timeout = {.tv_sec = 15};
    for (unsigned i = 0; i < 2; ++i) {
        if (setsockopt(controls[i][0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(controls[i][0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(controls[i][1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(controls[i][1], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
            return -1;
    }
    pid_t actors[2] = {-1, -1};
    for (unsigned i = 0; i < 2; ++i) {
        actors[i] = fork();
        if (actors[i] < 0) return -1;
        if (!actors[i]) {
            close(controls[i][0]); close(foreign_group); close(plan);
            close(i ? slot0 : slot1);
            int result = owner_group_dead_actor(client, rpc_path,
                i ? slot1 : slot0, controls[i][1], i == 1);
            _exit(result);
        }
        close(controls[i][1]);
    }
    for (unsigned i = 0; i < 2; ++i) {
        char token = 0;
        if (recv(controls[i][0], &token, 1, 0) != 1 || token != 'C') {
            errno = EPROTO; return -1;
        }
    }
    close(controls[0][0]);
    int dead_status = 0;
    while (waitpid(actors[0], &dead_status, 0) < 0) if (errno != EINTR) return -1;
    if (!WIFEXITED(dead_status) || WEXITSTATUS(dead_status)) { errno = ECHILD; return -1; }
    errno = 0;
    if (ker_socket_client_owner_group_publish(client, plan) != -1 || errno != ESRCH) {
        errno = EPROTO; return -1;
    }
    (void)send(controls[1][0], "R", 1, MSG_NOSIGNAL);
    close(controls[1][0]);
    int live_status = 0;
    while (waitpid(actors[1], &live_status, 0) < 0) if (errno != EINTR) return -1;
    if (!WIFEXITED(live_status) || WEXITSTATUS(live_status)) { errno = ECHILD; return -1; }
    close(slot0); close(slot1); close(plan);
    puts("OWNER_GROUP_DEAD_OWNER_FAIL_CLOSED_OK"); fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5) { fprintf(stderr, "usage: client <rpc-path> <read-only-group-cap> <inherited-probe> <preload-library>\n"); return 2; }
    char *end = NULL; long parsed = strtol(argv[2], &end, 10);
    if (!argv[2][0] || !end || *end || parsed < 0 || parsed > INT32_MAX) return 2;
    int denied_group = (int)parsed;
    struct ker_socket_client client;
    CHECK(ker_socket_client_open(&client, argv[1]) == 0);
    enum ker_socket_broker_kind kind; int flags = -1;
    CHECK(ker_socket_client_describe(&client, denied_group, &kind, &flags) == 0);
    CHECK(kind == KER_SOCKET_BROKER_REUSEPORT_GROUP && flags == 0);
    errno = 0;
    CHECK(ker_socket_client_dup(&client, denied_group) == -1 && errno == EOPNOTSUPP);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_select(&client, denied_group, 0) == -1 && errno == EACCES);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_member(&client, denied_group, 0) == -1 && errno == EACCES);
    errno = 0;
    CHECK(ker_socket_client_member_census_create(&client, denied_group, 0) == -1 &&
        errno == EACCES);
    struct ker_socket_member_census_snapshot invalid_snapshot = {0};
    errno = 0;
    CHECK(ker_socket_client_member_census_snapshot(&client, denied_group,
        &invalid_snapshot) == -1 && errno == ENOTSOCK);

    CHECK(owner_group_smoke(&client, argv[1], denied_group) == 0);
    CHECK(owner_group_history_rejection(&client, argv[1], denied_group) == 0);
    CHECK(owner_group_dead_owner_rejection(&client, argv[1], denied_group) == 0);

    /* Census capabilities contain immutable member metadata but retain no
     * group/listener reference. Prove both live LISTEN rows, inherited opaque
     * kind-5 exec behavior, and empty snapshots after the final group handles
     * close while the census caps themselves remain open. */
    struct sockaddr_in census_address = {.sin_family = AF_INET, .sin_port = htons(4099)};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &census_address.sin_addr) == 1);
    int census_group = ker_socket_client_reuseport_group_create(&client, &census_address, 8);
    CHECK(census_group >= 0);
    int census_member0 = ker_socket_client_reuseport_group_member(&client, census_group, 0);
    int census_member1 = ker_socket_client_reuseport_group_member(&client, census_group, 1);
    CHECK(census_member0 >= 0 && census_member1 >= 0);
    int census0 = ker_socket_client_member_census_create(&client, census_group, 0);
    int census1 = ker_socket_client_member_census_create(&client, census_group, 1);
    CHECK(census0 >= 0 && census1 >= 0);
    CHECK(ker_socket_client_describe(&client, census0, &kind, &flags) == 0 &&
        kind == KER_SOCKET_BROKER_MEMBER_CENSUS && flags == 0);
    errno = 0;
    CHECK(ker_socket_client_dup(&client, census0) == -1 && errno == EOPNOTSUPP);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_select(&client, census0, 0) == -1 &&
        errno == ENOTSOCK);
    errno = 0;
    CHECK(ker_socket_client_member_census_create(&client, census_group, 2) == -1 &&
        errno == EINVAL);
    errno = 0;
    CHECK(ker_socket_client_member_census_snapshot(&client, census_member0,
        &invalid_snapshot) == -1 && errno == ENOTSOCK);
    uint64_t census_cookie0 = 0, census_cookie1 = 0;
    socklen_t census_cookie_length = sizeof(uint64_t);
    CHECK(ker_socket_client_getsockopt(&client, census_member0, SOL_SOCKET, SO_COOKIE,
        &census_cookie0, &census_cookie_length) == 0 && census_cookie_length == sizeof(uint64_t));
    census_cookie_length = sizeof(uint64_t);
    CHECK(ker_socket_client_getsockopt(&client, census_member1, SOL_SOCKET, SO_COOKIE,
        &census_cookie1, &census_cookie_length) == 0 && census_cookie_length == sizeof(uint64_t));
    CHECK(census_cookie0 && census_cookie1 && census_cookie0 != census_cookie1);
    CHECK(snapshot_live_member(&client, census0, census_member0, census_cookie0) == 0);
    CHECK(snapshot_live_member(&client, census1, census_member1, census_cookie1) == 0);
    CHECK(snapshot_live_member(&client, census0, census_member0, census_cookie0) == 0);
    CHECK(snapshot_live_member(&client, census1, census_member1, census_cookie1) == 0);
    CHECK(exec_inherited_group_probe(argv[1], argv[3], argv[4], census0, false,
        "census") == 0);
    CHECK(exec_inherited_group_probe(argv[1], argv[3], argv[4], census1, true,
        "census") == 0);
    CHECK(close(census_member0) == 0 && close(census_member1) == 0 &&
        close(census_group) == 0);
    bool census_empty = false;
    struct timespec census_pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (unsigned attempt = 0; attempt < 5000; ++attempt) {
        struct ker_socket_member_census_snapshot first_snapshot = {0};
        struct ker_socket_member_census_snapshot second_snapshot = {0};
        CHECK(ker_socket_client_member_census_snapshot(&client, census0,
            &first_snapshot) == 0);
        CHECK(ker_socket_client_member_census_snapshot(&client, census1,
            &second_snapshot) == 0);
        CHECK(first_snapshot.listener_cookie == census_cookie0 &&
            second_snapshot.listener_cookie == census_cookie1);
        CHECK((first_snapshot.total == 0 &&
                first_snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 0) ||
            (first_snapshot.total == 1 &&
                first_snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1));
        CHECK((second_snapshot.total == 0 &&
                second_snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 0) ||
            (second_snapshot.total == 1 &&
                second_snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1));
        if (first_snapshot.total == 0 && second_snapshot.total == 0) {
            census_empty = true;
            break;
        }
        (void)nanosleep(&census_pause, NULL);
    }
    CHECK(census_empty);
    CHECK(close(census0) == 0 && close(census1) == 0);
    puts("CENSUS_LIFETIME_OK"); fflush(stdout);

    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4097)};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) == 1);
    struct sockaddr_in occupied = address; occupied.sin_port = htons(4096);
    int prebound = ker_socket_client_socket(&client, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(prebound >= 0);
    CHECK(ker_socket_client_bind(&client, prebound, (struct sockaddr *)&occupied, sizeof(occupied)) == 0);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_create(&client, &occupied, 8) == -1 && errno == EADDRINUSE);
    CHECK(close(prebound) == 0);
    int group = ker_socket_client_reuseport_group_create(&client, &address, 16);
    CHECK(group >= 0);
    CHECK(exec_inherited_group_probe(argv[1], argv[3], argv[4], group, false, "group") == 0);
    CHECK(ker_socket_client_describe(&client, group, &kind, &flags) == 0 &&
        kind == KER_SOCKET_BROKER_REUSEPORT_GROUP && flags == 0);
    CHECK(exec_inherited_group_probe(argv[1], argv[3], argv[4], group, true, "group") == 0);
    CHECK(ker_socket_client_describe(&client, group, &kind, &flags) == 0 &&
        kind == KER_SOCKET_BROKER_REUSEPORT_GROUP && flags == 0);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_create(&client, &address, 16) == -1 && errno == EADDRINUSE);
    int descriptor_flags = fcntl(group, F_GETFD);
    CHECK(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC));
    CHECK(ker_socket_client_describe(&client, group, &kind, &flags) == 0);
    CHECK(kind == KER_SOCKET_BROKER_REUSEPORT_GROUP && flags == 0);
    int group_alias = dup(group);
    CHECK(group_alias >= 0);
    descriptor_flags = fcntl(group_alias, F_GETFD);
    CHECK(descriptor_flags >= 0 && !(descriptor_flags & FD_CLOEXEC));
    CHECK(close(group) == 0);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_select(&client, group_alias, 2) == -1 && errno == EINVAL);
    struct sockaddr_in other_address = address; other_address.sin_port = htons(4099);
    int other_group = ker_socket_client_reuseport_group_create(&client, &other_address, 8);
    CHECK(other_group >= 0);
    CHECK(ker_socket_client_reuseport_group_select(&client, other_group, 1) == 0);
    CHECK(ker_socket_client_reuseport_group_select(&client, group_alias, 0) == 0);

    int enabled = 1;
    int ordinary = ker_socket_client_socket(&client, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(ordinary >= 0);
    struct sock_fprog arbitrary_filter = {.len = 1,
        .filter = (struct sock_filter *)(uintptr_t)1};
    errno = 0;
    CHECK(ker_socket_client_setsockopt(&client, ordinary, SOL_SOCKET,
        SO_ATTACH_REUSEPORT_CBPF, &arbitrary_filter, sizeof(arbitrary_filter)) == -1 &&
        errno == EOPNOTSUPP);
    errno = 0;
    CHECK(ker_socket_client_bind(&client, ordinary, (struct sockaddr *)&address, sizeof(address)) == -1 && errno == EADDRINUSE);
    enabled = 1;
    CHECK(ker_socket_client_setsockopt(&client, ordinary, SOL_SOCKET, SO_REUSEPORT,
        &enabled, sizeof(enabled)) == 0);
    errno = 0;
    CHECK(ker_socket_client_listen(&client, ordinary, 8) == -1 && errno == EOPNOTSUPP);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_select(&client, ordinary, 1) == -1 && errno == ENOTSOCK);
    int hostpipe[2]; CHECK(pipe2(hostpipe, O_CLOEXEC | O_NONBLOCK) == 0);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_select(&client, hostpipe[1], 1) == -1 && errno == EBADF);
    close(hostpipe[0]); close(hostpipe[1]);
    int member0 = ker_socket_client_reuseport_group_member(&client, group_alias, 0);
    int member1 = ker_socket_client_reuseport_group_member(&client, group_alias, 1);
    CHECK(member0 >= 0 && member1 >= 0);
    int member0_flags = fcntl(member0, F_GETFD), member1_flags = fcntl(member1, F_GETFD);
    CHECK(member0_flags >= 0 && member1_flags >= 0 &&
        (member0_flags & FD_CLOEXEC) && (member1_flags & FD_CLOEXEC));
    int member0_alias = ker_socket_client_dup(&client, member0);
    CHECK(member0_alias >= 0);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_select(&client, member1, 0) == -1 && errno == ENOTSOCK);
    errno = 0;
    CHECK(ker_socket_client_reuseport_group_member(&client, member0, 1) == -1 && errno == ENOTSOCK);
    errno = 0;
    CHECK(ker_socket_client_listen(&client, member0_alias, 8) == -1 && errno == EOPNOTSUPP);
    errno = 0;
    CHECK(ker_socket_client_bind(&client, member0, (struct sockaddr *)&address, sizeof(address)) == -1 && errno == EOPNOTSUPP);
    errno = 0;
    CHECK(ker_socket_client_listen(&client, member1, 16) == -1 && errno == EOPNOTSUPP);
    errno = 0;
    CHECK(ker_socket_client_setsockopt(&client, member0, SOL_SOCKET, SO_REUSEADDR,
        &enabled, sizeof(enabled)) == -1 && errno == EOPNOTSUPP);
    int reuseport = 0; socklen_t reuseport_length = sizeof(reuseport);
    CHECK(ker_socket_client_getsockopt(&client, member0, SOL_SOCKET, SO_REUSEPORT,
        &reuseport, &reuseport_length) == 0 && reuseport_length == sizeof(reuseport) && reuseport == 1);
    errno = 0;
    CHECK(ker_socket_client_shutdown(&client, member1, SHUT_RDWR) == -1 && errno == EOPNOTSUPP);
    int epoll = ker_socket_client_epoll_create1(&client, EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event event0 = {.events = EPOLLIN, .data.u64 = UINT64_C(0x771100)};
    struct epoll_event event1 = {.events = EPOLLIN, .data.u64 = UINT64_C(0x771101)};
    CHECK(ker_socket_client_epoll_ctl(&client, epoll, EPOLL_CTL_ADD, member0, &event0) == 0);
    CHECK(ker_socket_client_epoll_ctl(&client, epoll, EPOLL_CTL_ADD, member1, &event1) == 0);
    CHECK(close(denied_group) == 0);

    CHECK(ker_socket_client_reuseport_group_select(&client, group_alias, 0) == 0);
    puts("GROUP_READY_0"); fflush(stdout);
    CHECK(wait_token(&client, epoll, UINT64_C(0x771100), UINT64_C(0x771101)) == 0);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, member1, NULL, NULL,
        SOCK_NONBLOCK | SOCK_CLOEXEC) == -1 && errno == EAGAIN);
    int accepted0 = ker_socket_client_accept4(&client, member0, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(accepted0 >= 0);
    char first[32] = {0};
    CHECK(read_exact(&client, accepted0, first, 8) == 0 && !memcmp(first, "FIRST-00", 8));
    CHECK(write_exact(&client, accepted0, "REPLY-00", 8) == 0);
    puts("ACCEPTED_0"); fflush(stdout);

    CHECK(ker_socket_client_reuseport_group_select(&client, group_alias, 1) == 0);
    puts("GROUP_READY_1"); fflush(stdout);
    CHECK(wait_token(&client, epoll, UINT64_C(0x771101), UINT64_C(0x771100)) == 0);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, member0, NULL, NULL,
        SOCK_NONBLOCK | SOCK_CLOEXEC) == -1 && errno == EAGAIN);
    int accepted1 = ker_socket_client_accept4(&client, member1, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(accepted1 >= 0);
    char second[32] = {0};
    CHECK(read_exact(&client, accepted1, second, 8) == 0 && !memcmp(second, "SECOND-1", 8));
    CHECK(write_exact(&client, accepted1, "REPLY-01", 8) == 0);
    CHECK(read_exact(&client, accepted0, first, 8) == 0 && !memcmp(first, "FLIP-000", 8));
    CHECK(write_exact(&client, accepted0, "FLIP-ACK", 8) == 0);
    puts("ACCEPTED_1_AND_PRIOR_STREAM_OK"); fflush(stdout);

    CHECK(ker_socket_client_reuseport_group_select(&client, group_alias, 0) == 0);
    puts("GROUP_READY_0_AGAIN"); fflush(stdout);
    CHECK(wait_token(&client, epoll, UINT64_C(0x771100), UINT64_C(0x771101)) == 0);
    errno = 0;
    CHECK(ker_socket_client_accept4(&client, member1, NULL, NULL,
        SOCK_NONBLOCK | SOCK_CLOEXEC) == -1 && errno == EAGAIN);
    int accepted2 = ker_socket_client_accept4(&client, member0, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(accepted2 >= 0);
    char third[32] = {0};
    CHECK(read_exact(&client, accepted2, third, 8) == 0 && !memcmp(third, "THIRD-00", 8));
    CHECK(write_exact(&client, accepted2, "REPLY-02", 8) == 0);
    CHECK(ker_socket_client_reuseport_group_select(&client, group_alias, 1) == 0);
    CHECK(ker_socket_client_reuseport_group_select(&client, group_alias, 0) == 0);

    CHECK(close(member0) == 0); CHECK(close(member1) == 0); CHECK(close(group_alias) == 0);
    CHECK(close(member0_alias) == 0);
    CHECK(close(other_group) == 0);
    puts("ALL_GROUP_HANDLES_CLOSED"); fflush(stdout);
    CHECK(write_exact(&client, accepted0, "AFTER-CLOSE", 11) == 0);
    puts("ACCEPTED_STREAM_AFTER_LISTENER_CLOSE"); fflush(stdout);
    CHECK(read_exact(&client, accepted0, first, 12) == 0 && !memcmp(first, "CLOSE-REPLY!", 12));
    CHECK(close(accepted0) == 0); CHECK(close(accepted1) == 0); CHECK(close(accepted2) == 0);
    CHECK(close(epoll) == 0); CHECK(close(ordinary) == 0);
    ker_socket_client_close(&client);
    puts("GROUP_CLIENT_DONE"); fflush(stdout);
    return 0;
}
