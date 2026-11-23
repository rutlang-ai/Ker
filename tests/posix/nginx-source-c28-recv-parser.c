#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <stdlib.h>

/* Keep the real historical client archive linkable for the rest of this
 * source fixture, but make every broker entrypoint reachable from
 * source_c28_command_loop() fail closed. This test exercises only the
 * authenticated CLOSE receive/reply path; any accidental native broker call
 * is a fixture failure. */
static int source_fixture_forbid_owner_group_control(
    struct ker_socket_client *, int);
static int source_fixture_forbid_cutover_begin(struct ker_socket_client *, int);
static int source_fixture_forbid_census_create(struct ker_socket_client *, int,
    unsigned);
static int source_fixture_forbid_cutover_poll(struct ker_socket_client *, int,
    struct ker_socket_group_cutover_status *);
static int source_fixture_forbid_cutover_commit_before(
    struct ker_socket_client *, int, uint64_t);
static int source_fixture_forbid_census_snapshot(struct ker_socket_client *, int,
    struct ker_socket_member_census_snapshot *);
static int source_fixture_forbid_cutover_abort(struct ker_socket_client *, int);
static int source_fixture_forbid_cutover_abort_before(
    struct ker_socket_client *, int, uint64_t);
static int source_fixture_forbid_retry_plan(struct ker_socket_client *, int);
static int source_fixture_forbid_retire_initial_listener(
    struct ker_socket_client *, int);

#define ker_socket_client_owner_group_control source_fixture_forbid_owner_group_control
#define ker_socket_client_owner_group_cutover_begin source_fixture_forbid_cutover_begin
#define ker_socket_client_member_census_create source_fixture_forbid_census_create
#define ker_socket_client_owner_group_cutover_poll source_fixture_forbid_cutover_poll
#define ker_socket_client_owner_group_cutover_commit_before source_fixture_forbid_cutover_commit_before
#define ker_socket_client_member_census_snapshot source_fixture_forbid_census_snapshot
#define ker_socket_client_owner_group_cutover_abort source_fixture_forbid_cutover_abort
#define ker_socket_client_owner_group_cutover_abort_before source_fixture_forbid_cutover_abort_before
#define ker_socket_client_owner_group_retry_plan source_fixture_forbid_retry_plan
#define ker_socket_client_owner_group_retire_initial_listener source_fixture_forbid_retire_initial_listener
#define main source_c22_helper_entrypoint
#include "nginx-owner-group-controller.c"
#undef main
#undef ker_socket_client_owner_group_control
#undef ker_socket_client_owner_group_cutover_begin
#undef ker_socket_client_member_census_create
#undef ker_socket_client_owner_group_cutover_poll
#undef ker_socket_client_owner_group_cutover_commit_before
#undef ker_socket_client_member_census_snapshot
#undef ker_socket_client_owner_group_cutover_abort
#undef ker_socket_client_owner_group_cutover_abort_before
#undef ker_socket_client_owner_group_retry_plan
#undef ker_socket_client_owner_group_retire_initial_listener

#include <dirent.h>
#include <sys/syscall.h>

static int source_fixture_forbid_native_broker_call(void)
{
    abort();
}

static int source_fixture_forbid_owner_group_control(
    struct ker_socket_client *client, int plan)
{
    (void)client; (void)plan;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_cutover_begin(struct ker_socket_client *client,
    int plan)
{
    (void)client; (void)plan;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_census_create(struct ker_socket_client *client,
    int group, unsigned index)
{
    (void)client; (void)group; (void)index;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_cutover_poll(struct ker_socket_client *client,
    int cutover, struct ker_socket_group_cutover_status *status)
{
    (void)client; (void)cutover; (void)status;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_cutover_commit_before(
    struct ker_socket_client *client, int cutover, uint64_t deadline_ns)
{
    (void)client; (void)cutover; (void)deadline_ns;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_census_snapshot(struct ker_socket_client *client,
    int census, struct ker_socket_member_census_snapshot *snapshot)
{
    (void)client; (void)census; (void)snapshot;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_cutover_abort(struct ker_socket_client *client,
    int cutover)
{
    (void)client; (void)cutover;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_cutover_abort_before(
    struct ker_socket_client *client, int cutover, uint64_t deadline_ns)
{
    (void)client; (void)cutover; (void)deadline_ns;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_retry_plan(struct ker_socket_client *client, int plan)
{
    (void)client; (void)plan;
    return source_fixture_forbid_native_broker_call();
}

static int source_fixture_forbid_retire_initial_listener(
    struct ker_socket_client *client, int plan)
{
    (void)client; (void)plan;
    return source_fixture_forbid_native_broker_call();
}

static int descriptor_open(int fd)
{
    errno = 0;
    return fcntl(fd, F_GETFD) >= 0 || errno != EBADF;
}

static int send_packet(int sender, const void *bytes, size_t length,
    const int *rights, size_t right_count)
{
    struct iovec iov = {.iov_base = (void *)bytes, .iov_len = length};
    char control[CMSG_SPACE(sizeof(int) * 8)] = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (right_count) {
        message.msg_control = control;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * right_count);
        struct cmsghdr *c = CMSG_FIRSTHDR(&message);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * right_count);
        memcpy(CMSG_DATA(c), rights, sizeof(int) * right_count);
    }
    return sendmsg(sender, &message, MSG_NOSIGNAL) == (ssize_t)length ? 0 : -1;
}

static int receive_and_parse(int receiver, size_t control_bytes,
    uint8_t request[SOURCE_C28_REQUEST_BYTES], int mutate_flags,
    ssize_t *received, int *actual_flags, int *delivered, size_t delivered_count,
    size_t *actual_delivered_count,
    struct source_c28_received_credentials *credentials)
{
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 8)] = {0};
    struct iovec iov = {.iov_base = request, .iov_len = SOURCE_C28_REQUEST_BYTES};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = control_bytes};
    *received = recvmsg(receiver, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (*received < 0) return -1;
    *actual_flags = message.msg_flags;
    size_t n = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c;
            c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
                c->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes = c->cmsg_len - CMSG_LEN(0);
            int *fds = (int *)CMSG_DATA(c);
            for (size_t i = 0; i + sizeof(int) <= bytes && n < delivered_count;
                    i += sizeof(int)) delivered[n++] = fds[i / sizeof(int)];
        }
    }
    *actual_delivered_count = n;
    if (mutate_flags) message.msg_flags |= mutate_flags;
    return source_c28_parse_received(*received, &message, request, credentials);
}

static int expect_rights_closed(const int *fds, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (descriptor_open(fds[i])) return -1;
    return 0;
}

static int setup_pair(int pair[2])
{
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) return -1;
    int passcred = 1;
    if (setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred))) return -1;
    return 0;
}

static uint64_t self_start_ticks(void)
{
    FILE *file = fopen("/proc/self/stat", "re");
    if (!file) return 0;
    char line[4096];
    size_t length = fread(line, 1, sizeof(line) - 1, file);
    int failed = ferror(file);
    fclose(file);
    if (failed || !length) return 0;
    line[length] = '\0';
    char *field = strrchr(line, ')');
    if (!field) return 0;
    field += 2;
    for (unsigned index = 0; index < 19; ++index) {
        field = strchr(field, ' ');
        if (!field) return 0;
        while (*field == ' ') ++field;
    }
    char *end = NULL;
    unsigned long long value = strtoull(field, &end, 10);
    return end != field ? (uint64_t)value : 0;
}

static void build_valid_request(uint8_t request[SOURCE_C28_REQUEST_BYTES],
    uint64_t deadline)
{
    memset(request, 0, SOURCE_C28_REQUEST_BYTES);
    memcpy(request, SOURCE_C28_MAGIC, 8);
    request[8] = SOURCE_C28_VERSION;
    request[10] = SOURCE_C28_PARK;
    source_put_le32(request + 12, SOURCE_C28_REQUEST_BYTES);
    source_put_le64(request + 16, 1);
    source_put_le64(request + 24, deadline);
}

static int test_valid_cloexec_echo(void)
{
    int pair[2];
    if (setup_pair(pair)) return -1;
    uint8_t sent[SOURCE_C28_REQUEST_BYTES], received[SOURCE_C28_REQUEST_BYTES] = {0};
    build_valid_request(sent, now_ns() + UINT64_C(50000000));
    if (send_packet(pair[0], sent, sizeof(sent), NULL, 0)) return -1;
    ssize_t length;
    int rights[1];
    int flags = 0;
    size_t delivered_count = 0;
    struct source_c28_received_credentials credentials;
    int result = receive_and_parse(pair[1], CMSG_SPACE(sizeof(struct ucred)),
        received, 0, &length, &flags, rights, 0, &delivered_count, &credentials);
    int valid_credentials = credentials.count == 1 && !credentials.unexpected &&
        credentials.value.pid == getpid() && credentials.value.uid == getuid() &&
        credentials.value.gid == getgid();
    if (result || length != SOURCE_C28_REQUEST_BYTES ||
            memcmp(sent, received, sizeof(sent)) || !valid_credentials ||
            !(flags & MSG_CMSG_CLOEXEC)) return -1;
    close(pair[0]); close(pair[1]);
    return 0;
}

static int test_expired_request_deadline(void)
{
    int pair[2], pipe_fds[2], delivered[1] = {-1};
    if (setup_pair(pair)) return -1;
    if (pipe2(pipe_fds, O_CLOEXEC)) return -1;
    uint8_t sent[SOURCE_C28_REQUEST_BYTES], received[SOURCE_C28_REQUEST_BYTES] = {0};
    build_valid_request(sent, now_ns() - 1);
    if (send_packet(pair[0], sent, sizeof(sent), &pipe_fds[0], 1)) return -1;
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = {.iov_base = received, .iov_len = sizeof(received)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t count = recvmsg(pair[1], &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c;
            c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
                c->cmsg_len >= CMSG_LEN(sizeof(int)))
            memcpy(delivered, CMSG_DATA(c), sizeof(int));
    }
    struct source_c28_received_credentials credentials;
    int parsed = source_c28_parse_received(count, &message, received, &credentials);
    int expired = !source_c28_request_deadline_valid(received,
        now_ns() + UINT64_C(1000000000), now_ns());
    int rights_closed = delivered[0] >= 0 && !descriptor_open(delivered[0]);
    close(pipe_fds[0]); close(pipe_fds[1]); close(pair[0]); close(pair[1]);
    return parsed < 0 && expired && rights_closed ? 0 : -1;
}

static int test_envelope_controls(void)
{
    int pair[2], pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0 || setup_pair(pair)) return -1;
    struct source_provider_record bundle = {0};
    uint8_t sent[SOURCE_C28_REQUEST_BYTES], received[SOURCE_C28_REQUEST_BYTES] = {0};
    uint64_t start = self_start_ticks(), deadline = now_ns() + UINT64_C(50000000);
    build_valid_request(sent, deadline);
    memcpy(sent + SOURCE_C28_HEADER_BYTES, &bundle, sizeof(bundle));
    if (!start || send_packet(pair[0], sent, sizeof(sent), NULL, 0)) return -1;
    char control[CMSG_SPACE(sizeof(struct ucred))] = {0};
    struct iovec iov = {.iov_base = received, .iov_len = sizeof(received)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t count = recvmsg(pair[1], &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    struct source_c28_received_credentials credentials;
    int status = source_c28_parse_received(count, &message, received, &credentials);
    int valid = status == 0 && !source_c28_validate_request(received, &bundle,
        &credentials, pidfd, getpid(), start, 1, deadline, now_ns(), false, false);
    struct source_c28_received_credentials wrong = credentials;
    wrong.value.pid++;
    int wrong_pid = source_c28_validate_request(received, &bundle, &wrong,
        pidfd, getpid(), start, 1, deadline, now_ns(), false, false) == EACCES;
    int wrong_sequence = source_c28_validate_request(received, &bundle, &credentials,
        pidfd, getpid(), start, 2, deadline, now_ns(), false, false) == EALREADY;
    struct source_provider_record different = {0};
    different.backlog = 1;
    int wrong_bundle = source_c28_validate_request(received, &different, &credentials,
        pidfd, getpid(), start, 1, deadline, now_ns(), false, false) == EPROTO;
    int late = source_c28_validate_request(received, &bundle, &credentials,
        pidfd, getpid(), start, 1, deadline, deadline, false, false) == ETIMEDOUT;
    uint8_t invalid[SOURCE_C28_REQUEST_BYTES];
    memcpy(invalid, received, sizeof(invalid));
    invalid[8]++;
    int wrong_version = source_c28_validate_request(invalid, &bundle, &credentials,
        pidfd, getpid(), start, 1, deadline, now_ns(), false, false) == EPROTO;
    memcpy(invalid, received, sizeof(invalid));
    invalid[10] = 99;
    int wrong_operation = source_c28_validate_request(invalid, &bundle, &credentials,
        pidfd, getpid(), start, 1, deadline, now_ns(), false, false) == EOPNOTSUPP;
    invalid[10] = SOURCE_C28_RETRY_SLOT;
    int retry_opt_in = source_c28_validate_request(invalid, &bundle, &credentials,
        pidfd, getpid(), start, 1, deadline, now_ns(), false, false) == EOPNOTSUPP &&
        !source_c28_validate_request(invalid, &bundle, &credentials,
            pidfd, getpid(), start, 1, deadline, now_ns(), true, false);
    close(pidfd); close(pair[0]); close(pair[1]);
    return valid && wrong_pid && wrong_sequence && wrong_bundle && late &&
        wrong_version && wrong_operation && retry_opt_in ? 0 : -1;
}

static int test_idle_grant_expiry(void)
{
    int pair[2], pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0 || setup_pair(pair)) return -1;
    uint64_t start = self_start_ticks();
    int result = source_c28_wait_request(pair[1], pidfd, getpid(), start,
        now_ns() + UINT64_C(5000000));
    int expired = result < 0 && errno == ETIMEDOUT;
    close(pidfd); close(pair[0]); close(pair[1]);
    return expired ? 0 : -1;
}

static int test_authenticated_close_echo_only(void)
{
    int pair[2], pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0 || setup_pair(pair)) return -1;
    int passcred = 1;
    if (setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred))) return -1;
    uint64_t start = self_start_ticks();
    struct source_provider_record bundle = {0};
    uint8_t request[SOURCE_C28_REQUEST_BYTES];
    uint64_t deadline = now_ns() + UINT64_C(1000000000);
    build_valid_request(request, deadline);
    request[10] = SOURCE_C28_CLOSE;
    memcpy(request + SOURCE_C28_HEADER_BYTES, &bundle, sizeof(bundle));
    if (!start || send_packet(pair[0], request, sizeof(request), NULL, 0)) return -1;
    struct ker_socket_client client = {0};
    int loop_result = source_c28_command_loop(pair[1], &client, -1, -1, -1,
        &bundle, pidfd, getpid(), start, deadline, false);
    uint8_t reply[SOURCE_C28_REPLY_BYTES] = {0};
    char control[CMSG_SPACE(sizeof(struct ucred))] = {0};
    struct iovec iov = {.iov_base = reply, .iov_len = sizeof(reply)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t received = recvmsg(pair[0], &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    size_t cred_count = 0;
    struct ucred cred = {0};
    int unexpected = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c;
            c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
                c->cmsg_len == CMSG_LEN(sizeof(cred))) {
            memcpy(&cred, CMSG_DATA(c), sizeof(cred));
            ++cred_count;
        } else unexpected = 1;
    }
    int valid = loop_result == 0 && received == SOURCE_C28_REPLY_BYTES &&
        !memcmp(reply, request, sizeof(request)) && (int32_t)source_get_le32(
            reply + SOURCE_C28_REQUEST_BYTES) == 0 && cred_count == 1 && !unexpected &&
        cred.pid == getpid() && cred.uid == getuid() && cred.gid == getgid() &&
        !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
        !(message.msg_flags & ~MSG_CMSG_CLOEXEC);
    close(pidfd); close(pair[0]); close(pair[1]);
    return valid ? 0 : -1;
}

static int test_rights_closed(size_t payload_length, size_t control_bytes,
    int mutate_flags, size_t send_right_count, size_t expected_count,
    int expected_output_flags)
{
    int pair[2], pipes[8][2], send_fds[8], received_fds[8] = {-1};
    if (setup_pair(pair)) return -1;
    for (size_t i = 0; i < send_right_count; ++i) {
        if (pipe2(pipes[i], O_CLOEXEC)) return -1;
        send_fds[i] = pipes[i][0];
    }
    uint8_t sent[SOURCE_C28_REQUEST_BYTES] = {0}, received[SOURCE_C28_REQUEST_BYTES] = {0};
    if (payload_length == sizeof(sent)) memcpy(sent, SOURCE_C28_MAGIC, 8);
    if (send_packet(pair[0], sent, payload_length, send_fds, send_right_count)) return -1;
    ssize_t length;
    int actual_flags = 0;
    size_t actual_count = 0;
    int result = receive_and_parse(pair[1], control_bytes, received, mutate_flags,
        &length, &actual_flags, received_fds, expected_count,
        &actual_count, &(struct source_c28_received_credentials){0});
    int closed = expect_rights_closed(received_fds, expected_count);
    for (size_t i = 0; i < send_right_count; ++i) { close(pipes[i][0]); close(pipes[i][1]); }
    close(pair[0]); close(pair[1]);
    return result < 0 && closed == 0 && actual_count == expected_count &&
        (actual_flags & expected_output_flags) == expected_output_flags ? 0 : -1;
}

int main(void)
{
    CHECK(test_valid_cloexec_echo() == 0);
    CHECK(test_expired_request_deadline() == 0);
    CHECK(test_envelope_controls() == 0);
    CHECK(test_idle_grant_expiry() == 0);
    CHECK(test_authenticated_close_echo_only() == 0);
    CHECK(test_rights_closed(7, CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int)),
        0, 1, 1, 0) == 0);
    CHECK(test_rights_closed(0, CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int)),
        0, 1, 1, 0) == 0);
    CHECK(test_rights_closed(SOURCE_C28_REQUEST_BYTES,
        CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int)),
        0, 3, 1, MSG_CTRUNC) == 0);
    CHECK(test_rights_closed(SOURCE_C28_REQUEST_BYTES,
        CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int)),
        MSG_EOR, 1, 1, 0) == 0);
    return 0;
}
