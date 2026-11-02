#define _GNU_SOURCE
#include "runtime-service-client.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void ker_runtime_service_client_test_configure(uint64_t timeout_ns,
    unsigned post_receive_delay_ms);

static const uint8_t nonce[KER_RUNTIME_SERVICE_NONCE_BYTES] = {
    0x31, 0x11, 0x22, 0x45, 0xa6, 0xb7, 0xc8, 0xd9,
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87
};
static const uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};
static const uint8_t role_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES] = {
    0x91, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};
static const uint8_t lease_id[KER_RUNTIME_SERVICE_LEASE_BYTES] = {
    0xa1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};
static const uint8_t worker_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
};
static int server_error;
static int wrong_profile_case;
static int late_delegation_case;
static char server_path[KER_RUNTIME_SERVICE_PATH_MAX + 1];
static int server_listener = -1;

static int server_fail(int error)
{
    server_error = error;
    return -1;
}

static int receive_one(int fd, uint8_t *packet, size_t capacity, size_t expected)
{
    struct iovec iov = {.iov_base = packet, .iov_len = capacity};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    ssize_t size = recvmsg(fd, &message, MSG_TRUNC);
    if (size < 0) return -1;
    if ((size_t)size != expected || (message.msg_flags & MSG_TRUNC)) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int send_header(int fd, uint16_t operation, uint64_t sequence,
    const uint8_t response_lease[KER_RUNTIME_SERVICE_LEASE_BYTES],
    const uint8_t *body, size_t body_length)
{
    struct ker_runtime_service_header header = {0};
    header.magic = KER_RUNTIME_SERVICE_MAGIC;
    header.version = KER_RUNTIME_SERVICE_VERSION;
    header.operation = operation;
    header.packet_length = (uint32_t)(sizeof(header) + body_length);
    header.sequence = sequence;
    header.service_epoch = 9;
    memcpy(header.run_nonce, nonce, sizeof(nonce));
    if (response_lease) memcpy(header.lease_id, response_lease, sizeof(header.lease_id));
    struct iovec iov[2] = {
        {.iov_base = &header, .iov_len = sizeof(header)},
        {.iov_base = (void *)body, .iov_len = body_length}
    };
    struct msghdr message = {.msg_iov = iov, .msg_iovlen = body_length ? 2u : 1u};
    ssize_t expected = (ssize_t)(sizeof(header) + body_length);
    return sendmsg(fd, &message, MSG_NOSIGNAL) == expected ? 0 : -1;
}

static int send_header_with_fd(int fd, uint16_t operation, uint64_t sequence,
    const uint8_t response_lease[KER_RUNTIME_SERVICE_LEASE_BYTES], int passed_fd)
{
    struct ker_runtime_service_header header = {0};
    header.magic = KER_RUNTIME_SERVICE_MAGIC;
    header.version = KER_RUNTIME_SERVICE_VERSION;
    header.operation = operation;
    header.packet_length = sizeof(header);
    header.sequence = sequence;
    header.service_epoch = 9;
    memcpy(header.run_nonce, nonce, sizeof(nonce));
    if (response_lease) memcpy(header.lease_id, response_lease, sizeof(header.lease_id));
    struct iovec iov = {.iov_base = &header, .iov_len = sizeof(header)};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));
    return sendmsg(fd, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(header) ? 0 : -1;
}

static int accept_one(int listener)
{
    int fd;
    do { fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); }
    while (fd < 0 && errno == EINTR);
    return fd;
}

static void *service_thread(void *unused)
{
    (void)unused;
    uint8_t packet[sizeof(struct ker_runtime_service_header) +
        sizeof(struct ker_runtime_service_claim)];
    int fd = accept_one(server_listener);
    if (fd < 0) { server_fail(errno); return NULL; }
    if (receive_one(fd, packet, sizeof(packet), sizeof(packet))) goto fail;
    struct ker_runtime_service_header request;
    memcpy(&request, packet, sizeof(request));
    struct ker_runtime_service_claim claim;
    memcpy(&claim, packet + sizeof(request), sizeof(claim));
    if (request.magic != KER_RUNTIME_SERVICE_MAGIC ||
        request.version != KER_RUNTIME_SERVICE_VERSION ||
        request.operation != KER_RUNTIME_SERVICE_CLAIM || request.sequence != 1 ||
        request.service_epoch != 9 || request.status ||
        memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
        memcmp(claim.ticket, ticket, sizeof(ticket)) ||
        memcmp(claim.profile_hash, role_hash, sizeof(role_hash)) ||
        memcmp(request.lease_id, (uint8_t[KER_RUNTIME_SERVICE_LEASE_BYTES]){0},
            KER_RUNTIME_SERVICE_LEASE_BYTES)) {
        errno = EPROTO; goto fail;
    }
    if (send_header(fd, KER_RUNTIME_SERVICE_CLAIM, 1, lease_id,
            worker_profile_hash, sizeof(worker_profile_hash))) goto fail;
    if (receive_one(fd, packet, sizeof(packet), sizeof(struct ker_runtime_service_header)))
        goto fail;
    memcpy(&request, packet, sizeof(request));
    if (wrong_profile_case) {
        if (request.operation != KER_RUNTIME_SERVICE_RELEASE || request.sequence != 2 ||
            request.status || request.service_epoch != 9 ||
            memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
            memcmp(request.lease_id, lease_id, sizeof(lease_id))) {
            errno = EPROTO; goto fail;
        }
        /* Simulate a release whose request reached the supervisor but whose
         * reply was lost. The client must reconnect cleanup-only and never
         * promote this wrong-profile lease through CHECK. */
        close(fd);
        fd = accept_one(server_listener);
        if (fd < 0) { server_fail(errno); return NULL; }
        if (receive_one(fd, packet, sizeof(packet), sizeof(struct ker_runtime_service_header)))
            goto fail;
        memcpy(&request, packet, sizeof(request));
        if (request.operation != KER_RUNTIME_SERVICE_RELEASE || request.sequence != 1 ||
            request.status || request.service_epoch != 9 ||
            memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
            memcmp(request.lease_id, lease_id, sizeof(lease_id))) {
            errno = EPROTO; goto fail;
        }
        if (send_header(fd, KER_RUNTIME_SERVICE_RELEASE, 1, lease_id, NULL, 0)) goto fail;
        close(fd);
        return NULL;
    }
    if (request.operation != KER_RUNTIME_SERVICE_CHECK || request.sequence != 2 ||
        request.status || request.service_epoch != 9 ||
        memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
        memcmp(request.lease_id, lease_id, sizeof(lease_id))) {
        errno = EPROTO; goto fail;
    }
    int passed_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (passed_fd < 0) goto fail;
    if (send_header_with_fd(fd, KER_RUNTIME_SERVICE_CHECK, 2, lease_id, passed_fd)) {
        close(passed_fd); goto fail;
    }
    close(passed_fd);
    close(fd);

    fd = accept_one(server_listener);
    if (fd < 0) { server_fail(errno); return NULL; }
    if (receive_one(fd, packet, sizeof(packet), sizeof(struct ker_runtime_service_header)))
        goto fail;
    memcpy(&request, packet, sizeof(request));
    if (request.operation != KER_RUNTIME_SERVICE_CHECK || request.sequence != 1 ||
        request.status || request.service_epoch != 9 ||
        memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
        memcmp(request.lease_id, lease_id, sizeof(lease_id))) {
        errno = EPROTO; goto fail;
    }
    if (send_header(fd, KER_RUNTIME_SERVICE_CHECK, 1, lease_id, NULL, 0)) goto fail;
    if (receive_one(fd, packet, sizeof(packet), sizeof(struct ker_runtime_service_header)))
        goto fail;
    memcpy(&request, packet, sizeof(request));
    if (request.operation != KER_RUNTIME_SERVICE_RELEASE || request.sequence != 2 ||
        request.status || request.service_epoch != 9 ||
        memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
        memcmp(request.lease_id, lease_id, sizeof(lease_id))) {
        errno = EPROTO; goto fail;
    }
    if (send_header(fd, KER_RUNTIME_SERVICE_RELEASE, 2, lease_id, NULL, 0)) goto fail;
    close(fd);
    return NULL;

fail: {
        int error = errno;
        close(fd);
        server_fail(error);
        return NULL;
    }
}

static int receive_bind_with_pidfd(int fd, uint8_t *packet, size_t capacity,
    size_t expected)
{
    struct iovec iov = {.iov_base = packet, .iov_len = capacity};
    char control[CMSG_SPACE(sizeof(int) * 4)] = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    ssize_t size = recvmsg(fd, &message, MSG_CMSG_CLOEXEC | MSG_TRUNC);
    int received_fd = -1;
    unsigned rights = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
            size_t count = bytes / sizeof(int);
            const int *fds = (const int *)CMSG_DATA(cmsg);
            for (size_t i = 0; i < count; ++i) {
                ++rights;
                if (received_fd < 0) received_fd = fds[i];
                else (void)close(fds[i]);
            }
        }
    }
    if (size < 0) return -1;
    if ((size_t)size != expected || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        rights != 1) {
        if (received_fd >= 0) close(received_fd);
        errno = EPROTO;
        return -1;
    }
    close(received_fd);
    return 0;
}

static void *late_delegation_service_thread(void *unused)
{
    (void)unused;
    uint8_t packet[sizeof(struct ker_runtime_service_header) +
        sizeof(struct ker_runtime_service_claim)];
    int fd = accept_one(server_listener);
    if (fd < 0) { server_fail(errno); return NULL; }
    size_t claim_size = sizeof(struct ker_runtime_service_header) +
        sizeof(struct ker_runtime_service_claim);
    if (receive_one(fd, packet, sizeof(packet), claim_size)) goto fail;
    struct ker_runtime_service_header request;
    memcpy(&request, packet, sizeof(request));
    struct ker_runtime_service_claim claim;
    memcpy(&claim, packet + sizeof(request), sizeof(claim));
    if (request.operation != KER_RUNTIME_SERVICE_CLAIM || request.sequence != 1 ||
        request.status || request.service_epoch != 9 ||
        memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
        memcmp(claim.ticket, ticket, sizeof(ticket)) ||
        memcmp(claim.profile_hash, role_hash, sizeof(role_hash))) {
        errno = EPROTO; goto fail;
    }
    if (send_header(fd, KER_RUNTIME_SERVICE_CLAIM, 1, lease_id,
            worker_profile_hash, sizeof(worker_profile_hash))) goto fail;

    size_t intent_size = sizeof(struct ker_runtime_service_header) +
        sizeof(struct ker_runtime_service_delegate_intent);
    if (receive_one(fd, packet, sizeof(packet), intent_size)) goto fail;
    memcpy(&request, packet, sizeof(request));
    struct ker_runtime_service_delegate_intent intent;
    memcpy(&intent, packet + sizeof(request), sizeof(intent));
    if (request.operation != KER_RUNTIME_SERVICE_DELEGATE_INTENT ||
        request.sequence != 2 || request.status || request.service_epoch != 9 ||
        memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
        memcmp(request.lease_id, lease_id, sizeof(lease_id)) ||
        intent.role != KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1 || intent.reserved ||
        !memcmp(intent.request_nonce, (uint8_t[KER_RUNTIME_SERVICE_NONCE_BYTES]){0},
            KER_RUNTIME_SERVICE_NONCE_BYTES)) {
        errno = EPROTO; goto fail;
    }

    if (late_delegation_case == 2) {
        struct ker_runtime_service_delegate_intent_result intent_result = {0};
        memset(intent_result.intent_id, 0x6b, sizeof(intent_result.intent_id));
        if (send_header(fd, KER_RUNTIME_SERVICE_DELEGATE_INTENT, 2, lease_id,
                (const uint8_t *)&intent_result, sizeof(intent_result))) goto fail;
        size_t bind_size = sizeof(struct ker_runtime_service_header) +
            sizeof(struct ker_runtime_service_delegate_bind);
        if (receive_bind_with_pidfd(fd, packet, sizeof(packet), bind_size)) goto fail;
        memcpy(&request, packet, sizeof(request));
        struct ker_runtime_service_delegate_bind bind;
        memcpy(&bind, packet + sizeof(request), sizeof(bind));
        if (request.operation != KER_RUNTIME_SERVICE_DELEGATE_BIND ||
            request.sequence != 3 || request.status || request.service_epoch != 9 ||
            memcmp(request.run_nonce, nonce, sizeof(nonce)) ||
            memcmp(request.lease_id, lease_id, sizeof(lease_id)) ||
            memcmp(bind.intent_id, intent_result.intent_id, sizeof(bind.intent_id))) {
            errno = EPROTO; goto fail;
        }
    }

    struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000000};
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
    if (late_delegation_case == 1) {
        struct ker_runtime_service_delegate_intent_result result = {0};
        memset(result.intent_id, 0x7c, sizeof(result.intent_id));
        if (send_header(fd, KER_RUNTIME_SERVICE_DELEGATE_INTENT, 2, lease_id,
                (const uint8_t *)&result, sizeof(result))) goto fail;
    } else {
        struct ker_runtime_service_delegate_bind_result result = {0};
        memset(result.ticket, 0x9d, sizeof(result.ticket));
        result.role = KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1;
        if (send_header(fd, KER_RUNTIME_SERVICE_DELEGATE_BIND, 3, lease_id,
                (const uint8_t *)&result, sizeof(result))) goto fail;
    }
    /* A timed-out attempt is terminal locally; a second mutation must never
     * reach the supervisor. Give the caller enough time to try and close. */
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    int ready;
    do { ready = poll(&poll_fd, 1, 300); } while (ready < 0 && errno == EINTR);
    if (ready > 0 && (poll_fd.revents & POLLIN)) {
        uint8_t unexpected[128];
        ssize_t count = recv(fd, unexpected, sizeof(unexpected), MSG_DONTWAIT);
        if (count > 0) {
            errno = EPROTO;
            goto fail;
        }
    }
    if (ready < 0) {
        goto fail;
    }
    close(fd);
    return NULL;

fail: {
        int error = errno;
        close(fd);
        server_fail(error);
        return NULL;
    }
}

static int run_late_delegation_client(pid_t supervisor_pid,
    uint64_t supervisor_start,
    const uint8_t supervisor_exe_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES],
    int late_bind)
{
    struct ker_runtime_service_client client;
    ker_runtime_service_client_init(&client);
    ker_runtime_service_client_test_configure(UINT64_C(1000000000), 0);
    if (ker_runtime_service_claim(&client, server_path, nonce, 9, ticket, role_hash,
            worker_profile_hash, supervisor_pid, supervisor_start,
            supervisor_exe_hash)) {
        perror("late delegation claim");
        return 51;
    }
    ker_runtime_service_client_test_configure(UINT64_C(100000000), 0);
    uint8_t intent_id[KER_RUNTIME_SERVICE_INTENT_BYTES] = {0};
    int intent_result = ker_runtime_service_delegate_intent(&client,
        KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1, intent_id);
    if (!late_bind) {
        bool intent_output_clear = true;
        for (size_t i = 0; i < sizeof(intent_id); ++i)
            if (intent_id[i]) intent_output_clear = false;
        if (intent_result == 0 || errno != ETIMEDOUT ||
            !client.delegation_terminal || client.delegation_intent_valid ||
            !intent_output_clear) {
            fprintf(stderr, "late INTENT was not quarantined (errno=%d)\n", errno);
            return 52;
        }
        if (ker_runtime_service_delegate_intent(&client,
                KER_RUNTIME_SERVICE_ROLE_SLIM_STAGE1, intent_id) == 0) {
            fprintf(stderr, "late INTENT allowed another mutation\n");
            return 56;
        }
        struct pollfd late = {.fd = client.fd, .events = POLLIN};
        if (poll(&late, 1, 1000) <= 0 || !(late.revents & POLLIN)) return 57;
        uint8_t discard[sizeof(struct ker_runtime_service_header) +
            sizeof(struct ker_runtime_service_delegate_intent_result)];
        if (recv(client.fd, discard, sizeof(discard), 0) != (ssize_t)sizeof(discard))
            return 58;
    } else {
        if (intent_result) { perror("delegation intent"); return 52; }
        int child_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
        if (child_pidfd < 0) return 53;
        uint8_t bind_ticket[KER_RUNTIME_SERVICE_TICKET_BYTES];
        memset(bind_ticket, 0xa5, sizeof(bind_ticket));
        uint32_t child_role = 99;
        int result = ker_runtime_service_delegate_bind(&client, intent_id,
            child_pidfd, bind_ticket, &child_role);
        close(child_pidfd);
        bool ticket_was_cleared = true;
        for (size_t i = 0; i < sizeof(bind_ticket); ++i)
            if (bind_ticket[i]) ticket_was_cleared = false;
        if (result == 0 || errno != ETIMEDOUT || !client.delegation_terminal ||
            !client.failed || !client.delegation_intent_valid ||
            !ticket_was_cleared || child_role != 0) {
            fprintf(stderr, "late BIND exposed or reused a grant (errno=%d)\n", errno);
            return 54;
        }
        if (ker_runtime_service_delegate_bind(&client, intent_id, -1,
                bind_ticket, &child_role) == 0 || !client.delegation_terminal)
            return 55;
        struct pollfd late = {.fd = client.fd, .events = POLLIN};
        if (poll(&late, 1, 1000) <= 0 || !(late.revents & POLLIN)) return 57;
        uint8_t discard[sizeof(struct ker_runtime_service_header) +
            sizeof(struct ker_runtime_service_delegate_bind_result)];
        if (recv(client.fd, discard, sizeof(discard), 0) != (ssize_t)sizeof(discard))
            return 58;
    }
    ker_runtime_service_client_close(&client);
    return 0;
}

static int check_child_does_not_close_reused_fd(
    const struct ker_runtime_service_client *parent_client)
{
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        struct ker_runtime_service_client copy = *parent_client;
        int inherited = copy.fd;
        if (close(inherited)) _exit(20);
        int reused = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (reused != inherited) _exit(21);
        if (ker_runtime_service_reconnect(&copy) == 0 || errno != ECHILD)
            _exit(22);
        struct stat value;
        if (fstat(reused, &value) || !S_ISCHR(value.st_mode)) _exit(23);
        close(reused);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status)) { errno = ECHILD; return -1; }
    return 0;
}

static int read_start_ticks(pid_t pid, uint64_t *start_ticks)
{
    char path[64], buffer[4096];
    int size = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (size <= 0 || (size_t)size >= sizeof(path)) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    int error = errno;
    close(fd);
    errno = error;
    if (length <= 0) return -1;
    buffer[length] = '\0';
    char *cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ') { errno = EPROTO; return -1; }
    cursor += 2;
    for (unsigned field = 3; field < 22; ++field) {
        cursor = strchr(cursor, ' ');
        if (!cursor) { errno = EPROTO; return -1; }
        ++cursor;
    }
    char *end = NULL;
    unsigned long long value = strtoull(cursor, &end, 10);
    if (end == cursor || (*end != ' ' && *end != '\n' && *end != '\0')) {
        errno = EPROTO;
        return -1;
    }
    *start_ticks = (uint64_t)value;
    return 0;
}

static int executable_sha256(uint8_t digest[KER_RUNTIME_SERVICE_PROFILE_BYTES])
{
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) { close(fd); errno = ENOMEM; return -1; }
    uint8_t buffer[16384];
    unsigned digest_length = 0;
    int result = -1;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (!count) break;
        if (EVP_DigestUpdate(context, buffer, (size_t)count) != 1) goto done;
    }
    if (EVP_DigestFinal_ex(context, digest, &digest_length) == 1 && digest_length == 32)
        result = 0;
done: {
        int error = errno;
        EVP_MD_CTX_free(context);
        close(fd);
        if (result) errno = error ? error : EIO;
        return result;
    }
}

static int open_fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    closedir(directory);
    return count;
}

static int run_client(pid_t supervisor_pid, uint64_t supervisor_start,
    const uint8_t supervisor_exe_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES], int wrong_profile)
{
    struct ker_runtime_service_client client;
    ker_runtime_service_client_init(&client);
    ker_runtime_service_client_test_configure(UINT64_C(1000000000), 1050);
    uint8_t expected_profile[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    memcpy(expected_profile, worker_profile_hash, sizeof(expected_profile));
    if (wrong_profile) expected_profile[0] ^= 0xff;
    if (!ker_runtime_service_claim(&client, server_path, nonce, 9, ticket, role_hash,
            expected_profile, supervisor_pid, supervisor_start,
            supervisor_exe_hash) || errno != (wrong_profile ? EPROTO : ETIMEDOUT) ||
        !client.lease_valid ||
        memcmp(client.lease_id, lease_id, sizeof(lease_id))) {
        fprintf(stderr, "late claim/profile cleanup did not retain lease (errno=%d)\n", errno);
        return 31;
    }
    if (wrong_profile) {
        if (!client.cleanup_only || ker_runtime_service_check(&client) == 0 ||
            errno != EACCES) return 32;
        if (client.fd != -1) return 33;
        if (ker_runtime_service_reconnect(&client)) return 34;
        if (ker_runtime_service_release(&client)) return 35;
        return 0;
    }
    if (memcmp(client.worker_profile_hash, worker_profile_hash,
            sizeof(worker_profile_hash))) return 32;
    if (check_child_does_not_close_reused_fd(&client)) return 33;
    int before_rights_check = open_fd_count();
    if (before_rights_check < 0) return 34;
    if (ker_runtime_service_check(&client) == 0 || errno != EPROTO) return 35;
    int after_rights_check = open_fd_count();
    if (after_rights_check != before_rights_check) {
        fprintf(stderr, "SCM_RIGHTS rejection leaked a descriptor (%d -> %d)\n",
            before_rights_check, after_rights_check);
        return 36;
    }
    int old_fd = client.fd;
    ker_runtime_service_client_close(&client);
    int reused = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (reused != old_fd) return 37;
    if (ker_runtime_service_reconnect(&client)) {
        perror("runtime service reconnect after rights rejection"); return 38;
    }
    struct stat value;
    if (fstat(reused, &value) || !S_ISCHR(value.st_mode)) return 39;
    if (ker_runtime_service_release(&client)) return 40;
    close(reused);
    ker_runtime_service_client_close(&client);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 2)
        return 2;
    if (argc == 2) {
        if (!strcmp(argv[1], "--late-profile-mismatch")) wrong_profile_case = 1;
        else if (!strcmp(argv[1], "--late-delegation-intent")) late_delegation_case = 1;
        else if (!strcmp(argv[1], "--late-delegation-bind")) late_delegation_case = 2;
        else return 2;
    }
    char directory[] = "/dev/shm/ker-runtime-service-client-XXXXXX";
    if (!mkdtemp(directory)) { perror("mkdtemp"); return 1; }
    if (snprintf(server_path, sizeof(server_path), "%s/service", directory) < 0) {
        rmdir(directory); return 1;
    }
    server_listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (server_listener < 0) { perror("socket"); rmdir(directory); return 1; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, server_path, strlen(server_path) + 1);
    if (bind(server_listener, (struct sockaddr *)&address,
            (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(server_path) + 1)) ||
        listen(server_listener, 4)) {
        perror("bind/listen"); close(server_listener); rmdir(directory); return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, late_delegation_case ?
            late_delegation_service_thread : service_thread, NULL)) {
        close(server_listener); rmdir(directory); return 1;
    }
    uint64_t supervisor_start;
    uint8_t supervisor_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    if (read_start_ticks(getpid(), &supervisor_start) ||
        executable_sha256(supervisor_hash)) {
        perror("supervisor identity"); return 1;
    }
    pid_t client_pid = fork();
    if (client_pid < 0) { perror("fork client"); return 1; }
    if (!client_pid) _exit(late_delegation_case ?
        run_late_delegation_client(getppid(), supervisor_start, supervisor_hash,
            late_delegation_case == 2) :
        run_client(getppid(), supervisor_start, supervisor_hash, wrong_profile_case));
    int child_status = 0;
    if (waitpid(client_pid, &child_status, 0) != client_pid ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status)) {
        fprintf(stderr, "client process failed: status=%d\n", child_status);
        return 1;
    }
    pthread_join(thread, NULL);
    close(server_listener);
    if (server_error) { errno = server_error; perror("fake supervisor"); return 1; }
    rmdir(directory);
    return 0;
}
