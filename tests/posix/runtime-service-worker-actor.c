#define _GNU_SOURCE
#include "runtime-service-client.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int parse_u64(const char *name, uint64_t *value)
{
    const char *text = getenv(name);
    if (!text || !*text || !value) { errno = EINVAL; return -1; }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || !end || *end || !parsed) { errno = EINVAL; return -1; }
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_i32(const char *name, int32_t *value)
{
    uint64_t parsed;
    if (parse_u64(name, &parsed) || parsed > INT32_MAX) { errno = EINVAL; return -1; }
    *value = (int32_t)parsed;
    return 0;
}

static int parse_hex(const char *name, uint8_t *output, size_t output_length)
{
    const char *text = getenv(name);
    if (!text || strlen(text) != output_length * 2) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < output_length; ++i) {
        char pair[3] = {text[i * 2], text[i * 2 + 1], '\0'};
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(pair, &end, 16);
        if (errno || !end || *end || value > 255) { errno = EINVAL; return -1; }
        output[i] = (uint8_t)value;
    }
    return 0;
}

static void fail(const char *operation)
{
    fprintf(stderr, "runtime-service worker actor: %s: %s\n", operation,
        strerror(errno));
    exit(2);
}

static int tombstone_request(const char *path, uint64_t epoch,
    const uint8_t nonce[KER_RUNTIME_SERVICE_NONCE_BYTES],
    const uint8_t lease[KER_RUNTIME_SERVICE_LEASE_BYTES], uint16_t operation)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(address.sun_path)) { close(fd); errno = ENAMETOOLONG; return -1; }
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        int error = errno; close(fd); errno = error; return -1;
    }
    struct ker_runtime_service_header request = {0};
    request.magic = KER_RUNTIME_SERVICE_MAGIC;
    request.version = KER_RUNTIME_SERVICE_VERSION;
    request.operation = operation;
    request.packet_length = sizeof(request);
    request.sequence = 1;
    request.service_epoch = epoch;
    memcpy(request.run_nonce, nonce, sizeof(request.run_nonce));
    memcpy(request.lease_id, lease, sizeof(request.lease_id));
    if (send(fd, &request, sizeof(request), MSG_NOSIGNAL) != (ssize_t)sizeof(request)) {
        int error = errno ? errno : EIO; close(fd); errno = error; return -1;
    }
    struct ker_runtime_service_header response;
    ssize_t count;
    do { count = recv(fd, &response, sizeof(response), 0); }
    while (count < 0 && errno == EINTR);
    int error = errno;
    close(fd);
    if (count != (ssize_t)sizeof(response)) { errno = count < 0 ? error : EPROTO; return -1; }
    if (response.magic != KER_RUNTIME_SERVICE_MAGIC ||
        response.version != KER_RUNTIME_SERVICE_VERSION ||
        response.operation != operation || response.sequence != 1 ||
        response.service_epoch != epoch || memcmp(response.run_nonce, nonce,
            sizeof(response.run_nonce)) || memcmp(response.lease_id, lease,
            sizeof(response.lease_id)) || response.packet_length != sizeof(response)) {
        errno = EPROTO;
        return -1;
    }
    return response.status;
}

int main(int argc, char **argv)
{
    int expect_worker_death = argc == 2 && !strcmp(argv[1], "--expect-worker-death");
    int cleanup_lost_release = argc == 2 && !strcmp(argv[1], "--cleanup-lost-release");
    if (argc > 2 || (argc == 2 && !expect_worker_death && !cleanup_lost_release)) {
        fprintf(stderr, "usage: %s [--expect-worker-death|--cleanup-lost-release]\n", argv[0]);
        return 2;
    }
    const char *path = getenv("KER_RUNTIME_SERVICE_PATH");
    if (!path) { errno = EINVAL; fail("service path"); }
    uint8_t nonce[KER_RUNTIME_SERVICE_NONCE_BYTES];
    uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES];
    uint8_t profile[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t worker_profile[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint8_t supervisor_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
    uint64_t epoch, supervisor_start;
    int32_t supervisor_pid;
    if (parse_hex("KER_RUNTIME_SERVICE_NONCE", nonce, sizeof(nonce)) ||
        parse_hex("KER_RUNTIME_SERVICE_TICKET", ticket, sizeof(ticket)) ||
        parse_hex("KER_RUNTIME_SERVICE_PROFILE", profile, sizeof(profile)) ||
        parse_hex("KER_RUNTIME_SERVICE_WORKER_PROFILE", worker_profile, sizeof(worker_profile)) ||
        parse_hex("KER_RUNTIME_SERVICE_SUPERVISOR_EXE_SHA256", supervisor_hash,
            sizeof(supervisor_hash)) ||
        parse_u64("KER_RUNTIME_SERVICE_EPOCH", &epoch) ||
        parse_u64("KER_RUNTIME_SERVICE_SUPERVISOR_START_TICKS", &supervisor_start) ||
        parse_i32("KER_RUNTIME_SERVICE_SUPERVISOR_PID", &supervisor_pid))
        fail("runtime-service environment");
    uint64_t release_fd_value;
    if (parse_u64("KER_TEST_RELEASE_FD", &release_fd_value) || release_fd_value > INT32_MAX)
        fail("release fd");

    struct ker_runtime_service_client client;
    ker_runtime_service_client_init(&client);
    if (cleanup_lost_release) {
        uint8_t wrong_expected[sizeof(worker_profile)];
        memcpy(wrong_expected, worker_profile, sizeof(wrong_expected));
        wrong_expected[0] ^= UINT8_C(0xff);
        errno = 0;
        if (ker_runtime_service_claim(&client, path, nonce, epoch, ticket, profile,
                wrong_expected, supervisor_pid, supervisor_start, supervisor_hash) == 0 ||
            errno != EPROTO) fail("expected profile mismatch");
        uint8_t lease[KER_RUNTIME_SERVICE_LEASE_BYTES];
        memcpy(lease, client.lease_id, sizeof(lease));
        if (!client.cleanup_only || ker_runtime_service_check(&client) == 0 ||
            errno != EACCES) fail("cleanup-only CHECK denial");
        if (ker_runtime_service_reconnect(&client)) fail("cleanup-only reconnect");
        if (ker_runtime_service_release(&client)) fail("idempotent RELEASE retry");
        if (tombstone_request(path, epoch, nonce, lease, KER_RUNTIME_SERVICE_CHECK) != ESTALE)
            fail("released tombstone CHECK denial");
        uint8_t wrong_lease[sizeof(lease)];
        memcpy(wrong_lease, lease, sizeof(wrong_lease));
        wrong_lease[0] ^= UINT8_C(0xff);
        if (tombstone_request(path, epoch, nonce, wrong_lease,
                KER_RUNTIME_SERVICE_RELEASE) != ESTALE)
            fail("wrong-lease tombstone denial");
        pid_t child = fork();
        if (child < 0) fail("foreign tombstone test fork");
        if (child == 0)
            _exit(tombstone_request(path, epoch, nonce, lease,
                KER_RUNTIME_SERVICE_RELEASE) == ESTALE ? 0 : 1);
        int child_status;
        if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
            WEXITSTATUS(child_status) != 0) fail("foreign-actor tombstone denial");
        if (tombstone_request(path, epoch, nonce, lease, KER_RUNTIME_SERVICE_RELEASE) != 0)
            fail("released tombstone RELEASE retry");
        struct ker_runtime_service_client next;
        ker_runtime_service_client_init(&next);
        errno = 0;
        int new_claim = ker_runtime_service_claim(&next, path, nonce, epoch, ticket,
            profile, worker_profile, supervisor_pid, supervisor_start, supervisor_hash);
        int claim_error = errno;
        ker_runtime_service_client_close(&next);
        if (new_claim == 0 || claim_error != ESTALE)
            fail("consumed grant re-claim denial");
        ker_runtime_service_client_close(&client);
        puts("CLEANUP_SETTLED check_errno=13 tombstone_check=116 wrong_lease=116 foreign_actor=116 duplicate_release=0 claim_errno=116");
        fflush(stdout);
        return 0;
    }
    if (ker_runtime_service_claim(&client, path, nonce, epoch, ticket, profile,
            worker_profile, supervisor_pid, supervisor_start, supervisor_hash))
        fail("CLAIM");
    puts("CLAIMED");
    fflush(stdout);

    if (expect_worker_death) {
        char command;
        ssize_t count;
        do { count = read((int)release_fd_value, &command, 1); }
        while (count < 0 && errno == EINTR);
        if (count != 1 || command != 'R') { errno = count < 0 ? errno : EPIPE; fail("death barrier"); }
        if (ker_runtime_service_check(&client) == 0) {
            fputs("worker-death CHECK unexpectedly succeeded\n", stderr);
            return 3;
        }
        int check_error = errno;
        ker_runtime_service_client_close(&client);
        struct ker_runtime_service_client next;
        ker_runtime_service_client_init(&next);
        if (ker_runtime_service_claim(&next, path, nonce, epoch, ticket, profile,
                worker_profile, supervisor_pid, supervisor_start, supervisor_hash) == 0) {
            fputs("worker-death CLAIM unexpectedly issued a new lease\n", stderr);
            return 4;
        }
        int claim_error = errno;
        ker_runtime_service_client_close(&next);
        printf("DEAD_REJECTED check_errno=%d claim_errno=%d\n",
            check_error, claim_error);
        return 0;
    }
    char command;
    ssize_t count;
    do { count = read((int)release_fd_value, &command, 1); }
    while (count < 0 && errno == EINTR);
    if (count != 1 || command != 'C') { errno = count < 0 ? errno : EPIPE; fail("CHECK barrier"); }
    if (ker_runtime_service_check(&client)) fail("CHECK");
    puts("CHECKED");
    fflush(stdout);
    do { count = read((int)release_fd_value, &command, 1); }
    while (count < 0 && errno == EINTR);
    if (count != 1 || command != 'R') { errno = count < 0 ? errno : EPIPE; fail("release barrier"); }
    if (ker_runtime_service_release(&client)) fail("RELEASE");
    puts("RELEASED");
    fflush(stdout);
    ker_runtime_service_client_close(&client);
    return 0;
}
