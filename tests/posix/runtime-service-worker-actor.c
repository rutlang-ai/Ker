#define _GNU_SOURCE
#include "runtime-service-client.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv)
{
    int expect_worker_death = argc == 2 && !strcmp(argv[1], "--expect-worker-death");
    if (argc > 2 || (argc == 2 && !expect_worker_death)) {
        fprintf(stderr, "usage: %s [--expect-worker-death]\n", argv[0]);
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
