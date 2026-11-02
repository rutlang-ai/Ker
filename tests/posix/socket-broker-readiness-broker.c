#define _GNU_SOURCE
#include <ker/socket-broker-server.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "readiness broker:%d: %s: %s\n", __LINE__, #expr, strerror(errno)); \
    return 1; \
} } while (0)

static int hex_decode(const char *text, uint8_t *output, size_t output_size)
{
    if (!text || strlen(text) != output_size * 2) return -1;
    for (size_t i = 0; i < output_size; ++i) {
        unsigned value = 0;
        char pair[3] = {text[2 * i], text[2 * i + 1], '\0'};
        char *end = NULL;
        errno = 0;
        value = (unsigned)strtoul(pair, &end, 16);
        if (errno || !end || *end) return -1;
        output[i] = (uint8_t)value;
    }
    return 0;
}

static int decimal(const char *text, uint64_t *value)
{
    if (!text || !*text || !value) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || !end || *end || !parsed) return -1;
    *value = (uint64_t)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    (void)signal(SIGPIPE, SIG_IGN);
    bool skip_bootstrap = argc == 3 && strcmp(argv[2], "--skip-bootstrap") == 0;
    if (argc != 2 && !skip_bootstrap) {
        fprintf(stderr, "usage: broker-readiness <rpc-path> [--skip-bootstrap]\n");
        return 2;
    }
    const char *fd_text = getenv("KER_BROKER_READINESS_FD");
    const char *nonce_text = getenv("KER_BROKER_RUN_NONCE");
    const char *epoch_text = getenv("KER_BROKER_WORKER_EPOCH");
    const char *profile_text = getenv("KER_BROKER_WORKER_PROFILE_SHA256");
    const char *parent_start_text = getenv("KER_BROKER_SUPERVISOR_START_TICKS");
    uint64_t fd_value = 0, epoch = 0, parent_start = 0;
    uint8_t nonce[16], profile[32];
    CHECK(decimal(fd_text, &fd_value) == 0 && fd_value <= INT_MAX);
    int control_fd = (int)fd_value;
    CHECK(decimal(epoch_text, &epoch) == 0);
    CHECK(decimal(parent_start_text, &parent_start) == 0);
    CHECK(hex_decode(nonce_text, nonce, sizeof(nonce)) == 0);
    CHECK(hex_decode(profile_text, profile, sizeof(profile)) == 0);
    struct ker_socket_broker_server *server = ker_socket_broker_server_create(argv[1]);
    CHECK(server != NULL);
    CHECK(ker_socket_broker_server_readiness_attach(server, control_fd,
        nonce, epoch, profile, parent_start) == 0);
    CHECK(syscall(SYS_close, control_fd) == 0);
    if (!skip_bootstrap)
        CHECK(ker_socket_broker_server_bootstrap_complete_empty(server) == 0);
    puts("BROKER_ENTER");
    fflush(stdout);
    int result = ker_socket_broker_server_run(server, 0);
    int run_error = errno;
#ifdef KER_SOCKET_BROKER_READINESS_TESTING
    int parent_error = ker_socket_broker_server_readiness_test_parent_error(server);
    fprintf(stderr, "BROKER_PARENT_CHECK_ERROR=%d\n", parent_error);
#endif
    int destroy_result = ker_socket_broker_server_destroy_checked(server);
    int destroy_error = errno;
    if (skip_bootstrap) {
        if (!result || run_error != EINVAL || destroy_result) {
            errno = run_error ? run_error : destroy_error;
            perror("expected pre-run bootstrap rejection");
            return 1;
        }
        puts("BROKER_NO_READY");
        fflush(stdout);
        return 0;
    }
    if (result) {
        fprintf(stderr, "BROKER_RUN_ERROR=%d\n", run_error);
        errno = run_error;
        perror("broker readiness run");
    }
    if (destroy_result) { errno = destroy_error; perror("broker readiness destroy"); }
    if (result || destroy_result) return 1;
    puts("BROKER_DONE");
    fflush(stdout);
    return 0;
}
