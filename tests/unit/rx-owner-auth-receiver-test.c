#define main ker_socket_broker_fixture_unused_main
#include "../posix/socket-broker-rx-owner-relay-fixture.c"
#undef main

#include <dirent.h>

static int count_open_fds(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    while (readdir(directory)) ++count;
    (void)closedir(directory);
    return count;
}

int main(void)
{
    struct fixture fixture = {.owner_pidfd = -1, .supervisor_pidfd = -1};
    const char *fd_text = getenv("KER_RX_OWNER_AUTH_FD");
    const char *supervisor_text = getenv("KER_TEST_OWNER_SUPERVISOR_PID");
    const char *start_text = getenv("KER_TEST_OWNER_SUPERVISOR_START");
    const char *epoch_text = getenv("KER_TEST_OWNER_EPOCH");
    const char *nonce_text = getenv("KER_TEST_OWNER_NONCE");
    const char *expected_text = getenv("KER_TEST_OWNER_EXPECT_STATUS");
    char *end = NULL;
    long fd = fd_text ? strtol(fd_text, &end, 10) : -1;
    if (!fd_text || end == fd_text || *end || fd < 3 || !supervisor_text ||
        !start_text || !epoch_text || !expected_text ||
        decode_hex(nonce_text, fixture.nonce, sizeof(fixture.nonce))) return 2;
    fixture.relay_fd = (int)fd;
    fixture.supervisor_pid = (uint32_t)strtoul(supervisor_text, NULL, 10);
    fixture.supervisor_start = strtoull(start_text, NULL, 10);
    fixture.epoch = strtoull(epoch_text, NULL, 10);
    errno = 0;
    long expected = strtol(expected_text, &end, 10);
    if (errno || end == expected_text || *end) return 2;
    struct pollfd wait = {.fd = fixture.relay_fd, .events = POLLIN};
    if (poll(&wait, 1, 2000) != 1) return 2;
    int before = count_open_fds();
    int status = receive_supervisor_owner_auth(&fixture);
    if (fixture.owner_pidfd >= 0) close(fixture.owner_pidfd);
    if (fixture.supervisor_pidfd >= 0) close(fixture.supervisor_pidfd);
    int after = count_open_fds();
    fprintf(stderr, "OWNER_AUTH_RECEIVER status=%d fds_before=%d fds_after=%d\n",
        status, before, after);
    return status == expected && before == after ? 0 : 1;
}
