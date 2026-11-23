#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int ff_init(int argc, char * const argv[]);

static int secondary_authorization_enabled;

int
ker_fstack_nginx_worker_consume_authorization(unsigned int proc_id)
{
    if (!secondary_authorization_enabled || proc_id != 1)
        return 0;
    secondary_authorization_enabled = 0;
    return 1;
}

intptr_t ngx_max_sockets = 1024;
int is_fstack_fd(int fd) { return fd >= ngx_max_sockets; }

static int
write_profile(char *path, const char *contents)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t length = strlen(contents), done = 0;
    while (done < length) {
        ssize_t count = write(fd, contents + done, length - done);
        if (count <= 0) {
            int saved = errno;
            close(fd); unlink(path); errno = saved;
            return -1;
        }
        done += (size_t)count;
    }
    return close(fd);
}

static int
expect_reject(int expected_errno, char *const argv[])
{
    errno = 0;
    return ff_init(4, argv) == -1 && errno == expected_errno ? 0 : -1;
}

int
main(void)
{
    char config_path[] = "/tmp/ker-fstack-runtime-profile-XXXXXX";
    const char *broker = "/tmp/ker-fstack-runtime-profile-no-socket";
    char conf_arg[256];
    int config_fd = mkstemp(config_path);
    if (config_fd < 0 || close(config_fd) || write_profile(config_path, "")) {
        perror("write profile");
        return 1;
    }
    if (snprintf(conf_arg, sizeof(conf_arg), "--conf=%s", config_path) >=
        (int)sizeof(conf_arg)) {
        unlink(config_path);
        return 1;
    }
    char *secondary[] = {
        "nginx", "--conf=/unused", "--proc-id=1", "--proc-type=secondary"
    };
    char *secondary_valid[] = {
        "nginx", conf_arg, "--proc-id=1", "--proc-type=secondary"
    };
    char *primary[] = {"nginx", conf_arg, "--proc-id=0", "--proc-type=primary"};
    int failed = 0;

    if (expect_reject(ENOTSUP, secondary)) {
        fputs("FF nginx runtime accepted a secondary without the cooperative shim check\n", stderr);
        failed = 1;
    }
    if (setenv("FF_FAULT", "1", 1) || expect_reject(ENOTSUP, primary)) {
        fputs("FF nginx runtime did not reject FF_FAULT\n", stderr);
        failed = 1;
    }
    unsetenv("FF_FAULT");

    static const char valid_suffix[] = "\n[dpdk]\ngraceful_reload=0\n";
    char profile[1024];
    if (snprintf(profile, sizeof(profile),
        "[ker_socket_broker]\nversion=1\npath=%s%s", broker, valid_suffix) >=
        (int)sizeof(profile) || write_profile(config_path, profile)) {
        perror("write valid profile");
        unlink(config_path);
        return 1;
    }
    if (setenv("KER_SOCKET_BROKER_PATH", broker, 1)) {
        perror("set broker environment");
        unlink(config_path);
        return 1;
    }
    secondary_authorization_enabled = 1;
    if (expect_reject(ENOENT, secondary_valid) || secondary_authorization_enabled) {
        fputs("FF nginx runtime did not require and consume shim authorization for worker 1\n",
            stderr);
        failed = 1;
    }
    if (setenv("KER_SOCKET_BROKER_PATH", broker, 1) ||
        snprintf(profile, sizeof(profile),
            "[ker_socket_broker]\nversion=1\npath=%s\n[dpdk]\ngraceful_reload=1\n",
            broker) >= (int)sizeof(profile) || write_profile(config_path, profile) ||
        expect_reject(EINVAL, primary)) {
        fputs("FF nginx runtime did not reject graceful_reload=1\n", stderr);
        failed = 1;
    }
    if (snprintf(profile, sizeof(profile),
        "[ker_socket_broker]\nversion=1\npath=%s\nunknown=1\n[dpdk]\ngraceful_reload=0\n",
        broker) >= (int)sizeof(profile) || write_profile(config_path, profile) ||
        expect_reject(EINVAL, primary)) {
        fputs("FF nginx runtime did not reject an unknown profile setting\n", stderr);
        failed = 1;
    }
    if (setenv("KER_SOCKET_BROKER_PATH", "/tmp/different-broker", 1) ||
        snprintf(profile, sizeof(profile),
            "[ker_socket_broker]\nversion=1\npath=%s%s", broker, valid_suffix) >=
            (int)sizeof(profile) || write_profile(config_path, profile) ||
        expect_reject(EINVAL, primary)) {
        fputs("FF nginx runtime did not reject broker path disagreement\n", stderr);
        failed = 1;
    }
    if (setenv("KER_SOCKET_BROKER_PATH", broker, 1) ||
        expect_reject(ENOENT, primary)) {
        fputs("FF nginx runtime did not fail closed on an unreachable broker\n", stderr);
        failed = 1;
    }
    unlink(config_path);
    return failed;
}
