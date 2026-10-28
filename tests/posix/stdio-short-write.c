#define _GNU_SOURCE
#include "fd-table.h"
#include "lifecycle.h"
#include <errno.h>
#include <fcntl.h>
#include <lkl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #test, errno); \
    exit(1); \
} } while (0)

enum { APP_FD = 42, HEALTHY_FD = 43, NATIVE_FD = 17, HEALTHY_NATIVE_FD = 18 };
static struct ker_fd native_entries[] = {
    {.native = NATIVE_FD, .host = -1, .kind = KER_FD_SOCKET},
    {.native = HEALTHY_NATIVE_FD, .host = -1, .kind = KER_FD_SOCKET},
};
static int fail_after_partial;
static int write_error;
static size_t failed_write_requests[4];
static unsigned failed_write_calls;
static size_t healthy_write_requests[4];
static unsigned healthy_write_calls;
static char accepted[32];
static size_t accepted_length;
static char healthy_accepted[32];
static size_t healthy_accepted_length;

struct ker_fd *ker_fd_get(int fd)
{
    if (fd == APP_FD) return &native_entries[0];
    if (fd == HEALTHY_FD) return &native_entries[1];
    return NULL;
}

long ker_fd_put(struct ker_fd *entry)
{
    CHECK(entry == &native_entries[0] || entry == &native_entries[1]);
    return 0;
}

bool ker_native_ready(void) { return true; }

long lkl_syscall(long number, long *params)
{
    CHECK(number == __lkl__NR_fcntl && params[1] == F_GETFL);
    CHECK(params[0] == NATIVE_FD || params[0] == HEALTHY_NATIVE_FD);
    return O_WRONLY;
}

ssize_t __real_write(int fd, const void *buffer, size_t length);
ssize_t __wrap_write(int fd, const void *buffer, size_t length)
{
    if (fd == APP_FD) {
        CHECK(failed_write_calls < sizeof(failed_write_requests) / sizeof(failed_write_requests[0]));
        failed_write_requests[failed_write_calls++] = length;
        if (length == 0) return 0;
        if (failed_write_calls == 2 && fail_after_partial) {
            errno = write_error;
            return -1;
        }
        size_t count = failed_write_calls == 1 && length > 4 ? 4 : length;
        CHECK(accepted_length + count <= sizeof(accepted));
        memcpy(accepted + accepted_length, buffer, count);
        accepted_length += count;
        return (ssize_t)count;
    }
    if (fd == HEALTHY_FD) {
        CHECK(healthy_write_calls < sizeof(healthy_write_requests) / sizeof(healthy_write_requests[0]));
        healthy_write_requests[healthy_write_calls++] = length;
        if (length == 0) return 0;
        size_t count = healthy_write_calls == 1 && length > 4 ? 4 : length;
        CHECK(healthy_accepted_length + count <= sizeof(healthy_accepted));
        memcpy(healthy_accepted + healthy_accepted_length, buffer, count);
        healthy_accepted_length += count;
        return (ssize_t)count;
    }
    return __real_write(fd, buffer, length);
}

int __real_close(int fd);
int __wrap_close(int fd)
{
    if (fd == APP_FD || fd == HEALTHY_FD) return 0;
    return __real_close(fd);
}

static FILE *native_output(int fd, char *buffer, size_t capacity)
{
    FILE *stream = fdopen(fd, "w");
    CHECK(stream && fileno(stream) == fd);
    CHECK(setvbuf(stream, buffer, _IOFBF, capacity) == 0);
    return stream;
}

static void short_write_shutdown(bool fail)
{
    static char buffer[512];
    static const char payload[] = "abcdefgh";
    fail_after_partial = fail;
    write_error = EAGAIN;
    FILE *stream = native_output(APP_FD, buffer, sizeof(buffer));
    CHECK(fwrite(payload, 1, sizeof(payload) - 1, stream) == sizeof(payload) - 1);
    CHECK(failed_write_calls == 0 && accepted_length == 0 && !ferror(stream));

    int result = ker_native_stdio_shutdown();
    CHECK(failed_write_calls == 2 && failed_write_requests[0] == sizeof(payload) - 1 &&
          failed_write_requests[1] == 4);
    if (fail) {
        CHECK(result == -EAGAIN && accepted_length == 4 && ferror(stream));
        CHECK(!memcmp(accepted, payload, accepted_length));
        puts("PASS: shutdown retries 8-byte flush, accepts 4 bytes, then reports EAGAIN");
    } else {
        CHECK(result == 0 && accepted_length == sizeof(payload) - 1 && !ferror(stream));
        CHECK(!memcmp(accepted, payload, accepted_length));
        puts("PASS: shutdown retries short write and flushes all 8 bytes");
    }
    errno = 0;
    CHECK(fclose(stream) == EOF && errno == EBADF);
}

static void handled_error_does_not_poison_shutdown(void)
{
    static char failed_buffer[512], healthy_buffer[512];
    static const char payload[] = "abcdefgh";
    fail_after_partial = 1;
    write_error = EPIPE;
    FILE *failed = native_output(APP_FD, failed_buffer, sizeof(failed_buffer));
    CHECK(fwrite(payload, 1, sizeof(payload) - 1, failed) == sizeof(payload) - 1);
    CHECK(failed_write_calls == 0);
    errno = 0;
    CHECK(fflush(failed) == EOF && errno == EPIPE && ferror(failed));
    CHECK(failed_write_calls == 2 && accepted_length == 4);
    clearerr(failed);
    CHECK(!ferror(failed));
    CHECK(fclose(failed) == 0);

    FILE *healthy = native_output(HEALTHY_FD, healthy_buffer, sizeof(healthy_buffer));
    CHECK(fwrite(payload, 1, sizeof(payload) - 1, healthy) == sizeof(payload) - 1);
    CHECK(healthy_write_calls == 0);
    CHECK(ker_native_stdio_shutdown() == 0);
    CHECK(healthy_write_calls == 2 && healthy_write_requests[0] == sizeof(payload) - 1 &&
          healthy_write_requests[1] == 4 && healthy_accepted_length == sizeof(payload) - 1);
    CHECK(!memcmp(healthy_accepted, payload, healthy_accepted_length));
    errno = 0;
    CHECK(fclose(healthy) == EOF && errno == EBADF);
    puts("PASS: handled EPIPE/clearerr/close does not poison later healthy shutdown");
}

static void host_flush_error_does_not_poison_native_shutdown(void)
{
    static char host_buffer[512], native_buffer[512];
    static const char payload[] = "abcdefgh";
    FILE *host = fopen("/dev/full", "w");
    CHECK(host && setvbuf(host, host_buffer, _IOFBF, sizeof(host_buffer)) == 0);
    CHECK(fwrite("host", 1, 4, host) == 4);
    CHECK(!ferror(host));
    FILE *native = native_output(HEALTHY_FD, native_buffer, sizeof(native_buffer));
    CHECK(fwrite(payload, 1, sizeof(payload) - 1, native) == sizeof(payload) - 1);
    CHECK(healthy_write_calls == 0);

    CHECK(ker_native_stdio_shutdown() == 0);
    CHECK(ferror(host) && healthy_accepted_length == sizeof(payload) - 1);
    CHECK(fclose(host) == 0);
    errno = 0;
    CHECK(fclose(native) == EOF && errno == EBADF);
    puts("PASS: host-only fflush failure does not fail healthy native stdio shutdown");
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "partial-error")) short_write_shutdown(true);
    else if (!strcmp(argv[1], "retry-complete")) short_write_shutdown(false);
    else if (!strcmp(argv[1], "handled-closed-error")) handled_error_does_not_poison_shutdown();
    else if (!strcmp(argv[1], "host-flush-error")) host_flush_error_does_not_poison_native_shutdown();
    else CHECK(false);
    return 0;
}
