#define _GNU_SOURCE
#include "lifecycle.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <lkl.h>

static int64_t now_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}
static int queued(const char *path)
{
    long fd = lkl_sys_open(path, LKL_O_RDONLY, 0);
    if (fd < 0) return (int)fd;
    char buffer[4096], line[512];
    size_t used = 0;
    int result = 0;
    for (;;) {
        long count = lkl_sys_read(fd, buffer, sizeof(buffer));
        if (count < 0) { result = (int)count; break; }
        if (!count) break;
        for (long i = 0; i < count; ++i) {
            if (buffer[i] == '\n') {
                line[used] = 0;
                unsigned int sequence, state, tx, rx;
                if (sscanf(line, "%u: %*s %*s %x %x:%x", &sequence, &state, &tx, &rx) == 4 && tx)
                    result = 1;
                used = 0;
            } else {
                if (used + 1 >= sizeof(line)) { result = -EOVERFLOW; goto done; }
                line[used++] = buffer[i];
            }
        }
    }
done:
    lkl_sys_close(fd);
    return result;
}
int ker_native_drain(unsigned int timeout_ms)
{
    int64_t deadline = now_ns() + (int64_t)timeout_ms * INT64_C(1000000);
    for (;;) {
        int pending = queued("/proc/net/tcp");
        if (pending < 0) return pending;
        int ipv6 = queued("/proc/net/tcp6");
        if (ipv6 < 0) return ipv6;
        pending |= ipv6;
        if (pending <= 0) return pending;
        if (now_ns() >= deadline) return -ETIMEDOUT;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
}
