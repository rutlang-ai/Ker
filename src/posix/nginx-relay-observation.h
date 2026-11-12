/* Private host observations used by the actual Nginx relay and its signal
 * stress test. Deadlines are supplied by the caller; retries never renew them.
 * A zero read deadline preserves legacy single-attempt cycle observations. */
#ifndef KER_NGINX_RELAY_OBSERVATION_H
#define KER_NGINX_RELAY_OBSERVATION_H
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int rx_owner_relay_monotonic_ns(uint64_t *now)
{
    struct timespec value;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &value) || value.tv_sec < 0 ||
            value.tv_nsec < 0 || value.tv_nsec >= 1000000000L) return -1;
    *now = (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
    return 0;
}

static bool rx_owner_relay_before(uint64_t deadline)
{
    uint64_t now;
    if (rx_owner_relay_monotonic_ns(&now)) return false;
    if (now >= deadline) { errno = ETIMEDOUT; return false; }
    return true;
}

static ssize_t rx_owner_relay_read_host(const char *path, char *text,
    size_t bytes, uint64_t deadline)
{
    int fd;
    do {
        if (deadline && !rx_owner_relay_before(deadline)) return -1;
        fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    } while (deadline && fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    ssize_t count;
    do {
        if (deadline && !rx_owner_relay_before(deadline)) { count = -1; break; }
        count = syscall(SYS_read, fd, text, bytes);
    } while (deadline && count < 0 && errno == EINTR);
    int saved = errno;
    (void)syscall(SYS_close, fd);
    errno = saved;
    if (deadline && count >= 0 && !rx_owner_relay_before(deadline)) return -1;
    return count;
}
static int rx_owner_relay_pidfd_pid(int fd, pid_t *pid, uint64_t deadline)
{
    char path[64], text[256];
    int length = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -EINVAL;
    ssize_t count = rx_owner_relay_read_host(path, text, sizeof(text) - 1, deadline);
    int saved = errno;
    if (count <= 0) return count < 0 ? -saved : -EPROTO;
    text[count] = 0;
    char *line = strstr(text, "Pid:\t");
    if (!line) return -EINVAL;
    char *end = NULL;
    errno = 0;
    long value = strtol(line + 5, &end, 10);
    if (errno || end == line + 5 || (*end != '\n' && *end != 0) || value <= 0 ||
        value > INT_MAX) return -EINVAL;
    *pid = (pid_t)value;
    return 0;
}

#ifdef KER_NGINX_RELAY_OBSERVATION_TESTING
static unsigned rx_owner_relay_poll_interruptions;
#endif
static bool rx_owner_relay_pidfd_alive(int fd, uint64_t deadline)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP | POLLERR};
    if (fd < 0) return false;
    long ready;
    do {
        if (!rx_owner_relay_before(deadline)) return false;
        ready = syscall(SYS_poll, &pfd, 1, 0);
#ifdef KER_NGINX_RELAY_OBSERVATION_TESTING
        if (ready < 0 && errno == EINTR) ++rx_owner_relay_poll_interruptions;
#endif
    } while (ready < 0 && errno == EINTR);
    int saved = errno;
    if (ready != 0 || pfd.revents)
        dprintf(STDERR_FILENO, "ker RX relay pidfd observation failed fd=%d result=%ld revents=%x errno=%d\n",
            fd, ready, (unsigned)pfd.revents, saved);
    errno = saved;
    return ready == 0 && pfd.revents == 0 && rx_owner_relay_before(deadline);
}

static int
cycle_read_start_ticks_until(pid_t pid, uint64_t *ticks, uint64_t deadline)
{
    char path[64], buffer[4096], *cursor, *end;
    int length;
    ssize_t got;
    unsigned field;
    if (pid <= 0 || !ticks) { errno = EINVAL; return -1; }
    length = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) { errno = EOVERFLOW; return -1; }
    got = rx_owner_relay_read_host(path, buffer, sizeof(buffer) - 1, deadline);
    if (got < 0) return -1;
    if (got <= 0 || (size_t)got >= sizeof(buffer) - 1) { errno = EPROTO; return -1; }
    buffer[got] = '\0';
    cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ') { errno = EPROTO; return -1; }
    cursor += 2;
    /* Field 3 starts after comm; starttime is field 22. */
    for (field = 3; field <= 22; ++field) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) { errno = EPROTO; return -1; }
        end = cursor;
        while (*end && *end != ' ') ++end;
        if (field == 22) {
            char saved_char = *end;
            *end = '\0';
            errno = 0;
            unsigned long long value = strtoull(cursor, &end, 10);
            int parse_error = errno;
            *end = saved_char;
            if (parse_error || end == cursor || value == 0) { errno = EPROTO; return -1; }
            *ticks = (uint64_t)value;
            return 0;
        }
        cursor = end;
    }
    errno = EPROTO;
    return -1;
}

#endif
