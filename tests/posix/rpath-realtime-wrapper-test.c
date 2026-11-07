#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

static int call_gettimeofday(struct timeval *value, void *zone)
{
    int (*call)(struct timeval *, void *) = gettimeofday;
    return call(value, zone);
}

int main(void)
{
    struct timeval value = {.tv_sec = 17, .tv_usec = 23};
    struct timeval unchanged = value;
    struct timezone zone = {.tz_minuteswest = 61, .tz_dsttime = 2};

    if (unsetenv("KER_MPTCP_NATIVE_REALTIME")) return 1;
    if (call_gettimeofday(&value, NULL) || value.tv_sec < 1 || value.tv_usec < 0 || value.tv_usec >= 1000000) {
        fputs("host gettimeofday passthrough failed\n", stderr); return 1;
    }
    if (call_gettimeofday(NULL, &zone)) {
        fputs("null timeval timezone call failed\n", stderr); return 1;
    }
    if (setenv("KER_MPTCP_NATIVE_REALTIME", "1", 1)) return 1;
    if (call_gettimeofday(NULL, &zone)) {
        fputs("native mode did not preserve null timeval timezone behavior\n", stderr); return 1;
    }
    value = unchanged; errno = 0;
    if (call_gettimeofday(&value, NULL) != -1 || errno != ENOTCONN ||
        value.tv_sec != unchanged.tv_sec || value.tv_usec != unchanged.tv_usec) {
        fputs("native clock request did not fail closed without a network socket\n", stderr); return 1;
    }
    puts("PASS: rpath realtime wrapper preserves host and null-timeval ABI and fails closed");
    return 0;
}
