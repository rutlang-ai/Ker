#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

static int cleaned_up;

static void record(const char *event)
{
    const char *path = getenv("KER_DPDK_LOG_LIFETIME_VIOLATION");
    if (!path) return;
    FILE *record_file = fopen(path, "a");
    if (record_file) { fputs(event, record_file); fputc('\n', record_file); fclose(record_file); }
}

int rte_eal_cleanup(void)
{
    static int (*next_cleanup)(void);
    if (!next_cleanup) next_cleanup = dlsym(RTLD_NEXT, "rte_eal_cleanup");
    int result = next_cleanup();
    cleaned_up = 1;
    record("rte_eal_cleanup");
    return result;
}

int rte_openlog_stream(FILE *stream)
{
    static int (*next_openlog_stream)(FILE *);
    if (!next_openlog_stream) next_openlog_stream = dlsym(RTLD_NEXT, "rte_openlog_stream");
    if (cleaned_up) record("rte_openlog_stream after rte_eal_cleanup");
    return next_openlog_stream(stream);
}
