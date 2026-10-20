#define _GNU_SOURCE
#include "worker-log.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rte_log.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static int via_vlog(uint32_t level, uint32_t type, const char *format, ...)
{
    va_list args; va_start(args, format);
    int result = ker_worker_vlog(level, type, format, args);
    va_end(args); return result;
}
static void content(const char *path, const char *expected)
{
    FILE *file = fopen(path, "r"); CHECK(file);
    char bytes[1024]; size_t length = fread(bytes, 1, sizeof(bytes), file);
    CHECK(!ferror(file) && length == strlen(expected));
    CHECK(memcmp(bytes, expected, length) == 0);
    CHECK(fclose(file) == 0);
}
int main(void)
{
    char directory[] = "/tmp/ker-worker-log-XXXXXX"; CHECK(mkdtemp(directory));
    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/ker-io-42.log", directory);
    struct ker_worker_log log = {0};
    CHECK(ker_worker_log_close(&log) == 0 && !log.file);
    CHECK(ker_worker_log_open(&log, "/missing-ker-log-directory/child", 42, RTE_LOG_INFO) == -1);
    CHECK(!log.file);
    CHECK(ker_worker_log_open(&log, directory, 42, RTE_LOG_DEBUG) == 0);
    CHECK(log.file && rte_log_get_stream() == log.file);
    uint32_t old_global = rte_log_get_global_level();
    ker_worker_log_global_level(RTE_LOG_DEBUG);
    CHECK(rte_log_get_global_level() == RTE_LOG_DEBUG);
    CHECK(ker_worker_log(RTE_LOG_INFO, log.type, "x=%d\n", 42) == 5);
    CHECK(ker_worker_log(RTE_LOG_NOTICE, log.type, "static msg\n") == 11);
    CHECK(via_vlog(RTE_LOG_WARNING, log.type, "a=%d %s\n", 5, "ok") == 7);
    CHECK(ker_worker_log(RTE_LOG_DEBUG, log.type, "x") == 1);
    CHECK(ker_worker_log_level(UINT32_MAX, RTE_LOG_DEBUG) == -1);
    CHECK(ker_worker_log(RTE_LOG_INFO, UINT32_MAX, "invalid") == -1);
    CHECK(ker_worker_log_level(log.type, RTE_LOG_WARNING) == 0);
    CHECK(rte_log_get_level(log.type) == RTE_LOG_WARNING);
    CHECK(ker_worker_log(RTE_LOG_INFO, log.type, "category-filtered") == 0);
    CHECK(ker_worker_log_level(log.type, RTE_LOG_DEBUG) == 0);
    ker_worker_log_global_level(RTE_LOG_ERR);
    CHECK(ker_worker_log(RTE_LOG_WARNING, log.type, "global-filtered") == 0);
    ker_worker_log_global_level(RTE_LOG_DEBUG);
    FILE *other = tmpfile(); CHECK(other);
    CHECK(ker_worker_log_reset(other) == 0 && rte_log_get_stream() == other);
    CHECK(ker_worker_log(RTE_LOG_INFO, log.type, "other") == 5);
    CHECK(fseek(other, 0, SEEK_SET) == 0);
    char bytes[6] = {0}; CHECK(fread(bytes, 1, 5, other) == 5 && !strcmp(bytes, "other"));
    CHECK(ker_worker_log_reset(log.file) == 0); CHECK(fclose(other) == 0);
    int closed_fd = fileno(log.file);
    CHECK(ker_worker_log_close(&log) == 0 && !log.file && rte_log_get_stream() == stderr);
    CHECK(fcntl(closed_fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(ker_worker_log_close(&log) == 0);
    content(path, "x=42\nstatic msg\na=5 ok\nx");
    CHECK(ker_worker_log_open(&log, directory, 42, RTE_LOG_INFO) == 0);
    CHECK(ker_worker_log(RTE_LOG_INFO, log.type, "append\n") == 7);
    CHECK(ker_worker_log_close(&log) == 0);
    content(path, "x=42\nstatic msg\na=5 ok\nxappend\n");
    CHECK(unlink(path) == 0);
    puts("PASS: real DPDK open, ID filename, append, close, stream reset, levels, variadics and counts");

    CHECK(symlink("/dev/full", path) == 0);
    CHECK(ker_worker_log_open(&log, directory, 42, RTE_LOG_DEBUG) == 0);
    CHECK(ker_worker_log(RTE_LOG_INFO, log.type, "flush failure\n") == -1);
    CHECK(ker_worker_log_close(&log) == -1 && !log.file && rte_log_get_stream() == stderr);
    CHECK(ker_worker_log_open(&log, directory, 42, RTE_LOG_DEBUG) == 0);
    CHECK(fputs("buffered failure", log.file) >= 0);
    CHECK(ker_worker_log_close(&log) == -1 && !log.file && rte_log_get_stream() == stderr);
    CHECK(unlink(path) == 0 && rmdir(directory) == 0);
    ker_worker_log_global_level(old_global);
    puts("PASS: flush and buffered-close errors propagate, with a valid restored DPDK stream");
    return 0;
}
