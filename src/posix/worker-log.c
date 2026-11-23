#define _GNU_SOURCE
#include "worker-log.h"
#include <errno.h>
#include <limits.h>
#include <rte_log.h>

int ker_worker_log_reset(FILE *stream) { return rte_openlog_stream(stream); }
void ker_worker_log_global_level(uint32_t level) { rte_log_set_global_level(level); }
int ker_worker_log_level(uint32_t type, uint32_t level) { return rte_log_set_level(type, level); }
int ker_worker_vlog(uint32_t level, uint32_t type, const char *format, va_list args)
{
    int result = rte_vlog(level, type, format, args);
    /* DPDK returns vfprintf's count even if its following fflush fails. */
    if (result >= 0 && ferror(rte_log_get_stream())) return -1;
    return result;
}
int ker_worker_log(uint32_t level, uint32_t type, const char *format, ...)
{
    va_list args; va_start(args, format);
    int result = ker_worker_vlog(level, type, format, args);
    va_end(args); return result;
}
int ker_worker_log_open(struct ker_worker_log *log, const char *directory,
    unsigned int instance, uint32_t level)
{
    if (!directory || level < RTE_LOG_EMERG || level > RTE_LOG_DEBUG) { errno = EINVAL; return -1; }
    if (log->file) { errno = EBUSY; return -1; }
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/ker-io-%u.log", directory, instance);
    if (length < 0 || (size_t)length >= sizeof(path)) { errno = ENAMETOOLONG; return -1; }
    int type = rte_log_register("ker.io");
    if (type < 0) { errno = ENOMEM; return -1; }
    FILE *file = fopen(path, "a");
    if (!file) return -1;
    if (ker_worker_log_level(type, level) || ker_worker_log_reset(file)) {
        int saved = EIO; fclose(file); errno = saved; return -1;
    }
    log->file = file; log->type = type;
    return 0;
}
int ker_worker_log_close(struct ker_worker_log *log)
{
    if (!log->file) return 0;
    /* Never leave DPDK pointing at a closed FILE, including on flush failure. */
    if (ker_worker_log_reset(stderr)) { errno = EIO; return -1; }
    FILE *file = log->file; log->file = NULL;
    int failed = ferror(file), result = fclose(file);
    if (result) return result;
    if (failed) { errno = EIO; return -1; }
    return 0;
}
