#ifndef KER_WORKER_LOG_H
#define KER_WORKER_LOG_H
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
struct ker_worker_log { FILE *file; int type; };
/* The isolated worker owns DPDK's process-wide log stream. Close resets it
 * to stderr before releasing the file; initialize the state to zero. */
int ker_worker_log_open(struct ker_worker_log *log, const char *directory,
    unsigned int instance, uint32_t level);
int ker_worker_log_close(struct ker_worker_log *log);
int ker_worker_log_reset(FILE *stream);
void ker_worker_log_global_level(uint32_t level);
int ker_worker_log_level(uint32_t type, uint32_t level);
int ker_worker_vlog(uint32_t level, uint32_t type, const char *format, va_list args);
int ker_worker_log(uint32_t level, uint32_t type, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
#endif
