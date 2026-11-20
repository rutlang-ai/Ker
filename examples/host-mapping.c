#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "host-mapping.h"
#include "ff_log.h"
#ifdef FF_USE_PAGE_ARRAY
#error "The caller mapping example supports only the original non-page-array path"
#endif
static int mapping_log(uint32_t level, uint32_t type, const char *format, ...)
{
    (void)level; (void)type;
    va_list args;
    va_start(args, format);
    int result = vfprintf(stderr, format, args);
    va_end(args);
    return result;
}
#define ff_log mapping_log
#define ff_mmap example_host_mmap
#define ff_munmap example_host_munmap
#include "memory-functions.inc"
