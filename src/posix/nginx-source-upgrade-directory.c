#define _GNU_SOURCE
#include "nginx-source-upgrade-directory.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_memzone.h>
#include "ff_reload.h"
#include "ff_log.h"

_Static_assert(sizeof(struct ff_reload_gendir) ==
    KER_NGINX_SOURCE_UPGRADE_DIRECTORY_BYTES, "original generation directory ABI");

/* In the native profile EAL lives in the independent I/O actor. The original
 * F-Stack directory still owns registration and epoch allocation. Supply its
 * one memzone from the received shared descriptor and the authenticated role. */
static struct rte_memzone source_zone;
static bool source_slim;

static enum rte_proc_type_t source_process_type(void)
{
    return source_slim ? RTE_PROC_PRIMARY : RTE_PROC_SECONDARY;
}

static const struct rte_memzone *source_zone_lookup(const char *name)
{
    return source_zone.addr && !strcmp(name, FF_RELOAD_GENDIR_NAME) ?
        &source_zone : NULL;
}

static const struct rte_memzone *source_zone_reserve(const char *name,
    size_t size, int socket, unsigned flags)
{
    if (!source_slim || size != source_zone.len || socket != SOCKET_ID_ANY ||
            flags != 0)
        return NULL;
    return source_zone_lookup(name);
}

static int source_directory_log(uint32_t level, uint32_t logtype,
    const char *format, ...)
{
    (void)level;
    (void)logtype;
    va_list arguments;
    va_start(arguments, format);
    int result = vfprintf(stderr, format, arguments);
    va_end(arguments);
    return result;
}

__attribute__((noreturn, format(printf, 2, 3)))
static void source_directory_exit(int status, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    (void)vfprintf(stderr, format, arguments);
    va_end(arguments);
    _exit(status);
}

#define rte_eal_process_type source_process_type
#define rte_memzone_lookup source_zone_lookup
#define rte_memzone_reserve source_zone_reserve
#define rte_exit source_directory_exit
#define ff_log source_directory_log
#include "../../third_party/fstack-reload/ff_reload_gendir.c"
#undef ff_log
#undef rte_exit
#undef rte_memzone_reserve
#undef rte_memzone_lookup
#undef rte_eal_process_type

int ker_nginx_source_upgrade_directory_attach(int fd, bool slim)
{
    if (source_zone.addr) return -EALREADY;
    if (fd < 0 || !ff_global_cfg.dpdk.graceful_reload) return -EINVAL;
    struct stat descriptor;
    if (syscall(SYS_fstat, fd, &descriptor)) return -errno;
    const int required_seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW;
    int seals = (int)syscall(SYS_fcntl, fd, F_GET_SEALS, 0);
    if (!S_ISREG(descriptor.st_mode) || descriptor.st_uid != geteuid() ||
            descriptor.st_nlink != 0 ||
            descriptor.st_size != sizeof(struct ff_reload_gendir) ||
            seals != required_seals)
        return -EPROTO;

    void *directory = mmap(NULL, sizeof(struct ff_reload_gendir),
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (directory == MAP_FAILED) return -errno;
    source_zone.addr = directory;
    source_zone.len = sizeof(struct ff_reload_gendir);
    source_slim = slim;
    ff_reload_gendir_attach();
    return 0;
}

void ker_nginx_source_upgrade_directory_detach(void)
{
    if (!source_zone.addr) return;
    ff_reload_gendir_detach();
    (void)munmap(source_zone.addr, source_zone.len);
    source_zone.addr = NULL;
    source_zone.len = 0;
}
