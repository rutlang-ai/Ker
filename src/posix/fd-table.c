#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct ker_fd *entries[KER_FD_LIMIT];
struct ker_fd *ker_fd_get(int fd)
{
    if (fd < 0 || fd >= KER_FD_LIMIT) return NULL;
    pthread_mutex_lock(&mutex);
    struct ker_fd *entry = entries[fd];
    if (entry) atomic_fetch_add_explicit(&entry->references, 1, memory_order_relaxed);
    pthread_mutex_unlock(&mutex);
    return entry;
}
long ker_fd_put(struct ker_fd *entry)
{
    long result = 0;
    if (entry && atomic_fetch_sub_explicit(&entry->references, 1, memory_order_acq_rel) == 1) {
        result = lkl_sys_close(entry->native);
        if (entry->host >= 0) syscall(SYS_close, entry->host);
        free(entry);
    }
    return result;
}
static int error(long result)
{
    if (result < 0) { errno = (int)-result; return -1; }
    return (int)result;
}
int ker_fd_export(int native, enum ker_fd_kind kind, int host, int flags,
    int minimum, int fixed)
{
    struct ker_fd *entry = calloc(1, sizeof(*entry));
    int fd = -1, saved = ENOMEM;
    if (!entry) goto fail;
    entry->native = native;
    entry->host = host;
    entry->kind = kind;
    atomic_init(&entry->references, 1);
    atomic_init(&entry->turn, 0);
    fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_PATH | (flags & O_CLOEXEC), 0);
    if (fd < 0) { saved = errno; goto fail; }
    if (fd < minimum) {
        int next = syscall(SYS_fcntl, fd, flags & O_CLOEXEC ? F_DUPFD_CLOEXEC : F_DUPFD, minimum);
        saved = errno;
        syscall(SYS_close, fd);
        fd = next;
        if (fd < 0) goto fail;
    }
    if (fd >= KER_FD_LIMIT || fixed >= KER_FD_LIMIT) { saved = EMFILE; goto fail; }
    pthread_mutex_lock(&mutex);
    if (fixed >= 0 && fixed != fd) {
        if (syscall(SYS_dup3, fd, fixed, flags & O_CLOEXEC) < 0) {
            saved = errno;
            pthread_mutex_unlock(&mutex);
            goto fail;
        }
        syscall(SYS_close, fd);
        fd = fixed;
    }
    struct ker_fd *previous = entries[fd];
    entries[fd] = entry;
    pthread_mutex_unlock(&mutex);
    ker_fd_put(previous);
    return fd;
fail:
    if (fd >= 0) syscall(SYS_close, fd);
    if (host >= 0) syscall(SYS_close, host);
    lkl_sys_close(native);
    free(entry);
    errno = saved;
    return -1;
}
int ker_fd_close(int fd)
{
    pthread_mutex_lock(&mutex);
    struct ker_fd *entry = fd >= 0 && fd < KER_FD_LIMIT ? entries[fd] : NULL;
    if (entry) entries[fd] = NULL;
    long host = syscall(SYS_close, fd);
    int saved = errno;
    pthread_mutex_unlock(&mutex);
    long native = ker_fd_put(entry);
    if (host < 0) { errno = saved; return -1; }
    return error(native);
}
int ker_fd_dup_host(int oldfd, int newfd, int flags)
{
    pthread_mutex_lock(&mutex);
    long result = syscall(SYS_dup3, oldfd, newfd, flags);
    int saved = errno;
    struct ker_fd *previous = NULL;
    if (result >= 0 && newfd < KER_FD_LIMIT) {
        previous = entries[newfd];
        entries[newfd] = NULL;
    }
    pthread_mutex_unlock(&mutex);
    ker_fd_put(previous);
    if (result < 0) errno = saved;
    return (int)result;
}
void ker_fd_close_all(void)
{
    for (int fd = 0; fd < KER_FD_LIMIT; ++fd) {
        struct ker_fd *entry = ker_fd_get(fd);
        if (entry) { ker_fd_close(fd); ker_fd_put(entry); }
    }
}
