#define _GNU_SOURCE
#include "fd-table.h"
#include "syscall-result.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct ker_fd *entries[KER_FD_LIMIT];
static struct ker_fd *private_hosts;
struct host_snapshot { int fd; struct host_snapshot *next; };
static struct host_snapshot *snapshots;

static void register_private(struct ker_fd *entry)
{
    if (entry->kind == KER_FD_EPOLL && entry->host >= 0) {
        entry->private_next = private_hosts;
        private_hosts = entry;
    }
}
static void unregister_private(struct ker_fd *entry)
{
    struct ker_fd **link = &private_hosts;
    while (*link && *link != entry) link = &(*link)->private_next;
    if (*link) *link = entry->private_next;
    entry->private_next = NULL;
}
static int relocate_private(int fd)
{
    for (struct ker_fd *entry = private_hosts; entry; entry = entry->private_next) {
        if (entry->host != fd) continue;
        int replacement = syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 0);
        if (replacement < 0) return -1;
        entry->host = replacement;
        syscall(SYS_close, fd);
        break;
    }
    return 0;
}
static bool is_snapshot(int fd)
{
    for (struct host_snapshot *snapshot = snapshots; snapshot; snapshot = snapshot->next)
        if (snapshot->fd == fd) return true;
    return false;
}
static void unregister_snapshot(int fd)
{
    struct host_snapshot **link = &snapshots;
    while (*link && (*link)->fd != fd) link = &(*link)->next;
    if (*link) { struct host_snapshot *snapshot = *link; *link = snapshot->next; free(snapshot); }
}
struct ker_fd *ker_fd_get(int fd)
{
    if (fd < 0 || fd >= KER_FD_LIMIT) return NULL;
    pthread_mutex_lock(&mutex);
    struct ker_fd *entry = entries[fd];
    if (entry) atomic_fetch_add_explicit(&entry->references, 1, memory_order_relaxed);
    pthread_mutex_unlock(&mutex);
    return entry;
}
int ker_fd_same_file(int fd, int other)
{
    pthread_mutex_lock(&mutex);
    struct ker_fd *left = fd >= 0 && fd < KER_FD_LIMIT ? entries[fd] : NULL;
    struct ker_fd *right = other >= 0 && other < KER_FD_LIMIT ? entries[other] : NULL;
    if (left && right) {
        atomic_fetch_add_explicit(&left->references, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&right->references, 1, memory_order_relaxed);
        pthread_mutex_unlock(&mutex);
        long result = lkl_sys_fcntl(left->native, KER_F_DUPFD_QUERY, right->native);
        ker_fd_put(right); ker_fd_put(left);
        return ker_native_result(result);
    }
    /* Keep host classification and the host syscall in the same critical
     * section as dup2/close. No temporary fd allocation is needed. */
    long result;
    if (!left && !right) result = syscall(SYS_fcntl, fd, KER_F_DUPFD_QUERY, other);
    else result = syscall(SYS_fcntl, left ? other : fd, F_GETFD) < 0 ? -1 : 0;
    int saved = errno;
    pthread_mutex_unlock(&mutex);
    errno = saved;
    return (int)result;
}
long ker_fd_put(struct ker_fd *entry)
{
    long result = 0;
    if (entry && atomic_fetch_sub_explicit(&entry->references, 1, memory_order_acq_rel) == 1) {
        pthread_mutex_lock(&mutex);
        unregister_private(entry);
        int host = entry->host;
        entry->host = -1;
        if (host >= 0) syscall(SYS_close, host);
        pthread_mutex_unlock(&mutex);
        result = lkl_sys_close(entry->native);
        free(entry);
    }
    return result;
}
int ker_fd_export(int native, enum ker_fd_kind kind, int host, int flags,
    int minimum, int fixed)
{
    struct ker_fd *entry = calloc(1, sizeof(*entry));
    int fd = -1, saved = ENOMEM;
    bool locked = false;
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
    locked = true;
    register_private(entry);
    if (host >= 0) {
        struct host_snapshot **link = &snapshots;
        while (*link && (*link)->fd != host) link = &(*link)->next;
        if (*link) { struct host_snapshot *snapshot = *link; *link = snapshot->next; free(snapshot); }
    }
    if (fixed >= 0 && fixed != fd) {
        if (is_snapshot(fixed) || relocate_private(fixed) < 0) {
            saved = is_snapshot(fixed) ? EBUSY : errno;
            goto fail;
        }
        host = entry->host;
        if (syscall(SYS_dup3, fd, fixed, flags & O_CLOEXEC) < 0) {
            saved = errno;
            goto fail;
        }
        syscall(SYS_close, fd);
        fd = fixed;
    }
    struct ker_fd *previous = entries[fd];
    entries[fd] = entry;
    pthread_mutex_unlock(&mutex);
    locked = false;
    ker_fd_put(previous);
    return fd;
fail:
    if (!locked) pthread_mutex_lock(&mutex);
    if (entry) unregister_private(entry);
    if (entry && entry->host >= 0) host = entry->host;
    if (host >= 0) {
        unregister_snapshot(host);
        syscall(SYS_close, host);
        if (entry) entry->host = -1;
    }
    pthread_mutex_unlock(&mutex);
    if (fd >= 0) syscall(SYS_close, fd);
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
    return (int)ker_native_result(native);
}
int ker_fd_dup_host(int oldfd, int newfd, int flags)
{
    pthread_mutex_lock(&mutex);
    int result;
    if (is_snapshot(newfd)) { errno = EBUSY; result = -1; }
    else if (relocate_private(newfd) < 0) result = -1;
    else result = syscall(SYS_dup3, oldfd, newfd, flags);
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
int ker_fd_host_dup(struct ker_fd *entry)
{
    pthread_mutex_lock(&mutex);
    int fd = entry && entry->host >= 0 ? syscall(SYS_fcntl, entry->host, F_DUPFD_CLOEXEC, 0) : -1;
    int saved = errno;
    struct host_snapshot *snapshot = fd < 0 ? NULL : malloc(sizeof(*snapshot));
    if (fd >= 0 && !snapshot) { syscall(SYS_close, fd); fd = -1; saved = ENOMEM; }
    if (fd >= 0) { snapshot->fd = fd; snapshot->next = snapshots; snapshots = snapshot; }
    pthread_mutex_unlock(&mutex);
    if (fd < 0) errno = saved;
    return fd;
}
void ker_fd_host_put(int fd)
{
    pthread_mutex_lock(&mutex);
    struct host_snapshot **link = &snapshots;
    while (*link && (*link)->fd != fd) link = &(*link)->next;
    if (*link) { struct host_snapshot *snapshot = *link; *link = snapshot->next; free(snapshot); }
    syscall(SYS_close, fd);
    pthread_mutex_unlock(&mutex);
}
int ker_fd_epoll_host_create(int flags)
{
    pthread_mutex_lock(&mutex);
    int fd = syscall(SYS_epoll_create1, flags | EPOLL_CLOEXEC);
    int saved = errno;
    struct host_snapshot *snapshot = fd < 0 ? NULL : malloc(sizeof(*snapshot));
    if (fd >= 0 && !snapshot) { syscall(SYS_close, fd); fd = -1; saved = ENOMEM; }
    if (fd >= 0) { snapshot->fd = fd; snapshot->next = snapshots; snapshots = snapshot; }
    pthread_mutex_unlock(&mutex);
    if (fd < 0) errno = saved;
    return fd;
}
void ker_fd_close_all(void)
{
    for (int fd = 0; fd < KER_FD_LIMIT; ++fd) {
        struct ker_fd *entry = ker_fd_get(fd);
        if (entry) { ker_fd_close(fd); ker_fd_put(entry); }
    }
}

int close_range(unsigned first, unsigned last, int flags)
{
    if (first > last || (flags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC))) {
        errno = EINVAL; return -1;
    }
    /* CLOEXEC belongs to the application's host reservations. Closing or
     * unsharing the host table would strand native entries and can also close
     * runtime-private channels; expose that unsupported boundary explicitly. */
    pthread_mutex_lock(&mutex);
    bool native = ker_native_ready() || private_hosts || snapshots;
    if (!native) for (int fd = 0; fd < KER_FD_LIMIT; ++fd)
        if (entries[fd]) { native = true; break; }
    long value;
    if (native && flags != CLOSE_RANGE_CLOEXEC) { errno = EOPNOTSUPP; value = -1; }
    else value = syscall(SYS_close_range, first, last, flags);
    int saved = errno;
    pthread_mutex_unlock(&mutex);
    if (value < 0) errno = saved;
    return value;
}
