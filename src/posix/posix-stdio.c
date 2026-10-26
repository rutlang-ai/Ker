#define _GNU_SOURCE
#include "fd-table.h"
#include "lifecycle.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <lkl.h>

struct native_stream {
    struct native_stream *next;
    FILE *stream;
    atomic_int fd;
};
static pthread_mutex_t streams_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct native_stream *streams;
static atomic_bool flushing;
static atomic_int flush_error;

static ssize_t stream_read(void *opaque, char *bytes, size_t length)
{
    struct native_stream *cookie = opaque;
    int fd = atomic_load_explicit(&cookie->fd, memory_order_acquire);
    if (fd < 0) { errno = EBADF; return -1; }
    return read(fd, bytes, length);
}
static ssize_t stream_write(void *opaque, const char *bytes, size_t length)
{
    struct native_stream *cookie = opaque;
    int fd = atomic_load_explicit(&cookie->fd, memory_order_acquire);
    ssize_t result;
    if (fd < 0) { errno = EBADF; result = -1; }
    else result = write(fd, bytes, length);
    if (result < 0 || (!result && length)) {
        int error = result < 0 ? errno : EIO;
        if (atomic_load_explicit(&flushing, memory_order_relaxed)) {
            int expected = 0;
            atomic_compare_exchange_strong_explicit(&flush_error, &expected, error,
                memory_order_relaxed, memory_order_relaxed);
        }
        errno = error;
        return 0; /* GNU cookie write callbacks report an error with zero. */
    }
    return result;
}
static int stream_seek(void *opaque, off64_t *offset, int whence)
{
    struct native_stream *cookie = opaque;
    int fd = atomic_load_explicit(&cookie->fd, memory_order_acquire);
    if (fd < 0) { errno = EBADF; return -1; }
    off_t result = lseek(fd, (off_t)*offset, whence);
    if (result < 0) return -1;
    *offset = result;
    return 0;
}
static int stream_close(void *opaque)
{
    struct native_stream *cookie = opaque;
    pthread_mutex_lock(&streams_mutex);
    struct native_stream **link = &streams;
    while (*link && *link != cookie) link = &(*link)->next;
    if (*link) *link = cookie->next;
    pthread_mutex_unlock(&streams_mutex);
    int fd = atomic_exchange_explicit(&cookie->fd, -1, memory_order_acq_rel);
    int result;
    if (fd < 0) { errno = EBADF; result = -1; }
    else result = close(fd);
    int saved = errno;
    free(cookie);
    errno = saved;
    return result;
}
static bool stream_descriptor(FILE *stream, int *fd)
{
    bool found = false;
    pthread_mutex_lock(&streams_mutex);
    for (struct native_stream *cookie = streams; cookie; cookie = cookie->next)
        if (cookie->stream == stream) {
            *fd = atomic_load_explicit(&cookie->fd, memory_order_acquire);
            found = true; break;
        }
    pthread_mutex_unlock(&streams_mutex);
    return found;
}
FILE *fdopen(int fd, const char *mode)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) {
        FILE *(*original)(int, const char *) = dlsym(RTLD_NEXT, "fdopen");
        if (original) return original(fd, mode);
        errno = ENOSYS; return NULL;
    }
    int error = EINVAL;
    FILE *stream = NULL;
    if (!ker_native_ready()) { error = ENETDOWN; goto done; }
    char base = mode[0];
    if (base != 'r' && base != 'w' && base != 'a') goto done;
    bool update = false;
    /* Match glibc fdopen's mode scan, then normalize for fopencookie. */
    for (int i = 1; i < 5 && mode[i]; ++i) if (mode[i] == '+') { update = true; break; }
    long flags = lkl_sys_fcntl(entry->native, F_GETFL, 0);
    if (flags < 0) { error = (int)-flags; goto done; }
    if (((flags & O_ACCMODE) == O_RDONLY && (update || base != 'r')) ||
        ((flags & O_ACCMODE) == O_WRONLY && (update || base == 'r'))) goto done;
    if (base == 'a' && !(flags & O_APPEND)) {
        long changed = lkl_sys_fcntl(entry->native, F_SETFL, flags | O_APPEND);
        if (changed < 0) { error = (int)-changed; goto done; }
    }
    struct native_stream *cookie = calloc(1, sizeof(*cookie));
    if (!cookie) { error = ENOMEM; goto done; }
    atomic_init(&cookie->fd, fd);
    char normalized[] = {base, update ? '+' : '\0', '\0'};
    cookie_io_functions_t functions = {stream_read, stream_write, stream_seek, stream_close};
    stream = fopencookie(cookie, normalized, functions);
    if (!stream) { error = errno; free(cookie); goto done; }
    cookie->stream = stream;
    pthread_mutex_lock(&streams_mutex);
    cookie->next = streams; streams = cookie;
    pthread_mutex_unlock(&streams_mutex);
done:
    ker_fd_put(entry);
    if (!stream) errno = error;
    return stream;
}
FILE *_IO_fdopen(int fd, const char *mode) { return fdopen(fd, mode); }
int fileno(FILE *stream)
{
    int fd;
    if (stream_descriptor(stream, &fd)) { if (fd < 0) errno = EBADF; return fd; }
    int (*original)(FILE *) = dlsym(RTLD_NEXT, "fileno");
    if (original) return original(stream);
    errno = ENOSYS; return -1;
}
int fileno_unlocked(FILE *stream) { return fileno(stream); }
#define REOPEN(name) \
FILE *name(const char *path, const char *mode, FILE *stream) \
{ \
    int fd; \
    if (stream_descriptor(stream, &fd)) { errno = EOPNOTSUPP; return NULL; } \
    FILE *(*original)(const char *, const char *, FILE *) = dlsym(RTLD_NEXT, #name); \
    if (original) return original(path, mode, stream); \
    errno = ENOSYS; return NULL; \
}
REOPEN(freopen)
REOPEN(freopen64)

int ker_native_stdio_shutdown(void)
{
    atomic_store_explicit(&flush_error, 0, memory_order_relaxed);
    atomic_store_explicit(&flushing, true, memory_order_relaxed);
    /* libc owns FILE locking/lifetime during this traversal. Never hold the
     * registry mutex while acquiring FILE locks (fclose takes them in reverse). */
    (void)fflush(NULL);
    atomic_store_explicit(&flushing, false, memory_order_relaxed);
    pthread_mutex_lock(&streams_mutex);
    for (struct native_stream *cookie = streams; cookie; cookie = cookie->next)
        atomic_store_explicit(&cookie->fd, -1, memory_order_release);
    pthread_mutex_unlock(&streams_mutex);
    /* Subsequent fclose can free the cookie but must never close a reused host
     * fd after ker_fd_close_all has retired the original reservations. */
    return -atomic_load_explicit(&flush_error, memory_order_relaxed);
}
