/* Original Linux VMA-backed memory for native socket buffer page references. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include "native-buffer.h"
#include "fd-table.h"
#include "syscall-result.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <lkl.h>
#include <lkl/linux/mman.h>
struct mapping { struct mapping *next; void *address; size_t size; };
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct mapping *mappings;
static struct ker_native_buffer_counters totals;
/* Caller holds lock and has validated the native lifetime and size. */
static struct mapping *allocate(size_t size)
{
    struct mapping *item = malloc(sizeof(*item));
    if (!item) return NULL;
    void *address = lkl_sys_mmap(NULL, size, LKL_PROT_READ | LKL_PROT_WRITE,
        LKL_MAP_PRIVATE | LKL_MAP_ANONYMOUS, -1, 0);
    if ((uintptr_t)address >= (uintptr_t)-4095) {
        int error = (int)-(long)address;
        free(item); errno = error; return NULL;
    }
    *item = (struct mapping){.next = mappings, .address = address, .size = size};
    mappings = item;
    totals.allocations++; totals.live++; totals.bytes += size;
    return item;
}
void *ker_posix_buffer_alloc(size_t size)
{
    if (!size || size > INT_MAX) { errno = EINVAL; return NULL; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return NULL; }
    struct mapping *item = allocate(size);
    void *address = item ? item->address : NULL;
    pthread_mutex_unlock(&lock);
    return address;
}
static long release(struct mapping *item, bool shutdown)
{
    long result = lkl_sys_munmap((uintptr_t)item->address, item->size);
    if (!result) {
        totals.releases++; totals.live--; totals.bytes -= item->size;
        if (shutdown) totals.shutdown_releases++;
    }
    return result;
}
int ker_posix_buffer_free(void *address)
{
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return -1; }
    struct mapping **slot = &mappings;
    while (*slot && (*slot)->address != address) slot = &(*slot)->next;
    if (!*slot) { pthread_mutex_unlock(&lock); errno = EINVAL; return -1; }
    struct mapping *item = *slot;
    long result = release(item, false);
    if (!result) { *slot = item->next; free(item); }
    pthread_mutex_unlock(&lock);
    return (int)ker_native_result(result);
}
/* Keep the old mapping until both allocation and copying have succeeded.
 * This adapts the native memory domain; libc realloc cannot resize LKL VMAs. */
void *ker_posix_buffer_realloc(void *address, size_t size)
{
    /* F-Stack's zero-size helper is an identity operation even for a foreign
     * sentinel. Do not dereference, validate ownership or grant registration. */
    if (!size) return address;
    if (!address) return ker_posix_buffer_alloc(size);
    if (size > INT_MAX) { errno = EINVAL; return NULL; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return NULL; }
    struct mapping *old = mappings;
    while (old && old->address != address) old = old->next;
    if (!old) { pthread_mutex_unlock(&lock); errno = EINVAL; return NULL; }
    if (size == old->size) { pthread_mutex_unlock(&lock); return address; }
    struct mapping *fresh = allocate(size);
    if (!fresh) { pthread_mutex_unlock(&lock); return NULL; }
    memcpy(fresh->address, old->address, size < old->size ? size : old->size);
    long result = release(old, false);
    struct mapping *removed = result ? fresh : old;
    /* If releasing the old mapping fails, roll back only the fresh one. A
     * failed rollback remains registered for shutdown reclamation. */
    if (!result || !release(fresh, false)) {
        struct mapping **slot = &mappings;
        while (*slot != removed) slot = &(*slot)->next;
        *slot = removed->next;
        free(removed);
    }
    void *resized = result ? NULL : fresh->address;
    if (result) errno = (int)-result;
    pthread_mutex_unlock(&lock);
    return resized;
}
static int zerocopy_enabled(int native)
{
    int enabled = 0;
    int size = sizeof(enabled);
    long result = lkl_sys_getsockopt(native, SOL_SOCKET, SO_ZEROCOPY, (char *)&enabled, &size);
    return result < 0 ? (int)result : !!enabled;
}
/* SO_COOKIE identifies the original socket across dup aliases. Do not hold
 * the mapping registry while a blocking send waits for a receiver that may
 * need to allocate another buffer. Unrelated sockets use independent locks. */
struct ker_native_option_guard {
    struct ker_native_option_guard *next;
    uint64_t cookie;
    unsigned users;
    pthread_mutex_t mutex;
};
static pthread_mutex_t guards_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ker_native_option_guard *guards;
int ker_native_buffer_option_begin(int native, struct ker_native_option_guard **token)
{
    *token = NULL;
    if (!ker_native_ready()) return -ENETDOWN;
    uint64_t cookie;
    int size = sizeof(cookie);
    long result = lkl_sys_getsockopt(native, SOL_SOCKET, SO_COOKIE, (char *)&cookie, &size);
    if (result < 0) return (int)result;
    if (size != sizeof(cookie)) return -EIO;
    pthread_mutex_lock(&guards_lock);
    struct ker_native_option_guard *guard = guards;
    while (guard && guard->cookie != cookie) guard = guard->next;
    if (!guard) {
        guard = malloc(sizeof(*guard));
        if (!guard) { pthread_mutex_unlock(&guards_lock); return -ENOMEM; }
        *guard = (struct ker_native_option_guard){.cookie = cookie, .next = guards};
        int error = pthread_mutex_init(&guard->mutex, NULL);
        if (error) { free(guard); pthread_mutex_unlock(&guards_lock); return -error; }
        guards = guard;
    }
    guard->users++;
    pthread_mutex_unlock(&guards_lock);
    pthread_mutex_lock(&guard->mutex);
    *token = guard;
    return 0;
}
void ker_native_buffer_send_end(struct ker_native_option_guard *token)
{
    if (!token) return;
    pthread_mutex_unlock(&token->mutex);
    pthread_mutex_lock(&guards_lock);
    if (!--token->users) {
        struct ker_native_option_guard **slot = &guards;
        while (*slot != token) slot = &(*slot)->next;
        *slot = token->next;
        pthread_mutex_destroy(&token->mutex);
        free(token);
    }
    pthread_mutex_unlock(&guards_lock);
}
int ker_native_buffer_send_begin(int native, const struct iovec *iov, size_t count, int flags,
    struct ker_native_option_guard **token)
{
    *token = NULL;
    if (!(flags & MSG_ZEROCOPY)) return 0;
    int error = ker_native_buffer_option_begin(native, token);
    if (error) return error;
    int enabled = zerocopy_enabled(native);
    if (enabled < 0) error = enabled;
    else if (!enabled) return 0; /* Original Linux ignored-flag/copy semantics. */
    else if (count > IOV_MAX) error = -EMSGSIZE;
    else if (count && !iov) error = -EFAULT;
    if (!error) {
        pthread_mutex_lock(&lock);
        for (size_t i = 0; i < count; i++) {
            if (!iov[i].iov_len) continue;
            uintptr_t start = (uintptr_t)iov[i].iov_base;
            bool found = false;
            for (struct mapping *item = mappings; item; item = item->next) {
                uintptr_t base = (uintptr_t)item->address;
                if (start >= base && start - base < item->size &&
                    iov[i].iov_len <= item->size - (start - base)) { found = true; break; }
            }
            if (!found) { error = -EFAULT; break; }
        }
        pthread_mutex_unlock(&lock);
    }
    if (error) { ker_native_buffer_send_end(*token); *token = NULL; }
    return error;
}

int ker_native_buffers_close_all(struct ker_native_buffer_counters *counters)
{
    int error = 0;
    pthread_mutex_lock(&lock);
    while (mappings) {
        struct mapping *item = mappings;
        long result = release(item, true);
        if (result && !error) error = (int)result;
        mappings = item->next; free(item);
    }
    pthread_mutex_lock(&guards_lock);
    for (struct ker_native_option_guard *guard = guards; guard; guard = guard->next) totals.option_guards_live++;
    pthread_mutex_unlock(&guards_lock);
    if (totals.option_guards_live && !error) error = -EBUSY;
    *counters = totals;
    pthread_mutex_unlock(&lock);
    return error;
}
