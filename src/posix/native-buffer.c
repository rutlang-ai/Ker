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
struct mapping {
    struct mapping *next;
    void *address;
    size_t size;
    bool writer_owned, writer_root, segmented, retiring;
    struct mapping *segment_next;
    size_t capacity, written;
};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct mapping *mappings;
/* Destroyed writer records are kept off the live VMA registry until native
 * shutdown so malloc cannot recycle a stale opaque handle during this runtime. */
static struct mapping *retired_writers;
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
    if (item->writer_owned) { pthread_mutex_unlock(&lock); errno = EBUSY; return -1; }
    long result = release(item, false);
    if (!result) { *slot = item->next; free(item); }
    pthread_mutex_unlock(&lock);
    return (int)ker_native_result(result);
}
/* Bounds refer to the requested extent, not the Linux page-rounded VMA.
 * Keep ownership stable through the copy; no socket/protocol semantics live here. */
int ker_posix_buffer_write(void *address, size_t offset, const void *data, size_t length)
{
    if (!address || !data) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return -1; }
    struct mapping *item = mappings;
    while (item && item->address != address) item = item->next;
    if (item && item->writer_owned) { pthread_mutex_unlock(&lock); errno = EBUSY; return -1; }
    if (!item || offset > item->size || length > item->size - offset) {
        pthread_mutex_unlock(&lock); errno = EINVAL; return -1;
    }
    if (length) memmove((unsigned char *)address + offset, data, length);
    pthread_mutex_unlock(&lock);
    return (int)length; /* Allocations and therefore accepted lengths fit INT_MAX. */
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
    if (old->writer_owned) { pthread_mutex_unlock(&lock); errno = EBUSY; return NULL; }
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
/* Compare opaque handle values before dereferencing. Caller holds lock. */
static struct mapping *writer_mapping(struct ker_posix_buffer_writer *writer)
{
    for (struct mapping *item = mappings; item; item = item->next)
        if ((void *)item == (void *)writer && item->writer_root) return item;
    return NULL;
}
struct ker_posix_buffer_writer *ker_posix_buffer_writer_create(size_t capacity)
{
    if (capacity > INT_MAX) { errno = EINVAL; return NULL; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return NULL; }
    struct mapping *item = allocate(capacity ? capacity : 1);
    if (item) { item->writer_owned = true; item->writer_root = true; item->capacity = capacity; }
    pthread_mutex_unlock(&lock);
    return (struct ker_posix_buffer_writer *)item;
}
/* Each node remains a separate registered original-Linux VMA. Failed creation
 * leaves only an unmappable rollback failure registered for shutdown cleanup. */
struct ker_posix_buffer_writer *ker_posix_buffer_writer_create_segmented(size_t capacity, size_t segment_capacity)
{
    if (!capacity || capacity > INT_MAX || !segment_capacity || segment_capacity > INT_MAX ||
        (capacity - 1) / segment_capacity >= IOV_MAX) { errno = EINVAL; return NULL; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return NULL; }
    struct mapping *head = NULL, *tail = NULL;
    size_t remaining = capacity;
    while (remaining) {
        size_t size = remaining < segment_capacity ? remaining : segment_capacity;
        struct mapping *node = allocate(size);
        if (!node) {
            int saved = errno;
            while (head) {
                struct mapping *next = head->segment_next;
                if (!release(head, false)) {
                    struct mapping **slot = &mappings;
                    while (*slot != head) slot = &(*slot)->next;
                    *slot = head->next; free(head);
                }
                head = next;
            }
            pthread_mutex_unlock(&lock); errno = saved; return NULL;
        }
        node->writer_owned = true;
        if (tail) tail->segment_next = node;
        else head = node;
        tail = node; remaining -= size;
    }
    head->writer_root = true; head->segmented = true; head->capacity = capacity;
    pthread_mutex_unlock(&lock);
    return (struct ker_posix_buffer_writer *)head;
}
const void *ker_posix_buffer_writer_segment(struct ker_posix_buffer_writer *writer, size_t index,
    size_t *length, size_t *capacity, size_t *total_length)
{
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return NULL; }
    struct mapping *head = writer_mapping(writer), *node = head;
    if (head && head->retiring) { pthread_mutex_unlock(&lock); errno = EBUSY; return NULL; }
    size_t offset = 0;
    while (node && index) { offset += node->size; node = node->segment_next; index--; }
    if (!node) { pthread_mutex_unlock(&lock); errno = EINVAL; return NULL; }
    size_t used = head->written > offset ? head->written - offset : 0;
    if (used > node->size) used = node->size;
    if (length) *length = used;
    if (capacity) *capacity = head->segmented ? node->size : head->capacity;
    if (total_length) *total_length = head->written;
    const void *data = node->address;
    pthread_mutex_unlock(&lock);
    return data;
}
int ker_posix_buffer_writer_append(struct ker_posix_buffer_writer *writer, const void *data, size_t length)
{
    if (!writer || !data) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return -1; }
    struct mapping *item = writer_mapping(writer);
    if (item && item->retiring) { pthread_mutex_unlock(&lock); errno = EBUSY; return -1; }
    if (!item || length > item->capacity - item->written) {
        pthread_mutex_unlock(&lock); errno = EINVAL; return -1;
    }
    if (length && item->segmented) {
        /* Snapshot first: source may alias any borrowed segment. Allocation
         * failure must leave all bytes and the aggregate cursor unchanged. */
        unsigned char *copy = malloc(length);
        if (!copy) { pthread_mutex_unlock(&lock); return -1; }
        memcpy(copy, data, length);
        size_t skip = item->written, copied = 0;
        for (struct mapping *node = item; node && copied < length; node = node->segment_next) {
            if (skip >= node->size) { skip -= node->size; continue; }
            size_t count = node->size - skip;
            if (count > length - copied) count = length - copied;
            memcpy((unsigned char *)node->address + skip, copy + copied, count);
            copied += count; skip = 0;
        }
        free(copy);
    } else if (length) memmove((unsigned char *)item->address + item->written, data, length);
    item->written += length;
    pthread_mutex_unlock(&lock);
    return (int)length;
}
const void *ker_posix_buffer_writer_view(struct ker_posix_buffer_writer *writer, size_t *length, size_t *capacity)
{
    if (!writer) { errno = EINVAL; return NULL; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return NULL; }
    struct mapping *item = writer_mapping(writer);
    if (!item) { pthread_mutex_unlock(&lock); errno = EINVAL; return NULL; }
    if (item->retiring || item->segmented) {
        int error = item->retiring ? EBUSY : EOPNOTSUPP;
        pthread_mutex_unlock(&lock); errno = error; return NULL;
    }
    if (length) *length = item->written;
    if (capacity) *capacity = item->capacity;
    const void *data = item->address;
    pthread_mutex_unlock(&lock);
    return data;
}
/* Snapshot addresses only; callers retain the writer and wait for any original
 * Linux zerocopy completion before mutation or destruction, as for views. */
int ker_native_writer_range(struct ker_posix_buffer_writer *writer, size_t offset,
    size_t length, struct iovec *single, struct iovec **vectors, size_t *count)
{
    if (!writer || !length || length > INT_MAX) return -EINVAL;
    pthread_mutex_lock(&lock);
    int error = 0;
    struct mapping *head = writer_mapping(writer);
    if (!ker_native_ready()) error = -ENETDOWN;
    else if (!head) error = -EINVAL;
    else if (head->retiring) error = -EBUSY;
    else if (offset > head->written || length > head->written - offset) error = -EINVAL;
    if (error) { pthread_mutex_unlock(&lock); return error; }
    size_t needed = 0, skip = offset, remaining = length;
    for (struct mapping *node = head; node && remaining; node = node->segment_next) {
        if (skip >= node->size) { skip -= node->size; continue; }
        size_t bytes = node->size - skip;
        if (bytes > remaining) bytes = remaining;
        needed++; remaining -= bytes; skip = 0;
    }
    if (remaining || needed > IOV_MAX) { pthread_mutex_unlock(&lock); return -EINVAL; }
    struct iovec *result = needed == 1 ? single : malloc(needed * sizeof(*result));
    if (!result) { pthread_mutex_unlock(&lock); return -ENOMEM; }
    size_t index = 0; skip = offset; remaining = length;
    for (struct mapping *node = head; node && remaining; node = node->segment_next) {
        if (skip >= node->size) { skip -= node->size; continue; }
        size_t bytes = node->size - skip;
        if (bytes > remaining) bytes = remaining;
        result[index++] = (struct iovec){(unsigned char *)node->address + skip, bytes};
        remaining -= bytes; skip = 0;
    }
    *vectors = result; *count = needed;
    pthread_mutex_unlock(&lock);
    return 0;
}

int ker_posix_buffer_writer_destroy(struct ker_posix_buffer_writer *writer)
{
    if (!writer) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&lock);
    if (!ker_native_ready()) { pthread_mutex_unlock(&lock); errno = ENETDOWN; return -1; }
    struct mapping *item = writer_mapping(writer);
    if (!item) { pthread_mutex_unlock(&lock); errno = EINVAL; return -1; }
    long result = 0;
    /* Release children before the root so a failed partial teardown retains a
     * valid retry handle. Once any child is gone, only destroy is permitted. */
    while (item->segment_next) {
        struct mapping *node = item->segment_next;
        result = release(node, false);
        if (result) break;
        item->segment_next = node->segment_next;
        item->retiring = true;
        struct mapping **slot = &mappings;
        while (*slot != node) slot = &(*slot)->next;
        *slot = node->next;
        node->next = retired_writers; retired_writers = node;
    }
    if (!result) {
        result = release(item, false);
        if (!result) {
            struct mapping **slot = &mappings;
            while (*slot != item) slot = &(*slot)->next;
            *slot = item->next;
            item->next = retired_writers; retired_writers = item;
        }
    }
    pthread_mutex_unlock(&lock);
    return (int)ker_native_result(result);
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
    while (retired_writers) {
        struct mapping *item = retired_writers;
        retired_writers = item->next;
        free(item);
    }
    pthread_mutex_lock(&guards_lock);
    for (struct ker_native_option_guard *guard = guards; guard; guard = guard->next) totals.option_guards_live++;
    pthread_mutex_unlock(&guards_lock);
    if (totals.option_guards_live && !error) error = -EBUSY;
    *counters = totals;
    pthread_mutex_unlock(&lock);
    return error;
}
