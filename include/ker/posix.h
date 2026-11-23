#ifndef KER_POSIX_H
#define KER_POSIX_H
#include <ker/ker.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* These queries belong to the optional ker::posix component, initialized by
 * ker-run. The standard socket APIs are declared by the system POSIX headers. */
KER_API uint64_t ker_posix_capabilities(void);
/* Process-lifetime string, or NULL while the native instance is inactive. */
KER_API const char *ker_posix_kernel_release(void);
/* Allocate zero-initialized, page-aligned memory registered in original Linux
 * VMAs (not host malloc memory). size must be 1..INT_MAX. Returns NULL/errno.
 * Use buffer_free on the exact base, never libc free/munmap. An unknown base
 * fails EINVAL without affecting mappings. Both require an active native
 * instance. Do not race access/free/shutdown. Outstanding buffers are unmapped
 * after socket drain during native shutdown, invalidating every returned pointer.
 * Suitable for original Linux MSG_ZEROCOPY page references; callers must enable
 * SO_ZEROCOPY and process MSG_ERRQUEUE completion ranges, including COPIED,
 * before modifying/releasing referenced bytes. With SO_ZEROCOPY enabled, every
 * nonempty MSG_ZEROCOPY iovec must be contained within one allocated buffer;
 * other ranges fail EFAULT before Linux page lookup. Without SO_ZEROCOPY, the
 * flag retains original Linux ignored-flag/copy semantics for host memory.
 * sendmmsg keeps an accepted prefix when a later message has an invalid range.
 * This API does not remove copies
 * in the cross-process packet channel and is not end-to-end zero-copy. */
KER_API void *ker_posix_buffer_alloc(size_t size);
KER_API int ker_posix_buffer_free(void *address);
/* Resize a native buffer while preserving min(old_size, size) bytes. A new
 * extent is zero initialized; the address may change even when shrinking.
 * On failure NULL/errno leaves the original mapping valid. NULL with nonzero
 * size allocates. size==0 is a pointer identity/no-op (including NULL or an
 * unregistered pointer): it neither frees nor registers that pointer and does
 * not require an active instance. Other non-NULL inputs must be exact bases.
 * Complete every outstanding send before resize, just as before free; do not
 * race access/resize/free/shutdown. This is not libc realloc memory. */
KER_API void *ker_posix_buffer_realloc(void *address, size_t size);
/* Run the caller's callback on this thread until stop_run is requested.
 * NULL waits for a stop from another thread. Callback return values are ignored.
 * Exactly one run is allowed per native instance; nested/concurrent runs fail
 * EBUSY. A stop request does not interrupt a callback currently executing.
 * On successful return, original Linux is halted and all launcher-owned EAL workers have
 * been reaped. Native sockets are closed and cannot be used afterwards.
 * Before returning from the last callback, the caller must quiesce all other
 * native socket users. Do not cancel/longjmp out of run. stop_run is thread-safe,
 * idempotent and a no-op outside run; it is not async-signal-safe.
 * Returns 0 on complete teardown, -1/errno on failure (including ENETDOWN after
 * an earlier run). Requires ker-run's private supervisor channel. */
typedef int (*ker_posix_loop_func)(void *argument);
KER_API int ker_posix_run(ker_posix_loop_func loop, void *argument);
KER_API void ker_posix_stop_run(void);
#ifdef __cplusplus
}
#endif
#endif
