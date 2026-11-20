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
 * fails EINVAL without affecting mappings. Writer-owned storage fails EBUSY. Both require an active native
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
/* Copy length bytes into a registered native buffer at an explicit offset.
 * address must be its exact allocation base, data must be non-NULL and readable
 * for length bytes. Offset/length must fit the requested allocation size,
 * including for length==0; a valid zero-length write returns 0 without touching
 * bytes. Overlap has memmove semantics. Returns bytes copied (0..INT_MAX), or
 * -1/errno: EINVAL for invalid arguments/ranges/bases, ENETDOWN while inactive.
 * Rejection leaves every mapping and byte unchanged. This does not resize the
 * allocation or maintain an implicit packet/write cursor. Complete outstanding
 * zerocopy sends before modifying referenced bytes; do not race writes with
 * sends, direct accesses, resize, free or shutdown. */
KER_API int ker_posix_buffer_write(void *address, size_t offset, const void *data, size_t length);
/* Resize a native buffer while preserving min(old_size, size) bytes. A new
 * extent is zero initialized; the address may change even when shrinking.
 * On failure NULL/errno leaves the original mapping valid. NULL with nonzero
 * size allocates. size==0 is a pointer identity/no-op (including NULL or an
 * unregistered pointer): it neither frees nor registers that pointer and does
 * not require an active instance. Other non-NULL inputs must be exact bases.
 * Complete every outstanding send before resize, just as before free; do not
 * race access/resize/free/shutdown. This is not libc realloc memory. */
KER_API void *ker_posix_buffer_realloc(void *address, size_t size);
/* An owned append cursor over one registered original-Linux VMA. Capacity is
 * 0..INT_MAX; zero capacity owns a minimal one-byte backing allocation, while
 * its logical capacity/length stay zero. Raw buffer_alloc(0) still fails.
 * Handles are opaque. create returns NULL/errno; append returns copied bytes
 * or -1/errno, and advances length only on success. NULL data is invalid even
 * for zero length; a valid zero append does not change bytes or length.
 * view returns borrowed read-only data and optional length/capacity outputs;
 * on failure it returns NULL/errno without changing outputs. destroy returns
 * 0 or -1/errno; failed unmap retains the owner for retry. Unknown handles and
 * invalid capacities/append ranges fail EINVAL; inactive operations fail
 * ENETDOWN. Raw buffer_free/write/nonzero-realloc of writer storage fail EBUSY.
 * Synchronize owner access/transfer; wait for all zerocopy completions before
 * append/destroy. Send only the viewed length. Shutdown reclaims outstanding
 * owners and invalidates every handle/view. Destroy releases its VMA
 * immediately but retains registration metadata until native shutdown to
 * prevent allocator address reuse from making a stale handle refer to a new
 * owner; this is a deliberate per-runtime memory tradeoff. This is one VMA,
 * not a FreeBSD mbuf chain, and does not change ordinary Linux send semantics. */
struct ker_posix_buffer_writer;
KER_API struct ker_posix_buffer_writer *ker_posix_buffer_writer_create(size_t capacity);
KER_API int ker_posix_buffer_writer_append(struct ker_posix_buffer_writer *writer, const void *data, size_t length);
KER_API const void *ker_posix_buffer_writer_view(struct ker_posix_buffer_writer *writer, size_t *length, size_t *capacity);
KER_API int ker_posix_buffer_writer_destroy(struct ker_posix_buffer_writer *writer);
/* Segmented owned writer: capacity and segment_capacity must be 1..INT_MAX,
 * with at most IOV_MAX VMAs. append fills nodes in order, atomically advancing
 * the aggregate length. Segment views expose borrowed data, used bytes, local
 * capacity and aggregate length; invalid indices preserve all outputs.
 * Ordinary view/send reject segmented writers with EOPNOTSUPP. Use segment
 * views with native sendmsg; synchronize access and await all completions.
 * Partial destroy failures retain a retry handle: after any segment is freed,
 * append/views fail EBUSY until destroy succeeds. Shutdown reclaims residuals.
 * Handles retain their identity until shutdown, as for single-VMA writers. */
KER_API struct ker_posix_buffer_writer *ker_posix_buffer_writer_create_segmented(size_t capacity, size_t segment_capacity);
KER_API const void *ker_posix_buffer_writer_segment(struct ker_posix_buffer_writer *writer, size_t index,
    size_t *length, size_t *capacity, size_t *total_length);
/* Send a nonempty written range through an imported native socket. Bounds and
 * zero length fail EINVAL before sending; unregistered host descriptors fail
 * EBADF and native non-sockets fail ENOTSOCK. Returns accepted bytes or
 * -1/errno from original Linux. Flags, short sends and SIGPIPE follow send().
 * The writer/view/cursor stay caller-owned and unchanged on every outcome;
 * callers advance offset after short sends and wait for completions before
 * append/destroy. Do not race owner access or native shutdown. Ordinary send()
 * retains Linux empty-datagram behavior; this explicit owned-payload API rejects 0. */
KER_API int ker_posix_buffer_writer_send(struct ker_posix_buffer_writer *writer, int fd,
    size_t offset, size_t length, int flags);
/* Run callbacks synchronously on the calling thread until requested to stop.
 * A NULL callback waits for a stop from another thread. Callback results
 * are ignored. Only one run may own the native instance. A successful run
 * closes native sockets, halts Linux and waits for the launcher to reap
 * its DPDK worker. The application may continue using host resources. */
typedef int (*ker_posix_loop_func)(void *argument);
KER_API int ker_posix_run(ker_posix_loop_func callback, void *argument);
KER_API void ker_posix_stop_run(void);
/* Read the active original Linux CLOCK_REALTIME. Each output is optional.
 * Returns 0 on success or -1 with errno and leaves outputs intact on failure.
 * An inactive instance reports ENETDOWN. Quiesce callers before shutdown. */
KER_API int ker_posix_get_current_time(int64_t *seconds, long *nanoseconds);
#ifdef __cplusplus
}
#endif
#endif
