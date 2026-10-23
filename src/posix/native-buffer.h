#ifndef KER_NATIVE_BUFFER_H
#define KER_NATIVE_BUFFER_H
#include <stdint.h>
#include <stddef.h>
#include <sys/uio.h>
struct ker_native_buffer_counters { uint64_t allocations, releases, shutdown_releases, live, bytes, option_guards_live; };
/* A token keeps this original socket's SO_ZEROCOPY option stable through a syscall. */
struct ker_native_option_guard;
int ker_native_buffer_option_begin(int native, struct ker_native_option_guard **token);
int ker_native_buffer_send_begin(int native, const struct iovec *iov, size_t count, int flags, struct ker_native_option_guard **token);
void ker_native_buffer_send_end(struct ker_native_option_guard *token);
int ker_native_buffers_close_all(struct ker_native_buffer_counters *counters);
#endif
