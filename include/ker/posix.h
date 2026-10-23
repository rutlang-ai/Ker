#ifndef KER_POSIX_H
#define KER_POSIX_H
#include <ker/ker.h>
#ifdef __cplusplus
extern "C" {
#endif
/* These queries belong to the optional ker::posix component, initialized by
 * ker-run. The standard socket APIs are declared by the system POSIX headers. */
KER_API uint64_t ker_posix_capabilities(void);
/* Process-lifetime string, or NULL while the native instance is inactive. */
KER_API const char *ker_posix_kernel_release(void);
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
