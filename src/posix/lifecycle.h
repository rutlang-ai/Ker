#ifndef KER_POSIX_LIFECYCLE_H
#define KER_POSIX_LIFECYCLE_H
#include <stdbool.h>
typedef int (*ker_native_drain_progress_fn)(void *context);
/* Observe the native procfs send queues while Linux's scheduler and timers
 * continue to run. Returns zero after queues drain, or a negative errno. */
int ker_native_drain(unsigned int timeout_ms);
/* Same bounded drain, with a progress hook called between queue snapshots. */
int ker_native_drain_with_progress(unsigned int timeout_ms,
    ker_native_drain_progress_fn progress, void *context);
/* Run shutdown once: flush/close app descriptors and drain native send queues.
 * Return is the preparation status (zero means PREPARED); drain_result carries
 * a retained drain/flush error that finish reports after completing teardown.
 * With a non-NULL progress hook, potentially blocking census/stdio/fd cleanup
 * runs on one tracked helper while this caller remains the sole progress owner.
 * The hook must be bounded and must not wait on stdio or application locks that
 * cleanup may hold. An EBUSY retry must use the exact same hook and context;
 * cleanup continues on the helper until it is joined and preparation completes.
 * A NULL hook retains synchronous cleanup. */
int ker_native_finalize_prepare(ker_native_drain_progress_fn progress,
    void *context, int *drain_result);
/* Halt the native stack after prepare and any external consumer settlement.
 * Return is the phase status; finalize_result is the retained shutdown error. */
int ker_native_finalize_finish(int *finalize_result);
/* One-shot kernel/device teardown; also called by the preload destructor. */
int ker_native_finalize(void);
/* Process-copy boundary remains active once initialization begins. */
bool ker_native_process_isolated(void);
int ker_native_stdio_shutdown(void);
#endif
