#ifndef KER_POSIX_LIFECYCLE_H
#define KER_POSIX_LIFECYCLE_H
#include <stdbool.h>
/* Observe the native procfs send queues while Linux's scheduler and timers
 * continue to run. Returns zero after queues drain, or a negative errno. */
int ker_native_drain(unsigned int timeout_ms);
/* One-shot kernel/device teardown; also called by the preload destructor. */
int ker_native_finalize(void);
/* Process-copy boundary remains active once initialization begins. */
bool ker_native_process_isolated(void);
#endif
