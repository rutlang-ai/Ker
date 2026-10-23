#ifndef KER_POSIX_LIFECYCLE_H
#define KER_POSIX_LIFECYCLE_H
/* Observe the native procfs send queues while Linux's scheduler and timers
 * continue to run. Returns zero after queues drain, or a negative errno. */
int ker_native_drain(unsigned int timeout_ms);
/* One-shot kernel/device teardown; also called by the preload destructor. */
int ker_native_finalize(void);
#endif
