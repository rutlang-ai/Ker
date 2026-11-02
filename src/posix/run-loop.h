#ifndef KER_POSIX_RUN_LOOP_H
#define KER_POSIX_RUN_LOOP_H
/* Private host control channel; never a native Linux socket. */
int ker_run_control_init(int fd);
void ker_run_control_close(void);
#ifdef KER_C31_RX_DECISION_TESTING
/* BUILD_TESTING-only barrier: after the business callback exits, wait for one
 * byte from the harness before cleanup begins. */
int ker_posix_run_test_set_shutdown_barrier(int fd);
#endif
#endif
