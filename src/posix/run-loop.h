#ifndef KER_POSIX_RUN_LOOP_H
#define KER_POSIX_RUN_LOOP_H
/* Private host control channel; never a native Linux socket. */
int ker_run_control_init(int fd);
void ker_run_control_close(void);
#ifdef KER_C31_RX_DECISION_TESTING
#define KER_C31_TEST_API __attribute__((visibility("default")))
/* BUILD_TESTING-only barrier: after native prepare/drain, write 0x5a to
 * ready_fd, then wait for 0xa5 on release_fd before consumer settlement. */
KER_C31_TEST_API int ker_posix_run_test_set_shutdown_barrier(int ready_fd,
    int release_fd);
#endif
#endif
