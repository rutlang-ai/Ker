#ifndef KER_POSIX_RUN_LOOP_H
#define KER_POSIX_RUN_LOOP_H
/* Private host control channel; never a native Linux socket. */
int ker_run_control_init(int fd);
void ker_run_control_close(void);
#endif
