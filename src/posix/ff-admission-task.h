#ifndef KER_FF_ADMISSION_TASK_H
#define KER_FF_ADMISSION_TASK_H

#include <stdint.h>
#include <sys/types.h>

struct ker_ff_admission_task;

enum ker_ff_admission_task_status {
	KER_FF_ADMISSION_TASK_STARTING = 0,
	KER_FF_ADMISSION_TASK_READY = 1,
	KER_FF_ADMISSION_TASK_STOPPING = 2,
	KER_FF_ADMISSION_TASK_TERMINAL = 3
};

struct ker_ff_admission_task_config {
	uint32_t owner_mark;
	uint64_t registration_id;
	pid_t actor_pid;
	uid_t actor_uid;
	gid_t actor_gid;
	uint64_t actor_start_time;
	int actor_pidfd;
	int peer_fd;
};

/* Private cross-DSO lifecycle bridge. The task retains authenticated host
 * descriptors and all original-LKL queue/identity state inside ker-posix. */
int ker_posix_ff_admission_task_start(
	const struct ker_ff_admission_task_config *config,
	struct ker_ff_admission_task **task);
int ker_posix_ff_admission_task_poll(struct ker_ff_admission_task *task,
	uint64_t *queue_lease);
int ker_posix_ff_admission_task_set_listener(
	struct ker_ff_admission_task *task, int listener_fd);
int ker_posix_ff_admission_task_listener_closed(
	struct ker_ff_admission_task *task, int listener_fd);
int ker_posix_ff_admission_task_request_stop(
	struct ker_ff_admission_task *task);
int ker_posix_ff_admission_task_release(
	struct ker_ff_admission_task *task);

/* Internal ker-posix run-loop shutdown hook; not part of the broker bridge. */
void ker_ff_admission_task_runtime_shutdown(void);

#endif
