#define _GNU_SOURCE
#include "../../src/posix/ff-admission-channel.h"

#include <ker/reload.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "ff_config.h"
#include "ff_flow_map.h"


/* This is a host-only fixture executable, started before ker-run. It owns the
 * unchanged original F-Stack map and never initializes/forks an LKL kernel. */
#include "../../src/compat/reload.c"
#include "../../third_party/fstack-flow-map/ff_flow_map.c"

static int active(void *context)
{
	(void)context;
	return ff_flow_map_active();
}

static int admit(const struct ker_ff_admission_key *key, int *created,
		 void *context)
{
	struct ff_flow_key original;
	(void)context;
	memcpy(&original, key, sizeof(original));
	return ff_flow_map_admit(&original, created);
}

static int map_revoke(const struct ker_ff_admission_key *key, void *context)
{
	struct ff_flow_key original;
	(void)context;
	memcpy(&original, key, sizeof(original));
	return ff_flow_map_revoke(&original);
}

static int write_state(const char *path, const char *value)
{
	int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) return -errno;
	size_t size = strlen(value);
	ssize_t count = syscall(SYS_write, fd, value, size);
	int result = count == (ssize_t)size ? 0 : -EIO;
	if (syscall(SYS_close, fd) && !result) result = -errno;
	return result;
}

static int read_controller(const char *path, pid_t *pid, uint64_t *lease)
{
	char buffer[64];
	int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) return -errno;
	ssize_t count = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1);
	int saved = errno;
	(void)syscall(SYS_close, fd);
	if (count <= 0) return count < 0 ? -saved : -EPROTO;
	buffer[count] = '\0';
	errno = 0;
	char *end = NULL;
	long value = strtol(buffer, &end, 10);
	if (errno || end == buffer || *end != ' ' || value <= 0 || value > INT_MAX)
		return -EPROTO;
	char *lease_end = NULL;
	errno = 0;
	unsigned long long lease_value = strtoull(end + 1, &lease_end, 10);
	if (errno || lease_end == end + 1 || (*lease_end && *lease_end != '\n') || !lease_value)
		return -EPROTO;
	*pid = (pid_t)value;
	*lease = (uint64_t)lease_value;
	return 0;
}

static int wait_controller(const char *path, pid_t *pid, uint64_t *lease)
{
	struct timespec start;
	if (clock_gettime(CLOCK_MONOTONIC, &start)) return -errno;
	for (;;) {
		int result = read_controller(path, pid, lease);
		if (!result) return 0;
		if (result != -ENOENT) return result;
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now)) return -errno;
		if (now.tv_sec - start.tv_sec > 20) return -ETIMEDOUT;
		const struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

int main(int argc, char **argv)
{
	if (argc != 3) return 2;
	const char *path = argv[1];
	const char *prefix = argv[2];
	char state_path[PATH_MAX], controller_path[PATH_MAX];
	if (snprintf(state_path, sizeof(state_path), "%s.state", prefix) >= (int)sizeof(state_path) ||
	    snprintf(controller_path, sizeof(controller_path), "%s.controller", prefix) >= (int)sizeof(controller_path))
		return 2;
	struct stat parent;
	char directory[PATH_MAX];
	if (strlen(path) >= sizeof(directory)) return 2;
	strcpy(directory, path);
	char *slash = strrchr(directory, '/');
	if (!slash) return 2;
	*slash = '\0';
	if (stat(directory, &parent) || parent.st_uid != getuid() ||
	    (parent.st_mode & 0777) != 0700 || !S_ISDIR(parent.st_mode)) return 2;
	int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (listener < 0) return 2;
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	if (strlen(path) >= sizeof(address.sun_path)) return 2;
	strcpy(address.sun_path, path);
	(void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
	if (bind(listener, (struct sockaddr *)&address,
		offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) || listen(listener, 1)) return 2;
	size_t state_size = ker_reload_state_size();
	void *state = calloc(1, state_size);
	if (!state || ker_reload_state_init(state, state_size, 0) ||
	    ker_reload_bind_state(state, state_size, 1, 0)) return 2;
	ff_flow_map_cap_set(64);
	ff_flow_map_open();
	if (!ff_flow_map_active() || !ff_reload_state_attached() ||
	    !ff_global_cfg.dpdk.graceful_reload || write_state(state_path, "OWNER_READY")) return 2;
	pid_t controller_pid = 0;
	uint64_t queue_lease = 0;
	if (wait_controller(controller_path, &controller_pid, &queue_lease)) return 2;
	int connection = -1;
	struct timespec begin;
	if (clock_gettime(CLOCK_MONOTONIC, &begin)) return 2;
	for (;;) {
		connection = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
		if (connection >= 0) break;
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 2;
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - begin.tv_sec > 20) return 2;
		const struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
	int passcred = 1;
	if (setsockopt(connection, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred))) return 2;
	struct ker_ff_admission_channel *channel = NULL;
	if (ker_ff_admission_channel_open(connection, controller_pid, getuid(), getgid(),
		queue_lease, &channel)) return 2;
	connection = -1;
	if (write_state(state_path, "OWNER_CONNECTED")) return 2;
	const struct ker_ff_admission_map_ops ops = {
		.active = active, .admit = admit, .revoke = map_revoke};
	int result;
	for (;;) {
		result = ker_ff_admission_channel_owner_step(channel, &ops);
		if (result == -ECONNRESET || result == -EPIPE) break;
		if (result && result != -EAGAIN && result != -EWOULDBLOCK) return 2;
		if (result) {
			const struct timespec pause = {.tv_nsec = 1000000};
			(void)nanosleep(&pause, NULL);
		}
	}
	ker_ff_admission_channel_close(channel);
	uint64_t inserted = 0, duplicates = 0, full = 0, grown = 0, revoked = 0;
	uint32_t capacity = 0;
	ff_flow_map_stats2(&inserted, &duplicates, &full, &grown, NULL, NULL,
		&capacity, &revoked);
	char final_state[160];
	if (snprintf(final_state, sizeof(final_state),
		"OWNER_DONE inserted=%llu duplicates=%llu full=%llu grown=%llu capacity=%u revoked=%llu",
		(unsigned long long)inserted, (unsigned long long)duplicates,
		(unsigned long long)full,
		(unsigned long long)grown, capacity, (unsigned long long)revoked) >=
		(int)sizeof(final_state) || write_state(state_path, final_state)) return 2;
	ff_flow_map_close();
	ker_reload_unbind_state();
	free(state);
	(void)syscall(SYS_close, listener);
	(void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
	return 0;
}
