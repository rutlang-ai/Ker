#define _GNU_SOURCE
#include "check.h"
#include "../src/posix/ff-admission-channel.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ker/reload.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "ff_config.h"
#include "ff_flow_map.h"

#include "../src/compat/reload.c"
#include "../third_party/fstack-flow-map/ff_flow_map.c"

static int map_active(void *context)
{
	(void)context;
	return ff_flow_map_active();
}

static int map_context_live(void *context)
{
	(void)context;
	return ff_reload_state_attached() && ff_global_cfg.dpdk.graceful_reload;
}

static int map_admit(const struct ker_ff_admission_key *key, int *created,
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

struct disconnect_sync {
	int entered_fd;
	int release_fd;
	int block_admit;
};

static struct ker_ff_admission_result receive_result(
	struct ker_ff_admission_channel *channel, uint16_t expected);

static int synchronized_admit(const struct ker_ff_admission_key *key, int *created,
			      void *opaque)
{
	struct disconnect_sync *sync = opaque;
	int status = map_admit(key, created, NULL);
	if (sync->block_admit && key->source_port == htons(42009)) {
		char marker = 'A';
		if (write(sync->entered_fd, &marker, 1) != 1 ||
		    read(sync->release_fd, &marker, 1) != 1 || marker != 'R')
			return -EIO;
	}
	return status;
}

static struct ker_ff_admission_key make_key(uint16_t port)
{
	struct ker_ff_admission_key key = {0};
	key.source[0] = htonl(0xc0000201);
	key.destination[0] = htonl(0xc0000202);
	key.source_port = htons(port);
	key.destination_port = htons(8080);
	return key;
}

static uint64_t deadline_after_250ms(void)
{
	struct timespec now;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec +
		UINT64_C(250000000);
}

static uint64_t monotonic_ns(void)
{
	struct timespec now;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static void disconnect_owner_child(int endpoint, pid_t controller_pid, int ready_fd,
				   int entered_fd, int release_fd, int mode)
{
	struct ker_ff_admission_channel *channel = NULL;
	struct ker_ff_admission_key key = make_key(42009);
	struct disconnect_sync sync = {
		.entered_fd = entered_fd, .release_fd = release_fd,
		.block_admit = mode != 2};
	struct ker_ff_admission_map_ops ops = {
		.active = map_active, .admit = synchronized_admit,
		.revoke = map_revoke, .context = &sync};
	size_t state_size = ker_reload_state_size();
	void *state = calloc(1, state_size);
	CHECK(state != NULL);
	CHECK(!ker_reload_state_init(state, state_size, 0));
	CHECK(!ker_reload_bind_state(state, state_size, 1, 0));
	ff_flow_map_open();
	CHECK(ff_flow_map_active() && ff_reload_state_attached());
	if (mode == 1) {
		int created = 0;
		struct ff_flow_key original;
		memcpy(&original, &key, sizeof(original));
		CHECK(ff_flow_map_admit(&original, &created) == 1 && created == 1);
	}
	CHECK(!ker_ff_admission_channel_open(endpoint, controller_pid, getuid(), getgid(),
		UINT64_C(0x8877665544332211), &channel));
	char marker = 'R';
	CHECK(write(ready_fd, &marker, 1) == 1);
	(void)close(ready_fd);
	int result;
	do {
		result = ker_ff_admission_channel_owner_step(channel, &ops);
		if (result == -EAGAIN || result == -EWOULDBLOCK) {
			const struct timespec pause = {.tv_nsec = 1000000};
			nanosleep(&pause, NULL);
		}
	} while (result == -EAGAIN || result == -EWOULDBLOCK || result == 0);
	CHECK(result == (mode == 2 ? -ECONNRESET : -EPIPE));
	struct ff_flow_key original;
	memcpy(&original, &key, sizeof(original));
	uint64_t inserted = 0, duplicates = 0, full = 0, grown = 0, revoked = 0;
	uint32_t capacity = 0;
	ff_flow_map_stats2(&inserted, &duplicates, &full, &grown, NULL, NULL,
		&capacity, &revoked);
	CHECK(ff_flow_map_lookup(&original) == (mode == 0 ? 0 : 1));
	CHECK(revoked == (mode == 0 ? 1U : 0U));
	ker_ff_admission_channel_close(channel);
	ff_flow_map_close();
	ker_reload_unbind_state();
	free(state);
	_exit(0);
}

static void initial_result_disconnect_case(int mode)
{
	int endpoints[2], ready_pipe[2], entered_pipe[2], release_pipe[2];
	const uint64_t lease = UINT64_C(0x8877665544332211);
	CHECK(!ker_ff_admission_channel_pair(endpoints));
	CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0);
	CHECK(pipe2(entered_pipe, O_CLOEXEC) == 0);
	CHECK(pipe2(release_pipe, O_CLOEXEC) == 0);
	pid_t controller_pid = getpid();
	pid_t owner = fork();
	CHECK(owner >= 0);
	if (owner == 0) {
		(void)close(endpoints[0]);
		(void)close(ready_pipe[0]);
		(void)close(entered_pipe[0]);
		(void)close(release_pipe[1]);
		disconnect_owner_child(endpoints[1], controller_pid, ready_pipe[1],
			entered_pipe[1], release_pipe[0], mode);
		_exit(1);
	}
	(void)close(endpoints[1]);
	(void)close(ready_pipe[1]);
	(void)close(entered_pipe[1]);
	(void)close(release_pipe[0]);
	struct ker_ff_admission_channel *channel = NULL;
	CHECK(!ker_ff_admission_channel_open(endpoints[0], owner, getuid(), getgid(),
		lease, &channel));
	char marker;
	CHECK(read(ready_pipe[0], &marker, 1) == 1 && marker == 'R');
	(void)close(ready_pipe[0]);
	struct ker_ff_admission_request request = {
		.lease = lease, .command_id = 1, .deadline_ns = deadline_after_250ms(),
		.packet_id = 0x4209, .key = make_key(42009)};
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	if (mode == 2) {
		struct ker_ff_admission_result result = receive_result(channel, KER_FF_ADMISSION_RESULT);
		CHECK(result.status == 0 && result.allowed == 1 && result.created == 1);
		CHECK(!ker_ff_admission_channel_send_control(channel,
			KER_FF_ADMISSION_PREPARE_ACCEPT, 1, request.packet_id));
		result = receive_result(channel, KER_FF_ADMISSION_PREPARED);
		CHECK(result.status == 0);
		ker_ff_admission_channel_close(channel);
	} else {
		CHECK(read(entered_pipe[0], &marker, 1) == 1 && marker == 'A');
		ker_ff_admission_channel_close(channel);
		marker = 'R';
		CHECK(write(release_pipe[1], &marker, 1) == 1);
	}
	(void)close(entered_pipe[0]);
	(void)close(release_pipe[1]);
	int wait_status = 0;
	CHECK(waitpid(owner, &wait_status, 0) == owner && WIFEXITED(wait_status) &&
		WEXITSTATUS(wait_status) == 0);
}

static void wait_until_deadline(uint64_t deadline)
{
	while (monotonic_ns() < deadline) {
		const struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

static struct ker_ff_admission_result receive_result(
	struct ker_ff_admission_channel *channel, uint16_t expected)
{
	struct ker_ff_admission_result result;
	uint64_t deadline = deadline_after_250ms();
	int saw_late_result = 0;
	uint64_t late_command = 0;
	uint32_t late_packet = 0;
	for (;;) {
		int status = ker_ff_admission_channel_receive(channel, &result);
		if (status == expected) {
			if (saw_late_result) {
				CHECK(expected == KER_FF_ADMISSION_CANCELLED &&
				      result.command_id == late_command && result.packet_id == late_packet);
			}
			return result;
		}
		if (status == KER_FF_ADMISSION_RESULT && expected == KER_FF_ADMISSION_CANCELLED) {
			CHECK(!saw_late_result && result.lease != 0 && result.command_id != 0 &&
			      result.packet_id != 0 && result.status <= 0 && result.status >= -4095);
			late_command = result.command_id;
			late_packet = result.packet_id;
			saw_late_result = 1;
			continue;
		}
		if (status != -EAGAIN && status != -EWOULDBLOCK)
			fprintf(stderr, "channel receive expected=%u status=%d\n", expected, status);
		CHECK(status == -EAGAIN || status == -EWOULDBLOCK);
		struct timespec now;
		CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
		uint64_t current = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
		CHECK(current < deadline);
		struct timespec pause = {.tv_nsec = 1000000};
		nanosleep(&pause, NULL);
	}
}

static void owner_child(int endpoint, pid_t controller_pid, int ready_fd,
		uint64_t lease)
{
	struct ker_ff_admission_channel *channel = NULL;
	struct ker_ff_admission_map_ops ops = {
		.active = map_active, .admit = map_admit, .revoke = map_revoke};
	struct ker_ff_admission_key accepted = make_key(42001);
	struct ker_ff_admission_key cancelled = make_key(42002);
	struct ker_ff_admission_key expired = make_key(42003);
	struct ker_ff_admission_key aborted = make_key(42004);
	struct ker_ff_admission_key closed = make_key(42005);
	struct ker_ff_admission_key prepared_expired = make_key(42006);
	struct ker_ff_admission_key duplicate_expired = make_key(42007);
	size_t state_size = ker_reload_state_size();
	void *state = calloc(1, state_size);
	CHECK(state != NULL);
	CHECK(!ker_reload_state_init(state, state_size, 0));
	CHECK(!ker_reload_bind_state(state, state_size, 1, 0));
	ff_flow_map_open();
	CHECK(ff_flow_map_active() && ff_reload_state_attached());
	CHECK(!ker_ff_admission_channel_open(endpoint, controller_pid, getuid(), getgid(),
		lease, &channel));
	char ready = 'R';
	CHECK(write(ready_fd, &ready, 1) == 1);
	(void)close(ready_fd);
	for (;;) {
		int result = ker_ff_admission_channel_owner_step(channel, &ops);
		if (result == -ECONNRESET) break;
		CHECK(result == 0 || result == -EAGAIN || result == -EWOULDBLOCK);
		struct timespec pause = {.tv_nsec = 1000000};
		nanosleep(&pause, NULL);
	}
	struct ff_flow_key accepted_key, cancelled_key;
	struct ff_flow_key expired_key, aborted_key, closed_key;
	struct ff_flow_key prepared_expired_key, duplicate_expired_key;
	memcpy(&accepted_key, &accepted, sizeof(accepted_key));
	memcpy(&cancelled_key, &cancelled, sizeof(cancelled_key));
	memcpy(&expired_key, &expired, sizeof(expired_key));
	memcpy(&aborted_key, &aborted, sizeof(aborted_key));
	memcpy(&closed_key, &closed, sizeof(closed_key));
	memcpy(&prepared_expired_key, &prepared_expired, sizeof(prepared_expired_key));
	memcpy(&duplicate_expired_key, &duplicate_expired, sizeof(duplicate_expired_key));
	CHECK(ff_flow_map_lookup(&accepted_key) == 1);
	CHECK(ff_flow_map_lookup(&cancelled_key) == 0);
	CHECK(ff_flow_map_lookup(&expired_key) == 0);
	CHECK(ff_flow_map_lookup(&aborted_key) == 0);
	CHECK(ff_flow_map_lookup(&closed_key) == 0);
	CHECK(ff_flow_map_lookup(&prepared_expired_key) == 0);
	CHECK(ff_flow_map_lookup(&duplicate_expired_key) == 1);
	ff_flow_map_close();
	ker_reload_unbind_state();
	free(state);
	ker_ff_admission_channel_close(channel);
	_exit(0);
}

static void credential_rejection_case(void)
{
	int endpoints[2];
	const uint64_t lease = UINT64_C(0x8877665544332211);
	CHECK(!ker_ff_admission_channel_pair(endpoints));
	pid_t expected = getpid();
	pid_t sender = fork();
	CHECK(sender >= 0);
	if (sender == 0) {
		(void)close(endpoints[0]);
		struct ker_ff_admission_channel *channel = NULL;
		CHECK(!ker_ff_admission_channel_open(endpoints[1], expected, getuid(),
			getgid(), lease, &channel));
		struct ker_ff_admission_request request = {
			.lease = lease, .command_id = 1, .deadline_ns = deadline_after_250ms(),
			.packet_id = 0x4312, .key = make_key(43001)};
		CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
		ker_ff_admission_channel_close(channel);
		_exit(0);
	}
	(void)close(endpoints[1]);
	struct ker_ff_admission_channel *channel = NULL;
	CHECK(!ker_ff_admission_channel_open(endpoints[0], expected, getuid(),
		getgid(), lease, &channel));
	struct ker_ff_admission_result result;
	int status;
	do {
		status = ker_ff_admission_channel_receive(channel, &result);
		if (status == -EAGAIN || status == -EWOULDBLOCK) {
			struct timespec pause = {.tv_nsec = 1000000};
			nanosleep(&pause, NULL);
		}
	} while (status == -EAGAIN || status == -EWOULDBLOCK);
	CHECK(status == -EPERM);
	ker_ff_admission_channel_close(channel);
	int child_status = 0;
	CHECK(waitpid(sender, &child_status, 0) == sender && WIFEXITED(child_status) &&
	      WEXITSTATUS(child_status) == 0);
}

static size_t open_fd_count(void)
{
	DIR *directory = opendir("/proc/self/fd");
	CHECK(directory != NULL);
	size_t count = 0;
	struct dirent *entry;
	while ((entry = readdir(directory)) != NULL)
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
	CHECK(!closedir(directory));
	return count;
}

static void ancillary_rejection_case(void)
{
	int endpoints[2], pipe_fds[2];
	const uint64_t lease = UINT64_C(0x0102030405060708);
	CHECK(!ker_ff_admission_channel_pair(endpoints));
	CHECK(pipe(pipe_fds) == 0);
	pid_t sender = fork();
	CHECK(sender >= 0);
	if (sender == 0) {
		(void)close(endpoints[0]);
		char payload = 'x';
		char control[CMSG_SPACE(sizeof(int))] = {0};
		struct iovec vector = {.iov_base = &payload, .iov_len = sizeof(payload)};
		struct msghdr message = {
			.msg_control = control, .msg_controllen = sizeof(control),
			.msg_iov = &vector, .msg_iovlen = 1};
		struct cmsghdr *header = CMSG_FIRSTHDR(&message);
		CHECK(header != NULL);
		header->cmsg_level = SOL_SOCKET;
		header->cmsg_type = SCM_RIGHTS;
		header->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(header), &pipe_fds[1], sizeof(int));
		CHECK(sendmsg(endpoints[1], &message, MSG_NOSIGNAL) == 1);
		(void)close(pipe_fds[1]);
		/* Keep the authenticated peer alive until the parent has opened the
		 * channel and rejected the queued SCM_RIGHTS message. */
		char release;
		CHECK(read(pipe_fds[0], &release, 1) == 1 && release == 'R');
		(void)close(pipe_fds[0]);
		(void)close(endpoints[1]);
		_exit(0);
	}
	(void)close(endpoints[1]);
	(void)close(pipe_fds[0]);
	struct ker_ff_admission_channel *channel = NULL;
	CHECK(!ker_ff_admission_channel_open(endpoints[0], sender, getuid(), getgid(),
		lease, &channel));
	struct ker_ff_admission_result result;
	int status;
	size_t before = open_fd_count();
	for (;;) {
		status = ker_ff_admission_channel_receive(channel, &result);
		if (status != -EAGAIN && status != -EWOULDBLOCK) break;
		struct timespec pause = {.tv_nsec = 1000000};
		nanosleep(&pause, NULL);
	}
	size_t after = open_fd_count();
	char release = 'R';
	CHECK(write(pipe_fds[1], &release, 1) == 1);
	(void)close(pipe_fds[1]);
	CHECK(status == -EPROTO);
	CHECK(after == before);
	ker_ff_admission_channel_close(channel);
	int child_status = 0;
	CHECK(waitpid(sender, &child_status, 0) == sender && WIFEXITED(child_status) &&
	      WEXITSTATUS(child_status) == 0);
}

struct window_test_context { unsigned retires; unsigned rearms; };

struct test_admission_wire {
	uint32_t magic;
	uint16_t version;
	uint16_t command;
	uint32_t length;
	uint32_t flags;
	uint64_t lease;
	uint64_t command_id;
	uint64_t deadline_ns;
	uint32_t packet_id;
	struct ker_ff_admission_key key;
	int32_t status;
	uint32_t allowed;
	uint32_t created;
	uint32_t reserved;
} __attribute__((packed));

_Static_assert(sizeof(struct test_admission_wire) == 100,
	"private test wire ABI");

static void inject_window_command(int fd, uint16_t command, uint64_t lease,
	uint64_t command_id)
{
	struct test_admission_wire wire = {
		.magic = UINT32_C(0x4b464151),
		.version = KER_FF_ADMISSION_CHANNEL_VERSION,
		.command = command, .length = sizeof(wire),
		.lease = lease, .command_id = command_id};
	CHECK(syscall(SYS_sendto, fd, &wire, sizeof(wire), MSG_NOSIGNAL, NULL, 0) ==
		(ssize_t)sizeof(wire));
}

static struct test_admission_wire receive_window_reply(int fd, pid_t owner)
{
	struct test_admission_wire wire = {0};
	char control[CMSG_SPACE(sizeof(struct ucred))] = {0};
	struct iovec vector = {.iov_base = &wire, .iov_len = sizeof(wire)};
	struct msghdr message = {.msg_control = control, .msg_controllen = sizeof(control),
		.msg_iov = &vector, .msg_iovlen = 1};
	uint64_t deadline = deadline_after_250ms() + UINT64_C(1000000000);
	ssize_t received;
	for (;;) {
		received = syscall(SYS_recvmsg, fd, &message, MSG_CMSG_CLOEXEC);
		if (received >= 0) break;
		CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
		CHECK(monotonic_ns() < deadline);
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
	CHECK(received == sizeof(wire) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
	struct cmsghdr *header = CMSG_FIRSTHDR(&message);
	CHECK(header && header->cmsg_level == SOL_SOCKET &&
		header->cmsg_type == SCM_CREDENTIALS &&
		header->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
	struct ucred credentials;
	memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
	CHECK(credentials.pid == owner && credentials.uid == getuid() &&
		credentials.gid == getgid());
	return wire;
}

static int window_retire(void *argument)
{
	struct window_test_context *context = argument;
	if (!ff_flow_map_active()) return -ESTALE;
	ff_flow_map_close();
	++context->retires;
	return ff_flow_map_active() ? -EIO : 0;
}

static int window_rearm(void *argument)
{
	struct window_test_context *context = argument;
	if (ff_flow_map_active()) return -EALREADY;
	ff_flow_map_open();
	++context->rearms;
	return ff_flow_map_active() ? 0 : -ENOMEM;
}

static void window_owner_child(int endpoint, pid_t controller, int ready_fd,
	uint64_t lease)
{
	struct ker_ff_admission_channel *channel = NULL;
	size_t state_size = ker_reload_state_size();
	void *state = calloc(1, state_size);
	CHECK(state != NULL);
	CHECK(!ker_reload_state_init(state, state_size, 0));
	CHECK(!ker_reload_bind_state(state, state_size, 1, 0));
	ff_global_cfg.dpdk.graceful_reload = 1;
	ff_flow_map_open();
	CHECK(ff_flow_map_active() && ff_reload_state_attached());
	struct window_test_context context = {0};
	struct ker_ff_admission_map_ops ops = {
		.context_live = map_active, .active = map_active,
		.admit = map_admit, .revoke = map_revoke,
		.retire = window_retire, .rearm = window_rearm,
		.context = &context};
	CHECK(!ker_ff_admission_channel_open(endpoint, controller, getuid(), getgid(),
		lease, &channel));
	char byte = 'R';
	CHECK(write(ready_fd, &byte, 1) == 1);
	(void)close(ready_fd);
	for (;;) {
		int status = ker_ff_admission_channel_owner_step(channel, &ops);
		if (status == -ECONNRESET) break;
		CHECK(status == 0 || status == -EAGAIN || status == -EWOULDBLOCK);
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
	CHECK(context.retires == 3 && context.rearms == 2 &&
		!ff_flow_map_active());
	ff_flow_map_close();
	ker_reload_unbind_state();
	free(state);
	ker_ff_admission_channel_close(channel);
	_exit(0);
}

static void inactive_map_owner_child(int endpoint, pid_t controller,
	int ready_fd, uint64_t lease)
{
	struct ker_ff_admission_channel *channel = NULL;
	size_t state_size = ker_reload_state_size();
	void *state = calloc(1, state_size);
	CHECK(state != NULL);
	CHECK(!ker_reload_state_init(state, state_size, 0));
	CHECK(!ker_reload_bind_state(state, state_size, 1, 0));
	ff_global_cfg.dpdk.graceful_reload = 1;
	CHECK(!ff_flow_map_active() && ff_reload_state_attached());
	struct ker_ff_admission_map_ops ops = {
		.context_live = map_context_live, .active = map_active,
		.admit = map_admit, .revoke = map_revoke};
	CHECK(!ker_ff_admission_channel_open(endpoint, controller, getuid(), getgid(),
		lease, &channel));
	char byte = 'R';
	CHECK(write(ready_fd, &byte, 1) == 1);
	(void)close(ready_fd);
	for (;;) {
		int status = ker_ff_admission_channel_owner_step(channel, &ops);
		if (status == -ECONNRESET) break;
		CHECK(status == 0 || status == -EAGAIN || status == -EWOULDBLOCK);
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
	CHECK(!ff_flow_map_active());
	ker_reload_unbind_state();
	free(state);
	ker_ff_admission_channel_close(channel);
	_exit(0);
}

static void inactive_map_admission_case(void)
{
	const uint64_t lease = UINT64_C(0x2200000000000000);
	int endpoints[2], ready_pipe[2];
	CHECK(!ker_ff_admission_channel_pair(endpoints));
	CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0);
	pid_t controller = getpid();
	pid_t owner = fork();
	CHECK(owner >= 0);
	if (!owner) {
		(void)close(endpoints[0]);
		(void)close(ready_pipe[0]);
		inactive_map_owner_child(endpoints[1], controller, ready_pipe[1], lease);
		_exit(1);
	}
	(void)close(endpoints[1]);
	(void)close(ready_pipe[1]);
	struct ker_ff_admission_channel *channel = NULL;
	CHECK(!ker_ff_admission_channel_open(endpoints[0], owner, getuid(), getgid(),
		lease, &channel));
	char byte;
	CHECK(read(ready_pipe[0], &byte, 1) == 1 && byte == 'R');
	(void)close(ready_pipe[0]);
	struct ker_ff_admission_request request = {
		.lease = lease, .command_id = 1, .deadline_ns = deadline_after_250ms(),
		.packet_id = 0x7711, .key = make_key(43002)};
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	struct ker_ff_admission_result result = receive_result(channel,
		KER_FF_ADMISSION_RESULT);
	CHECK(result.status == 0 && result.allowed == 1 && result.created == 0);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_CANCEL, 1, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_CANCELLED);
	CHECK(result.status == 0);
	ker_ff_admission_channel_close(channel);
	int child_status = 0;
	CHECK(waitpid(owner, &child_status, 0) == owner && WIFEXITED(child_status) &&
		WEXITSTATUS(child_status) == 0);
}

static void window_command_validation_case(void)
{
	const uint64_t lease = UINT64_C(0x1100000000000000);
	int endpoints[2], ready_pipe[2];
	CHECK(!ker_ff_admission_channel_pair(endpoints));
	CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0);
	pid_t controller = getpid();
	pid_t owner = fork();
	CHECK(owner >= 0);
	if (!owner) {
		(void)close(endpoints[0]);
		(void)close(ready_pipe[0]);
		window_owner_child(endpoints[1], controller, ready_pipe[1], lease);
		_exit(1);
	}
	(void)close(endpoints[1]);
	(void)close(ready_pipe[1]);
	struct ker_ff_admission_channel *channel = NULL;
	CHECK(!ker_ff_admission_channel_open(endpoints[0], owner, getuid(), getgid(),
		lease, &channel));
	char byte;
	CHECK(read(ready_pipe[0], &byte, 1) == 1 && byte == 'R');
	(void)close(ready_pipe[0]);
	CHECK(!ker_ff_admission_channel_send_retire(channel, 1));
	struct ker_ff_admission_result result = receive_result(channel,
		KER_FF_ADMISSION_RETIRED);
	CHECK(result.status == 0 && result.lease == lease && result.command_id == 1);
	/* Authenticated but stale owner commands must be rejected without changing
	 * the retired map/lease; the valid next command remains usable afterward. */
	inject_window_command(endpoints[0], KER_FF_ADMISSION_REARM,
		lease + 1, 1);
	struct test_admission_wire rejected = receive_window_reply(endpoints[0], owner);
	CHECK(rejected.magic == UINT32_C(0x4b464151) &&
		rejected.command == KER_FF_ADMISSION_REARMED &&
		rejected.lease == lease + 1 && rejected.command_id == 1 &&
		rejected.status == -EPROTO && !rejected.allowed && !rejected.created);
	CHECK(ker_ff_admission_channel_send_rearm(channel, lease - 1, 2) == -EINVAL);
	CHECK(ker_ff_admission_channel_send_rearm(channel, lease + 1, 1) == -EINVAL);
	CHECK(!ker_ff_admission_channel_send_rearm(channel, lease + 1, 2));
	result = receive_result(channel, KER_FF_ADMISSION_REARMED);
	CHECK(result.status == 0 && result.lease == lease + 1 && result.command_id == 2);
	CHECK(!ker_ff_admission_channel_send_retire(channel, 3));
	result = receive_result(channel, KER_FF_ADMISSION_RETIRED);
	CHECK(result.status == 0 && result.lease == lease + 1 && result.command_id == 3);
	inject_window_command(endpoints[0], KER_FF_ADMISSION_REARM, lease, 4);
	rejected = receive_window_reply(endpoints[0], owner);
	CHECK(rejected.command == KER_FF_ADMISSION_REARMED &&
		rejected.lease == lease && rejected.command_id == 4 &&
		rejected.status == -ESTALE && !rejected.allowed && !rejected.created);
	CHECK(ker_ff_admission_channel_send_rearm(channel, lease + 2, 3) == -EINVAL);
	CHECK(!ker_ff_admission_channel_send_rearm(channel, lease + 2, 4));
	result = receive_result(channel, KER_FF_ADMISSION_REARMED);
	CHECK(result.status == 0 && result.lease == lease + 2 && result.command_id == 4);
	CHECK(!ker_ff_admission_channel_send_retire(channel, 5));
	result = receive_result(channel, KER_FF_ADMISSION_RETIRED);
	CHECK(result.status == 0 && result.lease == lease + 2 && result.command_id == 5);
	ker_ff_admission_channel_close(channel);
	int child_status = 0;
	CHECK(waitpid(owner, &child_status, 0) == owner && WIFEXITED(child_status) &&
		WEXITSTATUS(child_status) == 0);
}

int main(void)
{
	int endpoints[2], ready_pipe[2];
	const uint64_t lease = UINT64_C(0x1122334455667788);
	struct ker_ff_admission_key prepared_expired = make_key(42006);
	struct ker_ff_admission_key duplicate_expired = make_key(42007);
	credential_rejection_case();
	ancillary_rejection_case();
	initial_result_disconnect_case(0);
	initial_result_disconnect_case(1);
	initial_result_disconnect_case(2);
	CHECK(!ker_ff_admission_channel_pair(endpoints));
	CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0);
	pid_t controller = getpid();
	pid_t owner = fork();
	CHECK(owner >= 0);
	if (owner == 0) {
		(void)close(endpoints[0]);
		(void)close(ready_pipe[0]);
		owner_child(endpoints[1], controller, ready_pipe[1], lease);
		_exit(1);
	}
	(void)close(endpoints[1]);
	(void)close(ready_pipe[1]);
	struct ker_ff_admission_channel *channel = NULL;
	CHECK(!ker_ff_admission_channel_open(endpoints[0], owner, getuid(), getgid(),
		lease, &channel));
	char ready;
	CHECK(read(ready_pipe[0], &ready, 1) == 1 && ready == 'R');
	(void)close(ready_pipe[0]);
	struct ker_ff_admission_request request = {
		.lease = lease, .command_id = 1, .deadline_ns = deadline_after_250ms(),
		.packet_id = 0x1234, .key = make_key(42001)};
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	struct ker_ff_admission_result result = receive_result(channel, KER_FF_ADMISSION_RESULT);
	CHECK(result.lease == lease && result.command_id == 1 && result.packet_id == request.packet_id);
	CHECK(result.status == 0 && result.allowed == 1 && result.created == 1);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_PREPARE_ACCEPT, 1, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_PREPARED);
	CHECK(result.status == 0 && result.command_id == 1);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_FINALIZE, 1, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_FINALIZED);
	CHECK(result.status == 0 && result.command_id == 1);
	request.command_id = 2;
	request.packet_id++;
	request.deadline_ns = deadline_after_250ms();
	request.key = make_key(42002);
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_CANCEL, 2, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_CANCELLED);
	CHECK(result.status == 0 && result.command_id == 2);
	request.command_id = 3;
	request.packet_id++;
	request.deadline_ns = 1;
	request.key = make_key(42003);
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	result = receive_result(channel, KER_FF_ADMISSION_RESULT);
	CHECK(result.status == -ETIMEDOUT && result.allowed == 0 && result.created == 0);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_FINALIZE, 3, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_FINALIZED);
	CHECK(result.status == 0 && result.command_id == 3);
	request.command_id = 4;
	request.packet_id++;
	request.deadline_ns = deadline_after_250ms();
	request.key = make_key(42004);
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	result = receive_result(channel, KER_FF_ADMISSION_RESULT);
	CHECK(result.status == 0 && result.allowed == 1 && result.created == 1);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_PREPARE_ACCEPT, 4, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_PREPARED);
	CHECK(result.status == 0 && result.command_id == 4);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_CANCEL_UNSENT, 4, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_CANCELLED);
	CHECK(result.status == 0 && result.command_id == 4);
	request.command_id = 5;
	request.packet_id++;
	request.deadline_ns = deadline_after_250ms();
	request.key = make_key(42005);
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	result = receive_result(channel, KER_FF_ADMISSION_RESULT);
	CHECK(result.status == 0 && result.allowed == 1 && result.created == 1);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_CANCEL, 5, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_CANCELLED);
	CHECK(result.status == 0 && result.command_id == 5);
	request.command_id = 6;
	request.packet_id++;
	request.deadline_ns = deadline_after_250ms();
	request.key = prepared_expired;
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	result = receive_result(channel, KER_FF_ADMISSION_RESULT);
	CHECK(result.status == 0 && result.allowed == 1 && result.created == 1);
	wait_until_deadline(request.deadline_ns);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_PREPARE_ACCEPT, 6, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_PREPARED);
	CHECK(result.status == -ETIMEDOUT && result.allowed == 0 && result.created == 0);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_CANCEL_UNSENT, 6, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_CANCELLED);
	CHECK(result.status == 0 && result.command_id == 6);
	request.command_id = 7;
	request.packet_id++;
	request.deadline_ns = deadline_after_250ms();
	request.key = duplicate_expired;
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	result = receive_result(channel, KER_FF_ADMISSION_RESULT);
	CHECK(result.status == 0 && result.allowed == 1 && result.created == 1);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_PREPARE_ACCEPT, 7, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_PREPARED);
	CHECK(result.status == 0);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_FINALIZE, 7, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_FINALIZED);
	CHECK(result.status == 0);
	request.command_id = 8;
	request.packet_id++;
	request.deadline_ns = deadline_after_250ms();
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	result = receive_result(channel, KER_FF_ADMISSION_RESULT);
	CHECK(result.status == 0 && result.allowed == 1 && result.created == 0);
	wait_until_deadline(request.deadline_ns);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_PREPARE_ACCEPT, 8, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_PREPARED);
	CHECK(result.status == -ETIMEDOUT && result.allowed == 0 && result.created == 0);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_CANCEL_UNSENT, 8, request.packet_id));
	result = receive_result(channel, KER_FF_ADMISSION_CANCELLED);
	CHECK(result.status == 0 && result.command_id == 8);
	ker_ff_admission_channel_close(channel);
	int wait_status = 0;
	CHECK(waitpid(owner, &wait_status, 0) == owner && WIFEXITED(wait_status) &&
	      WEXITSTATUS(wait_status) == 0);
	window_command_validation_case();
	inactive_map_admission_case();
	puts("PASS: credentialed owner commands preserve prepared reservations, roll back an unprepared admission on initial RESULT disconnect, prove inactive-map allow/created=0, and reject stale window leases/command IDs");
	return 0;
}
