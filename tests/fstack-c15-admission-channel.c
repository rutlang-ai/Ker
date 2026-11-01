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

int main(void)
{
	int endpoints[2], ready_pipe[2];
	const uint64_t lease = UINT64_C(0x1122334455667788);
	struct ker_ff_admission_key prepared_expired = make_key(42006);
	struct ker_ff_admission_key duplicate_expired = make_key(42007);
	credential_rejection_case();
	ancillary_rejection_case();
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
	puts("PASS: credentialed cross-process owner commands execute original map on one owner thread; prepared reservation retained, cancel/expired/dead-controller paths avoid unaccepted entries");
	return 0;
}
