#define _GNU_SOURCE
#include "ff-admission-channel.h"
#include "ff-admission-queue.h"
#include "ff-owner-requests-diag.h"
#include "ff-admission-request-identity.h"
#include "tcp-request-revoke.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define C15_MARK UINT32_C(0x4c150001)

static int host_write_file(const char *path, const char *value)
{
	long fd = syscall(SYS_openat, AT_FDCWD, path,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) return -errno;
	size_t length = strlen(value);
	ssize_t written = syscall(SYS_write, (int)fd, value, length);
	int result = written == (ssize_t)length ? 0 : -EIO;
	if (syscall(SYS_close, (int)fd) && !result) result = -errno;
	return result;
}

static int read_command(const char *path, char *command, size_t capacity)
{
	long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) return -errno;
	ssize_t size = syscall(SYS_read, (int)fd, command, capacity - 1);
	int saved = errno;
	(void)syscall(SYS_close, (int)fd);
	if (size < 0) return -saved;
	if ((size_t)size == capacity - 1) return -E2BIG;
	command[size] = '\0';
	if (size > 0 && command[size - 1] == '\n') command[size - 1] = '\0';
	return (int)size;
}

static uint64_t monotonic_ns(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static int wait_command(const char *path, const char *expected, uint64_t deadline)
{
	for (;;) {
		char command[32] = {0};
		int size = read_command(path, command, sizeof(command));
		if (size >= 0 && !strcmp(command, expected)) {
			(void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
			return 0;
		}
		if (monotonic_ns() >= deadline) return -ETIMEDOUT;
		const struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

static int connect_owner(const char *path, pid_t *owner_pid,
			uint64_t owner_lease,
			struct ker_ff_admission_channel **channel)
{
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	struct pollfd waitfd;
	int passcred = 1;
	int error = 0;
	 socklen_t error_length = sizeof(error);
	const char *pid_text = getenv("KER_C15_OWNER_PID");
	if (!pid_text || !*pid_text) return -EINVAL;
	errno = 0;
	char *end = NULL;
	long parsed = strtol(pid_text, &end, 10);
	if (errno || end == pid_text || *end || parsed <= 0 || parsed > INT_MAX)
		return -EINVAL;
	*owner_pid = (pid_t)parsed;
	if (strlen(path) >= sizeof(address.sun_path)) return -ENAMETOOLONG;
	strcpy(address.sun_path, path);
	long fd = syscall(SYS_socket, AF_UNIX,
		SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) return -errno;
	if (syscall(SYS_setsockopt, (int)fd, SOL_SOCKET, SO_PASSCRED,
		&passcred, sizeof(passcred)) != 0) {
		int result = -errno; (void)syscall(SYS_close, (int)fd); return result;
	}
	if (syscall(SYS_connect, (int)fd, &address,
		offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) != 0) {
		if (errno != EINPROGRESS && errno != EAGAIN) {
			int result = -errno; (void)syscall(SYS_close, (int)fd); return result;
		}
		waitfd = (struct pollfd){.fd = (int)fd, .events = POLLOUT};
		int ready = (int)syscall(SYS_poll, &waitfd, 1, 3000);
		if (ready <= 0 || syscall(SYS_getsockopt, (int)fd, SOL_SOCKET, SO_ERROR,
			&error, &error_length) != 0 || error) {
			int result = ready < 0 ? -errno : (ready == 0 ? -ETIMEDOUT : -(error ? error : errno));
			(void)syscall(SYS_close, (int)fd); return result;
		}
	}
	int result = ker_ff_admission_channel_open((int)fd, *owner_pid,
		getuid(), getgid(), owner_lease, channel);
	if (result) (void)syscall(SYS_close, (int)fd);
	return result;
}

static int receive_channel(struct ker_ff_admission_channel *channel,
			   int expected, uint64_t deadline,
			   struct ker_ff_admission_result *result)
{
	for (;;) {
		int status = ker_ff_admission_channel_receive(channel, result);
		if (status == expected) return result->status;
		if (status < 0 && status != -EAGAIN && status != -EWOULDBLOCK) return status;
		if (monotonic_ns() >= deadline) return -ETIMEDOUT;
		const struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

static int accept_application_connection(int listener_fd, unsigned timeout_ms)
{
	uint64_t deadline = monotonic_ns() + (uint64_t)timeout_ms * UINT64_C(1000000);
	for (;;) {
		int accepted = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
		if (accepted >= 0) {
			return close(accepted) == 0 ? 0 : -errno;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			return -errno;
		if (monotonic_ns() >= deadline) return -ETIMEDOUT;
		const struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

/* Test-only controller entry point. The authoritative flow map is in a
 * separate original F-Stack owner process; this thread only consumes the
 * original LKL NFQUEUE and sequences owner commands/verdicts. */
int ker_c15_admission_test_run(int listener_fd, const char *prefix)
{
	char state_path[PATH_MAX], command_path[PATH_MAX], pid_path[PATH_MAX];
	const char *owner_path = getenv("KER_C15_OWNER_PATH");
	struct ker_ff_admission_queue *queue = NULL;
	struct ker_ff_admission_channel *channel = NULL;
	struct ker_ff_admission_packet packet;
	struct ker_ff_admission_request request = {0};
	struct ker_ff_admission_result response = {0};
	struct ker_ff_owner_requests_state census;
	struct ker_ff_admission_request_identity *identity = NULL;
	struct ker_tcp_request_revoke_request request_identity = {0};
	atomic_bool cancel = false;
	pid_t owner_pid = 0;
	uint64_t command_id = 0;
	unsigned int admitted = 0;
	int map_full_rejected = 0;
	int prepared = 0;
	int accept_sent = 0;
	int unread_accept_ack = getenv("KER_C15_UNREAD_ACCEPT_ACK") != NULL;
	int stopped_owner_timeout = getenv("KER_C15_STOP_OWNER_TIMEOUT") != NULL;
	int duplicate_mode = getenv("KER_C15_DUPLICATE_MODE") != NULL;
	const char *expire_after_prepared_env = getenv("KER_C15_EXPIRE_AFTER_PREPARED");
	unsigned int expire_after_prepared_index = expire_after_prepared_env ?
		(unsigned int)strtoul(expire_after_prepared_env, NULL, 10) : 0;
	unsigned int packet_limit = expire_after_prepared_index ?
		expire_after_prepared_index : duplicate_mode ? 2U : 17U;
	int prepared_expiry_handled = 0;
	int owner_timeout_handled = 0;
	unsigned int current_index = 0;
	int listener_owned = 1, result = -EINVAL;
	const char *failure_stage = "setup";
	if (listener_fd < 0 || !prefix || !*prefix || !owner_path || !*owner_path)
		goto out;
	if (snprintf(state_path, sizeof(state_path), "%s.state", prefix) >= (int)sizeof(state_path) ||
	    snprintf(command_path, sizeof(command_path), "%s.command", prefix) >= (int)sizeof(command_path) ||
	    snprintf(pid_path, sizeof(pid_path), "%s.pid", prefix) >= (int)sizeof(pid_path))
		goto out;
	long host_pid = syscall(SYS_getpid);
	if (host_pid <= 0 || host_pid > INT_MAX) goto out;
	char state[128];
	result = ker_ff_admission_queue_start(C15_MARK, &queue);
	if (result) goto out;
	uint64_t queue_lease = ker_ff_admission_queue_lease(queue);
	if (!queue_lease || snprintf(state, sizeof(state), "CONNECTING pid=%ld lease=%llu",
	    host_pid, (unsigned long long)queue_lease) >= (int)sizeof(state) ||
	    host_write_file(pid_path, state)) { result = -EIO; goto out; }
	result = connect_owner(owner_path, &owner_pid, queue_lease, &channel);
	if (result) goto out;
	if (host_write_file(state_path, "OWNER_CONNECTED")) { result = -EIO; goto out; }
	/* The kernel mark gate and authenticated map owner are ready before the
	 * application descriptor becomes a listening socket. */
	if (listen(listener_fd, 64) != 0) { result = -errno; goto out; }
	if (host_write_file(state_path, "READY")) { result = -EIO; goto out; }
	for (unsigned int index = 1; index <= ((unread_accept_ack || stopped_owner_timeout) ?
	    1U : packet_limit); ++index) {
		current_index = index;
	uint32_t admitted_created = 0;
		prepared = 0;
		accept_sent = 0;
		uint64_t wait_deadline = monotonic_ns() + UINT64_C(10000000000);
		int got_packet = 0;
		failure_stage = "queue-receive";
		while (monotonic_ns() < wait_deadline) {
			result = ker_ff_admission_queue_receive(queue, &packet, 20);
			if (result < 0) goto out;
			if (result == 1) { got_packet = 1; break; }
		}
		if (!got_packet || packet.mark != C15_MARK || !packet.lease || !packet.id ||
		    packet.local_port != htons(8080)) { result = -EPROTO; goto out; }
		if (packet.lease != queue_lease) { result = -ESTALE; goto reject_packet; }
		struct ker_ff_admission_ipv4_tuple tuple = {
			.local = {.sin_family = AF_INET, .sin_port = packet.local_port,
				.sin_addr.s_addr = packet.local_address},
			.remote = {.sin_family = AF_INET, .sin_port = packet.remote_port,
				.sin_addr.s_addr = packet.remote_address}};
		result = ker_ff_admission_request_identity_begin(listener_fd, &tuple,
			C15_MARK, &identity);
		failure_stage = "request-identity-begin";
		if (result) goto reject_packet;
		uint64_t identity_deadline = packet.deadline_ns;
		for (;;) {
			failure_stage = "request-identity-step";
			result = ker_ff_admission_request_identity_step(identity, &cancel,
				&request_identity);
			if (result < 0) goto reject_packet;
			if (result == 1) break;
			if (monotonic_ns() >= identity_deadline) { result = -ETIMEDOUT; goto reject_packet; }
			const struct timespec pause = {.tv_nsec = 1000000};
			(void)nanosleep(&pause, NULL);
		}
		char options_hex[81] = {0};
		for (unsigned int i = 0; i < packet.tcp_options_length; ++i)
			(void)snprintf(options_hex + 2 * i, sizeof(options_hex) - 2 * i,
				"%02x", packet.tcp_options[i]);
		if (snprintf(state, sizeof(state), "HELD index=%u server_seq=%u options=%s",
			index, ntohl(packet.server_sequence), options_hex) >= (int)sizeof(state) ||
		    host_write_file(state_path, state)) { result = -EIO; goto out; }
		failure_stage = "wait-admit";
		result = wait_command(command_path, "ADMIT", packet.deadline_ns);
		if (result) goto reject_packet;
		request.lease = packet.lease;
		request.command_id = ++command_id;
		request.deadline_ns = packet.deadline_ns;
		request.packet_id = packet.id;
		request.key.family = 0;
		request.key.source[0] = packet.remote_address;
		request.key.destination[0] = packet.local_address;
		request.key.source_port = packet.remote_port;
		request.key.destination_port = packet.local_port;
		failure_stage = "owner-admit-send";
		result = ker_ff_admission_channel_send_admit(channel, &request);
		if (result) goto reject_packet;
		failure_stage = "owner-admit-result";
		result = receive_channel(channel, KER_FF_ADMISSION_RESULT,
			packet.deadline_ns, &response);
		int map_full = 0;
		if (!result) {
			if (!response.allowed && !response.created) map_full = 1;
			else if (response.allowed != 1 || response.created > 1)
				result = -EPROTO;
			else admitted_created = response.created;
		}
		if (result || map_full) {
			int admission_error = result ? result : -ENOBUFS;
			if (ker_ff_admission_request_identity_revalidate(identity)) {
				result = -ESTALE;
				goto reject_packet;
			}
			int revoke_result = ker_native_tcp_request_revoke(&request_identity);
			if (revoke_result) { result = revoke_result; goto reject_packet; }
			int cancel_status = ker_ff_admission_channel_send_control(channel,
				KER_FF_ADMISSION_CANCEL, command_id, packet.id);
			if (!cancel_status)
				cancel_status = receive_channel(channel, KER_FF_ADMISSION_CANCELLED,
					packet.deadline_ns, &response);
			int dropped = 0;
			int drop_status = ker_ff_admission_queue_verdict(queue, packet.lease,
				packet.deadline_ns, packet.id, 0, &dropped);
			ker_ff_admission_request_identity_close(identity);
			identity = NULL;
			if (stopped_owner_timeout && admission_error == -ETIMEDOUT &&
			    !revoke_result && dropped) {
				if (host_write_file(state_path,
					"OWNER_TIMEOUT request_revoked=true drop_sent=true")) {
					result = -EIO;
					goto out;
				}
				owner_timeout_handled = 1;
				result = 0;
			} else if (map_full && !cancel_status && !drop_status && dropped) {
				map_full_rejected = 1;
				if (snprintf(state, sizeof(state),
					"REJECTED index=%u map_full=true request_revoked=true", index) >=
					(int)sizeof(state) || host_write_file(state_path, state)) {
					result = -EIO;
					goto out;
				}
				result = 0;
			} else {
				(void)snprintf(state, sizeof(state),
					"REJECTED index=%u admission_error=%d c14=%d cancel=%d drop=%d",
					index, admission_error, revoke_result, cancel_status, drop_status);
				(void)host_write_file(state_path, state);
				result = admission_error;
				goto out;
			}
			break;
		}
		result = ker_ff_admission_channel_send_control(channel,
			KER_FF_ADMISSION_PREPARE_ACCEPT, command_id, packet.id);
		failure_stage = "owner-prepare-send";
		if (result) goto reject_packet;
		failure_stage = "owner-prepare-result";
		result = receive_channel(channel, KER_FF_ADMISSION_PREPARED,
			packet.deadline_ns, &response);
		if (result) goto reject_packet;
		prepared = 1;
		result = ker_ff_admission_request_identity_revalidate(identity);
		failure_stage = "listener-revalidate";
		if (result) goto reject_packet;
		if (expire_after_prepared_index == index) {
			/* Deterministically exercise the interval after PREPARED and before
			 * NF_ACCEPT is sent. A zero sent flag is definitive: this call checks
			 * the absolute packet deadline before sending any netlink message. */
			while (monotonic_ns() < packet.deadline_ns) {
				const struct timespec pause = {.tv_nsec = 1000000};
				(void)nanosleep(&pause, NULL);
			}
			int sent = 0;
			result = ker_ff_admission_queue_verdict(queue, packet.lease,
				packet.deadline_ns, packet.id, 1, &sent);
			accept_sent = sent;
			if (result != -ETIMEDOUT || sent != 0) goto out;
			failure_stage = "accept-unsent-expired";
			goto reject_packet;
		}
		int sent = 0;
		if (unread_accept_ack) {
			result = ker_ff_admission_queue_test_accept_unread_ack(queue,
				packet.lease, packet.deadline_ns, packet.id, &sent);
			accept_sent = sent;
			if (sent != 1 || result != -ECONNRESET) goto out;
			ker_ff_admission_request_identity_close(identity);
			identity = NULL;
			if (host_write_file(state_path, "ACCEPT_SENT_UNCERTAIN map_retained=true")) {
				result = -EIO;
				goto out;
			}
			result = wait_command(command_path, "STOP",
				monotonic_ns() + UINT64_C(10000000000));
			if (result) goto out;
			result = accept_application_connection(listener_fd, 5000);
			if (result) goto out;
			(void)close(listener_fd);
			listener_owned = 0;
			result = ker_ff_owner_requests_begin(&census, C15_MARK);
			if (result) goto out;
			uint64_t requests = UINT64_MAX;
			uint64_t cleanup_deadline = monotonic_ns() + UINT64_C(3000000000);
			for (;;) {
				result = ker_ff_owner_requests_step(&census, &cancel, &requests);
				if (result < 0 || result == 1) break;
				if (monotonic_ns() >= cleanup_deadline) { result = -ETIMEDOUT; break; }
			}
			ker_ff_owner_requests_close(&census);
			if (result != 1 || requests) { result = -EBUSY; goto out; }
			result = ker_ff_admission_queue_disarm_after_quiescence(queue);
			if (result) goto out;
			ker_ff_admission_queue_close(queue);
			queue = NULL;
			ker_ff_admission_channel_close(channel);
			channel = NULL;
			result = host_write_file(state_path, "DONE");
			goto out;
		}
		result = ker_ff_admission_queue_verdict(queue, packet.lease,
			packet.deadline_ns, packet.id, 1, &sent);
		accept_sent = sent;
		if (result || !sent) {
			if (!sent) {
				failure_stage = "accept-definitely-unsent";
				goto reject_packet;
			}
			goto out; /* a full ACCEPT send may already be irreversible */
		}
		result = ker_ff_admission_channel_send_control(channel,
			KER_FF_ADMISSION_FINALIZE, command_id, packet.id);
		if (result) goto out; /* accepted packet may already be on the wire */
		result = receive_channel(channel, KER_FF_ADMISSION_FINALIZED,
			packet.deadline_ns, &response);
		if (result) goto out;
		prepared = 0;
		ker_ff_admission_request_identity_close(identity);
		identity = NULL;
		admitted++;
		if (!stopped_owner_timeout && !(duplicate_mode && index == 1)) {
			result = accept_application_connection(listener_fd, 5000);
			if (result) goto out;
		}
		if (snprintf(state, sizeof(state), "ADMITTED index=%u map_created=%u", index,
			admitted_created) >=
			(int)sizeof(state) || host_write_file(state_path, state)) { result = -EIO; goto out; }
		/* Keep the first admission observable to the harness before processing
		 * the retransmitted SYN-ACK in this duplicate-map control. */
		if (duplicate_mode && index == 1) {
			failure_stage = "duplicate-harness-continue";
			result = wait_command(command_path, "NEXT",
				monotonic_ns() + UINT64_C(10000000000));
			if (result) goto out;
		}
	}
post_admission_packets:
	if (!prepared_expiry_handled && !unread_accept_ack && !stopped_owner_timeout && !duplicate_mode &&
	    (admitted != 16 || !map_full_rejected)) {
		result = -EPROTO;
		goto out;
	}
	if (duplicate_mode && admitted != (prepared_expiry_handled ? 1U : 2U)) {
		result = -EPROTO;
		goto out;
	}
	if (expire_after_prepared_index && !prepared_expiry_handled) {
		result = -EPROTO;
		goto out;
	}
	if (stopped_owner_timeout && !owner_timeout_handled) { result = -EPROTO; goto out; }
	result = wait_command(command_path, "STOP", monotonic_ns() + UINT64_C(10000000000));
	if (result) goto out;
	(void)close(listener_fd);
	listener_owned = 0;
	if (stopped_owner_timeout) {
		/* A retransmitted SYNACK may still be queued inside NFQUEUE even when
		 * userspace never received it. Closing the consumer flushes those
		 * queued skbs as DROP and leaves the mark gate armed. */
		ker_ff_admission_queue_close(queue);
		queue = NULL;
	}
	result = ker_ff_owner_requests_begin(&census, C15_MARK);
	if (result) goto out;
	uint64_t requests = UINT64_MAX;
	uint64_t cleanup_deadline = monotonic_ns() + UINT64_C(3000000000);
	for (;;) {
		result = ker_ff_owner_requests_step(&census, &cancel, &requests);
		if (result < 0 || result == 1) break;
		if (monotonic_ns() >= cleanup_deadline) { result = -ETIMEDOUT; break; }
	}
	ker_ff_owner_requests_close(&census);
	if (result != 1 || requests) { result = -EBUSY; goto out; }
	if (queue) {
		result = ker_ff_admission_queue_disarm_after_quiescence(queue);
		if (result) goto out;
		ker_ff_admission_queue_close(queue);
		queue = NULL;
	}
	ker_ff_admission_channel_close(channel);
	channel = NULL;
	result = host_write_file(state_path, "DONE");
	goto out;

reject_packet:
	;
	/* Only a fully sent ACCEPT can have crossed the irreversible boundary. If
	 * ACCEPT was not sent, revoke the exact request, cancel a newly created map
	 * entry and send DROP with a separate cleanup deadline. */
	int request_revoked = 0, owner_cancelled = 0, drop_sent = 0;
	int cleanup_error = 0;
	if (prepared && !accept_sent && channel) {
		if (identity) {
			int identity_result = ker_ff_admission_request_identity_revalidate(identity);
			if (!identity_result) {
				cleanup_error = ker_native_tcp_request_revoke(&request_identity);
				request_revoked = cleanup_error == 0;
			} else {
				cleanup_error = identity_result;
			}
		}
		int cancel_result = ker_ff_admission_channel_send_control(channel,
			KER_FF_ADMISSION_CANCEL_UNSENT, command_id, packet.id);
		if (!cancel_result) {
			cancel_result = receive_channel(channel, KER_FF_ADMISSION_CANCELLED,
				monotonic_ns() + UINT64_C(1000000000), &response);
			if (!cancel_result) owner_cancelled = 1;
		}
		if (!cleanup_error) cleanup_error = cancel_result;
	}
	if (queue) {
		int drop_result = ker_ff_admission_queue_verdict(queue, packet.lease,
			monotonic_ns() + UINT64_C(1000000000), packet.id, 0, &drop_sent);
		if (!cleanup_error && (drop_result || drop_sent != 1))
			cleanup_error = drop_result ? drop_result : -EIO;
	}
	if (failure_stage && !strcmp(failure_stage, "accept-unsent-expired") &&
	    request_revoked && owner_cancelled && drop_sent == 1 && !cleanup_error) {
		prepared = 0;
		if (identity) ker_ff_admission_request_identity_close(identity);
		identity = NULL;
		prepared_expiry_handled = 1;
		if (snprintf(state, sizeof(state),
			"EXPIRED_PREPARED index=%u accept_sent=0 request_revoked=1 "
			"owner_cancelled=1 drop_sent=1", current_index) >= (int)sizeof(state) ||
			host_write_file(state_path, state)) {
			result = -EIO;
			goto out;
		}
		result = 0;
		goto post_admission_packets;
	}
	if (cleanup_error) {
		result = cleanup_error;
	}
	(void)snprintf(state, sizeof(state),
		"REJECTED_BEFORE_ACCEPT stage=%.32s err=%d revoke=%d cancel=%d drop=%d",
		failure_stage, result, request_revoked, owner_cancelled, drop_sent);
	(void)host_write_file(state_path, state);
out:
	if (identity) ker_ff_admission_request_identity_close(identity);
	if (listener_owned && listener_fd >= 0) (void)close(listener_fd);
	if (queue) ker_ff_admission_queue_close(queue);
	if (channel) ker_ff_admission_channel_close(channel);
	return result;
}
