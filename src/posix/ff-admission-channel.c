#define _GNU_SOURCE
#include "ff-admission-channel.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifdef KER_C15_TEST_DELAY_PREPARED_REPLY
extern void ker_c15_test_hold_prepared_reply(int owner_prepared, int status,
					     uint32_t allowed, uint32_t created);
#endif

#define KER_FF_ADMISSION_CHANNEL_MAGIC UINT32_C(0x4b464151)
#define KER_FF_ADMISSION_MAX_MESSAGE 256U

struct ker_ff_admission_wire {
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

_Static_assert(sizeof(struct ker_ff_admission_wire) == 100,
	"C15 admission channel wire ABI");

struct ker_ff_admission_channel {
	int fd;
	int peer_pidfd;
	pid_t peer_pid;
	uid_t peer_uid;
	gid_t peer_gid;
	uint64_t peer_start_time;
	dev_t peer_exe_device;
	ino_t peer_exe_inode;
	uint64_t lease;
	pthread_t owner_thread;
	int owner_thread_bound;
	int response_pending;
	struct ker_ff_admission_wire response;
	int owner_state;
	int owner_prepared;
	uint64_t owner_last_command_id;
	struct ker_ff_admission_wire current;
	uint64_t controller_last_command_id;
	uint64_t controller_command_id;
	uint32_t controller_packet_id;
	int controller_state;
	uint32_t controller_allowed;
	uint32_t controller_created;
};

static int process_start_time(pid_t pid, uint64_t *start_time)
{
	char path[64], buffer[4096];
	int length = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	if (length <= 0 || (size_t)length >= sizeof(path)) return -EOVERFLOW;
	int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) return -errno;
	ssize_t count;
	do { count = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1); }
	while (count < 0 && errno == EINTR);
	int saved = errno;
	(void)syscall(SYS_close, fd);
	if (count <= 0) return count < 0 ? -saved : -EPROTO;
	buffer[count] = '\0';
	char *cursor = strrchr(buffer, ')');
	if (!cursor || cursor[1] != ' ') return -EPROTO;
	cursor += 2;
	for (unsigned field = 3; field < 22; ++field) {
		while (*cursor == ' ') ++cursor;
		if (!*cursor) return -EPROTO;
		while (*cursor && *cursor != ' ') ++cursor;
	}
	while (*cursor == ' ') ++cursor;
	if (!*cursor) return -EPROTO;
	errno = 0;
	char *end = NULL;
	unsigned long long value = strtoull(cursor, &end, 10);
	if (errno || end == cursor || (*end && *end != ' ')) return -EPROTO;
	*start_time = (uint64_t)value;
	return 0;
}

static int peer_identity(struct ker_ff_admission_channel *channel)
{
	struct pollfd pidfd = {.fd = channel->peer_pidfd, .events = POLLIN};
	struct stat executable;
	char path[64];
	uint64_t start_time;
	int length = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)channel->peer_pid);
	if (length <= 0 || (size_t)length >= sizeof(path)) return -EOVERFLOW;
	int ready = (int)syscall(SYS_poll, &pidfd, 1, 0);
	if (ready < 0) return -errno;
	if (ready && (pidfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) return -ESRCH;
	int result = process_start_time(channel->peer_pid, &start_time);
	if (result) return result;
	if (start_time != channel->peer_start_time) return -ESTALE;
	if (syscall(SYS_newfstatat, AT_FDCWD, path, &executable, 0) != 0)
		return -errno;
	if (executable.st_dev != channel->peer_exe_device ||
	    executable.st_ino != channel->peer_exe_inode) return -ESTALE;
	return 0;
}

static int credentials_match(struct ker_ff_admission_channel *channel,
			     const struct msghdr *message)
{
	const struct ucred *credentials = NULL;
	int malformed = 0, received_rights = 0;
	for (struct cmsghdr *control = CMSG_FIRSTHDR((struct msghdr *)message);
	     control; control = CMSG_NXTHDR((struct msghdr *)message, control)) {
		if (control->cmsg_level != SOL_SOCKET) {
			malformed = 1;
			continue;
		}
		if (control->cmsg_type == SCM_RIGHTS) {
			received_rights = 1;
			if (control->cmsg_len < CMSG_LEN(0)) {
				malformed = 1;
				continue;
			}
		size_t bytes = control->cmsg_len - CMSG_LEN(0);
			if (bytes % sizeof(int)) malformed = 1;
			for (size_t offset = 0; offset + sizeof(int) <= bytes;
			     offset += sizeof(int)) {
				int received_fd;
				memcpy(&received_fd, (unsigned char *)CMSG_DATA(control) + offset,
				       sizeof(received_fd));
				(void)syscall(SYS_close, received_fd);
			}
			continue;
		}
		if (control->cmsg_type != SCM_CREDENTIALS ||
		    control->cmsg_len != CMSG_LEN(sizeof(struct ucred)) || credentials) {
			malformed = 1;
			continue;
		}
		credentials = (const struct ucred *)CMSG_DATA(control);
	}
	if (malformed || received_rights) return -EPROTO;
	if (!credentials || credentials->pid != channel->peer_pid ||
	    credentials->uid != channel->peer_uid || credentials->gid != channel->peer_gid)
		return -EPERM;
	return peer_identity(channel);
}

static int send_wire(struct ker_ff_admission_channel *channel,
		     const struct ker_ff_admission_wire *wire)
{
	struct iovec vector = {.iov_base = (void *)wire, .iov_len = sizeof(*wire)};
	struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
	ssize_t sent = syscall(SYS_sendmsg, channel->fd, &message,
		MSG_DONTWAIT | MSG_NOSIGNAL);
	if (sent < 0) return -errno;
	return (size_t)sent == sizeof(*wire) ? 0 : -EIO;
}

static int receive_wire(struct ker_ff_admission_channel *channel,
			struct ker_ff_admission_wire *wire)
{
	char control_bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 8)];
	struct iovec vector = {.iov_base = wire, .iov_len = sizeof(*wire)};
	struct msghdr message = {
		.msg_control = control_bytes,
		.msg_controllen = sizeof(control_bytes),
		.msg_iov = &vector,
		.msg_iovlen = 1,
	};
	ssize_t received = syscall(SYS_recvmsg, channel->fd, &message,
		MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
	if (received < 0) return -errno;
	int result = credentials_match(channel, &message);
	if (received == 0) return -ECONNRESET;
	if (result) return result;
	if (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
	    (size_t)received != sizeof(*wire)) return -EMSGSIZE;
	if (wire->magic != KER_FF_ADMISSION_CHANNEL_MAGIC ||
	    wire->version != KER_FF_ADMISSION_CHANNEL_VERSION ||
	    wire->length != sizeof(*wire) || wire->flags || wire->reserved ||
	    wire->lease != channel->lease || !wire->command_id ||
	    (wire->command <= KER_FF_ADMISSION_CANCEL_UNSENT &&
	     (wire->status || wire->allowed || wire->created)))
		return -EPROTO;
	return 1;
}

static void response_from_current(struct ker_ff_admission_channel *channel,
				  uint16_t command, int status)
{
	channel->response = channel->current;
	channel->response.command = command;
	channel->response.status = status;
	channel->response.deadline_ns = 0;
	memset(&channel->response.key, 0, sizeof(channel->response.key));
	channel->response_pending = 1;
}

static void response_for_command(struct ker_ff_admission_channel *channel,
				 const struct ker_ff_admission_wire *request,
				 uint16_t command, int status)
{
	channel->response = *request;
	channel->response.command = command;
	channel->response.status = status;
	channel->response.allowed = 0;
	channel->response.created = 0;
	channel->response.deadline_ns = 0;
	memset(&channel->response.key, 0, sizeof(channel->response.key));
	channel->response_pending = 1;
}

#ifdef KER_C16_ADMISSION_TEST_TRACE
static int test_hold_finalized_response(struct ker_ff_admission_channel *channel)
{
	static int consumed;
	const char *path = getenv("KER_C16_TEST_HOLD_FINALIZED_FIFO");
	if (consumed || !path || !*path) return 0;
	consumed = 1;
	/* FINALIZED's wire result is intentionally zeroed. Inspect the retained
	 * owner-side transaction state here to prove the test holds a settled,
	 * newly-created map entry rather than an unprepared request. */
	if (channel->current.status || channel->current.allowed != 1 ||
	    channel->current.created != 1 || channel->owner_prepared)
		return -EPROTO;
	static const char marker[] =
		"C16_FINALIZED_REPLY_HELD owner_state=settled allowed=1 created=1 map_retained=1\n";
	(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) return -errno;
	char release;
	ssize_t count;
	do { count = syscall(SYS_read, fd, &release, sizeof(release)); }
	while (count < 0 && errno == EINTR);
	int error = count == 1 && release == 'R' ? 0 :
		count < 0 ? -errno : -ECONNRESET;
	(void)syscall(SYS_close, fd);
	return error;
}

static int test_hold_prepared_response(struct ker_ff_admission_channel *channel)
{
	static int consumed;
	const char *path = getenv("KER_C16_TEST_HOLD_PREPARED_FIFO");
	if (consumed || !path || !*path) return 0;
	consumed = 1;
	if (channel->current.status || channel->current.allowed != 1 ||
	    channel->current.created != 1 || !channel->owner_prepared)
		return -EPROTO;
	static const char marker[] =
		"C16_PREPARED_REPLY_HELD owner_prepared=1 created=1 reservation=retained\n";
	(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) return -errno;
	char release;
	ssize_t count;
	do { count = syscall(SYS_read, fd, &release, sizeof(release)); }
	while (count < 0 && errno == EINTR);
	int error = count == 1 && release == 'R' ? 0 :
		count < 0 ? -errno : -ECONNRESET;
	(void)syscall(SYS_close, fd);
	return error;
}
#endif

static int send_pending_response(struct ker_ff_admission_channel *channel)
{
	int result;
	if (!channel->response_pending) return 0;
#ifdef KER_C16_ADMISSION_TEST_TRACE
	if (channel->response.command == KER_FF_ADMISSION_FINALIZED) {
		int hold = test_hold_finalized_response(channel);
		if (hold) return hold;
	}
	if (channel->response.command == KER_FF_ADMISSION_PREPARED) {
		int hold = test_hold_prepared_response(channel);
		if (hold) return hold;
	}
#endif
#ifdef KER_C15_TEST_DELAY_PREPARED_REPLY
	if (channel->response.command == KER_FF_ADMISSION_PREPARED)
		ker_c15_test_hold_prepared_reply(channel->owner_prepared,
			channel->response.status, channel->current.allowed,
			channel->current.created);
#endif
	result = send_wire(channel, &channel->response);
	if (result == 0) channel->response_pending = 0;
	return result;
}

int ker_ff_admission_channel_pair(int endpoints[2])
{
	int passcred = 1;
	if (!endpoints) return -EINVAL;
	endpoints[0] = endpoints[1] = -1;
	if (syscall(SYS_socketpair, AF_UNIX,
		SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, endpoints) != 0)
		return -errno;
	if (syscall(SYS_setsockopt, endpoints[0], SOL_SOCKET, SO_PASSCRED,
		&passcred, sizeof(passcred)) != 0 ||
	    syscall(SYS_setsockopt, endpoints[1], SOL_SOCKET, SO_PASSCRED,
		&passcred, sizeof(passcred)) != 0) {
		int error = errno;
		syscall(SYS_close, endpoints[0]); syscall(SYS_close, endpoints[1]);
		endpoints[0] = endpoints[1] = -1;
		return -error;
	}
	return 0;
}

int ker_ff_admission_channel_open(int fd, pid_t expected_peer,
				  uid_t expected_uid, gid_t expected_gid,
				  uint64_t lease,
				  struct ker_ff_admission_channel **output)
{
	struct ker_ff_admission_channel *channel;
	struct stat executable;
	int type = 0, passcred = 0;
	socklen_t length;
	char path[64];
	uint64_t start_time;
	int result;
	if (fd < 0 || expected_peer <= 0 || !lease || !output) return -EINVAL;
	*output = NULL;
	length = sizeof(type);
	if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0 ||
	    type != SOCK_SEQPACKET || length != sizeof(type)) return -EPROTO;
	length = sizeof(passcred);
	if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_PASSCRED, &passcred, &length) != 0 ||
	    !passcred || length != sizeof(passcred)) return -EPROTO;
	int pidfd = (int)syscall(SYS_pidfd_open, expected_peer, 0);
	if (pidfd < 0) return -errno;
	result = process_start_time(expected_peer, &start_time);
	int path_length = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)expected_peer);
	if (!result && (path_length <= 0 || (size_t)path_length >= sizeof(path))) result = -EOVERFLOW;
	if (!result && syscall(SYS_newfstatat, AT_FDCWD, path, &executable, 0) != 0)
		result = -errno;
	if (result) { (void)syscall(SYS_close, pidfd); return result; }
	channel = calloc(1, sizeof(*channel));
	if (!channel) { (void)syscall(SYS_close, pidfd); return -ENOMEM; }
	channel->fd = fd;
	channel->peer_pidfd = pidfd;
	channel->peer_pid = expected_peer;
	channel->peer_uid = expected_uid;
	channel->peer_gid = expected_gid;
	channel->peer_start_time = start_time;
	channel->peer_exe_device = executable.st_dev;
	channel->peer_exe_inode = executable.st_ino;
	channel->lease = lease;
	*output = channel;
	return 0;
}

void ker_ff_admission_channel_close(struct ker_ff_admission_channel *channel)
{
	if (!channel) return;
	if (channel->fd >= 0) (void)syscall(SYS_close, channel->fd);
	if (channel->peer_pidfd >= 0) (void)syscall(SYS_close, channel->peer_pidfd);
	free(channel);
}

int ker_ff_admission_channel_send_admit(struct ker_ff_admission_channel *channel,
					const struct ker_ff_admission_request *request)
{
	struct ker_ff_admission_wire wire = {0};
	if (!channel || !request || request->lease != channel->lease ||
	    !request->command_id || request->command_id <= channel->controller_last_command_id ||
	    channel->controller_state || !request->deadline_ns ||
	    request->key.family != 0 || request->key.reserved || request->key.padding ||
	    request->key.source[1] || request->key.source[2] || request->key.source[3] ||
	    request->key.destination[1] || request->key.destination[2] ||
	    request->key.destination[3] || !request->key.source_port ||
	    !request->key.destination_port)
		return -EINVAL;
	wire.magic = KER_FF_ADMISSION_CHANNEL_MAGIC;
	wire.version = KER_FF_ADMISSION_CHANNEL_VERSION;
	wire.command = KER_FF_ADMISSION_ADMIT;
	wire.length = sizeof(wire);
	wire.lease = request->lease;
	wire.command_id = request->command_id;
	wire.deadline_ns = request->deadline_ns;
	wire.packet_id = request->packet_id;
	wire.key = request->key;
	int result = send_wire(channel, &wire);
	if (!result) {
		channel->controller_last_command_id = request->command_id;
		channel->controller_command_id = request->command_id;
		channel->controller_packet_id = request->packet_id;
		channel->controller_state = 1;
	}
	return result;
}

int ker_ff_admission_channel_send_control(struct ker_ff_admission_channel *channel,
					  uint16_t command, uint64_t command_id,
					  uint32_t packet_id)
{
	struct ker_ff_admission_wire wire = {0};
	if (!channel || !command_id || !channel->controller_state ||
	    command_id != channel->controller_command_id ||
	    packet_id != channel->controller_packet_id ||
	    (command != KER_FF_ADMISSION_CANCEL &&
	     command != KER_FF_ADMISSION_PREPARE_ACCEPT &&
	     command != KER_FF_ADMISSION_FINALIZE &&
	     command != KER_FF_ADMISSION_CANCEL_UNSENT)) return -EINVAL;
	wire.magic = KER_FF_ADMISSION_CHANNEL_MAGIC;
	wire.version = KER_FF_ADMISSION_CHANNEL_VERSION;
	wire.command = command;
	wire.length = sizeof(wire);
	wire.lease = channel->lease;
	wire.command_id = command_id;
	wire.packet_id = packet_id;
	if (command == KER_FF_ADMISSION_PREPARE_ACCEPT &&
	    (channel->controller_state != 2 || !channel->controller_allowed)) return -EPERM;
	if (command == KER_FF_ADMISSION_FINALIZE &&
	    channel->controller_state != 3 && channel->controller_state != 2) return -EPROTO;
	if (command == KER_FF_ADMISSION_FINALIZE && channel->controller_state == 2 &&
	    channel->controller_allowed) return -EPERM;
	if (command == KER_FF_ADMISSION_CANCEL && channel->controller_state == 3) return -EALREADY;
	if (command == KER_FF_ADMISSION_CANCEL_UNSENT && channel->controller_state != 3)
		return -EPROTO;
	int result = send_wire(channel, &wire);
	if (!result) {
		if (command == KER_FF_ADMISSION_CANCEL ||
		    command == KER_FF_ADMISSION_CANCEL_UNSENT) channel->controller_state = 4;
		else if (command == KER_FF_ADMISSION_PREPARE_ACCEPT) channel->controller_state = 3;
		else channel->controller_state = 5;
	}
	return result;
}

int ker_ff_admission_channel_receive(struct ker_ff_admission_channel *channel,
				     struct ker_ff_admission_result *result)
{
	struct ker_ff_admission_wire wire;
	int status;
	if (!channel || !result) return -EINVAL;
	for (;;) {
		status = receive_wire(channel, &wire);
		if (status <= 0) return status;
		break;
	}
	if (wire.command < KER_FF_ADMISSION_RESULT ||
	    wire.command > KER_FF_ADMISSION_FINALIZED || wire.deadline_ns ||
	    wire.allowed > 1 || wire.created > 1 || (wire.created && !wire.allowed) ||
	    (wire.command != KER_FF_ADMISSION_RESULT &&
	     (wire.allowed || wire.created)) ||
	    wire.status > 0 || wire.status < -4095 ||
	    (wire.status && (wire.allowed || wire.created)) ||
	    memcmp(&wire.key, &(struct ker_ff_admission_key){0}, sizeof(wire.key)) ||
	    !channel->controller_state || wire.command_id != channel->controller_command_id ||
	    wire.packet_id != channel->controller_packet_id)
		return -EPROTO;
	if (wire.command == KER_FF_ADMISSION_RESULT) {
		if (channel->controller_state == 1) {
			channel->controller_state = 2;
			channel->controller_allowed = wire.allowed;
			channel->controller_created = wire.created;
		} else if (channel->controller_state != 4) {
			return -EPROTO;
		}
	} else if (wire.command == KER_FF_ADMISSION_PREPARED) {
		if (channel->controller_state != 3 && channel->controller_state != 4)
			return -EPROTO;
	} else if (wire.command == KER_FF_ADMISSION_CANCELLED) {
		if (channel->controller_state != 4)
			return -EPROTO;
		if (!wire.status) channel->controller_state = 0;
	} else if (wire.command == KER_FF_ADMISSION_FINALIZED) {
		if (channel->controller_state != 5 && channel->controller_state != 2)
			return -EPROTO;
		if (!wire.status) channel->controller_state = 0;
	}
	*result = (struct ker_ff_admission_result){
		.lease = wire.lease, .command_id = wire.command_id,
		.packet_id = wire.packet_id, .status = wire.status,
		.allowed = wire.allowed, .created = wire.created};
	return wire.command;
}

static int key_valid(const struct ker_ff_admission_key *key)
{
	return key->family == 0 && !key->reserved && !key->padding &&
		!key->source[1] && !key->source[2] && !key->source[3] &&
		!key->destination[1] && !key->destination[2] && !key->destination[3] &&
		key->source_port && key->destination_port;
}

static int owner_cleanup_unprepared(struct ker_ff_admission_channel *channel,
				    const struct ker_ff_admission_map_ops *ops)
{
	if (!channel->owner_state || channel->owner_prepared || !channel->current.created)
		return 0;
	struct ker_ff_admission_key key;
	memcpy(&key, &channel->current.key, sizeof(key));
	if (ops->revoke(&key, ops->context) != 1) return -ESTALE;
	channel->owner_state = 0;
	channel->owner_prepared = 0;
	return 0;
}

int ker_ff_admission_channel_owner_step(struct ker_ff_admission_channel *channel,
					const struct ker_ff_admission_map_ops *ops)
{
	struct ker_ff_admission_wire command;
	struct timespec now;
	uint64_t now_ns;
	int received;
	if (!channel || !ops || !ops->active || !ops->admit || !ops->revoke)
		return -EINVAL;
	if (!channel->owner_thread_bound) {
		channel->owner_thread = pthread_self();
		channel->owner_thread_bound = 1;
	} else if (!pthread_equal(channel->owner_thread, pthread_self())) {
		return -EPERM;
	}
	if (channel->response_pending) {
		int response = send_pending_response(channel);
		if (response == -EPIPE || response == -ECONNRESET) {
			int cleanup = owner_cleanup_unprepared(channel, ops);
			return cleanup ? cleanup : response;
		}
		return response;
	}
	received = receive_wire(channel, &command);
	if (received <= 0) {
		if (received == -ECONNRESET) {
			int cleanup = owner_cleanup_unprepared(channel, ops);
			return cleanup ? cleanup : received;
		}
		return received;
	}
	if (command.command == KER_FF_ADMISSION_ADMIT) {
		int created = 0, allowed = 0, status = 0;
		struct ker_ff_admission_key key;
		memcpy(&key, &command.key, sizeof(key));
		if (channel->owner_state) {
			response_for_command(channel, &command, KER_FF_ADMISSION_RESULT, -EBUSY);
			return send_pending_response(channel);
		}
		if (command.command_id <= channel->owner_last_command_id) {
			response_for_command(channel, &command, KER_FF_ADMISSION_RESULT, -ESTALE);
			return send_pending_response(channel);
		}
		if (!key_valid(&key) || command.deadline_ns == 0)
			status = -EINVAL;
		else if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			status = -errno;
		else {
			now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
			if (now_ns >= command.deadline_ns) status = -ETIMEDOUT;
			else {
				int active = ops->active(ops->context);
				if (active <= 0) status = active < 0 ? active : -ENOTCONN;
			}
			if (!status) {
				allowed = ops->admit(&key, &created, ops->context);
				if ((allowed != 0 && allowed != 1) ||
				    (created != 0 && created != 1) || (!allowed && created))
					status = -EPROTO;
				if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) status = -errno;
				else {
					now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
					if (now_ns >= command.deadline_ns) status = -ETIMEDOUT;
				}
				if (status && created) {
					if (ops->revoke(&key, ops->context) != 1) status = -ESTALE;
					created = 0;
				}
			}
		}
		channel->current = command;
		channel->owner_last_command_id = command.command_id;
		channel->current.allowed = created ? 1U : status ? 0U : (uint32_t)allowed;
		channel->current.created = (uint32_t)created;
		channel->current.status = status;
		channel->owner_state = 1;
		response_from_current(channel, KER_FF_ADMISSION_RESULT, status);
		channel->response.allowed = channel->current.allowed;
		channel->response.created = channel->current.created;
		return send_pending_response(channel);
	}
	if (command.command != KER_FF_ADMISSION_CANCEL &&
	    command.command != KER_FF_ADMISSION_CANCEL_UNSENT &&
	    command.command != KER_FF_ADMISSION_PREPARE_ACCEPT &&
	    command.command != KER_FF_ADMISSION_FINALIZE)
		return -EPROTO;
	if (!channel->owner_state || command.lease != channel->current.lease ||
	    command.command_id != channel->current.command_id ||
	    command.packet_id != channel->current.packet_id) {
		response_for_command(channel, &command, KER_FF_ADMISSION_FINALIZED, -ESTALE);
		return send_pending_response(channel);
	}
	if (command.command == KER_FF_ADMISSION_CANCEL ||
	    command.command == KER_FF_ADMISSION_CANCEL_UNSENT) {
		int status = 0;
		if (channel->owner_prepared &&
		    command.command != KER_FF_ADMISSION_CANCEL_UNSENT) status = -EALREADY;
		else if (channel->current.created) {
			struct ker_ff_admission_key key;
			memcpy(&key, &channel->current.key, sizeof(key));
			if (ops->revoke(&key, ops->context) != 1) status = -ESTALE;
		}
		if (!status) {
			channel->owner_state = 0;
			channel->owner_prepared = 0;
		}
		response_for_command(channel, &command, KER_FF_ADMISSION_CANCELLED, status);
		return send_pending_response(channel);
	}
	if (command.command == KER_FF_ADMISSION_PREPARE_ACCEPT) {
		int status = channel->owner_prepared ? -EALREADY :
			(channel->current.status || !channel->current.allowed ? -EPERM : 0);
		if (!status) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
				status = -errno;
			} else {
				now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
				if (now_ns >= channel->current.deadline_ns) status = -ETIMEDOUT;
			}
		}
		if (status == -ETIMEDOUT && channel->current.created) {
			struct ker_ff_admission_key key;
			memcpy(&key, &channel->current.key, sizeof(key));
			if (ops->revoke(&key, ops->context) != 1) {
				status = -ESTALE;
			} else {
				channel->current.created = 0;
				channel->current.allowed = 0;
				channel->current.status = -ETIMEDOUT;
			}
		}
		if (!status) channel->owner_prepared = 1;
		response_for_command(channel, &command, KER_FF_ADMISSION_PREPARED, status);
		return send_pending_response(channel);
	}
	if (channel->current.allowed && !channel->owner_prepared) {
		response_for_command(channel, &command, KER_FF_ADMISSION_FINALIZED, -EPERM);
		return send_pending_response(channel);
	}
	channel->owner_state = 0;
	channel->owner_prepared = 0;
	response_for_command(channel, &command, KER_FF_ADMISSION_FINALIZED, 0);
	return send_pending_response(channel);
}
