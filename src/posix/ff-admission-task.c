#define _GNU_SOURCE
#include "ff-admission-task.h"
#include "ff-admission-queue.h"
#include "ff-admission-channel.h"
#include "ff-admission-request-identity.h"
#include "ff-owner-admission-control.h"
#include "tcp-request-revoke.h"
#include "fd-table.h"
#include "lkl-overlay/arch/lkl/include/uapi/asm/ker_ff_admission_queue.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <lkl.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

#define TASK_HELLO_VERSION KER_FF_OWNER_ADMISSION_HELLO_VERSION

enum task_state { TASK_STARTING, TASK_READY, TASK_FAILED, TASK_STOPPING,
	TASK_TERMINAL };

struct ker_ff_admission_task {
	pthread_mutex_t lock;
	pthread_t thread;
	bool thread_started;
	bool joined;
	bool stop_requested;
	bool listener_closed;
	int listener_fd;
	struct ker_fd *listener_entry;
	uint64_t listener_cookie;
	uint32_t mark;
	uint64_t registration_id;
	pid_t actor_pid;
	uid_t actor_uid;
	gid_t actor_gid;
	uint64_t actor_start_time;
	int actor_pidfd;
	int peer_fd;
	int peer_monitor_fd;
	enum task_state state;
	int status;
	uint64_t lease;
	uint64_t next_command_id;
	struct ker_ff_admission_queue *queue;
	struct ker_ff_admission_channel *channel;
};

static pthread_mutex_t task_global_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ker_ff_admission_task *active_task;
static uint64_t task_now_ns(void);

#ifdef KER_C16_ADMISSION_TEST_TRACE
static void task_test_trace(const char *event,
	const struct ker_ff_admission_packet *packet)
{
	char line[128];
	uint64_t now_ns = task_now_ns();
	int length = snprintf(line, sizeof(line),
		"C16_ADMISSION %s remote_port=%u now_ns=%llu deadline_ns=%llu\n",
		event, (unsigned)ntohs(packet->remote_port),
		(unsigned long long)now_ns,
		(unsigned long long)packet->deadline_ns);
	if (length > 0 && (size_t)length < sizeof(line))
		(void)syscall(SYS_write, STDOUT_FILENO, line, (size_t)length);
}
#else
#define task_test_trace(event, packet) ((void)0)
#endif

static uint64_t task_now_ns(void)
{
	struct timespec now = {0};
	if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 || now.tv_nsec < 0 ||
	    now.tv_nsec >= 1000000000L ||
	    (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) /
		UINT64_C(1000000000))
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static bool task_should_stop(struct ker_ff_admission_task *task)
{
	pthread_mutex_lock(&task->lock);
	bool stop = task->stop_requested || task->listener_closed;
	pthread_mutex_unlock(&task->lock);
	struct pollfd actor = {.fd = task->actor_pidfd, .events = POLLIN};
	int ready = (int)syscall(SYS_poll, &actor, 1, 0);
	if (ready > 0 &&
	    (actor.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
		stop = true;
	struct pollfd peer = {.fd = task->peer_monitor_fd, .events = POLLIN | POLLHUP};
	ready = task->peer_monitor_fd >= 0 ?
		(int)syscall(SYS_poll, &peer, 1, 0) : 0;
	if (ready > 0 &&
	    (peer.revents & (POLLHUP | POLLERR | POLLNVAL))) stop = true;
	return stop;
}

static bool task_peer_gone(struct ker_ff_admission_task *task)
{
	struct pollfd peers[2] = {
		{.fd = task->actor_pidfd, .events = POLLIN},
		{.fd = task->peer_monitor_fd, .events = POLLIN | POLLHUP}};
	int count = (int)syscall(SYS_poll, peers, 2, 0);
	return count > 0 &&
		((peers[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) ||
		 (peers[1].revents & (POLLHUP | POLLERR | POLLNVAL)));
}

static int task_wait_result(struct ker_ff_admission_task *task, uint16_t expected,
	uint64_t deadline, struct ker_ff_admission_result *result, bool cleanup)
{
	for (;;) {
		if (cleanup ? task_peer_gone(task) : task_should_stop(task))
			return cleanup ? -ECONNRESET : -ECANCELED;
		int status = ker_ff_admission_channel_receive(task->channel, result);
		if (status == expected) return result->status;
		/* Replies are strictly serialized by command ID. Silently skipping an
		 * unexpected positive message can turn a late or duplicated response
		 * into apparent progress for the current transaction. */
		if (status > 0) return -EPROTO;
		if (status < 0 && status != -EAGAIN && status != -EWOULDBLOCK)
			return status;
		uint64_t now = task_now_ns();
		if (!now) return -EIO;
		if (now >= deadline) return -ETIMEDOUT;
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

static int task_wait_cancelled(struct ker_ff_admission_task *task,
	uint64_t deadline, bool admit_result_may_be_late,
	bool prepare_was_sent,
	struct ker_ff_admission_result *result)
{
	bool saw_result = false, saw_prepared = false;
	for (;;) {
		if (task_peer_gone(task)) return -ECONNRESET;
		int command = ker_ff_admission_channel_receive(task->channel, result);
		if (command == KER_FF_ADMISSION_CANCELLED) return result->status;
		if (command == KER_FF_ADMISSION_RESULT && admit_result_may_be_late &&
		    !saw_result) {
			saw_result = true;
			continue;
		}
		if (command == KER_FF_ADMISSION_PREPARED && prepare_was_sent &&
		    !saw_prepared) {
			saw_prepared = true;
			continue;
		}
		if (command > 0) return -EPROTO;
		if (command < 0 && command != -EAGAIN && command != -EWOULDBLOCK)
			return command;
		uint64_t now = task_now_ns();
		if (!now) return -EIO;
		if (now >= deadline) return -ETIMEDOUT;
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

static void task_drop_packet(struct ker_ff_admission_task *task,
	const struct ker_ff_admission_packet *packet)
{
	int sent = 0;
	(void)ker_ff_admission_queue_verdict(task->queue, packet->lease,
		packet->deadline_ns, packet->id, 0, &sent);
}

static int task_process_packet(struct ker_ff_admission_task *task,
	const struct ker_ff_admission_packet *packet, int listener_fd)
{
	struct ker_ff_admission_request_identity *identity = NULL;
	struct ker_ff_admission_request request = {0};
	struct ker_ff_admission_result response = {0};
	struct ker_tcp_request_revoke_request request_identity = {0};
	struct ker_ff_admission_ipv4_tuple tuple = {
		.local = {.sin_family = AF_INET, .sin_port = packet->local_port,
			.sin_addr.s_addr = packet->local_address},
		.remote = {.sin_family = AF_INET, .sin_port = packet->remote_port,
			.sin_addr.s_addr = packet->remote_address}};
	atomic_bool cancel = false;
	int status = -EPROTO;
	bool map_command_sent = false, prepare_sent = false, accept_sent = false;
	bool request_identity_ready = false, admit_result_received = false;
	bool request_revoke_attempted = false, request_revoked = false;
	bool map_cancelled = false;
	if (packet->mark != task->mark || packet->lease != task->lease ||
	    !packet->id || listener_fd < 0 || !packet->deadline_ns)
		goto drop;
	uint64_t current_cookie = 0;
	int cookie_length = sizeof(current_cookie);
	long cookie_status = lkl_sys_getsockopt((unsigned int)task->listener_entry->native,
		SOL_SOCKET, SO_COOKIE, (char *)&current_cookie, &cookie_length);
	if (cookie_status < 0 || cookie_length != sizeof(current_cookie) ||
	    current_cookie != task->listener_cookie) {
		status = cookie_status < 0 ? (int)cookie_status : -ESTALE;
		goto drop;
	}
	status = ker_ff_admission_request_identity_begin(listener_fd, &tuple,
		task->mark, &identity);
	if (status) goto drop;
	uint64_t now;
	for (;;) {
		if (task_should_stop(task)) {
			atomic_store_explicit(&cancel, true, memory_order_relaxed);
			status = -ECANCELED;
			goto drop;
		}
		status = ker_ff_admission_request_identity_step(identity, &cancel,
			&request_identity);
		if (status == 1) {
			request_identity_ready = true;
			task_test_trace("identity-ready", packet);
			break;
		}
		if (status < 0) goto drop;
		now = task_now_ns();
		if (!now || now >= packet->deadline_ns) { status = -ETIMEDOUT; goto drop; }
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
	if (task->next_command_id == UINT64_MAX) {
		status = -EOVERFLOW;
		goto drop;
	}
	request.lease = packet->lease;
	request.command_id = ++task->next_command_id;
	request.deadline_ns = packet->deadline_ns;
	request.packet_id = packet->id;
	request.key.family = 0;
	request.key.source[0] = packet->remote_address;
	request.key.destination[0] = packet->local_address;
	request.key.source_port = packet->remote_port;
	request.key.destination_port = packet->local_port;
	status = ker_ff_admission_channel_send_admit(task->channel, &request);
	if (status) goto drop;
	map_command_sent = true;
	status = task_wait_result(task, KER_FF_ADMISSION_RESULT,
		packet->deadline_ns, &response, false);
	admit_result_received = response.lease == packet->lease &&
		response.command_id == request.command_id && response.packet_id == packet->id;
	if (status == -ETIMEDOUT) task_test_trace("owner-timeout", packet);
	if (status) goto drop;
	if (response.status) {
		status = response.status;
		goto drop;
	}
	if (response.allowed == 0 && response.created == 0) {
		status = ker_ff_admission_request_identity_revalidate(identity);
		if (status) goto drop;
		request_revoke_attempted = true;
		status = ker_native_tcp_request_revoke(&request_identity);
		if (status) goto drop;
		request_revoked = true;
		task_test_trace("request-revoked", packet);
		goto drop;
	}
	if (response.allowed != 1 || response.created > 1) {
		status = -EPROTO;
		goto drop;
	}
	status = ker_ff_admission_channel_send_control(task->channel,
		KER_FF_ADMISSION_PREPARE_ACCEPT, request.command_id, packet->id);
	if (status) goto drop;
	/* The command may have reached the owner even when its PREPARED response
	 * arrives after the packet deadline. Track the send independently. */
	prepare_sent = true;
	status = task_wait_result(task, KER_FF_ADMISSION_PREPARED,
		packet->deadline_ns, &response, false);
	if (status) goto drop;
	status = ker_ff_admission_request_identity_revalidate(identity);
	if (status) goto drop;
	int sent = 0;
	status = ker_ff_admission_queue_verdict(task->queue, packet->lease,
		packet->deadline_ns, packet->id, 1, &sent);
	accept_sent = sent != 0;
	if (accept_sent) {
		/* Once a full NF_ACCEPT send may have entered LKL, preserve the map even
		 * if its ACK is lost; the original packet may already be on the wire. */
		if (!status) {
			status = ker_ff_admission_channel_send_control(task->channel,
				KER_FF_ADMISSION_FINALIZE, request.command_id, packet->id);
			if (!status) status = task_wait_result(task,
				KER_FF_ADMISSION_FINALIZED, packet->deadline_ns, &response, false);
		}
		/* A sent verdict with a lost/error ACK is uncertain. Keep the map
		 * entry and quarantine this admission task rather than claiming healthy
		 * state or starting another transaction on an unsettled owner channel. */
		if (sent && status == 0 && response.status) status = response.status;
		if (status) {
			if (status == -ETIMEDOUT) task_test_trace("finalized-timeout", packet);
			/* No later packet may reuse this owner channel/map transaction. */
			task_test_trace("accepted-quarantine-map-retained", packet);
			status = -EOWNERDEAD;
		}
		goto out;
	}
	if (!status) status = -EIO;
	drop:
	/* A rejected or expired packet must never leave its exact original reqsk
	 * in SYN_RECV. Do this before waiting for an FF owner that may be stopped;
	 * the independent broker deadline remains authoritative. */
	if (request_identity_ready && !request_revoke_attempted &&
	    !request_revoked && !accept_sent) {
		int revoke_status = ker_ff_admission_request_identity_revalidate(identity);
		if (!revoke_status) {
			request_revoke_attempted = true;
			revoke_status = ker_native_tcp_request_revoke(&request_identity);
		}
		if (!revoke_status) request_revoked = true;
		else if (!status || status == -ETIMEDOUT) status = revoke_status;
		if (request_revoked) task_test_trace("request-revoked", packet);
	}
	/* DROP the held skb before bounded owner cleanup. A complete DROP send with
	 * an uncertain ACK remains fail-closed in the queue layer. */
	task_drop_packet(task, packet);
	if (prepare_sent && !accept_sent && !map_cancelled) {
		int cancel = ker_ff_admission_channel_send_control(task->channel,
			KER_FF_ADMISSION_CANCEL_UNSENT, request.command_id, packet->id);
		uint64_t cleanup_now = task_now_ns();
		uint64_t cleanup_deadline = cleanup_now &&
			cleanup_now <= UINT64_MAX - UINT64_C(250000000) ?
			cleanup_now + UINT64_C(250000000) : 0;
		if (!cancel && cleanup_deadline) {
			cancel = task_wait_cancelled(task, cleanup_deadline, false, true,
				&response);
			if (!cancel && !response.status) map_cancelled = true;
		}
		if (!map_cancelled) status = cancel ? cancel : -EIO;
	} else if (map_command_sent && !accept_sent && !map_cancelled) {
		if (!ker_ff_admission_channel_send_control(task->channel,
			KER_FF_ADMISSION_CANCEL, request.command_id, packet->id)) {
			uint64_t cleanup_now = task_now_ns();
			uint64_t cleanup_deadline = cleanup_now &&
				cleanup_now <= UINT64_MAX - UINT64_C(250000000) ?
				cleanup_now + UINT64_C(250000000) : 0;
			if (cleanup_deadline && !task_wait_cancelled(task,
				cleanup_deadline, !admit_result_received, false, &response) &&
				!response.status) map_cancelled = true;
		}
		if (!map_cancelled) status = -EIO;
	}
	out:
	if (identity) ker_ff_admission_request_identity_close(identity);
	return status;
}

static void task_set_terminal(struct ker_ff_admission_task *task, int status)
{
	pthread_mutex_lock(&task->lock);
	task->status = status;
	task->state = status ? TASK_FAILED : TASK_TERMINAL;
	pthread_mutex_unlock(&task->lock);
}

static void *task_worker(void *argument)
{
	struct ker_ff_admission_task *task = argument;
	struct ker_ff_admission_queue *queue = NULL;
	struct ker_ff_admission_channel *channel = NULL;
	int status = ker_ff_admission_queue_start(task->mark, &queue);
	if (status) goto terminal;
	uint64_t lease = ker_ff_admission_queue_lease(queue);
	if (!lease) { status = -EPROTO; goto terminal; }
	struct ker_ff_owner_admission_hello_reply ready = {
		.magic = KER_FF_OWNER_ADMISSION_HELLO_MAGIC,
		.version = TASK_HELLO_VERSION,
		.length = sizeof(ready), .registration_id = task->registration_id,
		.queue_lease = lease, .status = 0};
	task->peer_monitor_fd = (int)syscall(SYS_fcntl, task->peer_fd,
		F_DUPFD_CLOEXEC, 0);
	if (task->peer_monitor_fd < 0) { status = -errno; goto terminal; }
	status = ker_ff_admission_channel_open(task->peer_fd, task->actor_pid,
		task->actor_uid, task->actor_gid, lease, &channel);
	if (status) goto terminal;
	int channel_fd = task->peer_fd;
	task->peer_fd = -1;
	/* Publish readiness to the broker before the owner can observe READY and
	 * race its first socket RPC against the broker's endpoint pump. The queue
	 * and authenticated channel are already live at this point. */
	pthread_mutex_lock(&task->lock);
	task->queue = queue;
	task->channel = channel;
	task->lease = lease;
	task->state = TASK_READY;
	pthread_mutex_unlock(&task->lock);
	ssize_t sent = syscall(SYS_sendto, channel_fd, &ready, sizeof(ready),
		MSG_NOSIGNAL, NULL, 0);
	if (sent != sizeof(ready)) { status = sent < 0 ? -errno : -EIO; goto terminal; }
	for (;;) {
		if (task_should_stop(task)) break;
		struct ker_ff_admission_packet packet = {0};
		status = ker_ff_admission_queue_receive(queue, &packet, 10);
		if (status < 0) break;
		if (!status) continue;
		pthread_mutex_lock(&task->lock);
		int listener_fd = task->listener_closed ? -1 : task->listener_fd;
		pthread_mutex_unlock(&task->lock);
		if (listener_fd < 0) {
			task_drop_packet(task, &packet);
			continue;
		}
		status = task_process_packet(task, &packet, listener_fd);
		if (status && status != -ETIMEDOUT && status != -ECANCELED &&
		    status != -ENOENT && status != -ENOBUFS)
			break;
	}
	if (channel) ker_ff_admission_channel_close(channel);
	if (queue) ker_ff_admission_queue_close(queue); /* gate remains armed */
	if (task->peer_monitor_fd >= 0) {
		(void)syscall(SYS_close, task->peer_monitor_fd);
		task->peer_monitor_fd = -1;
	}
	pthread_mutex_lock(&task->lock);
	task->channel = NULL;
	task->queue = NULL;
	pthread_mutex_unlock(&task->lock);
	task_set_terminal(task, status == -ECANCELED ? 0 : status);
	return NULL;

terminal:
	if (channel) ker_ff_admission_channel_close(channel);
	if (queue) ker_ff_admission_queue_close(queue);
	if (task->peer_fd >= 0) {
		(void)syscall(SYS_close, task->peer_fd);
		task->peer_fd = -1;
	}
	if (task->peer_monitor_fd >= 0) {
		(void)syscall(SYS_close, task->peer_monitor_fd);
		task->peer_monitor_fd = -1;
	}
	task_set_terminal(task, status ? status : -EIO);
	return NULL;
}

static int validate_peer(const struct ker_ff_admission_task_config *config)
{
	struct ucred peer = {0};
	socklen_t length = sizeof(peer);
	if (syscall(SYS_getsockopt, config->peer_fd, SOL_SOCKET, SO_PEERCRED,
			&peer, &length) || length != sizeof(peer))
		return -(errno ? errno : EPROTO);
	if (peer.pid != config->actor_pid || peer.uid != config->actor_uid ||
	    peer.gid != config->actor_gid)
		return -EACCES;
	int pidfd = -1;
	length = sizeof(pidfd);
	if (syscall(SYS_getsockopt, config->peer_fd, SOL_SOCKET, SO_PEERPIDFD,
			&pidfd, &length) || length != sizeof(pidfd)) {
		if (pidfd >= 0) (void)syscall(SYS_close, pidfd);
		return -(errno ? errno : EPROTO);
	}
	struct pollfd pfd = {.fd = pidfd, .events = POLLIN};
	int ready = (int)syscall(SYS_poll, &pfd, 1, 0);
	int status = ready < 0 ? -errno : ready &&
		(pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) ? -ESRCH : 0;
	(void)syscall(SYS_close, pidfd);
	return status;
}

int ker_posix_ff_admission_task_start(
	const struct ker_ff_admission_task_config *config,
	struct ker_ff_admission_task **output)
{
	if (!config || !output || !config->owner_mark ||
	    config->owner_mark > INT32_MAX || !config->registration_id ||
	    config->actor_pid <= 0 || config->actor_pidfd < 0 || config->peer_fd < 0 ||
	    !config->actor_start_time)
		return -EINVAL;
	*output = NULL;
	int status = validate_peer(config);
	if (status) return status;
	struct ker_ff_admission_task *task = calloc(1, sizeof(*task));
	if (!task) return -ENOMEM;
	if (pthread_mutex_init(&task->lock, NULL)) { free(task); return -ENOMEM; }
	task->mark = config->owner_mark;
	task->registration_id = config->registration_id;
	task->actor_pid = config->actor_pid;
	task->actor_uid = config->actor_uid;
	task->actor_gid = config->actor_gid;
	task->actor_start_time = config->actor_start_time;
	task->actor_pidfd = (int)syscall(SYS_fcntl, config->actor_pidfd,
		F_DUPFD_CLOEXEC, 0);
	task->peer_fd = (int)syscall(SYS_fcntl, config->peer_fd,
		F_DUPFD_CLOEXEC, 0);
	task->peer_monitor_fd = -1;
	task->listener_fd = -1;
	task->lease = 0;
	task->next_command_id = 0;
	task->state = TASK_STARTING;
	if (task->actor_pidfd < 0 || task->peer_fd < 0) {
		status = -errno;
		goto fail;
	}
	pthread_mutex_lock(&task_global_lock);
	if (active_task) {
		pthread_mutex_unlock(&task_global_lock);
		status = -EBUSY;
		goto fail;
	}
	active_task = task;
	pthread_mutex_unlock(&task_global_lock);
	int created = pthread_create(&task->thread, NULL, task_worker, task);
	if (created) {
		pthread_mutex_lock(&task_global_lock);
		active_task = NULL;
		pthread_mutex_unlock(&task_global_lock);
		status = -created;
		goto fail;
	}
	task->thread_started = true;
	*output = task;
	return 0;

fail:
	if (task->actor_pidfd >= 0) (void)syscall(SYS_close, task->actor_pidfd);
	if (task->peer_fd >= 0) (void)syscall(SYS_close, task->peer_fd);
	if (task->peer_monitor_fd >= 0) (void)syscall(SYS_close, task->peer_monitor_fd);
	pthread_mutex_destroy(&task->lock);
	free(task);
	return status;
}

int ker_posix_ff_admission_task_poll(struct ker_ff_admission_task *task,
	uint64_t *queue_lease)
{
	if (!task || !queue_lease) return -EINVAL;
	pthread_mutex_lock(&task->lock);
	int status = task->state == TASK_READY ? KER_FF_ADMISSION_TASK_READY :
		(task->state == TASK_STARTING ? KER_FF_ADMISSION_TASK_STARTING :
		 task->state == TASK_STOPPING ? KER_FF_ADMISSION_TASK_STOPPING :
		 task->state == TASK_TERMINAL ? KER_FF_ADMISSION_TASK_TERMINAL :
		 task->status ? task->status : -ECONNRESET);
	uint64_t lease = task->lease;
	pthread_mutex_unlock(&task->lock);
	if (status == 1) *queue_lease = lease;
	return status;
}

int ker_posix_ff_admission_task_set_listener(
	struct ker_ff_admission_task *task, int listener_fd)
{
	if (!task || listener_fd < 0) return -EINVAL;
	struct ker_fd *entry = ker_fd_get(listener_fd);
	if (!entry || entry->kind != KER_FD_SOCKET) {
		if (entry) ker_fd_put(entry);
		return -ENOTSOCK;
	}
	int domain = 0, type = 0, protocol = 0, accepting = 0, mark = 0;
	int fastopen = 0;
	int length = sizeof(int);
	long result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
		SO_DOMAIN, (char *)&domain, &length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	if (length != sizeof(domain)) { ker_fd_put(entry); return -EPROTO; }
	length = sizeof(int);
	result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
		SO_TYPE, (char *)&type, &length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	if (length != sizeof(type)) { ker_fd_put(entry); return -EPROTO; }
	length = sizeof(int);
	result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
		SO_PROTOCOL, (char *)&protocol, &length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	if (length != sizeof(protocol)) { ker_fd_put(entry); return -EPROTO; }
	length = sizeof(int);
	result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
		SO_ACCEPTCONN, (char *)&accepting, &length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	if (length != sizeof(accepting)) { ker_fd_put(entry); return -EPROTO; }
	length = sizeof(int);
	result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
		SO_MARK, (char *)&mark, &length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	if (length != sizeof(mark)) { ker_fd_put(entry); return -EPROTO; }
	length = sizeof(int);
	result = lkl_sys_getsockopt((unsigned int)entry->native, IPPROTO_TCP,
		TCP_FASTOPEN, (char *)&fastopen, &length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	if (length != sizeof(fastopen)) { ker_fd_put(entry); return -EPROTO; }
	struct sockaddr_in local = {0};
	int local_length = sizeof(local);
	result = lkl_sys_getsockname((unsigned int)entry->native,
		(struct lkl_sockaddr *)&local, &local_length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	uint64_t cookie = 0;
	int cookie_length = sizeof(cookie);
	result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
		SO_COOKIE, (char *)&cookie, &cookie_length);
	if (result < 0) { ker_fd_put(entry); return (int)result; }
	if (domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP ||
	    accepting || (uint32_t)mark != task->mark || fastopen ||
	    local_length != sizeof(local) || local.sin_family != AF_INET ||
	    !local.sin_port || !cookie || cookie_length != sizeof(cookie)) {
		ker_fd_put(entry);
		return -EOPNOTSUPP;
	}
	pthread_mutex_lock(&task->lock);
	if (task->state != TASK_READY || task->listener_entry || task->stop_requested) {
		pthread_mutex_unlock(&task->lock);
		ker_fd_put(entry);
		return -EBUSY;
	}
	task->listener_fd = listener_fd;
	task->listener_entry = entry;
	task->listener_cookie = cookie;
	pthread_mutex_unlock(&task->lock);
	return 0;
}

int ker_posix_ff_admission_task_listener_closed(
	struct ker_ff_admission_task *task, int listener_fd)
{
	if (!task || listener_fd < 0) return -EINVAL;
	pthread_mutex_lock(&task->lock);
	if (!task->listener_entry || task->listener_fd != listener_fd) {
		pthread_mutex_unlock(&task->lock);
		return -ESTALE;
	}
	task->listener_closed = true;
	task->stop_requested = true;
	if (task->state != TASK_FAILED && task->state != TASK_TERMINAL)
		task->state = TASK_STOPPING;
	pthread_mutex_unlock(&task->lock);
	return 0;
}

int ker_posix_ff_admission_task_request_stop(
	struct ker_ff_admission_task *task)
{
	if (!task) return -EINVAL;
	pthread_mutex_lock(&task->lock);
	task->stop_requested = true;
	if (task->state != TASK_FAILED && task->state != TASK_TERMINAL)
		task->state = TASK_STOPPING;
	pthread_mutex_unlock(&task->lock);
	return 0;
}

int ker_posix_ff_admission_task_release(struct ker_ff_admission_task *task)
{
	if (!task) return -EINVAL;
	pthread_mutex_lock(&task_global_lock);
	if (active_task != task) {
		pthread_mutex_unlock(&task_global_lock);
		return -ESTALE;
	}
	pthread_mutex_lock(&task->lock);
	if (task->state != TASK_TERMINAL && task->state != TASK_FAILED) {
		pthread_mutex_unlock(&task->lock);
		pthread_mutex_unlock(&task_global_lock);
		return -EBUSY;
	}
	pthread_mutex_unlock(&task->lock);
	if (task->thread_started && !task->joined) {
		int result = pthread_join(task->thread, NULL);
		if (result) {
			pthread_mutex_unlock(&task_global_lock);
			return -result;
		}
		task->joined = true;
	}
	active_task = NULL;
	pthread_mutex_unlock(&task_global_lock);
	if (task->listener_entry) ker_fd_put(task->listener_entry);
	if (task->actor_pidfd >= 0) (void)syscall(SYS_close, task->actor_pidfd);
	if (task->peer_fd >= 0) (void)syscall(SYS_close, task->peer_fd);
	pthread_mutex_destroy(&task->lock);
	free(task);
	return 0;
}

void ker_ff_admission_task_runtime_shutdown(void)
{
	pthread_mutex_lock(&task_global_lock);
	struct ker_ff_admission_task *task = active_task;
	if (task) {
		pthread_mutex_lock(&task->lock);
		task->stop_requested = true;
		if (task->state != TASK_FAILED && task->state != TASK_TERMINAL)
			task->state = TASK_STOPPING;
		pthread_mutex_unlock(&task->lock);
	}
	if (task && task->thread_started && !task->joined) {
		if (!pthread_join(task->thread, NULL)) task->joined = true;
	}
	pthread_mutex_unlock(&task_global_lock);
}
