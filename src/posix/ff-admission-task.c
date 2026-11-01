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
enum task_window_state { WINDOW_ACTIVE, WINDOW_RETIRING, WINDOW_RETIRED,
	WINDOW_REARMING, WINDOW_QUARANTINED };

struct ker_ff_admission_task {
	pthread_mutex_t lock;
	pthread_t thread;
	bool thread_started;
	bool joined;
	bool stop_requested;
	bool retire_requested;
	bool rearm_requested;
	bool accept_uncertain;
	bool listener_closed;
	bool listener_ref_released;
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
	enum task_window_state window_state;
	int status;
	uint64_t lease;
	uint64_t next_command_id;
	uint64_t epoch;
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
static void task_test_window_status(const char *event, int status)
{
	char line[128];
	int length = snprintf(line, sizeof(line),
		"C17_WINDOW_TASK %s status=%d now_ns=%llu\n", event, status,
		(unsigned long long)task_now_ns());
	if (length > 0 && (size_t)length < sizeof(line))
		(void)syscall(SYS_write, STDOUT_FILENO, line, (size_t)length);
}
static void task_test_lifecycle_trace(const char *event)
{
	char line[128];
	int length = snprintf(line, sizeof(line), "C16_ADMISSION %s\n", event);
	if (length > 0 && (size_t)length < sizeof(line))
		(void)syscall(SYS_write, STDOUT_FILENO, line, (size_t)length);
}
#else
#define task_test_trace(event, packet) ((void)0)
#define task_test_window_status(event, status) ((void)0)
#define task_test_lifecycle_trace(event) ((void)0)
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

static int task_drop_packet(struct ker_ff_admission_task *task,
	const struct ker_ff_admission_packet *packet)
{
	uint64_t now = task_now_ns();
	if (!now || now > UINT64_MAX - UINT64_C(250000000)) return -EIO;
	/* DROP is mandatory cleanup whether admission expired or failed earlier.
	 * Give its ACK a separate bounded cleanup deadline; this can never turn an
	 * expired packet into ACCEPT. */
	uint64_t cleanup_deadline = now + UINT64_C(250000000);
	int sent = 0;
	int status = ker_ff_admission_queue_verdict(task->queue, packet->lease,
		cleanup_deadline, packet->id, 0, &sent);
	return status;
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
	if (status) {
		if (status == -ETIMEDOUT) task_test_trace("prepared-timeout", packet);
		goto drop;
	}
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
			pthread_mutex_lock(&task->lock);
			task->accept_uncertain = true;
			pthread_mutex_unlock(&task->lock);
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
	int drop_status = task_drop_packet(task, packet);
	if (drop_status) status = drop_status;
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
		if (map_cancelled) task_test_trace("cancel-unsent-settled", packet);
		if (!map_cancelled) {
			task_test_trace("cancel-unsent-unresolved", packet);
			/* The owner may still hold the map reservation. Do not let the
			 * worker reuse this channel for another packet after an uncertain
			 * cancellation; quarantine it until the owner exits or resolves it. */
			status = -EOWNERDEAD;
		}
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
	pthread_mutex_lock(&task->lock);
	bool uncertain = task->accept_uncertain;
	pthread_mutex_unlock(&task->lock);
	return uncertain ? -EINPROGRESS : status;
}

static void task_set_terminal(struct ker_ff_admission_task *task, int status)
{
	pthread_mutex_lock(&task->lock);
	task->status = status;
	task->state = status ? TASK_FAILED : TASK_TERMINAL;
	if (status) task->window_state = WINDOW_QUARANTINED;
	pthread_mutex_unlock(&task->lock);
}

static void task_set_window(struct ker_ff_admission_task *task,
	enum task_window_state state)
{
	pthread_mutex_lock(&task->lock);
	task->window_state = state;
	pthread_mutex_unlock(&task->lock);
}

static bool task_retire_requested(struct ker_ff_admission_task *task)
{
	pthread_mutex_lock(&task->lock);
	bool requested = task->retire_requested;
	pthread_mutex_unlock(&task->lock);
	return requested;
}

static int task_next_command(struct ker_ff_admission_task *task,
	uint64_t *command_id)
{
	if (task->next_command_id == UINT64_MAX) return -EOVERFLOW;
	*command_id = ++task->next_command_id;
	return 0;
}

static int task_wait_window_reply(struct ker_ff_admission_task *task,
	uint16_t expected, uint64_t command_id, uint64_t lease,
	struct ker_ff_admission_result *response)
{
	uint64_t now = task_now_ns();
	if (!now || now > UINT64_MAX - UINT64_C(2000000000)) return -EIO;
	uint64_t deadline = now + UINT64_C(2000000000);
	for (;;) {
		if (task_peer_gone(task)) return -ECONNRESET;
		int received = ker_ff_admission_channel_receive(task->channel, response);
		if (received == expected) {
			if (response->lease != lease || response->command_id != command_id ||
			    response->packet_id || response->allowed || response->created)
				return -EPROTO;
			return response->status;
		}
		if (received > 0) return -EPROTO;
		if (received < 0 && received != -EAGAIN && received != -EWOULDBLOCK)
			return received;
		now = task_now_ns();
		if (!now) return -EIO;
		if (now >= deadline) return -ETIMEDOUT;
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
}

static int task_retire_window(struct ker_ff_admission_task *task,
	struct ker_ff_admission_queue **queue_ptr)
{
	struct ker_ff_admission_queue *queue = *queue_ptr;
	struct ker_ff_admission_packet packet;
	struct ker_ff_admission_result response = {0};
	int status;
	bool drained_successfully = false;
	pthread_mutex_lock(&task->lock);
	bool uncertain = task->accept_uncertain;
	pthread_mutex_unlock(&task->lock);
	if (uncertain) return -EINPROGRESS;
	/* Disable first, atomically with respect to the single LKL CPU. An already
	 * delivered deferred notification remains in this queue object and is
	 * processed below while the old map is still open. */
	if (task_should_stop(task)) return -ECANCELED;
	status = ker_ff_admission_queue_disable_for_retire(queue);
	if (status) return status;
	/* Drain notifications that entered the old queue before disable acquired
	 * the LKL CPU. No new hook can enqueue after that point. */
	for (unsigned drained = 0; drained < 128; ++drained) {
		status = ker_ff_admission_queue_receive(queue, &packet, 0);
		if (status < 0) return status;
		if (!status) {
			status = ker_ff_admission_queue_retire_drained(queue);
			if (status == 1) {
				drained_successfully = true;
				break;
			}
			if (status < 0) return status;
			continue;
		}
		status = task_process_packet(task, &packet, task->listener_fd);
		if (status && status != -ETIMEDOUT && status != -ECANCELED &&
		    status != -ENOENT && status != -ENOBUFS) return status;
		if (drained == 127) return -EOVERFLOW;
	}
	if (!drained_successfully) return -EOVERFLOW;
	/* Do not publish a pointer to a queue after its fd has been closed. */
	pthread_mutex_lock(&task->lock);
	if (task->queue == queue) task->queue = NULL;
	pthread_mutex_unlock(&task->lock);
	ker_ff_admission_queue_close(queue);
	*queue_ptr = NULL;
	uint64_t command_id;
	status = task_next_command(task, &command_id);
	if (status) return status;
	status = ker_ff_admission_channel_send_retire(task->channel, command_id);
	if (status) return status;
	status = task_wait_window_reply(task, KER_FF_ADMISSION_RETIRED,
		command_id, task->lease, &response);
	if (status) return status;
	task_set_window(task, WINDOW_RETIRED);
	pthread_mutex_lock(&task->lock);
	task->retire_requested = false;
	pthread_mutex_unlock(&task->lock);
	return 0;
}

static int task_listener_revalidate(struct ker_ff_admission_task *task,
	int listener_fd)
{
	struct ker_fd *entry = ker_fd_get(listener_fd);
	if (!entry) return -EBADF;
	if (entry != task->listener_entry) {
		ker_fd_put(entry);
		return -ESTALE;
	}
	int domain = 0, type = 0, protocol = 0, accepting = 0, mark = 0, fastopen = 0;
	int length = sizeof(int);
	long result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
		SO_DOMAIN, (char *)&domain, &length);
	if (result >= 0 && length == sizeof(domain)) {
		length = sizeof(type);
		result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
			SO_TYPE, (char *)&type, &length);
	} else if (result >= 0) result = -EPROTO;
	if (result >= 0 && length == sizeof(type)) {
		length = sizeof(protocol);
		result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
			SO_PROTOCOL, (char *)&protocol, &length);
	} else if (result >= 0) result = -EPROTO;
	if (result >= 0 && length == sizeof(protocol)) {
		length = sizeof(accepting);
		result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
			SO_ACCEPTCONN, (char *)&accepting, &length);
	} else if (result >= 0) result = -EPROTO;
	if (result >= 0 && length == sizeof(accepting)) {
		length = sizeof(mark);
		result = lkl_sys_getsockopt((unsigned int)entry->native, SOL_SOCKET,
			SO_MARK, (char *)&mark, &length);
	} else if (result >= 0) result = -EPROTO;
	if (result >= 0 && length == sizeof(mark)) {
		length = sizeof(fastopen);
		result = lkl_sys_getsockopt((unsigned int)entry->native, IPPROTO_TCP,
			TCP_FASTOPEN, (char *)&fastopen, &length);
	} else if (result >= 0) result = -EPROTO;
	if (result >= 0 && length != sizeof(fastopen)) result = -EPROTO;
	struct sockaddr_in local = {0};
	int local_length = sizeof(local);
	if (result >= 0) result = lkl_sys_getsockname((unsigned int)entry->native,
		(struct lkl_sockaddr *)&local, &local_length);
	uint64_t cookie = 0;
	int cookie_length = sizeof(cookie);
	if (result >= 0) result = lkl_sys_getsockopt((unsigned int)entry->native,
		SOL_SOCKET, SO_COOKIE, (char *)&cookie, &cookie_length);
	if (result >= 0 && (domain != AF_INET || type != SOCK_STREAM ||
	    protocol != IPPROTO_TCP || accepting != 1 ||
	    (uint32_t)mark != task->mark || fastopen ||
	    local_length != sizeof(local) || local.sin_family != AF_INET ||
	    !local.sin_port || cookie != task->listener_cookie ||
	    cookie_length != sizeof(cookie))) result = -ESTALE;
	ker_fd_put(entry);
	return (int)result;
}

static int task_syncookies_not_forced(void)
{
	char value[16] = {0};
	long fd = lkl_sys_open("/proc/sys/net/ipv4/tcp_syncookies",
		LKL_O_RDONLY | LKL_O_CLOEXEC, 0);
	if (fd < 0) return (int)fd;
	long amount = lkl_sys_read((unsigned int)fd, value, sizeof(value) - 1);
	long closed = lkl_sys_close((unsigned int)fd);
	if (amount <= 0) return amount < 0 ? (int)amount : -EPROTO;
	if (closed < 0) return (int)closed;
	value[amount] = '\0';
	char *cursor = value;
	while (*cursor == ' ' || *cursor == '\t') ++cursor;
	if (*cursor < '0' || *cursor > '2') return -EPROTO;
	int mode = *cursor++ - '0';
	while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
	       *cursor == '\n') ++cursor;
	if (*cursor) return -EPROTO;
	return mode == 2 ? -EOPNOTSUPP : 0;
}

static int task_rearm_window(struct ker_ff_admission_task *task,
	struct ker_ff_admission_queue **queue_ptr, int listener_fd)
{
	int status = task_listener_revalidate(task, listener_fd);
	if (status) return status;
	status = task_syncookies_not_forced();
	if (status) return status;
	struct ker_ff_admission_queue *queue = NULL;
	status = ker_ff_admission_queue_start(task->mark, &queue);
	if (status) return status;
	uint64_t new_lease = ker_ff_admission_queue_lease(queue);
	if (!new_lease || new_lease <= task->lease) {
		ker_ff_admission_queue_close(queue);
		return -ESTALE;
	}
	uint64_t command_id;
	status = task_next_command(task, &command_id);
	/* Listener close and REARM are serialized by task->lock. Revalidate after
	 * queue setup, immediately before arming the replacement lease. */
	pthread_mutex_lock(&task->lock);
	if (!status && (task->listener_closed || task->stop_requested))
		status = -ECANCELED;
	if (!status) status = task_listener_revalidate(task, listener_fd);
	if (!status) status = ker_ff_admission_channel_send_rearm(task->channel,
		new_lease, command_id);
	pthread_mutex_unlock(&task->lock);
	struct ker_ff_admission_result response = {0};
	if (!status) status = task_wait_window_reply(task,
		KER_FF_ADMISSION_REARMED, command_id, new_lease, &response);
	if (status) {
		/* The new gate may be active. Closing the consumer leaves it armed and
		 * fail-closed; never try to restore the old lease. */
		ker_ff_admission_queue_close(queue);
		return status;
	}
	*queue_ptr = queue;
	return 0;
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
	task->window_state = WINDOW_ACTIVE;
	task->epoch = 1;
	task->state = TASK_READY;
	pthread_mutex_unlock(&task->lock);
	ssize_t sent = syscall(SYS_sendto, channel_fd, &ready, sizeof(ready),
		MSG_NOSIGNAL, NULL, 0);
	if (sent != sizeof(ready)) { status = sent < 0 ? -errno : -EIO; goto terminal; }
	for (;;) {
		if (task_should_stop(task)) break;
		if (task_retire_requested(task)) {
			task_set_window(task, WINDOW_RETIRING);
			status = task_retire_window(task, &queue);
			task_test_window_status("retire-complete", status);
			if (status) {
				task_set_window(task, WINDOW_QUARANTINED);
				break;
			}
			pthread_mutex_lock(&task->lock);
			task->queue = NULL;
			pthread_mutex_unlock(&task->lock);
			for (;;) {
				if (task_should_stop(task)) break;
				pthread_mutex_lock(&task->lock);
				bool rearm = task->rearm_requested;
				pthread_mutex_unlock(&task->lock);
				if (rearm) break;
				struct timespec pause = {.tv_nsec = 1000000};
				(void)nanosleep(&pause, NULL);
			}
			if (task_should_stop(task)) break;
			pthread_mutex_lock(&task->lock);
			int listener_fd = task->listener_fd;
			pthread_mutex_unlock(&task->lock);
			task_set_window(task, WINDOW_REARMING);
			status = task_rearm_window(task, &queue, listener_fd);
			if (status) {
				task_set_window(task, WINDOW_QUARANTINED);
				break;
			}
			pthread_mutex_lock(&task->lock);
			if (task->listener_closed || task->stop_requested) {
				pthread_mutex_unlock(&task->lock);
				status = -ESTALE;
				task_set_window(task, WINDOW_QUARANTINED);
				break;
			}
			task->queue = queue;
			task->lease = ker_ff_admission_queue_lease(queue);
			++task->epoch;
			task->retire_requested = false;
			task->rearm_requested = false;
			task->window_state = WINDOW_ACTIVE;
			pthread_mutex_unlock(&task->lock);
			continue;
		}
		struct ker_ff_admission_packet packet = {0};
		status = ker_ff_admission_queue_receive(queue, &packet, 10);
		if (status < 0) break;
		if (!status) continue;
		pthread_mutex_lock(&task->lock);
		int listener_fd = task->listener_closed ? -1 : task->listener_fd;
		pthread_mutex_unlock(&task->lock);
		if (listener_fd < 0) {
			status = task_drop_packet(task, &packet);
			if (status) break;
			continue;
		}
		status = task_process_packet(task, &packet, listener_fd);
		pthread_mutex_lock(&task->lock);
		bool uncertain = task->accept_uncertain;
		pthread_mutex_unlock(&task->lock);
		if (uncertain) { status = -EINPROGRESS; break; }
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
	int status = task->state == TASK_READY ?
		(task->window_state == WINDOW_ACTIVE ? KER_FF_ADMISSION_TASK_READY :
		 task->window_state == WINDOW_RETIRING ? KER_FF_ADMISSION_TASK_RETIRING :
		 task->window_state == WINDOW_RETIRED ? KER_FF_ADMISSION_TASK_RETIRED :
		 task->window_state == WINDOW_REARMING ? KER_FF_ADMISSION_TASK_REARMING :
		 KER_FF_ADMISSION_TASK_QUARANTINED) :
		(task->state == TASK_STARTING ? KER_FF_ADMISSION_TASK_STARTING :
		 task->state == TASK_STOPPING ? KER_FF_ADMISSION_TASK_STOPPING :
		 task->state == TASK_TERMINAL ? KER_FF_ADMISSION_TASK_TERMINAL :
		 task->status ? task->status : -ECONNRESET);
	uint64_t lease = task->lease;
	pthread_mutex_unlock(&task->lock);
	if (status == 1) *queue_lease = lease;
	return status;
}

int ker_posix_ff_admission_task_poll_window(
	struct ker_ff_admission_task *task, uint32_t *state,
	uint64_t *queue_lease, uint64_t *epoch, int *task_status)
{
	if (!task || !state || !queue_lease || !epoch || !task_status) return -EINVAL;
	pthread_mutex_lock(&task->lock);
	uint32_t window = task->state == TASK_FAILED ?
		KER_FF_ADMISSION_TASK_QUARANTINED :
		task->state == TASK_STARTING ?
		KER_FF_ADMISSION_TASK_STARTING :
		task->state == TASK_STOPPING ? KER_FF_ADMISSION_TASK_STOPPING :
		task->state == TASK_TERMINAL ? KER_FF_ADMISSION_TASK_TERMINAL :
		task->window_state == WINDOW_ACTIVE ? KER_FF_ADMISSION_TASK_READY :
		task->window_state == WINDOW_RETIRING ? KER_FF_ADMISSION_TASK_RETIRING :
		task->window_state == WINDOW_RETIRED ? KER_FF_ADMISSION_TASK_RETIRED :
		task->window_state == WINDOW_REARMING ? KER_FF_ADMISSION_TASK_REARMING :
		KER_FF_ADMISSION_TASK_QUARANTINED;
	uint64_t lease = task->lease, current_epoch = task->epoch;
	int error = task->status;
	pthread_mutex_unlock(&task->lock);
	*state = window;
	*queue_lease = lease;
	*epoch = current_epoch;
	*task_status = error;
	return 0;
}

int ker_posix_ff_admission_task_window_action(
	struct ker_ff_admission_task *task, uint32_t action, int listener_fd)
{
#ifndef KER_FF_ADMISSION_WINDOW_SERIALIZED_LKL
	(void)task;
	(void)action;
	(void)listener_fd;
	return -EOPNOTSUPP;
#else
	if (!task) return -EINVAL;
	if (action == KER_FF_ADMISSION_WINDOW_RETIRE) {
		int profile = task_syncookies_not_forced();
		if (profile) return profile;
		pthread_mutex_lock(&task->lock);
		if (task->state != TASK_READY || task->window_state != WINDOW_ACTIVE ||
		    !task->listener_entry || task->listener_closed || task->stop_requested ||
		    task->retire_requested || task->accept_uncertain) {
			pthread_mutex_unlock(&task->lock);
			return -EBUSY;
		}
		task->retire_requested = true;
		task->window_state = WINDOW_RETIRING;
		pthread_mutex_unlock(&task->lock);
		return 0;
	}
	if (action == KER_FF_ADMISSION_WINDOW_REARM) {
		if (listener_fd < 0) return -EINVAL;
		int status = task_listener_revalidate(task, listener_fd);
		if (status) return status;
		pthread_mutex_lock(&task->lock);
		if (task->state != TASK_READY || task->window_state != WINDOW_RETIRED ||
		    task->listener_closed || task->stop_requested || task->rearm_requested ||
		    task->accept_uncertain) {
			pthread_mutex_unlock(&task->lock);
			return -EBUSY;
		}
		task->rearm_requested = true;
		task->window_state = WINDOW_REARMING;
		pthread_mutex_unlock(&task->lock);
		return 0;
	}
	return -EOPNOTSUPP;
#endif
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
	if (task->listener_fd != listener_fd ||
	    (!task->listener_entry && !task->listener_ref_released)) {
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
	if (task->listener_entry) {
		task_test_lifecycle_trace("listener-ref-put-at-task-release");
		ker_fd_put(task->listener_entry);
	}
	if (task->actor_pidfd >= 0) (void)syscall(SYS_close, task->actor_pidfd);
	if (task->peer_fd >= 0) (void)syscall(SYS_close, task->peer_fd);
	pthread_mutex_destroy(&task->lock);
	free(task);
	return 0;
}

void ker_ff_admission_task_runtime_shutdown(void)
{
	struct ker_fd *listener_entry = NULL;
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
	if (task && task->joined) {
		pthread_mutex_lock(&task->lock);
		listener_entry = task->listener_entry;
		task->listener_entry = NULL;
		task->listener_ref_released = true;
		pthread_mutex_unlock(&task->lock);
	}
	pthread_mutex_unlock(&task_global_lock);
	if (listener_entry) {
		ker_fd_put(listener_entry);
		task_test_lifecycle_trace("listener-ref-put-before-native-finalize");
	}
}
