#define _GNU_SOURCE
#include "fd-table.h"
#include "ff-admission-queue.h"
#include "ff-ingress-freeze-queue.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <lkl.h>
#include <limits.h>
#include <linux/filter.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define C24_MARK UINT32_C(0x4c240001)
#define C24_MAX_IDS 64U

struct echo_context {
	int fd;
	atomic_bool stop;
};

static uint64_t now_ns(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static void sleep_ns(uint64_t duration)
{
	struct timespec pause = {
		.tv_sec = (time_t)(duration / UINT64_C(1000000000)),
		.tv_nsec = (long)(duration % UINT64_C(1000000000)),
	};
	while (nanosleep(&pause, &pause) && errno == EINTR) {}
}

static int write_state(const char *path, const char *value)
{
	char temporary[PATH_MAX];
	int length = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
		(long)syscall(SYS_getpid));
	if (length < 0 || (size_t)length >= sizeof(temporary)) return -ENAMETOOLONG;
	long fd = syscall(SYS_openat, AT_FDCWD, temporary,
		O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) return -errno;
	size_t size = strlen(value), offset = 0;
	while (offset < size) {
		long written = syscall(SYS_write, (int)fd, value + offset, size - offset);
		if (written < 0 && errno == EINTR) continue;
		if (written <= 0) {
			int error = written < 0 ? errno : EIO;
			(void)syscall(SYS_close, (int)fd);
			(void)syscall(SYS_unlinkat, AT_FDCWD, temporary, 0);
			return -error;
		}
		offset += (size_t)written;
	}
	if (syscall(SYS_close, (int)fd) != 0) return -errno;
	if (syscall(SYS_renameat, AT_FDCWD, temporary, AT_FDCWD, path) != 0)
		return -errno;
	return 0;
}

static int read_command(const char *path, char *buffer, size_t capacity)
{
	long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) return -errno;
	long count = syscall(SYS_read, (int)fd, buffer, capacity - 1);
	int saved = errno;
	(void)syscall(SYS_close, (int)fd);
	if (count < 0) return -saved;
	if ((size_t)count == capacity - 1) return -E2BIG;
	buffer[count] = '\0';
	if (count > 0 && buffer[count - 1] == '\n') buffer[count - 1] = '\0';
	return (int)count;
}

static int wait_command(const char *path, const char *expected, uint64_t deadline)
{
	for (;;) {
		char command[32] = {0};
		int count = read_command(path, command, sizeof(command));
		if (count >= 0 && !strcmp(command, expected)) {
			(void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
			return 0;
		}
		if (count < 0 && count != -ENOENT) return count;
		if (now_ns() >= deadline) return -ETIMEDOUT;
		sleep_ns(UINT64_C(1000000));
	}
}

static int recv_exact(int fd, void *buffer, size_t size, uint64_t deadline)
{
	size_t offset = 0;
	while (offset < size) {
		long count = lkl_sys_recv(fd, (char *)buffer + offset, size - offset,
			LKL_MSG_DONTWAIT);
		if (count > 0) {
			offset += (size_t)count;
			continue;
		}
		if (count == 0) return -ECONNRESET;
		if (count != -EAGAIN && count != -EWOULDBLOCK && count != -EINTR)
			return (int)count;
		if (now_ns() >= deadline) return -ETIMEDOUT;
		sleep_ns(UINT64_C(1000000));
	}
	return 0;
}

static int send_all(int fd, const void *buffer, size_t size)
{
	size_t offset = 0;
	while (offset < size) {
		long count = lkl_sys_send(fd, (void *)((const char *)buffer + offset),
			size - offset, 0);
		if (count < 0) return (int)count;
		if (!count) return -EIO;
		offset += (size_t)count;
	}
	return 0;
}

static int reuseport_select(int listener_fd, uint32_t index)
{
	struct sock_filter instruction = {
		.code = BPF_RET | BPF_K,
		.k = index,
	};
	struct sock_fprog program = {.len = 1, .filter = &instruction};
	return (int)lkl_sys_setsockopt((unsigned int)listener_fd, SOL_SOCKET,
		SO_ATTACH_REUSEPORT_CBPF, (char *)&program, sizeof(program));
}

static int accept_selected_zero(int listener0, int listener1, uint64_t deadline)
{
	for (;;) {
		int accepted = (int)lkl_sys_accept4((unsigned int)listener0, NULL, NULL,
			LKL_O_NONBLOCK);
		if (accepted >= 0) return accepted;
		if (accepted != -EAGAIN && accepted != -EWOULDBLOCK) return accepted;
		int wrong = (int)lkl_sys_accept4((unsigned int)listener1, NULL, NULL,
			LKL_O_NONBLOCK);
		if (wrong >= 0) {
			(void)lkl_sys_close((unsigned int)wrong);
			return -EUCLEAN;
		}
		if (wrong != -EAGAIN && wrong != -EWOULDBLOCK) return wrong;
		if (now_ns() >= deadline) return -ETIMEDOUT;
		sleep_ns(UINT64_C(1000000));
	}
}

static int accept_selected_one(int listener0, int listener1, uint64_t deadline)
{
	for (;;) {
		int accepted = (int)lkl_sys_accept4((unsigned int)listener1, NULL, NULL,
			LKL_O_NONBLOCK);
		if (accepted >= 0) return accepted;
		if (accepted != -EAGAIN && accepted != -EWOULDBLOCK) return accepted;
		int wrong = (int)lkl_sys_accept4((unsigned int)listener0, NULL, NULL,
			LKL_O_NONBLOCK);
		if (wrong >= 0) {
			(void)lkl_sys_close((unsigned int)wrong);
			return -EUCLEAN;
		}
		if (wrong != -EAGAIN && wrong != -EWOULDBLOCK) return wrong;
		if (now_ns() >= deadline) return -ETIMEDOUT;
		sleep_ns(UINT64_C(1000000));
	}
}

static void *echo_worker(void *opaque)
{
	struct echo_context *context = opaque;
	char bytes[256];
	while (!atomic_load_explicit(&context->stop, memory_order_acquire)) {
		long count = lkl_sys_recv(context->fd, bytes, sizeof(bytes), LKL_MSG_DONTWAIT);
		if (count > 0) {
			if (send_all(context->fd, bytes, (size_t)count)) break;
		} else if (count == 0) {
			break;
		} else if (count != -EAGAIN && count != -EWOULDBLOCK && count != -EINTR) {
			break;
		}
		sleep_ns(UINT64_C(1000000));
	}
	return NULL;
}

/* BUILD_TESTING-only fixture. The caller owns the application listener fd;
 * this routine resolves and retains its actual native LKL entry. */
int ker_c24_ingress_freeze_test_run(int listener_fd, const char *prefix)
{
	struct ker_fd *listener = NULL;
	struct ker_ff_admission_queue *admission_queue = NULL;
	struct ker_ff_ingress_freeze_queue *queue = NULL;
	struct ker_ff_ingress_packet held, packets[C24_MAX_IDS];
	struct ker_ff_admission_packet admission_packet = {0};
	struct echo_context echo = {0};
	pthread_t echo_thread;
	char state_path[PATH_MAX], command_path[PATH_MAX], evidence_path[PATH_MAX];
	char bytes[16] = {0}, state[2048], failure_stage[48] = "setup";
	uint64_t cookie = 0;
	int cookie_length = sizeof(cookie);
	int accepted = -1, second_listener = -1, echo_started = 0, result = -EINVAL;
	uint32_t admission_packet_id = 0;
	int admission_sent = 0;
	int expiry_mode = getenv("KER_C24_INGRESS_EXPIRE") != NULL;
	int disarm_abort_mode = getenv("KER_C24_INGRESS_DISARM_ABORT") != NULL;
	int overflow_mode = getenv("KER_C24_INGRESS_OVERFLOW") != NULL;
	unsigned int packet_count = 0;
	if (listener_fd < 0 || !prefix || !*prefix ||
	    snprintf(state_path, sizeof(state_path), "%s.state", prefix) >= (int)sizeof(state_path) ||
	    snprintf(command_path, sizeof(command_path), "%s.command", prefix) >= (int)sizeof(command_path) ||
	    snprintf(evidence_path, sizeof(evidence_path), "%s.evidence", prefix) >= (int)sizeof(evidence_path))
		return -EINVAL;
	listener = ker_fd_get(listener_fd);
	if (!listener || listener->kind != KER_FD_SOCKET) {
		(void)snprintf(failure_stage, sizeof(failure_stage), "listener-fd-%d", listener_fd);
		result = -EBADF;
		goto out;
	}
	(void)snprintf(failure_stage, sizeof(failure_stage), "cookie");
	if (lkl_sys_getsockopt((unsigned int)listener->native, SOL_SOCKET, SO_COOKIE,
		(char *)&cookie, &cookie_length) < 0 || cookie_length != sizeof(cookie) || !cookie) {
		result = -EPROTO;
		goto out;
	}
	(void)snprintf(failure_stage, sizeof(failure_stage), "member1-setup");
	second_listener = (int)lkl_sys_socket(LKL_AF_INET,
		LKL_SOCK_STREAM | LKL_O_NONBLOCK | LKL_O_CLOEXEC,
		LKL_IPPROTO_TCP);
	if (second_listener < 0) { result = second_listener; second_listener = -1; goto out; }
	int reuseport = 1;
	int mark = C24_MARK;
	long option_result = lkl_sys_setsockopt((unsigned int)second_listener,
		SOL_SOCKET, SO_REUSEPORT, (char *)&reuseport, sizeof(reuseport));
	if (option_result < 0) { result = (int)option_result; goto out; }
	option_result = lkl_sys_setsockopt((unsigned int)second_listener,
		SOL_SOCKET, SO_MARK, (char *)&mark, sizeof(mark));
	if (option_result < 0) { result = (int)option_result; goto out; }
	struct lkl_sockaddr_in member_address = {
		.sin_family = LKL_AF_INET,
		.sin_port = htons(8081),
		.sin_addr.lkl_s_addr = htonl(UINT32_C(0xc6120002)),
	};
	result = (int)lkl_sys_bind((unsigned int)second_listener,
		(struct lkl_sockaddr *)&member_address, sizeof(member_address));
	if (result < 0) goto out;
	result = (int)lkl_sys_listen((unsigned int)second_listener, 8);
	if (result < 0) goto out;
	result = reuseport_select(listener->native, 0);
	if (result < 0) goto out;
	result = write_state(state_path, "READY");
	if (result) goto out;
	(void)snprintf(failure_stage, sizeof(failure_stage), "accept-old");
	accepted = accept_selected_zero(listener->native, second_listener,
		now_ns() + UINT64_C(5000000000));
	if (accepted < 0) { result = accepted; accepted = -1; goto out; }
	result = recv_exact(accepted, bytes, 3, now_ns() + UINT64_C(5000000000));
	if (result || memcmp(bytes, "old", 3)) { if (!result) result = -EPROTO; goto out; }
	result = send_all(accepted, "echo:old", 8);
	if (result) goto out;
	(void)snprintf(failure_stage, sizeof(failure_stage), "echo-thread");
	echo.fd = accepted;
	atomic_init(&echo.stop, false);
	result = pthread_create(&echo_thread, NULL, echo_worker, &echo);
	if (result) { result = -result; goto out; }
	echo_started = 1;
	result = write_state(state_path, "OLD_ECHO");
	if (result) goto out;
	(void)snprintf(failure_stage, sizeof(failure_stage), "arm");
	result = wait_command(command_path, "ARM", now_ns() + UINT64_C(10000000000));
	if (result) goto out;
	result = ker_ff_ingress_freeze_queue_start(listener->native, C24_MARK,
		cookie, &queue);
	if (result) goto out;
	(void)snprintf(failure_stage, sizeof(failure_stage), "q87-start");
	if (!expiry_mode && !disarm_abort_mode && !overflow_mode) {
		result = ker_ff_admission_queue_start(C24_MARK, &admission_queue);
		if (result) goto out;
	}
	result = write_state(state_path, "ARMED");
	if (result) goto out;
	(void)snprintf(failure_stage, sizeof(failure_stage), "receive-held");
	uint64_t receive_deadline = now_ns() + UINT64_C(10000000000);
	do {
		result = ker_ff_ingress_freeze_queue_receive(queue, &held, 250);
	} while (!result && now_ns() < receive_deadline);
	if (!result) {
		int disarm_result = ker_ff_ingress_freeze_queue_disarm(queue);
		struct ker_ff_ingress_packet diagnostic_packet = {0};
		int drain_result = disarm_result ? disarm_result :
			ker_ff_ingress_freeze_queue_drain(queue, &diagnostic_packet);
		(void)snprintf(failure_stage, sizeof(failure_stage),
			"noevent-disarm%d-drain%d", disarm_result, drain_result);
		result = -ETIMEDOUT;
		goto out;
	}
	if (result != 1) { if (!result) result = -ETIMEDOUT; goto out; }
	packets[packet_count++] = held;
	if (snprintf(state, sizeof(state), "HELD id=%u", held.id) >= (int)sizeof(state)) {
		result = -E2BIG;
		goto out;
	}
	result = write_state(state_path, state);
	if (result) goto out;
	if (overflow_mode) {
		(void)snprintf(failure_stage, sizeof(failure_stage), "overflow-receive-64");
		uint64_t overflow_deadline = now_ns() + UINT64_C(10000000000);
		while (packet_count < C24_MAX_IDS) {
			struct ker_ff_ingress_packet packet;
			result = ker_ff_ingress_freeze_queue_receive(queue, &packet, 250);
			if (result == 1) {
				packets[packet_count++] = packet;
				continue;
			}
			if (result < 0) goto out;
			if (now_ns() >= overflow_deadline) { result = -ETIMEDOUT; goto out; }
		}
		(void)snprintf(state, sizeof(state), "OVERFLOW_COUNT64 first_id=%u", held.id);
		result = write_state(state_path, state);
		if (result) goto out;
	}
	if (expiry_mode) {
		(void)snprintf(failure_stage, sizeof(failure_stage), "expire-check");
		while (now_ns() < held.deadline_ns + UINT64_C(10000000))
			sleep_ns(UINT64_C(10000000));
		result = ker_ff_ingress_freeze_queue_check(queue);
		if (result != -ETIMEDOUT) { if (!result) result = -EPROTO; goto out; }
		result = ker_ff_ingress_freeze_queue_quarantine(&queue);
		if (result) goto out;
		(void)snprintf(state, sizeof(state),
			"mode=expiry first_id=%u deadline_ns=%llu check=ETIMEDOUT quarantine=ok",
			held.id, (unsigned long long)held.deadline_ns);
		result = write_state(evidence_path, state);
		if (result) goto out;
		result = write_state(state_path, "EXPIRED_QUARANTINED");
		if (result) goto out;
		result = wait_command(command_path, "STOP", now_ns() + UINT64_C(5000000000));
		if (result) goto out;
	} else if (disarm_abort_mode) {
		(void)snprintf(failure_stage, sizeof(failure_stage), "abort-command");
		result = wait_command(command_path, "ABORT", now_ns() + UINT64_C(10000000000));
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "abort-disarm");
		result = ker_ff_ingress_freeze_queue_disarm(queue);
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "abort-drain");
		struct ker_ff_ingress_packet unexpected_packet;
		result = ker_ff_ingress_freeze_queue_drain(queue, &unexpected_packet);
		if (result) goto out;
		uint64_t attempts = 0, expired = 0, inventory_errors = 0;
		result = ker_ff_ingress_freeze_queue_counts(queue, &attempts, &expired,
			&inventory_errors);
		if (result || attempts != 1 || expired || inventory_errors) {
			if (!result) result = -EUCLEAN;
			goto out;
		}
		(void)snprintf(failure_stage, sizeof(failure_stage), "abort-quarantine");
		result = ker_ff_ingress_freeze_queue_quarantine(&queue);
		if (result) goto out;
		(void)snprintf(state, sizeof(state),
			"mode=disarm-abort first_id=%u attempts=%llu drain=clean "
			"quarantine=disarmed abort_before_select=1",
			held.id, (unsigned long long)attempts);
		result = write_state(evidence_path, state);
		if (result) goto out;
		result = write_state(state_path, "DISARMED_QUARANTINED");
		if (result) goto out;
		result = wait_command(command_path, "STOP", now_ns() + UINT64_C(5000000000));
		if (result) goto out;
	} else if (overflow_mode) {
		(void)snprintf(failure_stage, sizeof(failure_stage), "overflow-command");
		result = wait_command(command_path, "OVERFLOW_CUTOFF",
			now_ns() + UINT64_C(10000000000));
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "overflow-disarm");
		result = ker_ff_ingress_freeze_queue_disarm(queue);
		if (result) goto out;
		uint64_t attempts = 0, expired = 0, inventory_errors = 0;
		result = ker_ff_ingress_freeze_queue_counts(queue, &attempts, &expired,
			&inventory_errors);
		if (result || attempts <= C24_MAX_IDS || expired || inventory_errors) {
			if (!result) result = -EUCLEAN;
			goto out;
		}
		(void)snprintf(failure_stage, sizeof(failure_stage), "overflow-drain");
		struct ker_ff_ingress_packet unexpected_packet;
		int drain_result = ker_ff_ingress_freeze_queue_drain(queue,
			&unexpected_packet);
		if (drain_result != -EOVERFLOW && drain_result != -EUCLEAN) {
			result = drain_result ? drain_result : -EUCLEAN;
			goto out;
		}
		(void)snprintf(failure_stage, sizeof(failure_stage), "overflow-quarantine");
		result = ker_ff_ingress_freeze_queue_quarantine(&queue);
		if (result) goto out;
		int evidence_length = snprintf(state, sizeof(state),
			"mode=overflow held_ids=%u attempts=%llu expired=%llu "
			"inventory_errors=%llu drain_error=%d ids=", packet_count,
			(unsigned long long)attempts, (unsigned long long)expired,
			(unsigned long long)inventory_errors, drain_result);
		if (evidence_length < 0 || (size_t)evidence_length >= sizeof(state)) {
			result = -E2BIG;
			goto out;
		}
		size_t evidence_offset = (size_t)evidence_length;
		for (unsigned int index = 0; index < packet_count; index++) {
			int count = snprintf(state + evidence_offset, sizeof(state) - evidence_offset,
				"%s%u", index ? "," : "", packets[index].id);
			if (count < 0 || (size_t)count >= sizeof(state) - evidence_offset) {
				result = -E2BIG;
				goto out;
			}
			evidence_offset += (size_t)count;
		}
		result = write_state(evidence_path, state);
		if (result) goto out;
		result = write_state(state_path, "OVERFLOW_QUARANTINED");
		if (result) goto out;
		result = wait_command(command_path, "STOP", now_ns() + UINT64_C(5000000000));
		if (result) goto out;
	} else {
		result = wait_command(command_path, "SELECT1", now_ns() + UINT64_C(10000000000));
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "selector1");
		result = reuseport_select(listener->native, 1);
		if (result) goto out;
		result = write_state(state_path, "SELECTED1");
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "release-command");
		result = wait_command(command_path, "RELEASE", now_ns() + UINT64_C(10000000000));
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "disarm");
		result = ker_ff_ingress_freeze_queue_disarm(queue);
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "drain");
		for (;;) {
			struct ker_ff_ingress_packet packet;
			result = ker_ff_ingress_freeze_queue_drain(queue, &packet);
			if (!result) break;
			if (result != 1 || packet_count == C24_MAX_IDS) {
				if (result == 1) result = -EOVERFLOW;
				goto out;
			}
			packets[packet_count++] = packet;
		}
		result = ker_ff_ingress_freeze_queue_check(queue);
		if (result) {
			(void)snprintf(failure_stage, sizeof(failure_stage), "preaccept-check-%d", result);
			goto out;
		}
		(void)snprintf(failure_stage, sizeof(failure_stage), "accept-id");
		for (unsigned int index = 0; index < packet_count; index++) {
			int sent = 0;
			result = ker_ff_ingress_freeze_queue_accept(queue,
				packets[index].lease, packets[index].deadline_ns,
				packets[index].id, &sent);
			if (result || sent != 1) {
				(void)snprintf(failure_stage, sizeof(failure_stage),
					"accept-r%d-s%d-id%u", result, sent, packets[index].id);
				if (!result) result = -EIO;
				goto out;
			}
		}
		(void)snprintf(failure_stage, sizeof(failure_stage), "q87-receive-synack");
		uint64_t admission_deadline = now_ns() + UINT64_C(5000000000);
		for (;;) {
			result = ker_ff_admission_queue_receive(admission_queue,
				&admission_packet, 250);
			if (result) break;
			if (now_ns() >= admission_deadline) { result = -ETIMEDOUT; break; }
		}
		if (result != 1 || admission_packet.mark != C24_MARK ||
		    admission_packet.lease != ker_ff_admission_queue_lease(admission_queue) ||
		    ntohs(admission_packet.local_port) != 8081 ||
		    admission_packet.local_address != htonl(UINT32_C(0xc6120002)) ||
		    !admission_packet.remote_port) {
			if (result >= 0) result = -EPROTO;
			goto out;
		}
		admission_packet_id = admission_packet.id;
		(void)snprintf(failure_stage, sizeof(failure_stage), "q87-accept-id");
		result = ker_ff_admission_queue_verdict(admission_queue,
			admission_packet.lease, admission_packet.deadline_ns,
			admission_packet.id, 1, &admission_sent);
		if (result || admission_sent != 1) {
			if (!result) result = -EIO;
			goto out;
		}
		(void)snprintf(failure_stage, sizeof(failure_stage), "q87-retire");
		result = ker_ff_admission_queue_disable_for_retire(admission_queue);
		if (result || ker_ff_admission_queue_retire_drained(admission_queue) != 1) {
			if (!result) result = -EUCLEAN;
			goto out;
		}
		ker_ff_admission_queue_close(admission_queue);
		admission_queue = NULL;
		int evidence_length = snprintf(state, sizeof(state),
			"mode=release selector=1 held_packets=%u verified_attempts=%u "
			"expired=0 inventory_errors=0 q87_ids=%u q87_accept_sent=%d ids=",
			packet_count, packet_count, admission_packet_id, admission_sent);
		if (evidence_length < 0 || (size_t)evidence_length >= sizeof(state)) {
			result = -E2BIG;
			goto out;
		}
		size_t evidence_offset = (size_t)evidence_length;
		for (unsigned int index = 0; index < packet_count; index++) {
			int count = snprintf(state + evidence_offset, sizeof(state) - evidence_offset,
				"%s%u", index ? "," : "", packets[index].id);
			if (count < 0 || (size_t)count >= sizeof(state) - evidence_offset) {
				result = -E2BIG;
				goto out;
			}
			evidence_offset += (size_t)count;
		}
		result = write_state(evidence_path, state);
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "queue-close");
		result = ker_ff_ingress_freeze_queue_close(queue);
		if (result) goto out;
		queue = NULL;
		(void)snprintf(failure_stage, sizeof(failure_stage), "release-state");
		result = write_state(state_path, "RELEASED");
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "accept-new");
		(void)snprintf(failure_stage, sizeof(failure_stage), "accept-member1");
		int next = accept_selected_one(listener->native, second_listener,
			now_ns() + UINT64_C(5000000000));
		if (next < 0) { result = next; goto out; }
	result = write_state(state_path, "ACCEPTED_MEMBER1");
	if (result) { (void)lkl_sys_close((unsigned int)next); goto out; }
		int unexpected = (int)lkl_sys_accept4((unsigned int)listener->native,
			NULL, NULL, LKL_O_NONBLOCK);
		if (unexpected != -EAGAIN && unexpected != -EWOULDBLOCK) {
			if (unexpected >= 0) (void)lkl_sys_close((unsigned int)unexpected);
			(void)lkl_sys_close((unsigned int)next);
			result = -EUCLEAN;
			goto out;
		}
		struct lkl_pollfd data_ready = {.fd = next, .events = LKL_POLLIN};
		int poll_result = (int)lkl_sys_poll(&data_ready, 1, 5000);
		if (poll_result < 0) { result = poll_result; goto out; }
		if (!poll_result || !(data_ready.revents & LKL_POLLIN)) {
			result = -ETIMEDOUT;
			goto out;
		}
		result = write_state(state_path, "MEMBER1_DATA_READY");
		if (result) goto out;
		result = recv_exact(next, bytes, 3, now_ns() + UINT64_C(5000000000));
		if (!result && memcmp(bytes, "new", 3)) result = -EPROTO;
		if (!result) result = send_all(next, "echo:new", 8);
		(void)lkl_sys_close((unsigned int)next);
		if (result) goto out;
		(void)snprintf(failure_stage, sizeof(failure_stage), "stop-command");
		result = wait_command(command_path, "STOP", now_ns() + UINT64_C(5000000000));
		if (result) goto out;
	}
	result = write_state(state_path, "DONE");
	if (result) goto out;
	result = 0;
out:
	if (admission_queue) ker_ff_admission_queue_close(admission_queue);
	if (queue) {
		(void)ker_ff_ingress_freeze_queue_quarantine(&queue);
		if (queue) (void)ker_ff_ingress_freeze_queue_close(queue);
	}
	if (echo_started) {
		atomic_store_explicit(&echo.stop, true, memory_order_release);
		(void)pthread_join(echo_thread, NULL);
	}
	if (accepted >= 0) (void)lkl_sys_close((unsigned int)accepted);
	if (second_listener >= 0) (void)lkl_sys_close((unsigned int)second_listener);
	if (listener_fd >= 0) (void)close(listener_fd);
	if (listener) ker_fd_put(listener);
	if (result) {
		(void)snprintf(state, sizeof(state), "FAILED stage=%s error=%d fd=%d",
			failure_stage, result, listener_fd);
		(void)write_state(state_path, state);
	}
	return result;
}
