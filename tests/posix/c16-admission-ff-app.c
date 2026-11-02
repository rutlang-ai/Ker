#define _GNU_SOURCE
#include "ff-admission-channel.h"
#include "ff-admission-task.h"
#include "ff-owner-admission-control.h"
#include "socket-broker-preload-internal.h"

#include <ff_api.h>
#include <ff_config.h>
#include <ff_reload.h>
#include <ker/reload.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "ff_flow_map.h"

int ff_init(int argc, char * const argv[]);
void ff_stop_run(void);
int ker_sb_preload_ff_owner_admission_attach(
	const struct ker_ff_admission_map_ops *ops);
int ker_sb_posix_epoll_create1(int flags);
int ker_sb_posix_epoll_wait(int epfd, struct epoll_event *events,
	int maximum, int timeout);

intptr_t ngx_max_sockets = 1024;
int is_fstack_fd(int fd) { return fd >= ngx_max_sockets; }
int ff_flow_map_lookup(const struct ff_flow_key *key);

static void *reload_state;
static int listener_fd = -1;
static int retired_probe_fd = -1;
static int epoll_fd = -1;
static int initialized;
static unsigned accepted_count;
static unsigned requested_count;
static unsigned completed_count;
static int pump_failure_mode;
static int owner_probe_mode;
static int product_smoke_mode;
static int window_cycles_mode;
static int window_cancel_mode;
static int window_initial_reported;
static volatile sig_atomic_t window_is_retired;
static struct ff_flow_key window_cancel_key;
static int window_cancel_key_valid;
static volatile sig_atomic_t request_snapshot_requested;
static volatile sig_atomic_t retired_rpc_probe_requested;
static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t close_listener_requested;
static volatile sig_atomic_t retire_window_requested;
static volatile sig_atomic_t rearm_window_requested;
static int window_retiring;
static int window_rearming;
static int recursive_wait_checked;
static const char *setup_stage = "map bootstrap";
static uint64_t monotonic_ns(void);

static void request_snapshot_signal(int signal_number)
{
	(void)signal_number;
	if (window_cycles_mode && window_is_retired) {
		retired_rpc_probe_requested = 1;
		request_snapshot_requested = 1;
	} else if (owner_probe_mode) close_listener_requested = 1;
	else request_snapshot_requested = 1;
}

static void stop_signal(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static void retire_window_signal(int signal_number)
{
	(void)signal_number;
	retire_window_requested = 1;
}

static void rearm_window_signal(int signal_number)
{
	(void)signal_number;
	rearm_window_requested = 1;
}

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
	(void)context;
	if (!recursive_wait_checked && getenv("KER_C16_TEST_RECURSIVE_WAIT")) {
		recursive_wait_checked = 1;
		struct epoll_event event;
		errno = 0;
		int result = ker_sb_posix_epoll_wait(epoll_fd, &event, 1, 0);
		if (result != -1 || errno != EDEADLK) return -EPROTO;
		static const char marker[] = "C16_RECURSIVE_WAIT_EDEADLK\n";
		(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	}
	struct ff_flow_key original;
	memcpy(&original, key, sizeof(original));
	int allowed = ff_flow_map_admit(&original, created);
	if (window_cancel_mode && allowed == 1 && created && *created == 1) {
		window_cancel_key = original;
		window_cancel_key_valid = 1;
	}
	return allowed;
}

static int map_revoke(const struct ker_ff_admission_key *key, void *context)
{
	(void)context;
	struct ff_flow_key original;
	memcpy(&original, key, sizeof(original));
	return ff_flow_map_revoke(&original);
}

static int admission_listener_rejects_fastopen(int fd)
{
	int enabled = 1;
	errno = 0;
	if (ff_setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &enabled,
			sizeof(enabled)) != -1 || errno != EOPNOTSUPP) return -1;
	int value = -1;
	socklen_t length = sizeof(value);
	if (ff_getsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &value, &length) ||
	    length != sizeof(value) || value != 0) return -1;
	return 0;
}

static int map_retire(void *context)
{
	(void)context;
	if (!ff_flow_map_active()) return -ESTALE;
	if (window_cancel_mode) {
		uint64_t inserted = 0, revoked = 0;
		ff_flow_map_stats2(&inserted, NULL, NULL, NULL, NULL, NULL, NULL,
			&revoked);
		if (!window_cancel_key_valid || inserted != 1 || revoked != 1 ||
		    ff_flow_map_lookup(&window_cancel_key) != 0) return -EUCLEAN;
		char marker[128];
		int length = snprintf(marker, sizeof(marker),
			"C17_RETIRE_AFTER_CANCEL active=1 inserted=1 revoked=1 lookup=0 now_ns=%llu\n",
			(unsigned long long)monotonic_ns());
		if (length > 0 && (size_t)length < sizeof(marker))
			(void)syscall(SYS_write, STDOUT_FILENO, marker, (size_t)length);
	}
	ff_flow_map_close();
	return ff_flow_map_active() ? -EIO : 0;
}

static int map_rearm(void *context)
{
	(void)context;
	if (ff_flow_map_active()) return -EALREADY;
	ff_flow_map_open();
	return ff_flow_map_active() ? 0 : -ENOMEM;
}

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *bytes = buffer;
	size_t offset = 0;
	while (offset < length) {
		ssize_t count = ff_write(fd, bytes + offset, length - offset);
		if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (count <= 0) return -1;
		offset += (size_t)count;
	}
	return 0;
}

struct delayed_pipe_write { int fd; };

static void *write_pipe_after_delay(void *argument)
{
	struct delayed_pipe_write *writer = argument;
	struct timespec pause = {.tv_nsec = 20000000};
	(void)nanosleep(&pause, NULL);
	char byte = 'p';
	(void)syscall(SYS_write, writer->fd, &byte, 1);
	return NULL;
}

static uint64_t monotonic_ns(void)
{
	struct timespec now = {0};
	if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static int owner_wait_contract_checks(void)
{
	int host_pipe[2] = {-1, -1};
	int host_epoll = -1;
	if (syscall(SYS_pipe2, host_pipe, O_CLOEXEC | O_NONBLOCK)) return -1;
	host_epoll = (int)syscall(SYS_epoll_create1, EPOLL_CLOEXEC);
	if (host_epoll < 0) goto fail;
	struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0xc16001)};
	if (syscall(SYS_epoll_ctl, host_epoll, EPOLL_CTL_ADD, host_pipe[0], &event) ||
	    syscall(SYS_write, host_pipe[1], "h", 1) != 1) goto fail;
	errno = 0;
	int result = epoll_wait(host_epoll, &event, 1, 0);
	if (result != -1 || errno != EOPNOTSUPP) goto fail;
	if (syscall(SYS_epoll_wait, host_epoll, &event, 1, 0) != 1 ||
	    event.data.u64 != UINT64_C(0xc16001)) goto fail;
	char byte;
	if (syscall(SYS_read, host_pipe[0], &byte, 1) != 1 || byte != 'h') goto fail;
	(void)syscall(SYS_close, host_epoll);
	(void)syscall(SYS_close, host_pipe[0]);
	(void)syscall(SYS_close, host_pipe[1]);
	host_epoll = -1;
	host_pipe[0] = host_pipe[1] = -1;

	int ready_pipe[2] = {-1, -1};
	if (syscall(SYS_pipe2, ready_pipe, O_CLOEXEC | O_NONBLOCK)) return -1;
	event = (struct epoll_event){.events = EPOLLIN,
		.data.u64 = UINT64_C(0xc16002)};
	if (ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ready_pipe[0], &event)) {
		(void)syscall(SYS_close, ready_pipe[0]);
		(void)syscall(SYS_close, ready_pipe[1]);
		return -1;
	}
	struct delayed_pipe_write writer = {.fd = ready_pipe[1]};
	pthread_t thread;
	if (pthread_create(&thread, NULL, write_pipe_after_delay, &writer)) goto ready_fail;
	uint64_t start = monotonic_ns();
	result = ker_sb_posix_epoll_wait(epoll_fd, &event, 1, 10);
	uint64_t elapsed = monotonic_ns() - start;
	int join_status = pthread_join(thread, NULL);
	if (result != 0 || elapsed < UINT64_C(60000000) || join_status) goto ready_fail;
	result = ker_sb_posix_epoll_wait(epoll_fd, &event, 1, 0);
	if (result != 1 || event.data.u64 != UINT64_C(0xc16002) ||
	    syscall(SYS_read, ready_pipe[0], &byte, 1) != 1 || byte != 'p')
		goto ready_fail;
	if (ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ready_pipe[0], NULL))
		goto ready_fail;
	(void)syscall(SYS_close, ready_pipe[0]);
	(void)syscall(SYS_close, ready_pipe[1]);
	return 0;
ready_fail:
	(void)ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ready_pipe[0], NULL);
	(void)syscall(SYS_close, ready_pipe[0]);
	(void)syscall(SYS_close, ready_pipe[1]);
	return -1;
fail:
	if (host_epoll >= 0) (void)syscall(SYS_close, host_epoll);
	if (host_pipe[0] >= 0) (void)syscall(SYS_close, host_pipe[0]);
	if (host_pipe[1] >= 0) (void)syscall(SYS_close, host_pipe[1]);
	return -1;
}

static int pump_failure_retains_ready_event(void)
{
	int first_pipe[2] = {-1, -1}, next_pipe[2] = {-1, -1};
	if (syscall(SYS_pipe2, first_pipe, O_CLOEXEC | O_NONBLOCK) ||
	    syscall(SYS_pipe2, next_pipe, O_CLOEXEC | O_NONBLOCK)) goto fail;
	struct epoll_event first_event = {.events = EPOLLIN | EPOLLET | EPOLLONESHOT,
		.data.u64 = UINT64_C(0xc16003)};
	struct epoll_event next_event = {.events = EPOLLIN,
		.data.u64 = UINT64_C(0xc16004)};
	if (ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, first_pipe[0], &first_event) ||
	    ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, next_pipe[0], &next_event) ||
	    syscall(SYS_write, first_pipe[1], "a", 1) != 1 ||
	    setenv("KER_C16_TEST_PUMP_FAIL_AFTER_STEP", "1", 1)) goto fail;
	struct epoll_event observed = {0};
	int result = ker_sb_posix_epoll_wait(epoll_fd, &observed, 1, 1000);
	char byte;
	if (result != 1 || observed.data.u64 != UINT64_C(0xc16003) ||
	    syscall(SYS_read, first_pipe[0], &byte, 1) != 1 || byte != 'a' ||
	    syscall(SYS_write, next_pipe[1], "b", 1) != 1) goto fail;
	errno = 0;
	result = ker_sb_posix_epoll_wait(epoll_fd, &observed, 1, 1000);
	if (result != -1 || errno != ECONNRESET) goto fail;
	result = (int)syscall(SYS_epoll_wait, epoll_fd, &observed, 1, 0);
	if (result != 1 || observed.data.u64 != UINT64_C(0xc16004) ||
	    syscall(SYS_read, next_pipe[0], &byte, 1) != 1 || byte != 'b') goto fail;
	static const char marker[] = "C16_PUMP_FAILURE_EVENT_RETAINED sticky=ECONNRESET\n";
	(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	(void)syscall(SYS_close, first_pipe[0]);
	(void)syscall(SYS_close, first_pipe[1]);
	(void)syscall(SYS_close, next_pipe[0]);
	(void)syscall(SYS_close, next_pipe[1]);
	return 0;
fail:
	(void)unsetenv("KER_C16_TEST_PUMP_FAIL_AFTER_STEP");
	if (first_pipe[0] >= 0) (void)syscall(SYS_close, first_pipe[0]);
	if (first_pipe[1] >= 0) (void)syscall(SYS_close, first_pipe[1]);
	if (next_pipe[0] >= 0) (void)syscall(SYS_close, next_pipe[0]);
	if (next_pipe[1] >= 0) (void)syscall(SYS_close, next_pipe[1]);
	return -1;
}

static int finish_if_requested(void)
{
	static int reported;
	if (completed_count < requested_count || !stop_requested) return 0;
	if (!reported) {
		reported = 1;
		uint64_t inserted = 0, duplicates = 0, full = 0;
		ff_flow_map_stats(&inserted, &duplicates, &full);
		char result[128];
		int length = snprintf(result, sizeof(result),
			"C16_APP_DONE accepted=%u inserted=%llu duplicates=%llu full=%llu\n",
			accepted_count, (unsigned long long)inserted,
			(unsigned long long)duplicates, (unsigned long long)full);
		if (length > 0) (void)syscall(SYS_write, STDOUT_FILENO, result,
			(size_t)length);
	}
	ff_stop_run();
	return 1;
}

static void setup_owner(void)
{
	if (initialized) return;
	initialized = 1;
	ff_global_cfg.dpdk.graceful_reload = 1;
	setup_stage = "reload state allocation/bind";
	size_t state_size = ker_reload_state_size();
	reload_state = calloc(1, state_size);
	if (!reload_state || ker_reload_state_init(reload_state, state_size, 0) ||
	    ker_reload_bind_state(reload_state, state_size, 1, 0)) goto fail;
	ff_flow_map_cap_set(64);
	ff_flow_map_open();
	if (!ff_flow_map_active() || !ff_reload_state_attached() ||
	    !ff_global_cfg.dpdk.graceful_reload) goto fail;
	const struct ker_ff_admission_map_ops ops = {
		.context_live = map_context_live, .active = map_active,
		.admit = map_admit, .revoke = map_revoke,
		.retire = map_retire, .rearm = map_rearm};
	setup_stage = "broker admission attach";
	if (ker_sb_preload_ff_owner_admission_attach(&ops)) goto fail;
	setup_stage = "FF listener creation";
	listener_fd = ff_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		IPPROTO_TCP);
	if (listener_fd < 0) goto fail;
	if (admission_listener_rejects_fastopen(listener_fd)) goto fail;
	setup_stage = "FF listener bind";
	struct sockaddr_in address = {.sin_family = AF_INET,
		.sin_port = htons(8080)};
	if (inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1) goto fail;
	if (ff_bind(listener_fd, (struct linux_sockaddr *)&address, sizeof(address))) goto fail;
	setup_stage = "FF listener listen";
	if (ff_listen(listener_fd, 128)) goto fail;
	if (admission_listener_rejects_fastopen(listener_fd)) goto fail;
	if (window_cycles_mode) {
		setup_stage = "retired-window probe socket creation";
		retired_probe_fd = ff_socket(AF_INET,
			SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
		if (retired_probe_fd < 0) goto fail;
	}
	static const char tfo_guard[] =
		"C16_TFO_GUARD_PASS enabled=0 prebind=EOPNOTSUPP postlisten=EOPNOTSUPP\n";
	(void)syscall(SYS_write, STDOUT_FILENO, tfo_guard, sizeof(tfo_guard) - 1);
	setup_stage = "FF epoll creation";
	epoll_fd = ker_sb_posix_epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) goto fail;
	ker_sb_preload_lock();
	int broker_epoll_fd = -1;
	int epoll_composite = ker_sb_preload_composite_epoll_locked(epoll_fd,
		&broker_epoll_fd);
	ker_sb_preload_unlock();
	if (epoll_composite != 1 || broker_epoll_fd < 0) {
		errno = EOPNOTSUPP;
		goto fail;
	}
	setup_stage = "FF listener epoll registration";
	struct epoll_event event = {.events = EPOLLIN, .data.fd = listener_fd};
	if (ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener_fd, &event)) goto fail;
	if (!pump_failure_mode && !owner_probe_mode && !product_smoke_mode &&
	    !window_cycles_mode && !window_cancel_mode) {
		setup_stage = "owner wait contract checks";
		if (owner_wait_contract_checks()) goto fail;
	}
	const char *ready = product_smoke_mode ?
		"C16_APP_READY product_smoke=1 tfo_guard=ok\n" : getenv("KER_C16_TEST_PREPARE_ONCE") ?
		"C16_APP_READY pump_timeout=retained host_only=eopnotsupp one_use=ealready tfo_guard=ok\n" :
		"C16_APP_READY pump_timeout=retained host_only=eopnotsupp tfo_guard=ok\n";
	(void)syscall(SYS_write, STDOUT_FILENO, ready, strlen(ready));
	return;
fail:
	{
		char message[128];
		int length = snprintf(message, sizeof(message),
			"C16 app setup failed stage=%s errno=%d\n", setup_stage,
			errno ? errno : EIO);
		if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
			(size_t)length);
		_exit(2);
	}
}

static int owner_loop(void *unused)
{
	(void)unused;
	setup_owner();
	if (window_cycles_mode && !window_initial_reported) {
		window_initial_reported = 1;
		struct ker_ff_owner_admission_window window = {0};
		uint64_t inserted = 0;
		if (ker_sb_preload_ff_owner_admission_status(&window)) _exit(13);
		ff_flow_map_stats(&inserted, NULL, NULL);
		char marker[112];
		int length = snprintf(marker, sizeof(marker),
			"C17_WINDOW_INITIAL epoch=%llu lease=%llu active=%d inserted=%llu\n",
			(unsigned long long)window.epoch,
			(unsigned long long)window.queue_lease, ff_flow_map_active(),
			(unsigned long long)inserted);
		if (length > 0) (void)syscall(SYS_write, STDOUT_FILENO, marker,
			(size_t)length);
	}
	if (pump_failure_mode) {
		if (pump_failure_retains_ready_event()) _exit(7);
		ff_stop_run();
		return 0;
	}
	if (retire_window_requested) {
		retire_window_requested = 0;
		if (ker_sb_preload_ff_owner_admission_retire()) _exit(9);
		window_retiring = 1;
		if (window_cancel_mode) {
			static const char marker[] = "C17_RETIRE_BEGIN_ACK state=retiring\n";
			(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
		}
	}
	if (rearm_window_requested) {
		rearm_window_requested = 0;
		if (ker_sb_preload_ff_owner_admission_rearm()) _exit(10);
		window_rearming = 1;
	}
	if (window_retiring || window_rearming) {
		struct ker_ff_owner_admission_window window = {0};
		if (ker_sb_preload_ff_owner_admission_status(&window)) _exit(11);
		if (window_retiring && window.state == KER_FF_ADMISSION_TASK_RETIRED) {
			window_retiring = 0;
			window_is_retired = 1;
			uint64_t inserted = 0;
			ff_flow_map_stats(&inserted, NULL, NULL);
			char marker[128];
			int length = snprintf(marker, sizeof(marker),
				"C17_WINDOW_RETIRED epoch=%llu lease=%llu active=%d inserted=%llu\n",
				(unsigned long long)window.epoch,
				(unsigned long long)window.queue_lease, ff_flow_map_active(),
				(unsigned long long)inserted);
			if (length > 0) (void)syscall(SYS_write, STDOUT_FILENO, marker,
				(size_t)length);
		} else if (window_rearming &&
		    window.state == KER_FF_ADMISSION_TASK_READY) {
			window_rearming = 0;
			window_is_retired = 0;
			uint64_t inserted = 0;
			ff_flow_map_stats(&inserted, NULL, NULL);
			char marker[128];
			int length = snprintf(marker, sizeof(marker),
				"C17_WINDOW_READY epoch=%llu lease=%llu active=%d inserted=%llu\n",
				(unsigned long long)window.epoch,
				(unsigned long long)window.queue_lease, ff_flow_map_active(),
				(unsigned long long)inserted);
			if (length > 0) (void)syscall(SYS_write, STDOUT_FILENO, marker,
				(size_t)length);
		} else if (window.state == KER_FF_ADMISSION_TASK_QUARANTINED ||
		    window.status) _exit(12);
	}
	if (retired_rpc_probe_requested) {
		retired_rpc_probe_requested = 0;
		errno = 0;
		int rejected = ff_socket(AF_INET,
			SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
		if (rejected >= 0 || errno != EAGAIN) _exit(14);
		errno = 0;
		if (retired_probe_fd < 0 || ff_listen(retired_probe_fd, 16) != -1 ||
		    errno != EAGAIN) _exit(15);
		struct sockaddr_in local = {0};
		socklen_t local_length = sizeof(local);
		int accepting = -1;
		socklen_t accepting_length = sizeof(accepting);
		if (ff_getsockname(retired_probe_fd,
			(struct linux_sockaddr *)&local, &local_length) ||
		    local_length != sizeof(local) || local.sin_port ||
		    ff_getsockopt(retired_probe_fd, SOL_SOCKET, SO_ACCEPTCONN,
			&accepting, &accepting_length) ||
		    accepting_length != sizeof(accepting) || accepting != 0) _exit(16);
		static const char marker[] =
			"C17_RETIRED_RPC_EAGAIN socket=1 listen=1 native_unchanged=1\n";
		(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	}
	if (close_listener_requested) {
		close_listener_requested = 0;
		if (listener_fd < 0 ||
		    ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_DEL, listener_fd, NULL) ||
		    ff_close(listener_fd)) _exit(8);
		listener_fd = -1;
		static const char marker[] = "C16_LISTENER_CLOSED owner_alive=1\n";
		(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	}
	if (request_snapshot_requested) {
		request_snapshot_requested = 0;
		uint64_t request_count = UINT64_MAX, inserted = 0;
		int status = ker_sb_preload_ff_owner_requests(&request_count);
		ff_flow_map_stats(&inserted, NULL, NULL);
		char snapshot[128];
		int length = snprintf(snapshot, sizeof(snapshot),
			"C16_REQUESTS status=%d count=%llu inserted=%llu\n", status,
			(unsigned long long)request_count, (unsigned long long)inserted);
		if (length > 0) (void)syscall(SYS_write, STDOUT_FILENO, snapshot,
			(size_t)length);
		if (status) _exit(6);
	}
	if (finish_if_requested()) return 0;
	struct epoll_event event;
	int wait_status = ker_sb_preload_owner_wait_check();
	if (wait_status) {
		if (stop_requested && completed_count >= requested_count) {
			(void)finish_if_requested();
			return 0;
		}
		char message[96];
		int length = snprintf(message, sizeof(message),
			"C16 owner wait guard failed status=%d\n", wait_status);
		if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
			(size_t)length);
		_exit(3);
	}
	ker_sb_preload_lock();
	int current_epoll = -1;
	int current_composite = ker_sb_preload_composite_epoll_locked(epoll_fd,
		&current_epoll);
	ker_sb_preload_unlock();
	if (current_composite != 1 || current_epoll < 0) {
		char message[96];
		int length = snprintf(message, sizeof(message),
			"C16 composite epoll lost result=%d errno=%d\n",
			current_composite, errno);
		if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
			(size_t)length);
		_exit(3);
	}
	int ready = ker_sb_posix_epoll_wait(epoll_fd, &event, 1, 250);
	if (ready < 0) {
		if (errno == EINTR) return 0;
		if (stop_requested && completed_count >= requested_count) {
			(void)finish_if_requested();
			return 0;
		}
		char message[128];
		int length = snprintf(message, sizeof(message),
			"C16 app epoll wait failed errno=%d\n", errno);
		if (length > 0) (void)syscall(SYS_write, STDERR_FILENO, message,
			(size_t)length);
		_exit(3);
	}
	if (finish_if_requested()) return 0;
	if (!ready) return 0;
	if (event.data.fd == listener_fd) {
		for (;;) {
			int accepted = ff_accept4(listener_fd, NULL, NULL,
				SOCK_NONBLOCK | SOCK_CLOEXEC);
			if (accepted < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
				_exit(4);
			}
			if (accepted_count >= requested_count) _exit(4);
			struct epoll_event accepted_event = {
				.events = EPOLLIN, .data.fd = accepted};
		if (ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accepted,
			&accepted_event)) _exit(4);
			++accepted_count;
		}
	} else {
		int accepted = event.data.fd;
		char data[32];
		ssize_t count = ff_read(accepted, data, sizeof(data));
		if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
			return 0;
		if (count <= 0 || write_all(accepted, data, (size_t)count)) _exit(5);
		if (ker_sb_posix_epoll_ctl(epoll_fd, EPOLL_CTL_DEL, accepted, NULL) ||
		    ff_close(accepted)) _exit(5);
		++completed_count;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2) return 2;
	if (!strcmp(argv[1], "pump-failure")) {
		pump_failure_mode = 1;
		requested_count = 1;
	} else if (!strcmp(argv[1], "owner-probe")) {
		owner_probe_mode = 1;
		requested_count = 0;
	} else if (!strcmp(argv[1], "product-smoke")) {
		product_smoke_mode = 1;
		requested_count = 1;
	} else if (!strcmp(argv[1], "window-cycles")) {
		window_cycles_mode = 1;
		requested_count = 4;
	} else if (!strcmp(argv[1], "window-cancel")) {
		window_cancel_mode = 1;
		requested_count = 0;
	} else {
	char *end = NULL;
	unsigned long count = strtoul(argv[1], &end, 10);
	if (!end || *end || !count || count > 64) return 2;
	requested_count = (unsigned)count;
	}
	const char *broker = getenv("KER_SOCKET_BROKER_PATH");
	if (!broker || !*broker) return 2;
	char config_path[256], config[512], conf_arg[300];
	int length = snprintf(config_path, sizeof(config_path),
		"/dev/shm/ker-c16-ff-%ld.ini", (long)getpid());
	if (length <= 0 || (size_t)length >= sizeof(config_path)) return 2;
	length = snprintf(config, sizeof(config),
		"[ker_socket_broker]\nversion=1\npath=%s\n[dpdk]\ngraceful_reload=0\n", broker);
	if (length <= 0 || (size_t)length >= sizeof(config)) return 2;
	int fd = (int)syscall(SYS_openat, AT_FDCWD, config_path,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) return 2;
	if (syscall(SYS_write, fd, config, (size_t)length) != length ||
	    syscall(SYS_close, fd)) return 2;
	length = snprintf(conf_arg, sizeof(conf_arg), "--conf=%s", config_path);
	if (length <= 0 || (size_t)length >= sizeof(conf_arg)) return 2;
	char *arguments[] = {"nginx", conf_arg, "--proc-id=0", "--proc-type=primary"};
	if (ff_init(4, arguments)) return 2;
	struct sigaction snapshot_action = {0};
	snapshot_action.sa_handler = request_snapshot_signal;
	sigemptyset(&snapshot_action.sa_mask);
	if (sigaction(SIGUSR1, &snapshot_action, NULL)) return 2;
	struct sigaction stop_action = {0};
	stop_action.sa_handler = stop_signal;
	sigemptyset(&stop_action.sa_mask);
	if (sigaction(SIGUSR2, &stop_action, NULL)) return 2;
	struct sigaction retire_action = {0};
	retire_action.sa_handler = retire_window_signal;
	sigemptyset(&retire_action.sa_mask);
	if (sigaction(SIGWINCH, &retire_action, NULL)) return 2;
	struct sigaction rearm_action = {0};
	rearm_action.sa_handler = rearm_window_signal;
	sigemptyset(&rearm_action.sa_mask);
	if (sigaction(SIGHUP, &rearm_action, NULL)) return 2;
	ff_run(owner_loop, NULL);
	(void)syscall(SYS_unlinkat, AT_FDCWD, config_path, 0);
	if (listener_fd >= 0) (void)ff_close(listener_fd);
	if (retired_probe_fd >= 0) (void)ff_close(retired_probe_fd);
	if (epoll_fd >= 0) (void)ff_close(epoll_fd);
	ff_flow_map_close();
	ker_reload_unbind_state();
	free(reload_state);
	return 0;
}
