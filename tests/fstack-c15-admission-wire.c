#define _GNU_SOURCE
#include "check.h"
#include "../src/posix/ff-admission-queue.h"
#include "../src/posix/ff-admission-channel.h"
#include "../src/posix/ff-owner-requests-diag.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ker/reload.h>
#include <lkl.h>
#include <lkl_host.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ff_config.h"
#include "ff_flow_map.h"

#define OWNER_MARK UINT32_C(0x4c150001)

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

static uint64_t deadline_after_ms(unsigned milliseconds)
{
	struct timespec now;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec +
		(uint64_t)milliseconds * UINT64_C(1000000);
}

static void owner_process(int fd, int ready_fd, pid_t controller, uint64_t lease)
{
	size_t state_size = ker_reload_state_size();
	void *state = calloc(1, state_size);
	struct ker_ff_admission_channel *channel = NULL;
	struct ker_ff_admission_map_ops ops = {
		.active = map_active, .admit = map_admit, .revoke = map_revoke};
	CHECK(state != NULL);
	CHECK(!ker_reload_state_init(state, state_size, 0));
	CHECK(!ker_reload_bind_state(state, state_size, 1, 0));
	ff_flow_map_open();
	CHECK(ff_flow_map_active() && ff_reload_state_attached());
	CHECK(!ker_ff_admission_channel_open(fd, controller, getuid(), getgid(),
		lease, &channel));
	char ready = 'R';
	CHECK(write(ready_fd, &ready, 1) == 1);
	(void)close(ready_fd);
	for (;;) {
		int status = ker_ff_admission_channel_owner_step(channel, &ops);
		if (status == -ECONNRESET) break;
		CHECK(status == 0 || status == -EAGAIN || status == -EWOULDBLOCK);
		struct timespec pause = {.tv_nsec = 1000000};
		nanosleep(&pause, NULL);
	}
	ff_flow_map_close();
	ker_reload_unbind_state();
	free(state);
	ker_ff_admission_channel_close(channel);
	_exit(0);
}

static struct ker_ff_admission_result receive_command(
	struct ker_ff_admission_channel *channel, int expected, uint64_t deadline)
{
	for (;;) {
		struct ker_ff_admission_result result;
		int status = ker_ff_admission_channel_receive(channel, &result);
		if (status == expected) return result;
		CHECK(status == 0 || status == -EAGAIN || status == -EWOULDBLOCK);
		CHECK(deadline_after_ms(0) < deadline);
		struct timespec pause = {.tv_nsec = 1000000};
		nanosleep(&pause, NULL);
	}
}

static void burst_admission(struct ker_ff_admission_queue *queue,
    struct ker_ff_admission_channel *channel, unsigned listener,
    const struct sockaddr_in *address, uint64_t lease, unsigned round)
{
    enum { COUNT = 12 };
    int clients[COUNT];
    uint16_t ports[COUNT];
    int seen[COUNT] = {0};
    uint64_t until = deadline_after_ms(500);
    for (unsigned i = 0; i < COUNT; ++i) {
        clients[i] = (int)lkl_sys_socket(LKL_AF_INET,
            LKL_SOCK_STREAM | LKL_O_NONBLOCK | LKL_O_CLOEXEC, 0);
        CHECK(clients[i] >= 0);
        CHECK(lkl_sys_connect((unsigned)clients[i], (struct lkl_sockaddr *)address,
            sizeof(*address)) == -LKL_EINPROGRESS);
        struct sockaddr_in local;
        int length = sizeof(local);
        CHECK(!lkl_sys_getsockname((unsigned)clients[i], (struct lkl_sockaddr *)&local, &length));
        ports[i] = local.sin_port;
    }
    for (unsigned i = 0; i < COUNT; ++i) {
        struct lkl_pollfd fd = {.fd = clients[i], .events = LKL_POLLOUT};
        CHECK(!lkl_sys_poll(&fd, 1, 0));
    }
    for (unsigned i = 0; i < COUNT; ++i) {
        struct ker_ff_admission_packet packet;
        CHECK(ker_ff_admission_queue_receive(queue, &packet, 10) == 1);
        unsigned index = 0;
        while (index < COUNT && ports[index] != packet.remote_port) ++index;
        CHECK(index < COUNT && !seen[index]);
        seen[index] = 1;
        struct ker_ff_admission_request request = {
            .lease = lease, .command_id = 2 + round * COUNT + i, .packet_id = packet.id,
            .deadline_ns = packet.deadline_ns,
            .key = {.source = {packet.remote_address}, .destination = {packet.local_address},
                .source_port = packet.remote_port, .destination_port = packet.local_port}};
        CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
        struct ker_ff_admission_result result = receive_command(channel,
            KER_FF_ADMISSION_RESULT, packet.deadline_ns);
        CHECK(!result.status && result.allowed == 1 && result.created == 1);
        CHECK(!ker_ff_admission_channel_send_control(channel,
            KER_FF_ADMISSION_PREPARE_ACCEPT, request.command_id, packet.id));
        result = receive_command(channel, KER_FF_ADMISSION_PREPARED, packet.deadline_ns);
        CHECK(!result.status);
        int sent = 0;
        CHECK(!ker_ff_admission_queue_verdict(queue, packet.lease, packet.deadline_ns,
            packet.id, 1, &sent) && sent == 1);
        CHECK(!ker_ff_admission_channel_send_control(channel,
            KER_FF_ADMISSION_FINALIZE, request.command_id, packet.id));
        result = receive_command(channel, KER_FF_ADMISSION_FINALIZED, until);
        CHECK(!result.status);
        struct lkl_pollfd fd = {.fd = clients[index], .events = LKL_POLLOUT};
        CHECK(lkl_sys_poll(&fd, 1, 10) == 1 && (fd.revents & LKL_POLLOUT));
        long accepted = lkl_sys_accept(listener, NULL, NULL);
        CHECK(accepted >= 0);
        char byte = (char)(index + 1), received = 0;
        CHECK(lkl_sys_write((unsigned)clients[index], &byte, 1) == 1);
        CHECK(lkl_sys_read((unsigned)accepted, &received, 1) == 1 && received == byte);
        CHECK(!lkl_sys_close((unsigned)accepted));
        CHECK(!lkl_sys_close((unsigned)clients[index]));
        CHECK(deadline_after_ms(0) < until);
    }
    printf("C15_BURST_PASS batch=%u clients=12 admitted=12 payloads=12\n", round + 1);
}

int main(void)
{
	int endpoints[2], ready_pipe[2];
	const uint64_t lease = UINT64_C(0x15c150001);
	struct ker_ff_admission_channel *channel = NULL;
	struct ker_ff_admission_queue *queue = NULL;
	struct ker_ff_admission_packet packet;
	long listener = -1, client = -1, accepted = -1;
	pid_t owner, controller = getpid();
	int owner_status = 0;
	char ready;

	CHECK(!ker_ff_admission_channel_pair(endpoints));
	CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0);
	owner = fork();
	CHECK(owner >= 0);
	if (owner == 0) {
		(void)close(endpoints[0]);
		(void)close(ready_pipe[0]);
		owner_process(endpoints[1], ready_pipe[1], controller, lease);
		_exit(1);
	}
	(void)close(endpoints[1]);
	(void)close(ready_pipe[1]);
	CHECK(!ker_ff_admission_channel_open(endpoints[0], owner, getuid(), getgid(),
		lease, &channel));
	CHECK(read(ready_pipe[0], &ready, 1) == 1 && ready == 'R');
	(void)close(ready_pipe[0]);

	lkl_host_ops.print = NULL;
	CHECK(lkl_init(&lkl_host_ops) == 0);
	CHECK(lkl_start_kernel("%s", "mem=64M") == 0);
	CHECK(lkl_mount_fs("proc") == 0);
	CHECK(lkl_if_up(1) == 0);
	listener = lkl_sys_socket(LKL_AF_INET,
		LKL_SOCK_STREAM | LKL_O_CLOEXEC, 0);
	CHECK(listener >= 0);
	int mark = OWNER_MARK;
	CHECK(lkl_sys_setsockopt((unsigned)listener, LKL_SOL_SOCKET, LKL_SO_MARK,
		(char *)&mark, sizeof(mark)) == 0);
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	CHECK(lkl_sys_bind((unsigned)listener, (struct lkl_sockaddr *)&address,
		sizeof(address)) == 0);
	CHECK(lkl_sys_listen((unsigned)listener, 32) == 0);
	int address_length = sizeof(address);
	CHECK(lkl_sys_getsockname((unsigned)listener, (struct lkl_sockaddr *)&address,
		&address_length) == 0 && address_length == sizeof(address) && address.sin_port);
	CHECK(!ker_ff_admission_queue_start(OWNER_MARK, &queue));
	client = lkl_sys_socket(LKL_AF_INET,
		LKL_SOCK_STREAM | LKL_O_NONBLOCK | LKL_O_CLOEXEC, 0);
	CHECK(client >= 0);
	long connected = lkl_sys_connect((unsigned)client,
		(struct lkl_sockaddr *)&address, sizeof(address));
	CHECK(connected == -LKL_EINPROGRESS);
	int got_packet = 0;
	uint64_t packet_wait_deadline = deadline_after_ms(3000);
	do {
		int result = ker_ff_admission_queue_receive(queue, &packet, 250);
		if (result == 1) { got_packet = 1; break; }
		if (result < 0)
			fprintf(stderr, "C15 queue receive failed: %d\n", result);
		CHECK(result == 0);
	} while (deadline_after_ms(0) < packet_wait_deadline);
	CHECK(got_packet && packet.lease && packet.mark == OWNER_MARK &&
		packet.local_address == htonl(INADDR_LOOPBACK) &&
		packet.remote_address == htonl(INADDR_LOOPBACK) &&
		packet.local_port == address.sin_port && packet.remote_port);
	struct lkl_pollfd client_poll = {.fd = (int)client, .events = LKL_POLLOUT};
	CHECK(lkl_sys_poll(&client_poll, 1, 0) == 0);

	struct ker_ff_admission_request request = {
		/* The channel owner lease and kernel queue lease are distinct. */
		.lease = lease,
		.command_id = 1,
		.deadline_ns = packet.deadline_ns,
		.packet_id = packet.id,
		.key = {.source = {packet.remote_address},
			.destination = {packet.local_address},
			.source_port = packet.remote_port,
			.destination_port = packet.local_port}};
	CHECK(!ker_ff_admission_channel_send_admit(channel, &request));
	struct ker_ff_admission_result result = receive_command(channel,
		KER_FF_ADMISSION_RESULT, packet.deadline_ns);
	CHECK(!result.status && result.allowed == 1 && result.created == 1);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_PREPARE_ACCEPT, request.command_id, request.packet_id));
	result = receive_command(channel, KER_FF_ADMISSION_PREPARED,
		packet.deadline_ns);
	CHECK(!result.status);
	int sent_to_kernel = 0;
	CHECK(!ker_ff_admission_queue_verdict(queue, packet.lease,
		packet.deadline_ns, packet.id, 1, &sent_to_kernel));
	CHECK(sent_to_kernel == 1);
	CHECK(!ker_ff_admission_channel_send_control(channel,
		KER_FF_ADMISSION_FINALIZE, request.command_id, request.packet_id));
	result = receive_command(channel, KER_FF_ADMISSION_FINALIZED,
		deadline_after_ms(1000));
	CHECK(!result.status);
	client_poll.revents = 0;
	CHECK(lkl_sys_poll(&client_poll, 1, 1000) == 1 &&
		(client_poll.revents & LKL_POLLOUT));
	accepted = lkl_sys_accept((unsigned)listener, NULL, NULL);
	CHECK(accepted >= 0);
	CHECK(lkl_sys_close((unsigned)accepted) == 0);
	accepted = -1;
	CHECK(lkl_sys_close((unsigned)client) == 0);
	client = -1;
	for (unsigned round = 0; round < 6; ++round) {
		burst_admission(queue, channel, (unsigned)listener, &address, lease, round);
	}
	client = lkl_sys_socket(LKL_AF_INET,
		LKL_SOCK_STREAM | LKL_O_NONBLOCK | LKL_O_CLOEXEC, 0);
	CHECK(client >= 0);
	connected = lkl_sys_connect((unsigned)client,
		(struct lkl_sockaddr *)&address, sizeof(address));
	CHECK(connected == -LKL_EINPROGRESS);
	got_packet = 0;
	packet_wait_deadline = deadline_after_ms(3000);
	do {
		int receive = ker_ff_admission_queue_receive(queue, &packet, 250);
		if (receive == 1) { got_packet = 1; break; }
		CHECK(receive == 0);
	} while (deadline_after_ms(0) < packet_wait_deadline);
	CHECK(got_packet && packet.lease && packet.mark == OWNER_MARK);
	sent_to_kernel = 0;
	CHECK(ker_ff_admission_queue_test_drop_wrong_id(queue, packet.lease,
		packet.deadline_ns, packet.id, &sent_to_kernel) == -ENOENT);
	CHECK(sent_to_kernel == 1);
	CHECK(ker_ff_admission_queue_disarm_after_quiescence(queue) == -EBUSY);
	client_poll = (struct lkl_pollfd){.fd = (int)client, .events = LKL_POLLOUT};
	CHECK(lkl_sys_poll(&client_poll, 1, 0) == 0);
	ker_ff_admission_queue_close(queue);
	queue = NULL;
	CHECK(lkl_sys_close((unsigned)listener) == 0);
	listener = -1;
	CHECK(lkl_sys_poll(&client_poll, 1, 50) == 0);
	CHECK(lkl_sys_close((unsigned)client) == 0);
	client = -1;
	struct ker_ff_admission_queue *replacement = NULL;
	CHECK(ker_ff_admission_queue_start(OWNER_MARK, &replacement) == -EBUSY);
	CHECK(replacement == NULL);
	CHECK(lkl_sys_halt() == 0);
	lkl_cleanup();
	ker_ff_admission_channel_close(channel);
	channel = NULL;
	CHECK(waitpid(owner, &owner_status, 0) == owner && WIFEXITED(owner_status) &&
		WEXITSTATUS(owner_status) == 0);
	puts("PASS: original LKL holds SYNACK until map admission; matched negative DROP ACK keeps packet pending and blocks disarm");
	return 0;
}
