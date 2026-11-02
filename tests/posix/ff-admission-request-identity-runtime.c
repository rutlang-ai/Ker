#define _GNU_SOURCE
#include "ff-admission-request-identity.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define OWNER_MARK UINT32_C(0x4c150001)
#define REQUIRE(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "request identity runtime:%d: %s (errno=%d: %s)\n", \
			__LINE__, #condition, errno, strerror(errno)); \
		goto fail; \
	} \
} while (0)

extern int ker_native_tcp_request_revoke(
	const struct ker_tcp_request_revoke_request *request);

static int write_state(const char *prefix, const char *state)
{
	char path[512];
	if (snprintf(path, sizeof(path), "%s.state", prefix) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	FILE *file = fopen(path, "w");
	if (!file)
		return -errno;
	int result = fprintf(file, "%s\n", state) < 0 ? -EIO : 0;
	if (fclose(file) && !result)
		result = -errno;
	return result;
}

static int wait_command(const char *prefix, char *command, size_t capacity)
{
	if (capacity < 128)
		return -EINVAL;
	char path[512];
	if (snprintf(path, sizeof(path), "%s.command", prefix) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	struct timespec started;
	if (clock_gettime(CLOCK_MONOTONIC, &started))
		return -errno;
	for (;;) {
		FILE *file = fopen(path, "r");
		if (file) {
			char *parsed = fgets(command, (int)capacity, file);
			fclose(file);
			if (parsed) {
				command[strcspn(command, "\r\n")] = '\0';
				if (unlink(path))
					return -errno;
				return 0;
			}
		}
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			return -errno;
		int64_t elapsed = (int64_t)(now.tv_sec - started.tv_sec) *
			INT64_C(1000000000) + now.tv_nsec - started.tv_nsec;
		if (elapsed < 0 || elapsed >= INT64_C(30000000000))
			return -ETIMEDOUT;
		const struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
		while (nanosleep(&pause, NULL) && errno == EINTR) { }
	}
}

int main(void)
{
	const char *prefix = getenv("KER_C15_IDENTITY_CONTROL");
	int listener = -1;
	int listener_alias = -1;
	struct ker_ff_admission_request_identity *identity = NULL;
	REQUIRE(prefix && *prefix);
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
	REQUIRE(listener >= 0);
	REQUIRE(setsockopt(listener, SOL_SOCKET, SO_MARK, &(uint32_t){OWNER_MARK},
		sizeof(uint32_t)) == 0);
	struct sockaddr_in local = {.sin_family = AF_INET};
	REQUIRE(inet_pton(AF_INET, "198.18.0.2", &local.sin_addr) == 1);
	REQUIRE(bind(listener, (struct sockaddr *)&local, sizeof(local)) == 0);
	REQUIRE(listen(listener, 8) == 0);
	socklen_t local_length = sizeof(local);
	REQUIRE(getsockname(listener, (struct sockaddr *)&local, &local_length) == 0);
	REQUIRE(local_length == sizeof(local) && local.sin_port);
	char state[128];
	REQUIRE(snprintf(state, sizeof(state), "READY port=%u", ntohs(local.sin_port)) <
		(int)sizeof(state));
	REQUIRE(write_state(prefix, state) == 0);
	char command[128] = {0};
	REQUIRE(wait_command(prefix, command, sizeof(command)) == 0);
	unsigned int remote_port = 0;
	REQUIRE(sscanf(command, "LOOKUP %u", &remote_port) == 1 &&
		remote_port > 0 && remote_port <= UINT16_MAX);
	struct ker_ff_admission_ipv4_tuple tuple = {
		.local = local,
		.remote = {.sin_family = AF_INET, .sin_port = htons((uint16_t)remote_port)}};
	REQUIRE(inet_pton(AF_INET, "198.18.0.1", &tuple.remote.sin_addr) == 1);
	int begin_result = ker_ff_admission_request_identity_begin(listener, &tuple,
		OWNER_MARK, &identity);
	if (begin_result)
		fprintf(stderr, "request identity begin failed: %d\n", begin_result);
	REQUIRE(begin_result == 0);
	atomic_bool cancel = false;
	struct ker_tcp_request_revoke_request request = {0};
	int result;
	struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
	for (;;) {
		result = ker_ff_admission_request_identity_step(identity, &cancel, &request);
		if (result != 0)
			break;
		while (nanosleep(&pause, &pause) && errno == EINTR) { }
		pause = (struct timespec){.tv_sec = 0, .tv_nsec = 1000000};
	}
	REQUIRE(result == 1);
	REQUIRE(request.version == KER_TCP_REQUEST_REVOKE_VERSION &&
		request.mark == OWNER_MARK && request.family == AF_INET &&
		request.local_port == local.sin_port &&
		request.remote_port == tuple.remote.sin_port &&
		(request.request_cookie[0] != INET_DIAG_NOCOOKIE ||
		 request.request_cookie[1] != INET_DIAG_NOCOOKIE));
	REQUIRE(ker_ff_admission_request_identity_revalidate(identity) == 0);
	listener_alias = dup(listener);
	REQUIRE(listener_alias >= 0);
	REQUIRE(close(listener) == 0);
	listener = -1;
	REQUIRE(ker_ff_admission_request_identity_revalidate(identity) == -ESTALE);
	ker_ff_admission_request_identity_close(identity);
	identity = NULL;
	REQUIRE(ker_native_tcp_request_revoke(&request) == 0);
	int accepted = accept4(listener_alias, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	REQUIRE(accepted < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
	REQUIRE(write_state(prefix, "IDENTITY_REVOKED") == 0);
	REQUIRE(wait_command(prefix, command, sizeof(command)) == 0 &&
		!strcmp(command, "CANCEL"));
	tuple.remote.sin_port = htons((uint16_t)(remote_port == UINT16_MAX ?
		remote_port - 1 : remote_port + 1));
	REQUIRE(ker_ff_admission_request_identity_begin(listener_alias, &tuple, OWNER_MARK,
		&identity) == 0);
	atomic_store_explicit(&cancel, true, memory_order_release);
	REQUIRE(ker_ff_admission_request_identity_step(identity, &cancel, &request) ==
		-ECANCELED);
	ker_ff_admission_request_identity_close(identity);
	identity = NULL;
	REQUIRE(write_state(prefix, "CANCELLED") == 0);
	REQUIRE(wait_command(prefix, command, sizeof(command)) == 0 &&
		!strcmp(command, "CLOSE_DONE"));
	REQUIRE(write_state(prefix, "CLOSED_FD_REJECTED") == 0);
	REQUIRE(close(listener_alias) == 0);
	listener_alias = -1;
	return 0;
fail:
	ker_ff_admission_request_identity_close(identity);
	if (listener >= 0)
		close(listener);
	if (listener_alias >= 0)
		close(listener_alias);
	return 1;
}
