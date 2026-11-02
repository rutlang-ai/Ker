#define _GNU_SOURCE
#include "tcp-request-revoke.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "tcp request revoke runtime:%d: %s (errno=%d: %s)\n", \
			__LINE__, #condition, errno, strerror(errno)); \
		goto fail; \
	} \
} while (0)

#define CONTROL_TIMEOUT_MS 10000
#define DIAG_CAPACITY 65536
#define OWNER_MARK UINT32_C(0x4c140001)

extern int ker_member_census_test_clear_net_admin(void);
extern int ker_member_census_test_restore_capabilities(void);

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

static int wait_command(const char *prefix, const char *expected)
{
	char path[512];
	if (snprintf(path, sizeof(path), "%s.command", prefix) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	struct timespec start;
	if (clock_gettime(CLOCK_MONOTONIC, &start))
		return -errno;
	for (;;) {
		FILE *file = fopen(path, "r");
		if (file) {
			char command[64] = {0};
			bool matches = fscanf(file, "%63s", command) == 1 &&
				!strcmp(command, expected);
			fclose(file);
			if (matches) {
				unlink(path);
				return 0;
			}
		}
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			return -errno;
		int64_t elapsed = (int64_t)(now.tv_sec - start.tv_sec) * INT64_C(1000000000) +
			(now.tv_nsec - start.tv_nsec);
		if (elapsed < 0 || elapsed >= INT64_C(30000000000))
			return -ETIMEDOUT;
		const struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
		while (nanosleep(&pause, NULL) && errno == EINTR) { }
	}
}

static int diag_find_family(uint8_t family, uint16_t local_port, uint8_t state,
		     struct inet_diag_msg *found)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
	if (fd < 0)
		return -errno;
	struct {
		struct nlmsghdr header;
		struct inet_diag_req_v2 request;
	} query = {0};
	query.header.nlmsg_len = sizeof(query);
	query.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	query.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	query.header.nlmsg_seq = 0x14c14u;
	query.request.sdiag_family = family;
	query.request.sdiag_protocol = IPPROTO_TCP;
	query.request.idiag_states = UINT32_MAX;
	query.request.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
	query.request.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
	struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
	ssize_t sent = sendto(fd, &query, sizeof(query), 0,
		(struct sockaddr *)&kernel, sizeof(kernel));
	if (sent != (ssize_t)sizeof(query)) {
		int error = sent < 0 ? errno : EIO;
		close(fd);
		return -error;
	}
	unsigned char buffer[DIAG_CAPACITY];
	bool has_match = false;
	int status = 0;
	for (;;) {
		struct pollfd wait = {.fd = fd, .events = POLLIN};
		int ready = poll(&wait, 1, CONTROL_TIMEOUT_MS);
		if (ready <= 0) {
			status = ready ? -errno : -ETIMEDOUT;
			break;
		}
		ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
		if (received <= 0) {
			status = received < 0 ? -errno : -EPROTO;
			break;
		}
		int remaining = (int)received;
		for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
		     NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
			if (header->nlmsg_seq != query.header.nlmsg_seq) {
				status = -EPROTO;
				goto done;
			}
			if (header->nlmsg_type == NLMSG_DONE)
				goto done;
			if (header->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *error = NLMSG_DATA(header);
				status = error->error;
				goto done;
			}
			if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
			    header->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
				status = -EPROTO;
				goto done;
			}
			const struct inet_diag_msg *row = NLMSG_DATA(header);
			if (row->idiag_family != family || row->idiag_state != state ||
			    ntohs(row->id.idiag_sport) != local_port)
				continue;
			if (has_match) {
				status = -EEXIST;
				goto done;
			}
			*found = *row;
			has_match = true;
		}
		if (remaining) {
			status = -EPROTO;
			break;
		}
	}
done:
	close(fd);
	if (status)
		return status;
	return has_match ? 0 : -ENOENT;
}

static struct ker_tcp_request_revoke_request revoke_request(
	const struct inet_diag_msg *row, uint32_t mark, uint64_t listener_cookie)
{
	struct ker_tcp_request_revoke_request request = {
		.version = KER_TCP_REQUEST_REVOKE_VERSION,
		.mark = mark,
		.family = row->idiag_family,
		.local_port = row->id.idiag_sport,
		.remote_port = row->id.idiag_dport,
		.ifindex = row->id.idiag_if,
	};
	memcpy(request.local_address, row->id.idiag_src, sizeof(request.local_address));
	memcpy(request.remote_address, row->id.idiag_dst, sizeof(request.remote_address));
	memcpy(request.request_cookie, row->id.idiag_cookie, sizeof(request.request_cookie));
	request.listener_cookie[0] = (uint32_t)listener_cookie;
	request.listener_cookie[1] = (uint32_t)(listener_cookie >> 32);
	return request;
}

static int diag_find(uint16_t local_port, uint8_t state, struct inet_diag_msg *found)
{
	return diag_find_family(AF_INET, local_port, state, found);
}

static int wait_diag_family(uint8_t family, uint16_t port, uint8_t state,
		struct inet_diag_msg *row)
{
	struct timespec start;
	if (clock_gettime(CLOCK_MONOTONIC, &start))
		return -errno;
	for (;;) {
		int result = diag_find_family(family, port, state, row);
		if (!result)
			return 0;
		if (result != -ENOENT)
			return result;
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			return -errno;
		int64_t elapsed = (int64_t)(now.tv_sec - start.tv_sec) * INT64_C(1000000000) +
			(now.tv_nsec - start.tv_nsec);
		if (elapsed < 0 || elapsed >= INT64_C(5000000000))
			return -ETIMEDOUT;
		const struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
		while (nanosleep(&pause, NULL) && errno == EINTR) { }
	}
}

static int wait_diag(uint16_t port, uint8_t state, struct inet_diag_msg *row)
{
	return wait_diag_family(AF_INET, port, state, row);
}

int main(void)
{
	const char *prefix = getenv("KER_C14_REVOKE_CONTROL");
	int listener = -1;
	int accepted = -1;
	int listener6 = -1;
	int accepted6 = -1;
	REQUIRE(prefix && *prefix);
	/* Exercise the ioctl endpoint's strict request validation before any live
	 * request exists. This must fail with EINVAL, never report a false success. */
	struct ker_tcp_request_revoke_request invalid = {0};
	REQUIRE(ker_native_tcp_request_revoke(&invalid) == -EINVAL);
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
	uint64_t listener_cookie = 0;
	uint64_t listener6_cookie = 0;
	socklen_t cookie_length = sizeof(listener_cookie);
	REQUIRE(getsockopt(listener, SOL_SOCKET, SO_COOKIE, &listener_cookie,
		&cookie_length) == 0);
	REQUIRE(cookie_length == sizeof(listener_cookie) && listener_cookie);
	listener6 = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
	REQUIRE(listener6 >= 0);
	int only_v6 = 1;
	REQUIRE(setsockopt(listener6, IPPROTO_IPV6, IPV6_V6ONLY, &only_v6,
		sizeof(only_v6)) == 0);
	REQUIRE(setsockopt(listener6, SOL_SOCKET, SO_MARK, &(uint32_t){OWNER_MARK},
		sizeof(uint32_t)) == 0);
	struct sockaddr_in6 local6 = {.sin6_family = AF_INET6};
	REQUIRE(inet_pton(AF_INET6, "2001:db8::2", &local6.sin6_addr) == 1);
	REQUIRE(bind(listener6, (struct sockaddr *)&local6, sizeof(local6)) == 0);
	REQUIRE(listen(listener6, 8) == 0);
	socklen_t local6_length = sizeof(local6);
	REQUIRE(getsockname(listener6, (struct sockaddr *)&local6, &local6_length) == 0);
	REQUIRE(local6_length == sizeof(local6) && local6.sin6_port);
	cookie_length = sizeof(listener6_cookie);
	REQUIRE(getsockopt(listener6, SOL_SOCKET, SO_COOKIE, &listener6_cookie,
		&cookie_length) == 0 && cookie_length == sizeof(listener6_cookie));
	char state[128];
	REQUIRE(snprintf(state, sizeof(state), "READY port=%u port6=%u",
		ntohs(local.sin_port), ntohs(local6.sin6_port)) < (int)sizeof(state));
	REQUIRE(write_state(prefix, state) == 0);
	REQUIRE(wait_command(prefix, "REVOKE") == 0);
	struct inet_diag_msg request_row = {0};
	REQUIRE(wait_diag(ntohs(local.sin_port), TCP_SYN_RECV, &request_row) == 0);
	struct ker_tcp_request_revoke_request request = revoke_request(&request_row,
		OWNER_MARK, listener_cookie);
	struct ker_tcp_request_revoke_request wrong = request;
	wrong.mark++;
	REQUIRE(ker_native_tcp_request_revoke(&wrong) == -ESTALE);
	REQUIRE(diag_find(ntohs(local.sin_port), TCP_SYN_RECV, &request_row) == 0);
	wrong = request;
	wrong.listener_cookie[0] ^= 1u;
	REQUIRE(ker_native_tcp_request_revoke(&wrong) == -ESTALE);
	REQUIRE(diag_find(ntohs(local.sin_port), TCP_SYN_RECV, &request_row) == 0);
	wrong = request;
	wrong.request_cookie[0] ^= 1u;
	REQUIRE(ker_native_tcp_request_revoke(&wrong) == -ENOENT);
	REQUIRE(diag_find(ntohs(local.sin_port), TCP_SYN_RECV, &request_row) == 0);
	REQUIRE(ker_member_census_test_clear_net_admin() == 0);
	int denied = ker_native_tcp_request_revoke(&request);
	int restored = ker_member_census_test_restore_capabilities();
	REQUIRE(denied == -EPERM && restored == 0);
	REQUIRE(diag_find(ntohs(local.sin_port), TCP_SYN_RECV, &request_row) == 0);
	REQUIRE(ker_native_tcp_request_revoke(&request) == 0);
	REQUIRE(diag_find(ntohs(local.sin_port), TCP_SYN_RECV, &request_row) == -ENOENT);
	accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	REQUIRE(accepted < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
	REQUIRE(write_state(prefix, "REVOKED") == 0);
	REQUIRE(wait_command(prefix, "ACKWIN_CAPTURE") == 0);
	REQUIRE(wait_diag(ntohs(local.sin_port), TCP_SYN_RECV, &request_row) == 0);
	struct ker_tcp_request_revoke_request promoted = revoke_request(&request_row,
		OWNER_MARK, listener_cookie);
	REQUIRE(write_state(prefix, "ACKWIN_REQUEST_CAPTURED") == 0);
	REQUIRE(wait_command(prefix, "ACKWIN_PROMOTE") == 0);
	struct inet_diag_msg child_row = {0};
	REQUIRE(wait_diag(ntohs(local.sin_port), TCP_ESTABLISHED, &child_row) == 0);
	int promotion_race = ker_native_tcp_request_revoke(&promoted);
	REQUIRE(promotion_race == -ESTALE || promotion_race == -ENOENT ||
		promotion_race == -EAGAIN);
	accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	REQUIRE(accepted >= 0);
	REQUIRE(write_state(prefix, "ACKWIN_ACCEPTED") == 0);
	REQUIRE(wait_command(prefix, "ACKWIN_READ") == 0);
	char payload[5];
	ssize_t received = recv(accepted, payload, sizeof(payload), MSG_WAITALL);
	REQUIRE(received == (ssize_t)sizeof(payload) && !memcmp(payload, "hello", sizeof(payload)));
	REQUIRE(send(accepted, "world", 5, 0) == 5);
	REQUIRE(write_state(prefix, "ACKWIN_CHILD_SURVIVED") == 0);
	REQUIRE(wait_command(prefix, "START_IPV6") == 0);
	close(accepted);
	accepted = -1;
	close(listener);
	listener = -1;
	REQUIRE(write_state(prefix, "IPV6_READY") == 0);
	REQUIRE(wait_command(prefix, "REVOKE6") == 0);
	struct inet_diag_msg request6_row = {0};
	REQUIRE(wait_diag_family(AF_INET6, ntohs(local6.sin6_port), TCP_SYN_RECV,
		&request6_row) == 0);
	struct ker_tcp_request_revoke_request request6 = revoke_request(&request6_row,
		OWNER_MARK, listener_cookie);
	request6.listener_cookie[0] = (uint32_t)listener6_cookie;
	request6.listener_cookie[1] = (uint32_t)(listener6_cookie >> 32);
	REQUIRE(ker_native_tcp_request_revoke(&request6) == 0);
	REQUIRE(diag_find_family(AF_INET6, ntohs(local6.sin6_port), TCP_SYN_RECV,
		&request6_row) == -ENOENT);
	accepted6 = accept4(listener6, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	REQUIRE(accepted6 < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
	REQUIRE(write_state(prefix, "IPV6_REVOKED") == 0);
	REQUIRE(wait_command(prefix, "V6_DONE") == 0);
	close(listener6);
	listener6 = -1;
	listener6 = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
	REQUIRE(listener6 >= 0);
	REQUIRE(setsockopt(listener6, IPPROTO_IPV6, IPV6_V6ONLY, &only_v6,
		sizeof(only_v6)) == 0);
	REQUIRE(setsockopt(listener6, SOL_SOCKET, SO_REUSEADDR, &only_v6,
		sizeof(only_v6)) == 0);
	REQUIRE(setsockopt(listener6, SOL_SOCKET, SO_MARK, &(uint32_t){OWNER_MARK},
		sizeof(uint32_t)) == 0);
	REQUIRE(bind(listener6, (struct sockaddr *)&local6, sizeof(local6)) == 0);
	REQUIRE(listen(listener6, 8) == 0);
	uint64_t rebound_cookie = 0;
	cookie_length = sizeof(rebound_cookie);
	REQUIRE(getsockopt(listener6, SOL_SOCKET, SO_COOKIE, &rebound_cookie,
		&cookie_length) == 0 && cookie_length == sizeof(rebound_cookie));
	REQUIRE(rebound_cookie != listener6_cookie);
	REQUIRE(write_state(prefix, "IPV6_REBOUND") == 0);
	REQUIRE(wait_command(prefix, "REVOKE6_STALE") == 0);
	REQUIRE(wait_diag_family(AF_INET6, ntohs(local6.sin6_port), TCP_SYN_RECV,
		&request6_row) == 0);
	struct ker_tcp_request_revoke_request fresh6 = revoke_request(&request6_row,
		OWNER_MARK, rebound_cookie);
	int stale_result = ker_native_tcp_request_revoke(&request6);
	REQUIRE(stale_result == -ENOENT || stale_result == -ESTALE);
	REQUIRE(diag_find_family(AF_INET6, ntohs(local6.sin6_port), TCP_SYN_RECV,
		&request6_row) == 0);
	struct ker_tcp_request_revoke_request wrong_listener6 = fresh6;
	wrong_listener6.listener_cookie[0] = (uint32_t)listener6_cookie;
	wrong_listener6.listener_cookie[1] = (uint32_t)(listener6_cookie >> 32);
	REQUIRE(ker_native_tcp_request_revoke(&wrong_listener6) == -ESTALE);
	REQUIRE(diag_find_family(AF_INET6, ntohs(local6.sin6_port), TCP_SYN_RECV,
		&request6_row) == 0);
	REQUIRE(ker_native_tcp_request_revoke(&fresh6) == 0);
	REQUIRE(diag_find_family(AF_INET6, ntohs(local6.sin6_port), TCP_SYN_RECV,
		&request6_row) == -ENOENT);
	accepted6 = accept4(listener6, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	REQUIRE(accepted6 < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
	REQUIRE(write_state(prefix, "IPV6_REBOUND_REVOKED") == 0);
	REQUIRE(wait_command(prefix, "V6_DONE2") == 0);
	close(listener6);
	return 0;
fail:
	if (accepted >= 0)
		close(accepted);
	if (accepted6 >= 0)
		close(accepted6);
	if (listener >= 0)
		close(listener);
	if (listener6 >= 0)
		close(listener6);
	return 1;
}
