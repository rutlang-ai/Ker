#define _GNU_SOURCE
#include "ff-admission-request-identity.h"
#include "fd-table.h"

#include <errno.h>
#include <fcntl.h>
#include <lkl.h>
#include <lkl/linux/capability.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>

#define IDENTITY_NETLINK_PROTOCOL NETLINK_SOCK_DIAG
#define IDENTITY_QUERY_MAX_BYTES (1024u * 1024u)
#define IDENTITY_QUERY_MAX_DATAGRAMS 256u
#define IDENTITY_QUERY_MAX_ROWS 4096u
#define IDENTITY_QUERY_MAX_DURATION_NS UINT64_C(5000000000)
#define IDENTITY_RECV_CAPACITY 32768u
#define IDENTITY_POLL_MS 0
#define IDENTITY_TCP_INFO_SIZE 248u

struct identity_query {
	struct nlmsghdr header;
	struct inet_diag_req_v2 request;
	struct nlattr mark_attribute;
	struct inet_diag_bc_op mark_instruction;
	struct inet_diag_markcond mark_condition;
} __attribute__((packed));

struct ker_ff_admission_request_identity {
	struct ker_fd *listener_entry;
	int listener_app_fd;
	int listener_native_fd;
	int netlink_fd;
	uint32_t mark;
	uint32_t local_port_id;
	uint32_t sequence;
	uint64_t listener_cookie;
	uint64_t started_ns;
	uint64_t bytes;
	unsigned datagrams;
	unsigned rows;
	bool query_pending;
	bool complete;
	bool terminal;
	bool found_request;
	bool found_full_socket;
	struct ker_ff_admission_ipv4_tuple tuple;
	struct ker_tcp_request_revoke_request candidate;
	struct identity_query last_query;
};

static atomic_uint identity_sequence = 1;

static uint64_t monotonic_ns(void)
{
	struct timespec now = {0};
	if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
		(uint64_t)now.tv_nsec;
}

static void close_netlink(struct ker_ff_admission_request_identity *identity)
{
	if (identity->netlink_fd >= 0) {
		(void)lkl_sys_close((unsigned int)identity->netlink_fd);
		identity->netlink_fd = -1;
	}
	identity->query_pending = false;
}

static int terminal_error(struct ker_ff_admission_request_identity *identity,
	int error)
{
	identity->terminal = true;
	close_netlink(identity);
	return error;
}

static int check_deadline(const struct ker_ff_admission_request_identity *identity)
{
	uint64_t now = monotonic_ns();
	if (!now || now < identity->started_ns ||
	    now - identity->started_ns >= IDENTITY_QUERY_MAX_DURATION_NS)
		return -ETIMEDOUT;
	return 0;
}

static int require_net_admin(void)
{
	struct __lkl__user_cap_header_struct header = {
		.version = _LKL_LINUX_CAPABILITY_VERSION_3};
	struct __lkl__user_cap_data_struct data[2] = {{0}};
	long result = lkl_sys_capget(&header, data);
	if (result < 0)
		return (int)result;
	unsigned word = LKL_CAP_NET_ADMIN / 32;
	uint32_t bit = UINT32_C(1) << (LKL_CAP_NET_ADMIN % 32);
	return (data[word].effective & bit) ? 0 : -EPERM;
}

static int get_int_option(int fd, int option, int *value)
{
	int length = sizeof(*value);
	long result = lkl_sys_getsockopt((unsigned int)fd, SOL_SOCKET, option,
		(char *)value, &length);
	if (result < 0)
		return (int)result;
	return length == (int)sizeof(*value) ? 0 : -EPROTO;
}

static int validate_listener_fd_entry(
	const struct ker_ff_admission_request_identity *identity)
{
	struct ker_fd *current = ker_fd_get(identity->listener_app_fd);
	if (!current)
		return -ESTALE;
	bool same = current == identity->listener_entry &&
		current->kind == KER_FD_SOCKET &&
		current->native == identity->listener_native_fd;
	ker_fd_put(current);
	return same ? 0 : -ESTALE;
}

static int read_listener_identity(
	const struct ker_ff_admission_request_identity *identity,
	uint64_t *cookie_out)
{
	struct sockaddr_in bound = {0};
	int length = sizeof(bound);
	int domain = 0, type = 0, accepting = 0, mark = 0, protocol = 0;
	uint64_t cookie = 0;
	int cookie_length = sizeof(cookie);
	long result;
	int status;

	status = validate_listener_fd_entry(identity);
	if (status)
		return status;
	status = get_int_option(identity->listener_native_fd, SO_DOMAIN, &domain);
	if (status)
		return status;
	status = get_int_option(identity->listener_native_fd, SO_TYPE, &type);
	if (status)
		return status;
	status = get_int_option(identity->listener_native_fd, SO_PROTOCOL, &protocol);
	if (status)
		return status;
	status = get_int_option(identity->listener_native_fd, SO_ACCEPTCONN, &accepting);
	if (status)
		return status;
	status = get_int_option(identity->listener_native_fd, SO_MARK, &mark);
	if (status)
		return status;
	if (domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP ||
	    accepting != 1 ||
	    (uint32_t)mark != identity->mark)
		return -ESTALE;
	result = lkl_sys_getsockopt((unsigned int)identity->listener_native_fd, SOL_SOCKET,
		SO_COOKIE, (char *)&cookie, &cookie_length);
	if (result < 0)
		return (int)result;
	if (cookie_length != (int)sizeof(cookie) ||
	    ((uint32_t)cookie == INET_DIAG_NOCOOKIE &&
	     (uint32_t)(cookie >> 32) == INET_DIAG_NOCOOKIE))
		return -EPROTO;
	result = lkl_sys_getsockname((unsigned int)identity->listener_native_fd,
		(struct lkl_sockaddr *)&bound, &length);
	if (result < 0)
		return (int)result;
	if (length != (int)sizeof(bound) || bound.sin_family != AF_INET ||
	    !bound.sin_port || bound.sin_port != identity->tuple.local.sin_port)
		return -ESTALE;
	if ((bound.sin_addr.s_addr != htonl(INADDR_ANY) &&
	     bound.sin_addr.s_addr != identity->tuple.local.sin_addr.s_addr) ||
	    identity->tuple.local.sin_addr.s_addr == htonl(INADDR_ANY))
		return -ESTALE;
	status = validate_listener_fd_entry(identity);
	if (status)
		return status;
	if (cookie_out)
		*cookie_out = cookie;
	return 0;
}

static int validate_tuple(const struct ker_ff_admission_ipv4_tuple *tuple)
{
	if (!tuple || tuple->local.sin_family != AF_INET ||
	    tuple->remote.sin_family != AF_INET || !tuple->local.sin_port ||
	    !tuple->remote.sin_port ||
	    tuple->local.sin_addr.s_addr == htonl(INADDR_ANY) ||
	    tuple->remote.sin_addr.s_addr == htonl(INADDR_ANY))
		return -EINVAL;
	return 0;
}

static int start_query(struct ker_ff_admission_request_identity *identity)
{
	struct identity_query query = {0};
	struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
	uint32_t sequence = atomic_fetch_add_explicit(&identity_sequence, 1,
		memory_order_relaxed);
	if (!sequence)
		sequence = atomic_fetch_add_explicit(&identity_sequence, 1,
			memory_order_relaxed);
	query.header.nlmsg_len = sizeof(query);
	query.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	query.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	query.header.nlmsg_seq = sequence;
	query.request.sdiag_family = AF_INET;
	query.request.sdiag_protocol = IPPROTO_TCP;
	query.request.idiag_ext = 1u << (INET_DIAG_INFO - 1);
	query.request.idiag_states = UINT32_C(1) << TCP_SYN_RECV;
	query.request.id.idiag_sport = identity->tuple.local.sin_port;
	query.request.id.idiag_dport = identity->tuple.remote.sin_port;
	query.request.id.idiag_src[0] = identity->tuple.local.sin_addr.s_addr;
	query.request.id.idiag_dst[0] = identity->tuple.remote.sin_addr.s_addr;
	query.request.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
	query.request.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
	query.mark_attribute.nla_len = sizeof(query.mark_attribute) +
		sizeof(query.mark_instruction) + sizeof(query.mark_condition);
	query.mark_attribute.nla_type = INET_DIAG_REQ_BYTECODE;
	query.mark_instruction.code = INET_DIAG_BC_MARK_COND;
	query.mark_instruction.yes = sizeof(query.mark_instruction) +
		sizeof(query.mark_condition);
	query.mark_instruction.no = query.mark_attribute.nla_len;
	query.mark_condition.mark = identity->mark;
	query.mark_condition.mask = UINT32_MAX;
	if (query.header.nlmsg_len != sizeof(query) ||
	    query.mark_attribute.nla_len != sizeof(query) -
							   sizeof(query.header) -
							   sizeof(query.request))
		return -EPROTO;
	long sent = lkl_sys_sendto((unsigned int)identity->netlink_fd, &query,
		sizeof(query), 0, (struct lkl_sockaddr *)&kernel, sizeof(kernel));
	if (sent < 0)
		return (int)sent;
	if ((size_t)sent != sizeof(query))
		return -EIO;
	struct sockaddr_nl local = {0};
	int local_length = sizeof(local);
	long result = lkl_sys_getsockname((unsigned int)identity->netlink_fd,
		(struct lkl_sockaddr *)&local, &local_length);
	if (result < 0)
		return (int)result;
	if (local_length != (int)sizeof(local) || local.nl_family != AF_NETLINK ||
	    !local.nl_pid)
		return -EPROTO;
	identity->local_port_id = local.nl_pid;
	identity->sequence = sequence;
	identity->found_request = false;
	identity->found_full_socket = false;
	identity->last_query = query;
	identity->query_pending = true;
	return 0;
}

static bool row_matches_tuple(const struct inet_diag_msg *row,
	const struct ker_ff_admission_ipv4_tuple *tuple)
{
	if (row->idiag_family != AF_INET ||
	    row->id.idiag_sport != tuple->local.sin_port ||
	    row->id.idiag_dport != tuple->remote.sin_port ||
	    row->id.idiag_src[0] != tuple->local.sin_addr.s_addr ||
	    row->id.idiag_dst[0] != tuple->remote.sin_addr.s_addr)
		return false;
	return !row->id.idiag_src[1] && !row->id.idiag_src[2] &&
		!row->id.idiag_src[3] && !row->id.idiag_dst[1] &&
		!row->id.idiag_dst[2] && !row->id.idiag_dst[3];
}

static int parse_row(struct ker_ff_admission_request_identity *identity,
	const unsigned char *payload, size_t length)
{
	if (length < sizeof(struct inet_diag_msg))
		return -EPROTO;
	struct inet_diag_msg row;
	memcpy(&row, payload, sizeof(row));
	if (row.idiag_family != AF_INET || row.idiag_state != TCP_SYN_RECV)
		return -EPROTO;
	if (++identity->rows > IDENTITY_QUERY_MAX_ROWS)
		return -E2BIG;
	bool have_mark = false, have_info = false;
	const unsigned char *cursor = payload + sizeof(row);
	size_t remain = length - sizeof(row);
	while (remain) {
		if (remain < sizeof(struct nlattr))
			return -EPROTO;
		struct nlattr attribute;
		memcpy(&attribute, cursor, sizeof(attribute));
		if (attribute.nla_len < sizeof(attribute) || attribute.nla_len > remain)
			return -EPROTO;
		uint16_t type = attribute.nla_type & NLA_TYPE_MASK;
		uint16_t flags = attribute.nla_type & (NLA_F_NESTED | NLA_F_NET_BYTEORDER);
		size_t value_length = attribute.nla_len - sizeof(attribute);
		if (flags == (NLA_F_NESTED | NLA_F_NET_BYTEORDER))
			return -EPROTO;
		if (type == INET_DIAG_MARK) {
			uint32_t mark;
			if (flags || have_mark || value_length != sizeof(mark))
				return -EPROTO;
			memcpy(&mark, cursor + sizeof(attribute), sizeof(mark));
			if (mark != identity->mark)
				return -ESTALE;
			have_mark = true;
		} else if (type == INET_DIAG_INFO) {
			if (flags || have_info || value_length < IDENTITY_TCP_INFO_SIZE)
				return -EPROTO;
			have_info = true;
		}
		size_t aligned = NLA_ALIGN(attribute.nla_len);
		if (aligned > remain)
			return -EPROTO;
		cursor += aligned;
		remain -= aligned;
	}
	if (!have_mark)
		return -EPROTO;
	if (!row_matches_tuple(&row, &identity->tuple))
		return 0;
	if (have_info) {
		identity->found_full_socket = true;
		return 0;
	}
	if ((row.id.idiag_cookie[0] == INET_DIAG_NOCOOKIE &&
	     row.id.idiag_cookie[1] == INET_DIAG_NOCOOKIE) ||
	    identity->found_request)
		return identity->found_request ? -EEXIST : -EPROTO;
	struct ker_tcp_request_revoke_request candidate = {0};
	candidate.version = KER_TCP_REQUEST_REVOKE_VERSION;
	candidate.mark = identity->mark;
	candidate.family = AF_INET;
	candidate.local_port = row.id.idiag_sport;
	candidate.remote_port = row.id.idiag_dport;
	candidate.ifindex = row.id.idiag_if;
	memcpy(candidate.local_address, row.id.idiag_src, sizeof(candidate.local_address));
	memcpy(candidate.remote_address, row.id.idiag_dst, sizeof(candidate.remote_address));
	memcpy(candidate.request_cookie, row.id.idiag_cookie,
		sizeof(candidate.request_cookie));
	candidate.listener_cookie[0] = (uint32_t)identity->listener_cookie;
	candidate.listener_cookie[1] = (uint32_t)(identity->listener_cookie >> 32);
	identity->candidate = candidate;
	identity->found_request = true;
	return 0;
}

static int parse_datagram(struct ker_ff_admission_request_identity *identity,
	const unsigned char *bytes, size_t length, bool *complete)
{
	const unsigned char *cursor = bytes;
	size_t remain = length;
	*complete = false;
	while (remain) {
		if (remain < sizeof(struct nlmsghdr))
			return -EPROTO;
		struct nlmsghdr header;
		memcpy(&header, cursor, sizeof(header));
		size_t aligned = NLMSG_ALIGN(header.nlmsg_len);
		if (header.nlmsg_len < sizeof(header) || header.nlmsg_len > remain ||
		    aligned > remain || header.nlmsg_seq != identity->sequence ||
		    header.nlmsg_pid != identity->local_port_id ||
		    (header.nlmsg_flags & NLM_F_DUMP_INTR))
			return -EPROTO;
		const unsigned char *payload = cursor + sizeof(header);
		size_t payload_length = header.nlmsg_len - sizeof(header);
		if (header.nlmsg_type == NLMSG_ERROR) {
			if (payload_length < sizeof(struct nlmsgerr) || aligned != remain ||
			    (header.nlmsg_flags & ~NLM_F_CAPPED))
				return -EPROTO;
			struct nlmsgerr error;
			memcpy(&error, payload, sizeof(error));
			struct identity_query expected = identity->last_query;
			if (error.msg.nlmsg_len != expected.header.nlmsg_len ||
			    error.msg.nlmsg_type != expected.header.nlmsg_type ||
			    error.msg.nlmsg_flags != expected.header.nlmsg_flags ||
			    error.msg.nlmsg_seq != expected.header.nlmsg_seq ||
			    error.msg.nlmsg_pid != expected.header.nlmsg_pid ||
			    error.error >= 0 || error.error < -4095)
				return -EPROTO;
			size_t echoed = (header.nlmsg_flags & NLM_F_CAPPED) ? 0 :
				sizeof(expected) - sizeof(expected.header);
			if (payload_length != sizeof(error) + echoed ||
			    (echoed && memcmp(payload + sizeof(error),
				(unsigned char *)&expected + sizeof(expected.header), echoed)))
				return -EPROTO;
			return error.error;
		}
		if (header.nlmsg_type == NLMSG_DONE) {
			if (header.nlmsg_flags != NLM_F_MULTI ||
			    payload_length != sizeof(int32_t) || aligned != remain)
				return -EPROTO;
			int32_t status;
			memcpy(&status, payload, sizeof(status));
			if (status > 0 || status < -4095)
				return -EPROTO;
			if (status)
				return status;
			*complete = true;
			return 0;
		}
		if (header.nlmsg_type != SOCK_DIAG_BY_FAMILY ||
		    header.nlmsg_flags != NLM_F_MULTI)
			return -EPROTO;
		int result = parse_row(identity, payload, payload_length);
		if (result)
			return result;
		cursor += aligned;
		remain -= aligned;
	}
	return 0;
}

#ifdef KER_FF_ADMISSION_REQUEST_IDENTITY_TESTING
int ker_ff_admission_request_identity_test_parse(
	uint32_t mark, const struct ker_ff_admission_ipv4_tuple *tuple,
	uint64_t listener_cookie, uint32_t sequence, uint32_t local_port_id,
	const void *bytes, size_t length,
	struct ker_tcp_request_revoke_request *request, bool *complete)
{
	if (!tuple || !bytes || !request || !complete || !mark || !sequence ||
	    !local_port_id)
		return -EINVAL;
	struct ker_ff_admission_request_identity identity = {
		.mark = mark, .local_port_id = local_port_id, .sequence = sequence,
		.listener_cookie = listener_cookie, .tuple = *tuple};
	int result = parse_datagram(&identity, bytes, length, complete);
	if (result || !*complete)
		return result;
	if (identity.found_full_socket)
		return -ESTALE;
	if (!identity.found_request)
		return 0;
	*request = identity.candidate;
	return 1;
}
#endif

int ker_ff_admission_request_identity_begin(int listener_fd,
	const struct ker_ff_admission_ipv4_tuple *tuple, uint32_t expected_mark,
	struct ker_ff_admission_request_identity **output)
{
	if (!output)
		return -EINVAL;
	*output = NULL;
	if (listener_fd < 0 || !expected_mark)
		return -EINVAL;
	int status = validate_tuple(tuple);
	if (status)
		return status;
	struct ker_ff_admission_request_identity *identity = calloc(1,
		sizeof(*identity));
	if (!identity)
		return -ENOMEM;
	identity->listener_app_fd = listener_fd;
	identity->listener_entry = ker_fd_get(listener_fd);
	if (!identity->listener_entry) {
		int error = syscall(SYS_fcntl, listener_fd, F_GETFD) >= 0 ?
			-EOPNOTSUPP : -EBADF;
		free(identity);
		return error;
	}
	if (identity->listener_entry->kind != KER_FD_SOCKET) {
		ker_fd_put(identity->listener_entry);
		free(identity);
		return -EOPNOTSUPP;
	}
	identity->listener_native_fd = identity->listener_entry->native;
	identity->netlink_fd = -1;
	identity->mark = expected_mark;
	identity->tuple = *tuple;
	identity->started_ns = monotonic_ns();
	if (!identity->started_ns) {
		free(identity);
		return -EIO;
	}
	status = require_net_admin();
	if (status)
		goto fail;
	status = read_listener_identity(identity, &identity->listener_cookie);
	if (status)
		goto fail;
	identity->netlink_fd = (int)lkl_sys_socket(AF_NETLINK,
		SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
		IDENTITY_NETLINK_PROTOCOL);
	if (identity->netlink_fd < 0) {
		status = identity->netlink_fd;
		identity->netlink_fd = -1;
		goto fail;
	}
	int receive_buffer = 65536;
	long result = lkl_sys_setsockopt((unsigned int)identity->netlink_fd,
		SOL_SOCKET, SO_RCVBUF, (char *)&receive_buffer, sizeof(receive_buffer));
	if (result < 0) {
		status = (int)result;
		goto fail;
	}
	status = start_query(identity);
	if (status)
		goto fail;
	*output = identity;
	return 0;
fail:
	close_netlink(identity);
	ker_fd_put(identity->listener_entry);
	free(identity);
	return status;
}

int ker_ff_admission_request_identity_step(
	struct ker_ff_admission_request_identity *identity,
	const atomic_bool *cancel,
	struct ker_tcp_request_revoke_request *request)
{
	if (!identity || !cancel || !request || identity->terminal ||
	    identity->complete || identity->netlink_fd < 0)
		return -EINVAL;
	if (atomic_load_explicit(cancel, memory_order_acquire))
		return terminal_error(identity, -ECANCELED);
	int status = check_deadline(identity);
	if (status)
		return terminal_error(identity, status);
	if (!identity->query_pending) {
		uint64_t current_cookie = 0;
		status = read_listener_identity(identity, &current_cookie);
		if (status)
			return terminal_error(identity, status);
		if (current_cookie != identity->listener_cookie)
			return terminal_error(identity, -ESTALE);
		status = start_query(identity);
		if (status)
			return terminal_error(identity, status);
	}
	struct lkl_pollfd pollfd = {
		.fd = identity->netlink_fd, .events = LKL_POLLIN};
	long ready = lkl_sys_poll(&pollfd, 1, IDENTITY_POLL_MS);
	if (ready < 0)
		return terminal_error(identity, (int)ready);
	if (!ready)
		return 0;
	if (pollfd.revents & (LKL_POLLERR | LKL_POLLHUP | LKL_POLLNVAL))
		return terminal_error(identity, -EIO);
	if (!(pollfd.revents & LKL_POLLIN))
		return 0;
	unsigned char bytes[IDENTITY_RECV_CAPACITY];
	struct sockaddr_nl sender = {0};
	int sender_length = sizeof(sender);
	long received = lkl_sys_recvfrom((unsigned int)identity->netlink_fd, bytes,
		sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC,
		(struct lkl_sockaddr *)&sender, &sender_length);
	if (received == -EAGAIN || received == -EWOULDBLOCK)
		return 0;
	if (received < 0)
		return terminal_error(identity, (int)received);
	if (!received || (unsigned long)received > sizeof(bytes) ||
	    sender_length != (int)sizeof(sender) || sender.nl_family != AF_NETLINK ||
	    sender.nl_pid != 0 || sender.nl_groups != 0)
		return terminal_error(identity, -EPROTO);
	if (identity->datagrams >= IDENTITY_QUERY_MAX_DATAGRAMS ||
	    (uint64_t)received > IDENTITY_QUERY_MAX_BYTES - identity->bytes)
		return terminal_error(identity, -E2BIG);
	++identity->datagrams;
	identity->bytes += (uint64_t)received;
	bool complete = false;
	status = parse_datagram(identity, bytes, (size_t)received, &complete);
	if (status)
		return terminal_error(identity, status);
	status = check_deadline(identity);
	if (status)
		return terminal_error(identity, status);
	if (!complete)
		return 0;
	identity->query_pending = false;
	uint64_t current_cookie = 0;
	status = read_listener_identity(identity, &current_cookie);
	if (status)
		return terminal_error(identity, status);
	if (current_cookie != identity->listener_cookie)
		return terminal_error(identity, -ESTALE);
	if (identity->found_full_socket)
		return terminal_error(identity, -ESTALE);
	if (!identity->found_request)
		return 0;
	*request = identity->candidate;
	identity->complete = true;
	close_netlink(identity);
	return 1;
}

int ker_ff_admission_request_identity_revalidate(
	struct ker_ff_admission_request_identity *identity)
{
	if (!identity || !identity->complete)
		return -EINVAL;
	uint64_t current_cookie = 0;
	int status = read_listener_identity(identity, &current_cookie);
	if (status)
		return status;
	return current_cookie == identity->listener_cookie ? 0 : -ESTALE;
}

void ker_ff_admission_request_identity_close(
	struct ker_ff_admission_request_identity *identity)
{
	if (!identity)
		return;
	close_netlink(identity);
	ker_fd_put(identity->listener_entry);
	free(identity);
}
