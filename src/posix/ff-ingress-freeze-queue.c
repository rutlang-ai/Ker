#define _GNU_SOURCE
#include "ff-ingress-freeze-queue.h"
#include "ff-ingress-freeze-queue-parse.h"
#include "ff-ingress-freeze-state.h"
#include "lkl-overlay/arch/lkl/include/uapi/asm/ker_ff_admission_queue.h"

#include <arpa/inet.h>
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <limits.h>
#include <lkl/linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KER_FF_INGRESS_MAX_MESSAGE 4096U
#define KER_FF_INGRESS_COPY_RANGE 256U
#define KER_FF_INGRESS_MAX_HELD KER_FF_INGRESS_STATE_MAX_IDS
#define KER_FF_INGRESS_LEASE_NS UINT64_C(30000000000)
#define KER_FF_INGRESS_MISC_NAME "ker-ff-admission-queue"
#define KER_FF_INGRESS_MINOR_MAX ((1U << 20) - 1)
#define KER_NLA_ALIGN(length) (((length) + 3U) & ~3U)
#define KER_NLA_TYPE_MASK 0x3fffU

static atomic_uint control_path_sequence;


_Static_assert(sizeof(struct ker_ff_ingress_freeze_control) == 80,
	"private LKL queue-control ioctl ABI");

struct ker_nlattr {
	uint16_t nla_len;
	uint16_t nla_type;
};

struct ker_ff_ingress_freeze_queue {
	int fd;
	uint32_t sequence;
	uint32_t portid;
	uint32_t local_address;
	uint16_t local_port;
	struct ker_ff_ingress_freeze_state state;
	uint64_t lease;
	uint64_t deadline_ns;
	int released;
	bool accept_pending;
	uint32_t pending_packet_id;
	uint32_t pending_sequence;
	uint32_t pending_request_length;
	uint16_t pending_request_type;
	uint16_t pending_request_flags;
	uint64_t pending_ack_deadline_ns;
};


struct queue_message {
	struct lkl_nlmsghdr header;
	unsigned char payload[KER_FF_INGRESS_MAX_MESSAGE - sizeof(struct lkl_nlmsghdr)];
};

static size_t attr_put(unsigned char *buffer, size_t capacity, size_t offset,
		       uint16_t type, const void *data, size_t length)
{
	struct ker_nlattr attr;
	size_t aligned = KER_NLA_ALIGN(sizeof(attr) + length);

	if (offset > capacity || aligned > capacity - offset)
		return 0;
	attr.nla_type = type;
	attr.nla_len = (uint16_t)(sizeof(attr) + length);
	memcpy(buffer + offset, &attr, sizeof(attr));
	memcpy(buffer + offset + sizeof(attr), data, length);
	memset(buffer + offset + sizeof(attr) + length, 0,
	       aligned - sizeof(attr) - length);
	return offset + aligned;
}

static int receive_datagram(struct ker_ff_ingress_freeze_queue *queue,
			    unsigned char *buffer, size_t capacity,
			    struct lkl_sockaddr_nl *sender,
			    unsigned int *sender_length, unsigned int timeout_ms)
{
	struct lkl_pollfd pollfd = {.fd = queue->fd, .events = LKL_POLLIN};
	int address_length = sizeof(*sender);
	long result = lkl_sys_poll(&pollfd, 1, (int)timeout_ms);
	if (result < 0) return (int)result;
	if (!result) return 0;
	if (!(pollfd.revents & LKL_POLLIN)) return -EIO;
	*sender_length = sizeof(*sender);
	result = lkl_sys_recvfrom((unsigned int)queue->fd, buffer, capacity,
		LKL_MSG_TRUNC, (struct lkl_sockaddr *)sender,
		&address_length);
	if (result < 0) return (int)result;
	if ((size_t)result > capacity) return -EMSGSIZE;
	if (address_length < 0) return -EPROTO;
	*sender_length = (unsigned int)address_length;
	return (int)result;
}

static int wait_ack(struct ker_ff_ingress_freeze_queue *queue, uint32_t sequence,
		    uint16_t request_type, uint16_t request_flags,
		    uint32_t request_length, uint64_t deadline_ns)
{
	unsigned char reply[KER_FF_INGRESS_MAX_MESSAGE];
	struct timespec now;
	for (;;) {
		struct lkl_sockaddr_nl sender = {0};
		unsigned int sender_length = sizeof(sender);
	struct lkl_nlmsghdr *header;
	uint64_t current_ns;
	int remaining_ms;
	int result;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -errno;
		current_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
		if (current_ns >= deadline_ns) return -ETIMEDOUT;
		remaining_ms = (int)((deadline_ns - current_ns + 999999) / 1000000);
		result = receive_datagram(queue, reply, sizeof(reply), &sender,
			&sender_length, (unsigned int)remaining_ms);
		if (result <= 0) return result ? result : -ETIMEDOUT;
		if (sender_length != sizeof(sender) || sender.nl_family != LKL_AF_NETLINK ||
		    sender.nl_pid != 0 || sender.nl_groups || result < LKL_NLMSG_HDRLEN)
			return -EPROTO;
		header = (struct lkl_nlmsghdr *)reply;
		if (header->nlmsg_len != (uint32_t)result) return -EPROTO;
		if (header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) &&
		    header->nlmsg_seq == 0) {
			ker_ff_ingress_state_quarantine(&queue->state);
			return -EPROTO;
		}
		if (header->nlmsg_type != LKL_NLMSG_ERROR || header->nlmsg_pid != queue->portid ||
		    header->nlmsg_seq != sequence ||
		    header->nlmsg_len < (uint32_t)(LKL_NLMSG_HDRLEN + sizeof(struct lkl_nlmsgerr)))
			continue;
		struct lkl_nlmsgerr error;
		memcpy(&error, LKL_NLMSG_DATA(header), sizeof(error));
		if (error.msg.nlmsg_type != request_type || error.msg.nlmsg_seq != sequence ||
		    error.msg.nlmsg_flags != request_flags ||
		    error.msg.nlmsg_len != request_length ||
		    error.msg.nlmsg_pid != queue->portid || error.error > 0 ||
		    error.error < -4095)
			return -EPROTO;
		return error.error;
	}
}

static int send_config(struct ker_ff_ingress_freeze_queue *queue, uint8_t command,
		       const void *extra, size_t extra_length)
{
	struct queue_message message = {0};
	struct nfgenmsg nfgen = {
		.nfgen_family = AF_INET,
		.version = NFNETLINK_V0,
		.res_id = htons(KER_FF_INGRESS_FREEZE_QUEUE_NUMBER),
	};
	struct nfqnl_msg_config_cmd bind = {
		.command = command,
		.pf = htons(AF_INET),
	};
	struct lkl_sockaddr_nl kernel = {.nl_family = LKL_AF_NETLINK};
	size_t offset = sizeof(nfgen);
	long result;

	message.header.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
	message.header.nlmsg_flags = LKL_NLM_F_REQUEST | LKL_NLM_F_ACK;
	message.header.nlmsg_seq = ++queue->sequence;
	message.header.nlmsg_pid = queue->portid;
	memcpy(message.payload, &nfgen, sizeof(nfgen));
	if (command != NFQNL_CFG_CMD_NONE) {
		size_t next = attr_put(message.payload, sizeof(message.payload), offset,
				       NFQA_CFG_CMD, &bind, sizeof(bind));
		if (!next)
			return -E2BIG;
		offset = next;
	}
	if (extra_length) {
		if (offset > sizeof(message.payload) - extra_length)
			return -E2BIG;
		memcpy(message.payload + offset, extra, extra_length);
		offset += extra_length;
	}
	message.header.nlmsg_len = (uint32_t)(LKL_NLMSG_HDRLEN + offset);
	uint16_t request_type = message.header.nlmsg_type;
	result = lkl_sys_sendto((unsigned int)queue->fd, &message,
		message.header.nlmsg_len, 0, (struct lkl_sockaddr *)&kernel, sizeof(kernel));
	if (result < 0)
		return (int)result;
	if ((size_t)result != message.header.nlmsg_len)
		return -EIO;
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -errno;
	uint64_t deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
		now.tv_nsec + UINT64_C(250000000);
	return wait_ack(queue, queue->sequence, request_type,
		LKL_NLM_F_REQUEST | LKL_NLM_F_ACK, message.header.nlmsg_len,
		deadline_ns);
}

static int queue_control_fd(void)
{
	char buffer[4097];
	long fd = lkl_sys_open("/proc/misc", LKL_O_RDONLY | LKL_O_CLOEXEC, 0);
	long count;
	unsigned int minor = KER_FF_INGRESS_MINOR_MAX + 1;
	char *line;

	if (fd < 0)
		return (int)fd;
	count = lkl_sys_read((unsigned int)fd, buffer, sizeof(buffer) - 1);
	if (count < 0) {
		(void)lkl_sys_close((unsigned int)fd);
		return (int)count;
	}
	if (count == (long)sizeof(buffer) - 1) {
		(void)lkl_sys_close((unsigned int)fd);
		return -E2BIG;
	}
	if (lkl_sys_close((unsigned int)fd) < 0)
		return -EIO;
	buffer[count] = '\0';
	line = buffer;
	while (*line) {
		unsigned int candidate;
		char name[96];
		int consumed = 0;
		if (sscanf(line, "%u %95s%n", &candidate, name, &consumed) == 2 &&
		    !strcmp(name, KER_FF_INGRESS_MISC_NAME)) {
			if (minor != KER_FF_INGRESS_MINOR_MAX + 1)
				return -EPROTO;
			if (candidate > KER_FF_INGRESS_MINOR_MAX)
				return -ERANGE;
			minor = candidate;
		}
		char *newline = strchr(line, '\n');
		if (!newline)
			break;
		line = newline + 1;
	}
	if (minor == KER_FF_INGRESS_MINOR_MAX + 1)
		return -ENODEV;
	char path[80];
	unsigned int path_sequence = atomic_fetch_add(&control_path_sequence, 1) + 1;
	if (snprintf(path, sizeof(path), "/ker-ff-ingress-%ld-%u",
		     lkl_sys_getpid(), path_sequence) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	long result = lkl_sys_mknodat(LKL_AT_FDCWD, path,
		LKL_S_IFCHR | 0600, (minor & 0xffU) | (10U << 8) |
		((minor & ~0xffU) << 12));
	if (result < 0)
		return (int)result;
	int control = (int)lkl_sys_open(path, LKL_O_RDWR | LKL_O_CLOEXEC, 0);
	long removed = lkl_sys_unlinkat(LKL_AT_FDCWD, path, 0);
	if (control < 0)
		return control;
	if (removed < 0) {
		(void)lkl_sys_close((unsigned int)control);
		return (int)removed;
	}
	return control;
}

static int set_kernel_operation(struct ker_ff_ingress_freeze_queue *queue,
				uint32_t operation)
{
	struct ker_ff_ingress_freeze_control request = {
		.version = KER_FF_ADMISSION_QUEUE_VERSION,
		.operation = operation,
		.lease = queue->lease,
	};
	int fd = queue_control_fd();
	if (fd < 0) return fd;
	long result = lkl_sys_ioctl((unsigned int)fd, KER_FF_INGRESS_FREEZE_SET,
		(unsigned long)&request);
	long closed = lkl_sys_close((unsigned int)fd);
	if (result < 0) return (int)result;
	if (operation == KER_FF_INGRESS_FREEZE_DISARM) {
		queue->state.attempt_count = request.attempt_count;
		queue->state.expired_count = request.expired_count;
		queue->state.inventory_error_count = request.inventory_error_count;
	}
	return closed < 0 ? (int)closed : 0;
}

int ker_ff_ingress_freeze_queue_start_owned(int listener_native_fd,
				 uint32_t owner_mark, uint64_t listener_cookie,
				 struct ker_ff_ingress_freeze_queue **output,
				 int *arm_succeeded)
{
	struct ker_ff_ingress_freeze_queue *queue;
	struct lkl_sockaddr_nl local = {.nl_family = LKL_AF_NETLINK};
	struct ker_ff_ingress_freeze_control control = {
		.version = KER_FF_ADMISSION_QUEUE_VERSION,
		.operation = KER_FF_INGRESS_FREEZE_ARM,
		.listener_fd = listener_native_fd,
		.expected_mark = owner_mark,
		.expected_cookie = listener_cookie,
	};
	struct nfqnl_msg_config_params params = {
		.copy_range = htonl(KER_FF_INGRESS_COPY_RANGE),
		.copy_mode = NFQNL_COPY_PACKET,
	};
	unsigned char attributes[128];
	size_t offset = 0;
	uint32_t maxlen = htonl(KER_FF_INGRESS_MAX_HELD);
	uint32_t flags = 0, mask = htonl(NFQA_CFG_F_FAIL_OPEN);
	int fd, control_fd, result;
	long native;
	struct timespec start_time;

	if (!output || !arm_succeeded) return -EINVAL;
	*output = NULL;
	if (listener_native_fd < 0 || !owner_mark || owner_mark > INT32_MAX ||
	    !listener_cookie) return -EINVAL;
	*arm_succeeded = 0;
	if (clock_gettime(CLOCK_MONOTONIC, &start_time) != 0)
		return -errno;
	queue = calloc(1, sizeof(*queue));
	if (!queue)
		return -ENOMEM;
	native = lkl_sys_socket(LKL_AF_NETLINK, LKL_SOCK_RAW | LKL_O_CLOEXEC |
		LKL_O_NONBLOCK,
		LKL_NETLINK_NETFILTER);
	if (native < 0) { free(queue); return (int)native; }
	fd = (int)native;
	queue->fd = fd;
	result = (int)lkl_sys_bind((unsigned int)fd, (struct lkl_sockaddr *)&local, sizeof(local));
	if (result < 0)
		goto failure;
	int local_length = sizeof(local);
	result = (int)lkl_sys_getsockname((unsigned int)fd,
		(struct lkl_sockaddr *)&local, &local_length);
	if (result < 0 || local_length != sizeof(local) ||
	    local.nl_family != LKL_AF_NETLINK || !local.nl_pid) {
		result = result < 0 ? (int)result : -EPROTO;
		goto failure;
	}
	queue->portid = local.nl_pid;
	result = send_config(queue, NFQNL_CFG_CMD_BIND, NULL, 0);
	if (result < 0)
		goto failure;
	offset = attr_put(attributes, sizeof(attributes), offset, NFQA_CFG_PARAMS,
		&params, sizeof(params));
	offset = offset ? attr_put(attributes, sizeof(attributes), offset,
		NFQA_CFG_QUEUE_MAXLEN, &maxlen, sizeof(maxlen)) : 0;
	offset = offset ? attr_put(attributes, sizeof(attributes), offset,
		NFQA_CFG_FLAGS, &flags, sizeof(flags)) : 0;
	offset = offset ? attr_put(attributes, sizeof(attributes), offset,
		NFQA_CFG_MASK, &mask, sizeof(mask)) : 0;
	if (!offset) { result = -E2BIG; goto failure; }
	result = send_config(queue, NFQNL_CFG_CMD_NONE, attributes, offset);
	if (result < 0)
		goto failure;
	control_fd = queue_control_fd();
	if (control_fd < 0) { result = control_fd; goto failure; }
	result = (int)lkl_sys_ioctl((unsigned int)control_fd,
		KER_FF_INGRESS_FREEZE_SET, (unsigned long)&control);
	(void)lkl_sys_close((unsigned int)control_fd);
	if (result < 0)
		goto failure;
	*arm_succeeded = 1;
	queue->lease = control.lease;
	if (!queue->lease || !control.deadline_ns || !control.local_address ||
	    !control.local_port) { result = -EPROTO; goto failure; }
	queue->deadline_ns = (uint64_t)start_time.tv_sec * UINT64_C(1000000000) +
		start_time.tv_nsec + KER_FF_INGRESS_LEASE_NS;
	result = ker_ff_ingress_state_init(&queue->state, queue->lease,
		queue->deadline_ns);
	if (result) goto failure;
	queue->local_address = control.local_address;
	queue->local_port = control.local_port;
	*output = queue;
	return 0;

failure:
	/* On any post-ARM setup error, first confirm terminal quarantine while the
	 * exact queue handle and lease are still available. Preserve the handle for
	 * the broker controller if quarantine itself fails. */
	if (*arm_succeeded) {
		int quarantine = queue->lease ? set_kernel_operation(queue,
			KER_FF_INGRESS_FREEZE_QUARANTINE) : -EPROTO;
		if (quarantine < 0) {
			*output = queue;
			return quarantine;
		}
	}
	(void)lkl_sys_close((unsigned int)fd);
	free(queue);
	return result;
}

int ker_ff_ingress_freeze_queue_start(int listener_native_fd, uint32_t owner_mark,
				 uint64_t listener_cookie,
				 struct ker_ff_ingress_freeze_queue **output)
{
	if (!output) return -EINVAL;
	int arm_succeeded = 0;
	struct ker_ff_ingress_freeze_queue *queue = NULL;
	int status = ker_ff_ingress_freeze_queue_start_owned(listener_native_fd,
		owner_mark, listener_cookie, &queue, &arm_succeeded);
	if (status && queue) {
		/* Legacy private callers cannot retain a failed-start handle. Closing
		 * only drops notifications; the kernel gate remains fail closed. */
		(void)lkl_sys_close((unsigned int)queue->fd);
		free(queue);
		queue = NULL;
	}
	if (output) *output = status ? NULL : queue;
	return status;
}

uint64_t ker_ff_ingress_freeze_queue_lease(
				 const struct ker_ff_ingress_freeze_queue *queue)
{
	return queue ? queue->lease : 0;
}

uint64_t ker_ff_ingress_freeze_queue_deadline(
				 const struct ker_ff_ingress_freeze_queue *queue)
{
	return queue ? queue->deadline_ns : 0;
}

int ker_ff_ingress_freeze_queue_check(
	struct ker_ff_ingress_freeze_queue *queue)
{
	struct ker_ff_ingress_freeze_control request = {
		.version = KER_FF_ADMISSION_QUEUE_VERSION,
		.operation = KER_FF_INGRESS_FREEZE_CHECK,
	};
	if (!queue || queue->state.quarantined || queue->released) return -EINVAL;
	request.lease = queue->lease;
	int fd = queue_control_fd();
	if (fd < 0) return fd;
	long result = lkl_sys_ioctl((unsigned int)fd, KER_FF_INGRESS_FREEZE_SET,
		(unsigned long)&request);
	long closed = lkl_sys_close((unsigned int)fd);
	if (result < 0) return (int)result;
	return closed < 0 ? (int)closed : 0;
}

int ker_ff_ingress_freeze_queue_receive(struct ker_ff_ingress_freeze_queue *queue,
				   struct ker_ff_ingress_packet *packet,
				   unsigned int timeout_ms)
{
	unsigned char bytes[KER_FF_INGRESS_MAX_MESSAGE];
	struct lkl_sockaddr_nl sender = {0};
	unsigned int sender_length = sizeof(sender);
	struct ker_ff_ingress_packet parsed;
	int result;

	if (!queue || !packet || timeout_ms > 250 || queue->state.quarantined ||
	    queue->state.packet_count >= KER_FF_INGRESS_MAX_HELD ||
	    queue->state.drained)
		return -EINVAL;
	result = receive_datagram(queue, bytes, sizeof(bytes), &sender,
		&sender_length, timeout_ms);
	if (result <= 0) return result;
	queue->state.drained = false;
	if (sender_length != sizeof(sender) || sender.nl_family != LKL_AF_NETLINK ||
	    sender.nl_pid != 0 || sender.nl_groups) {
		ker_ff_ingress_state_quarantine(&queue->state);
		return -EPROTO;
	}
	result = ker_ff_ingress_parse_notification(bytes, (size_t)result,
		KER_FF_INGRESS_FREEZE_QUEUE_NUMBER, queue->local_address,
		queue->local_port, &parsed);
	if (result) {
		ker_ff_ingress_state_quarantine(&queue->state);
		return result;
	}
	parsed.lease = queue->lease;
	parsed.deadline_ns = queue->deadline_ns;
	result = ker_ff_ingress_state_record(&queue->state, parsed.id);
	if (result) return result;
	*packet = parsed;
	return 1;
}

static int queue_verdict(struct ker_ff_ingress_freeze_queue *queue,
			 uint64_t lease, uint64_t deadline_ns,
			 uint32_t packet_id, int accept,
			 int *sent_to_kernel, bool asynchronous)
{
	struct queue_message message = {0};
	struct nfgenmsg nfgen = {
		.nfgen_family = AF_INET,
		.version = NFNETLINK_V0,
		.res_id = htons(KER_FF_INGRESS_FREEZE_QUEUE_NUMBER),
	};
	struct nfqnl_msg_verdict_hdr verdict = {
		.verdict = htonl(accept ? NF_ACCEPT : NF_DROP),
		.id = htonl(packet_id),
	};
	struct lkl_sockaddr_nl kernel = {.nl_family = LKL_AF_NETLINK};
	size_t offset = sizeof(nfgen);
	long result;
	uint16_t request_type;
	uint16_t request_flags = LKL_NLM_F_REQUEST | LKL_NLM_F_ACK;
	uint64_t ack_deadline_ns;
	if (sent_to_kernel) *sent_to_kernel = 0;
	if (!queue || !sent_to_kernel || (accept != 0 && accept != 1) ||
	    queue->accept_pending)
		return -EINVAL;
	if (lease != queue->lease || deadline_ns != queue->deadline_ns)
		return -ESTALE;
	message.header.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
	message.header.nlmsg_flags = request_flags;
	message.header.nlmsg_seq = ++queue->sequence;
	message.header.nlmsg_pid = queue->portid;
	request_type = message.header.nlmsg_type;
	memcpy(message.payload, &nfgen, sizeof(nfgen));
	offset = attr_put(message.payload, sizeof(message.payload), offset,
		NFQA_VERDICT_HDR, &verdict, sizeof(verdict));
	if (!offset) return -E2BIG;
	message.header.nlmsg_len = (uint32_t)(LKL_NLMSG_HDRLEN + offset);
	if (accept) {
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -errno;
		uint64_t current_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
		if (current_ns >= deadline_ns)
			return -ETIMEDOUT;
		ack_deadline_ns = current_ns + UINT64_C(250000000);
		if (ack_deadline_ns > deadline_ns) ack_deadline_ns = deadline_ns;
	} else {
		ack_deadline_ns = deadline_ns;
	}
	result = lkl_sys_sendto((unsigned int)queue->fd, &message,
		message.header.nlmsg_len, 0, (struct lkl_sockaddr *)&kernel, sizeof(kernel));
	if (result < 0) return (int)result;
	*sent_to_kernel = 1;
	if ((size_t)result != message.header.nlmsg_len) {
		(void)ker_ff_ingress_state_finish_accept(&queue->state, packet_id,
			true, -EIO);
		return -EIO;
	}
	if (asynchronous) {
		queue->accept_pending = true;
		queue->pending_packet_id = packet_id;
		queue->pending_sequence = queue->sequence;
		queue->pending_request_length = message.header.nlmsg_len;
		queue->pending_request_type = request_type;
		queue->pending_request_flags = request_flags;
		queue->pending_ack_deadline_ns = ack_deadline_ns;
		return 0;
	}
	/* A complete send is irreversible/uncertain: the kernel may have already
	 * reinjected ACCEPT even if its later ACK cannot be observed. */
	result = wait_ack(queue, queue->sequence, request_type, request_flags,
		message.header.nlmsg_len, ack_deadline_ns);
	return ker_ff_ingress_state_finish_accept(&queue->state, packet_id,
		true, (int)result);
}

int ker_ff_ingress_freeze_queue_accept(struct ker_ff_ingress_freeze_queue *queue,
				   uint64_t lease, uint64_t deadline_ns,
				   uint32_t packet_id, int *sent_to_kernel)
{
	if (!queue) return -EINVAL;
	if (lease != queue->lease || deadline_ns != queue->deadline_ns)
		return -ESTALE;
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -errno;
	uint64_t now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
	int status = ker_ff_ingress_state_authorize_accept(&queue->state, lease,
		deadline_ns, packet_id, now_ns);
	if (status) return status;
	status = ker_ff_ingress_freeze_queue_check(queue);
	if (status) { ker_ff_ingress_state_quarantine(&queue->state); return status; }
	return queue_verdict(queue, lease, deadline_ns, packet_id, 1,
		sent_to_kernel, false);
}

int ker_ff_ingress_freeze_queue_accept_begin(
	struct ker_ff_ingress_freeze_queue *queue, uint64_t lease,
	uint64_t deadline_ns, uint32_t packet_id, int *sent_to_kernel)
{
	if (!queue || !sent_to_kernel) return -EINVAL;
	if (lease != queue->lease || deadline_ns != queue->deadline_ns) return -ESTALE;
	if (queue->accept_pending) return -EBUSY;
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -errno;
	uint64_t now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
	int status = ker_ff_ingress_state_authorize_accept(&queue->state, lease,
		deadline_ns, packet_id, now_ns);
	if (status) return status;
	status = ker_ff_ingress_freeze_queue_check(queue);
	if (status) { ker_ff_ingress_state_quarantine(&queue->state); return status; }
	return queue_verdict(queue, lease, deadline_ns, packet_id, 1,
		sent_to_kernel, true);
}

int ker_ff_ingress_freeze_queue_accept_poll(
	struct ker_ff_ingress_freeze_queue *queue)
{
	if (!queue || !queue->accept_pending) return -EINVAL;
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -errno;
	uint64_t now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
	if (now_ns >= queue->pending_ack_deadline_ns) {
		queue->accept_pending = false;
		(void)ker_ff_ingress_state_finish_accept(&queue->state,
			queue->pending_packet_id, true, -ETIMEDOUT);
		return -ETIMEDOUT;
	}
	unsigned char reply[KER_FF_INGRESS_MAX_MESSAGE];
	struct lkl_sockaddr_nl sender = {0};
	unsigned int sender_length = sizeof(sender);
	int result = receive_datagram(queue, reply, sizeof(reply), &sender,
		&sender_length, 0);
	if (result < 0) goto failure;
	if (!result) return 0;
	int ack_error = 0;
	int parsed = ker_ff_ingress_parse_verdict_ack(reply, (size_t)result,
		sender_length, sender.nl_family, sender.nl_pid, sender.nl_groups,
		queue->portid, queue->pending_sequence, queue->pending_request_type,
		queue->pending_request_flags, queue->pending_request_length, &ack_error);
	if (parsed < 0) { result = parsed; goto failure; }
	if (!parsed) return 0;
	queue->accept_pending = false;
	result = ker_ff_ingress_state_finish_accept(&queue->state,
		queue->pending_packet_id, true, ack_error);
	return result ? result : 1;

failure:
	queue->accept_pending = false;
	(void)ker_ff_ingress_state_finish_accept(&queue->state,
		queue->pending_packet_id, true, result);
	return result;
}


int ker_ff_ingress_freeze_queue_disarm(struct ker_ff_ingress_freeze_queue *queue)
{
	if (!queue || !queue->state.armed || queue->state.quarantined) return -EBUSY;
	int status = set_kernel_operation(queue, KER_FF_INGRESS_FREEZE_DISARM);
	if (!status)
		status = ker_ff_ingress_state_disarm(&queue->state,
			queue->state.attempt_count, queue->state.expired_count,
			queue->state.inventory_error_count);
	return status;
}

int ker_ff_ingress_freeze_queue_counts(
	const struct ker_ff_ingress_freeze_queue *queue, uint64_t *attempts,
	uint64_t *expired, uint64_t *inventory_errors)
{
	if (!queue || !attempts || !expired || !inventory_errors) return -EINVAL;
	if (queue->state.armed) return -EBUSY;
	*attempts = queue->state.attempt_count;
	*expired = queue->state.expired_count;
	*inventory_errors = queue->state.inventory_error_count;
	return 0;
}

int ker_ff_ingress_freeze_queue_drain(struct ker_ff_ingress_freeze_queue *queue,
				      struct ker_ff_ingress_packet *packet)
{
	if (!queue || !packet || queue->state.armed || queue->state.quarantined) return -EINVAL;
	int result;
	if (queue->state.packet_count < KER_FF_INGRESS_MAX_HELD) {
		result = ker_ff_ingress_freeze_queue_receive(queue, packet, 0);
		if (result != 0) return result;
	} else {
		unsigned char extra[KER_FF_INGRESS_MAX_MESSAGE];
		struct lkl_sockaddr_nl sender = {0};
		unsigned int sender_length = sizeof(sender);
		result = receive_datagram(queue, extra, sizeof(extra), &sender,
			&sender_length, 0);
		if (result < 0) { ker_ff_ingress_state_quarantine(&queue->state); return result; }
		if (result > 0) { ker_ff_ingress_state_quarantine(&queue->state); return -EOVERFLOW; }
	}
	return ker_ff_ingress_state_prove_drained(&queue->state);
}

int ker_ff_ingress_freeze_queue_quarantine(
	struct ker_ff_ingress_freeze_queue **queue_pointer)
{
	if (!queue_pointer || !*queue_pointer) return -EINVAL;
	struct ker_ff_ingress_freeze_queue *queue = *queue_pointer;
	if (queue->fd < 0) return -EINVAL;
	int status = set_kernel_operation(queue,
		KER_FF_INGRESS_FREEZE_QUARANTINE);
	if (status < 0) return status;
	ker_ff_ingress_state_quarantine(&queue->state);
	/* Netlink release flushes q88's queued original skbs. Keep the LKL gate and
	 * lease allocated: future matches continue to fail closed at NFQUEUE. */
	status = (int)lkl_sys_close((unsigned int)queue->fd);
	if (status < 0) return status;
	queue->fd = -1;
	free(queue);
	*queue_pointer = NULL;
	return status;
}

int ker_ff_ingress_freeze_queue_close(struct ker_ff_ingress_freeze_queue *queue)
{
	int status = 0;
	if (!queue) return -EINVAL;
	if (!ker_ff_ingress_state_can_close(&queue->state)) return -EBUSY;
	if (!queue->released) {
		status = set_kernel_operation(queue, KER_FF_INGRESS_FREEZE_RELEASE);
		if (status) return status;
		queue->released = 1;
	}
	if (queue->fd >= 0) {
		status = (int)lkl_sys_close((unsigned int)queue->fd);
		if (status < 0) return status;
	}
	if (status < 0) return status;
	free(queue);
	return status;
}
