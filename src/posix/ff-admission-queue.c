#define _GNU_SOURCE
#include "ff-admission-queue.h"
#include "lkl-overlay/arch/lkl/include/uapi/asm/ker_ff_admission_queue.h"

#include <arpa/inet.h>
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <lkl/linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KER_FF_QUEUE_MAX_MESSAGE 4096U
#define KER_FF_QUEUE_COPY_RANGE 256U
#define KER_FF_QUEUE_MISC_NAME "ker-ff-admission-queue"
#define KER_FF_QUEUE_MINOR_MAX ((1U << 20) - 1)
#define KER_NLA_ALIGN(length) (((length) + 3U) & ~3U)
#define KER_NLA_TYPE_MASK 0x3fffU

_Static_assert(sizeof(struct ker_ff_admission_queue_control) == 32,
	"private LKL queue-control ioctl ABI");

struct ker_nlattr {
	uint16_t nla_len;
	uint16_t nla_type;
};

struct ker_ff_admission_queue {
	int fd;
	uint32_t sequence;
	uint32_t portid;
	uint32_t mark;
	uint32_t pending_id;
	uint64_t lease;
	int pending;
	int deferred_valid;
	size_t deferred_length;
	struct lkl_sockaddr_nl deferred_sender;
	unsigned char deferred[KER_FF_QUEUE_MAX_MESSAGE];
};


struct queue_message {
	struct lkl_nlmsghdr header;
	unsigned char payload[KER_FF_QUEUE_MAX_MESSAGE - sizeof(struct lkl_nlmsghdr)];
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

static int receive_datagram(struct ker_ff_admission_queue *queue,
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

static int wait_ack(struct ker_ff_admission_queue *queue, uint32_t sequence,
		    uint16_t request_type, uint16_t request_flags,
		    uint32_t request_length, uint64_t deadline_ns)
{
	unsigned char reply[KER_FF_QUEUE_MAX_MESSAGE];
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
			if (queue->deferred_valid || (size_t)result > sizeof(queue->deferred))
				return -ENOBUFS;
			memcpy(queue->deferred, reply, (size_t)result);
			queue->deferred_length = (size_t)result;
			queue->deferred_sender = sender;
			queue->deferred_valid = 1;
			continue;
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

static int send_config(struct ker_ff_admission_queue *queue, uint8_t command,
		       const void *extra, size_t extra_length)
{
	struct queue_message message = {0};
	struct nfgenmsg nfgen = {
		.nfgen_family = AF_INET,
		.version = NFNETLINK_V0,
		.res_id = htons(KER_FF_ADMISSION_QUEUE_NUMBER),
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
	unsigned int minor = KER_FF_QUEUE_MINOR_MAX + 1;
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
		    !strcmp(name, KER_FF_QUEUE_MISC_NAME)) {
			if (minor != KER_FF_QUEUE_MINOR_MAX + 1)
				return -EPROTO;
			if (candidate > KER_FF_QUEUE_MINOR_MAX)
				return -ERANGE;
			minor = candidate;
		}
		char *newline = strchr(line, '\n');
		if (!newline)
			break;
		line = newline + 1;
	}
	if (minor == KER_FF_QUEUE_MINOR_MAX + 1)
		return -ENODEV;
	char path[80];
	if (snprintf(path, sizeof(path), "/ker-ff-admission-%ld", lkl_sys_getpid()) >=
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

static int set_kernel_mark(uint32_t mark, int enabled, uint64_t *lease)
{
	struct ker_ff_admission_queue_control request = {
		.version = KER_FF_ADMISSION_QUEUE_VERSION,
		.mark = enabled ? mark : 0,
		.enabled = enabled != 0,
		.expected_mark = enabled ? 0 : mark,
		.lease = enabled ? 0 : (lease ? *lease : 0),
	};
	int fd = queue_control_fd();
	if (fd < 0)
		return fd;
	long result = lkl_sys_ioctl((unsigned int)fd, KER_FF_ADMISSION_QUEUE_SET,
		(unsigned long)&request);
	long closed = lkl_sys_close((unsigned int)fd);
	if (result < 0)
		return (int)result;
	if (enabled && lease) *lease = request.lease;
	return closed < 0 ? (int)closed : 0;
}

int ker_ff_admission_queue_start(uint32_t owner_mark,
				 struct ker_ff_admission_queue **output)
{
	struct ker_ff_admission_queue *queue;
	struct lkl_sockaddr_nl local = {.nl_family = LKL_AF_NETLINK};
	struct ker_ff_admission_queue_control control = {
		.version = KER_FF_ADMISSION_QUEUE_VERSION,
		.mark = owner_mark,
		.enabled = 1,
	};
	struct nfqnl_msg_config_params params = {
		.copy_range = htonl(KER_FF_QUEUE_COPY_RANGE),
		.copy_mode = NFQNL_COPY_PACKET,
	};
	unsigned char attributes[128];
	size_t offset = 0;
	uint32_t maxlen = htonl(1);
	uint32_t flags = 0, mask = htonl(NFQA_CFG_F_FAIL_OPEN);
	int fd, control_fd, result;
	long native;

	if (!output || !owner_mark || owner_mark > INT32_MAX)
		return -EINVAL;
	*output = NULL;
	queue = calloc(1, sizeof(*queue));
	if (!queue)
		return -ENOMEM;
	native = lkl_sys_socket(LKL_AF_NETLINK, LKL_SOCK_RAW | LKL_O_CLOEXEC |
		LKL_O_NONBLOCK,
		LKL_NETLINK_NETFILTER);
	if (native < 0) { free(queue); return (int)native; }
	fd = (int)native;
	queue->fd = fd;
	queue->mark = owner_mark;
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
		KER_FF_ADMISSION_QUEUE_SET, (unsigned long)&control);
	(void)lkl_sys_close((unsigned int)control_fd);
	if (result < 0)
		goto failure;
	queue->lease = control.lease;
	if (!queue->lease) { result = -EPROTO; goto failure; }
	*output = queue;
	return 0;

failure:
	/* Never disable the kernel mark gate here: if it was already armed,
	 * absence of a queue consumer must continue to drop marked SYNACKs. */
	(void)lkl_sys_close((unsigned int)fd);
	free(queue);
	return result;
}

uint64_t ker_ff_admission_queue_lease(
				 const struct ker_ff_admission_queue *queue)
{
	return queue ? queue->lease : 0;
}

int ker_ff_admission_queue_receive(struct ker_ff_admission_queue *queue,
				   struct ker_ff_admission_packet *packet,
				   unsigned int timeout_ms)
{
	unsigned char bytes[KER_FF_QUEUE_MAX_MESSAGE];
	struct lkl_sockaddr_nl sender = {0};
	unsigned int sender_length = sizeof(sender);
	struct lkl_nlmsghdr *header;
	struct nfgenmsg *nfgen;
	struct ker_nlattr *attr;
	struct nfqnl_msg_packet_hdr packet_header = {0};
	uint32_t packet_mark = 0;
	int have_packet_header = 0, have_packet_mark = 0;
	unsigned char *payload = NULL;
	size_t payload_length = 0;
	int result;
	int remaining;

	if (!queue || !packet || timeout_ms > 250 || queue->pending)
		return -EINVAL;
	if (queue->deferred_valid) {
		result = (int)queue->deferred_length;
		sender = queue->deferred_sender;
		memcpy(bytes, queue->deferred, (size_t)result);
		queue->deferred_valid = 0;
	} else {
		result = receive_datagram(queue, bytes, sizeof(bytes), &sender,
			&sender_length, timeout_ms);
		if (result <= 0) return result;
	}
	if (result < LKL_NLMSG_HDRLEN + (int)sizeof(*nfgen) ||
	    sender_length != sizeof(sender) || sender.nl_family != LKL_AF_NETLINK ||
	    sender.nl_pid != 0 || sender.nl_groups)
		return -EPROTO;
	header = (struct lkl_nlmsghdr *)bytes;
	if (header->nlmsg_len != (uint32_t)result ||
	    header->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) ||
	    header->nlmsg_seq != 0 || header->nlmsg_pid != 0)
		return -EPROTO;
	nfgen = (struct nfgenmsg *)LKL_NLMSG_DATA(header);
	if (nfgen->nfgen_family != AF_INET || nfgen->version != NFNETLINK_V0 ||
	    nfgen->res_id != htons(KER_FF_ADMISSION_QUEUE_NUMBER))
		return -EPROTO;
	remaining = (int)header->nlmsg_len - LKL_NLMSG_HDRLEN - (int)sizeof(*nfgen);
	attr = (struct ker_nlattr *)((unsigned char *)nfgen + sizeof(*nfgen));
	while (remaining) {
		struct ker_nlattr attribute;
		if (remaining < (int)sizeof(attribute)) return -EPROTO;
		memcpy(&attribute, attr, sizeof(attribute));
		if (attribute.nla_len < sizeof(attribute) ||
		    attribute.nla_len > remaining)
			return -EPROTO;
		size_t length = attribute.nla_len - sizeof(attribute);
		const unsigned char *data = (const unsigned char *)attr + sizeof(attribute);
		switch (attribute.nla_type & KER_NLA_TYPE_MASK) {
		case NFQA_PACKET_HDR:
			if (have_packet_header || length != sizeof(packet_header) ||
			    attribute.nla_type != NFQA_PACKET_HDR) return -EPROTO;
			memcpy(&packet_header, data, sizeof(packet_header));
			have_packet_header = 1;
			break;
		case NFQA_MARK:
			if (have_packet_mark || length != sizeof(packet_mark) ||
			    attribute.nla_type != NFQA_MARK) return -EPROTO;
			memcpy(&packet_mark, data, sizeof(packet_mark));
			packet_mark = ntohl(packet_mark);
			have_packet_mark = 1;
			break;
		case NFQA_PAYLOAD:
			if (payload || length > KER_FF_QUEUE_COPY_RANGE ||
			    attribute.nla_type != NFQA_PAYLOAD) return -EPROTO;
			payload = (unsigned char *)(uintptr_t)data;
			payload_length = length;
			break;
		default:
			break;
		}
		size_t aligned = KER_NLA_ALIGN(attribute.nla_len);
		if (aligned > (size_t)remaining) return -EPROTO;
		remaining -= (int)aligned;
		attr = (struct ker_nlattr *)((unsigned char *)attr + aligned);
	}
	if (!have_packet_header || !have_packet_mark || !payload || packet_mark != queue->mark ||
	    packet_header.hook != NF_INET_LOCAL_OUT || packet_header.hw_protocol != htons(LKL_ETH_P_IP) ||
	    payload_length < sizeof(struct iphdr))
		return -EPROTO;
	struct iphdr iph;
	memcpy(&iph, payload, sizeof(iph));
	if (iph.version != 4 || iph.ihl < 5 || iph.protocol != IPPROTO_TCP ||
	    payload_length < (size_t)iph.ihl * 4 + sizeof(struct tcphdr))
		return -EPROTO;
	struct tcphdr tcp;
	memcpy(&tcp, payload + (size_t)iph.ihl * 4, sizeof(tcp));
	if (!tcp.syn || !tcp.ack || tcp.rst || tcp.doff < 5 || tcp.doff > 15 ||
	    payload_length < (size_t)iph.ihl * 4 + (size_t)tcp.doff * 4)
		return -EPROTO;
	memset(packet, 0, sizeof(*packet));
	packet->lease = queue->lease;
	struct timespec arrived;
	if (clock_gettime(CLOCK_MONOTONIC, &arrived) != 0) return -errno;
	packet->deadline_ns = (uint64_t)arrived.tv_sec * UINT64_C(1000000000) +
		arrived.tv_nsec + UINT64_C(250000000);
	packet->id = ntohl(packet_header.packet_id);
	packet->mark = packet_mark;
	/* NFQA carries the outgoing SYNACK; recover the original request tuple. */
	packet->local_address = iph.saddr;
	packet->remote_address = iph.daddr;
	packet->local_port = tcp.source;
	packet->remote_port = tcp.dest;
	packet->server_sequence = tcp.seq;
	packet->tcp_options_length = (uint8_t)((size_t)tcp.doff * 4 - sizeof(tcp));
	if (packet->tcp_options_length)
		memcpy(packet->tcp_options, payload + (size_t)iph.ihl * 4 + sizeof(tcp),
			packet->tcp_options_length);
	queue->pending_id = packet->id;
	queue->pending = 1;
	return 1;
}

static int queue_verdict(struct ker_ff_admission_queue *queue,
			 uint64_t lease, uint64_t deadline_ns,
			 uint32_t packet_id, int accept, int discard_ack,
			 int *sent_to_kernel)
{
	struct queue_message message = {0};
	struct nfgenmsg nfgen = {
		.nfgen_family = AF_INET,
		.version = NFNETLINK_V0,
		.res_id = htons(KER_FF_ADMISSION_QUEUE_NUMBER),
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
	if (sent_to_kernel) *sent_to_kernel = 0;
	if (!queue || !sent_to_kernel || lease != queue->lease ||
	    (accept != 0 && accept != 1) || !queue->pending ||
	    queue->pending_id != packet_id) return -EINVAL;
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
		if ((uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec >= deadline_ns)
			return -ETIMEDOUT;
	}
	result = lkl_sys_sendto((unsigned int)queue->fd, &message,
		message.header.nlmsg_len, 0, (struct lkl_sockaddr *)&kernel, sizeof(kernel));
	if (result < 0) return (int)result;
	if ((size_t)result != message.header.nlmsg_len) return -EIO;
	/* A complete send is irreversible/uncertain: the kernel may have already
	 * reinjected ACCEPT even if its later ACK cannot be observed. */
	*sent_to_kernel = 1;
	if (discard_ack) {
		/* ACCEPT may already be irreversible. For DROP, retain the pending
		 * lease until a matched ACK proves dequeue; socket close is the
		 * fail-closed cleanup for an uncertain queued packet. */
		if (accept) queue->pending = 0;
		(void)lkl_sys_close((unsigned int)queue->fd);
		queue->fd = -1;
		return -ECONNRESET;
	}
	result = wait_ack(queue, queue->sequence, request_type, request_flags,
		message.header.nlmsg_len, deadline_ns);
	if (result) return (int)result;
	queue->pending = 0;
	return 0;
}

int ker_ff_admission_queue_verdict(struct ker_ff_admission_queue *queue,
				   uint64_t lease, uint64_t deadline_ns,
				   uint32_t packet_id, int accept,
				   int *sent_to_kernel)
{
	return queue_verdict(queue, lease, deadline_ns, packet_id, accept, 0,
		sent_to_kernel);
}

#ifdef KER_C15_TEST_ACK_LOSS
int ker_ff_admission_queue_test_accept_unread_ack(
	struct ker_ff_admission_queue *queue, uint64_t lease, uint64_t deadline_ns,
	uint32_t packet_id, int *sent_to_kernel)
{
	if (!queue) return -EINVAL;
	return queue_verdict(queue, lease, deadline_ns, packet_id, 1, 1,
		sent_to_kernel);
}

int ker_ff_admission_queue_test_drop_wrong_id(
	struct ker_ff_admission_queue *queue, uint64_t lease, uint64_t deadline_ns,
	uint32_t packet_id, int *sent_to_kernel)
{
	if (!queue || !packet_id || packet_id == UINT32_MAX) return -EINVAL;
	/* Ask the actual kernel queue to DROP a nonexistent packet ID. The kernel
	 * returns a matched -ENOENT ACK and leaves the real pending packet queued. */
	uint32_t pending_id = queue->pending_id;
	queue->pending_id = packet_id + 1;
	int result = queue_verdict(queue, lease, deadline_ns, packet_id + 1,
		0, 0, sent_to_kernel);
	queue->pending_id = pending_id;
	return result;
}
#endif

int ker_ff_admission_queue_disarm_after_quiescence(
	struct ker_ff_admission_queue *queue)
{
	if (!queue || queue->pending || queue->deferred_valid) return -EBUSY;
	return set_kernel_mark(queue->mark, 0, &queue->lease);
}

void ker_ff_admission_queue_close(struct ker_ff_admission_queue *queue)
{
	if (!queue)
		return;
	if (queue->fd >= 0)
		(void)lkl_sys_close((unsigned int)queue->fd);
	free(queue);
}
