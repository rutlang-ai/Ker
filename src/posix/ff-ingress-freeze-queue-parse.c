#define _GNU_SOURCE
#include "ff-ingress-freeze-queue-parse.h"

#include <arpa/inet.h>
#include <errno.h>
#include <lkl/linux/netlink.h>
#include <lkl/asm/syscalls.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter_ipv4.h>
#include <lkl/linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>

#define KER_NLA_ALIGN(length) (((length) + 3U) & ~3U)
#define KER_NLA_TYPE_MASK 0x3fffU
#define KER_INGRESS_COPY_RANGE 256U
#define KER_INGRESS_MAX_MESSAGE 4096U

int ker_ff_ingress_parse_verdict_ack(const void *input, size_t length,
				     size_t sender_length, uint16_t sender_family,
				     uint32_t sender_pid, uint32_t sender_groups,
				     uint32_t portid, uint32_t sequence,
				     uint16_t request_type, uint16_t request_flags,
				     uint32_t request_length, int *ack_error)
{
	if (!input || !ack_error || !portid || !sequence ||
	    sender_length != sizeof(struct lkl_sockaddr_nl) ||
	    sender_family != LKL_AF_NETLINK || sender_pid || sender_groups ||
	    length < LKL_NLMSG_HDRLEN) return -EPROTO;
	struct lkl_nlmsghdr header;
	memcpy(&header, input, sizeof(header));
	if (header.nlmsg_len != length) return -EPROTO;
	if (header.nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) &&
	    header.nlmsg_seq == 0) return -EPROTO;
	if (header.nlmsg_type != LKL_NLMSG_ERROR || header.nlmsg_pid != portid ||
	    header.nlmsg_seq != sequence) return 0;
	if (header.nlmsg_len < LKL_NLMSG_HDRLEN + sizeof(struct lkl_nlmsgerr))
		return -EPROTO;
	struct lkl_nlmsgerr error;
	memcpy(&error, (const unsigned char *)input + LKL_NLMSG_HDRLEN,
	       sizeof(error));
	if (error.msg.nlmsg_type != request_type ||
	    error.msg.nlmsg_seq != sequence || error.msg.nlmsg_flags != request_flags ||
	    error.msg.nlmsg_len != request_length || error.msg.nlmsg_pid != portid ||
	    error.error > 0 || error.error < -4095) return -EPROTO;
	*ack_error = error.error;
	return 1;
}

struct ker_nlattr {
	uint16_t nla_len;
	uint16_t nla_type;
};

int ker_ff_ingress_parse_notification(const void *input, size_t length,
				      uint32_t queue_number,
				      uint32_t local_address,
				      uint16_t local_port,
				      struct ker_ff_ingress_packet *packet)
{
	const unsigned char *bytes = input;
	struct lkl_nlmsghdr header_storage;
	struct nfgenmsg nfgen_storage;
	const struct lkl_nlmsghdr *header = &header_storage;
	const struct nfgenmsg *nfgen = &nfgen_storage;
	const unsigned char *attr;
	struct nfqnl_msg_packet_hdr packet_header = {0};
	const unsigned char *payload = NULL;
	size_t payload_length = 0;
	int have_packet_header = 0;
	int remaining;

	if (!input || !packet || length < LKL_NLMSG_HDRLEN + sizeof(*nfgen) ||
	    length > KER_INGRESS_MAX_MESSAGE)
		return -EPROTO;
	memcpy(&header_storage, bytes, sizeof(header_storage));
	if (header->nlmsg_len != length ||
	    header->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) ||
	    header->nlmsg_seq != 0 || header->nlmsg_pid != 0)
		return -EPROTO;
	memcpy(&nfgen_storage, bytes + LKL_NLMSG_HDRLEN, sizeof(nfgen_storage));
	if (nfgen->nfgen_family != AF_INET || nfgen->version != NFNETLINK_V0 ||
	    nfgen->res_id != htons(queue_number))
		return -EPROTO;
	remaining = (int)header->nlmsg_len - LKL_NLMSG_HDRLEN - (int)sizeof(*nfgen);
	attr = bytes + LKL_NLMSG_HDRLEN + sizeof(*nfgen);
	while (remaining) {
		struct ker_nlattr attribute;
		if (remaining < (int)sizeof(attribute)) return -EPROTO;
		memcpy(&attribute, attr, sizeof(attribute));
		if (attribute.nla_len < sizeof(attribute) ||
		    attribute.nla_len > remaining)
			return -EPROTO;
		size_t data_length = attribute.nla_len - sizeof(attribute);
		const unsigned char *data = (const unsigned char *)attr + sizeof(attribute);
		switch (attribute.nla_type & KER_NLA_TYPE_MASK) {
		case NFQA_PACKET_HDR:
			if (have_packet_header || data_length != sizeof(packet_header) ||
			    attribute.nla_type != NFQA_PACKET_HDR)
				return -EPROTO;
			memcpy(&packet_header, data, sizeof(packet_header));
			have_packet_header = 1;
			break;
		case NFQA_PAYLOAD:
			if (payload || data_length > KER_INGRESS_COPY_RANGE ||
			    attribute.nla_type != NFQA_PAYLOAD)
				return -EPROTO;
			payload = data;
			payload_length = data_length;
			break;
		default:
			break;
		}
		size_t aligned = KER_NLA_ALIGN(attribute.nla_len);
		if (aligned > (size_t)remaining) return -EPROTO;
		remaining -= (int)aligned;
		attr += aligned;
	}
	if (!have_packet_header || !payload ||
	    packet_header.hook != NF_INET_LOCAL_IN ||
	    packet_header.hw_protocol != htons(LKL_ETH_P_IP) ||
	    payload_length < sizeof(struct iphdr))
		return -EPROTO;
	struct iphdr iph;
	memcpy(&iph, payload, sizeof(iph));
	if (iph.version != 4 || iph.ihl < 5 || iph.protocol != IPPROTO_TCP ||
	    payload_length < (size_t)iph.ihl * 4 + sizeof(struct tcphdr) ||
	    ntohs(iph.tot_len) < (unsigned int)iph.ihl * 4 + sizeof(struct tcphdr))
		return -EPROTO;
	struct tcphdr tcp;
	memcpy(&tcp, payload + (size_t)iph.ihl * 4, sizeof(tcp));
	if (!tcp.syn || tcp.ack || tcp.rst || tcp.fin || tcp.doff < 5 || tcp.doff > 15 ||
	    payload_length < (size_t)iph.ihl * 4 + (size_t)tcp.doff * 4 ||
	    ntohs(iph.tot_len) < (unsigned int)iph.ihl * 4 +
		(unsigned int)tcp.doff * 4 ||
	    iph.daddr != local_address || tcp.dest != local_port)
		return -EPROTO;
	uint32_t packet_id = ntohl(packet_header.packet_id);
	if (!packet_id) return -EPROTO;
	memset(packet, 0, sizeof(*packet));
	packet->id = packet_id;
	packet->local_address = iph.daddr;
	packet->remote_address = iph.saddr;
	packet->local_port = tcp.dest;
	packet->remote_port = tcp.source;
	return 0;
}
