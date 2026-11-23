#define _GNU_SOURCE
#include "ff-ingress-freeze-queue-parse.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter_ipv4.h>
#include <lkl/linux/netlink.h>
#include <lkl/asm/syscalls.h>
#include <lkl/linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "ingress freeze parser:%d: %s\n", __LINE__, #condition); \
		return 1; \
	} \
} while (0)

struct attr_header { uint16_t length; uint16_t type; };

struct wire_packet {
	unsigned char bytes[512];
	size_t length;
};

static size_t put_attr(unsigned char *bytes, size_t offset, uint16_t type,
		       const void *payload, size_t payload_length)
{
	struct attr_header attr = {.length = (uint16_t)(sizeof(attr) + payload_length),
		.type = type};
	size_t aligned = (attr.length + 3U) & ~3U;
	memcpy(bytes + offset, &attr, sizeof(attr));
	memcpy(bytes + offset + sizeof(attr), payload, payload_length);
	memset(bytes + offset + attr.length, 0, aligned - attr.length);
	return offset + aligned;
}

static struct wire_packet make_packet(uint8_t hook, uint32_t queue,
				      uint32_t destination,
				      int ack, int duplicate_header)
{
	struct wire_packet wire = {0};
	struct lkl_nlmsghdr *header = (struct lkl_nlmsghdr *)wire.bytes;
	struct nfgenmsg nfgen = {.nfgen_family = AF_INET, .version = NFNETLINK_V0,
		.res_id = htons((uint16_t)queue)};
	struct nfqnl_msg_packet_hdr packet_header = {
		.packet_id = htonl(77), .hw_protocol = htons(LKL_ETH_P_IP), .hook = hook};
	struct iphdr iph = {.version = 4, .ihl = 5, .protocol = IPPROTO_TCP,
		.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20),
		.saddr = htonl(0x0a000002), .daddr = destination};
	struct tcphdr tcp = {.source = htons(45000), .dest = htons(8080),
		.doff = 5, .syn = 1, .ack = ack != 0};
	size_t offset = LKL_NLMSG_HDRLEN;
	memcpy(wire.bytes + offset, &nfgen, sizeof(nfgen));
	offset += sizeof(nfgen);
	offset = put_attr(wire.bytes, offset, NFQA_PACKET_HDR,
		&packet_header, sizeof(packet_header));
	if (duplicate_header)
		offset = put_attr(wire.bytes, offset, NFQA_PACKET_HDR,
			&packet_header, sizeof(packet_header));
	unsigned char payload[sizeof(iph) + sizeof(tcp)];
	memcpy(payload, &iph, sizeof(iph));
	memcpy(payload + sizeof(iph), &tcp, sizeof(tcp));
	offset = put_attr(wire.bytes, offset, NFQA_PAYLOAD, payload, sizeof(payload));
	header->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET;
	header->nlmsg_seq = 0;
	header->nlmsg_pid = 0;
	header->nlmsg_len = (uint32_t)offset;
	wire.length = offset;
	return wire;
}

static size_t make_ack(unsigned char *bytes, uint32_t portid, uint32_t sequence,
		       uint16_t type, uint16_t flags, uint32_t request_length,
		       int error_code)
{
	struct lkl_nlmsghdr header = {.nlmsg_len = LKL_NLMSG_HDRLEN +
		sizeof(struct lkl_nlmsgerr), .nlmsg_type = LKL_NLMSG_ERROR,
		.nlmsg_seq = sequence, .nlmsg_pid = portid};
	struct lkl_nlmsgerr error = {.error = error_code,
		.msg = {.nlmsg_len = request_length, .nlmsg_type = type,
			.nlmsg_flags = flags, .nlmsg_seq = sequence, .nlmsg_pid = portid}};
	memcpy(bytes, &header, sizeof(header));
	memcpy(bytes + LKL_NLMSG_HDRLEN, &error, sizeof(error));
	return header.nlmsg_len;
}

static int test_verdict_ack(void)
{
	const uint32_t portid = 1234, sequence = 9, request_length = 44;
	const uint16_t request_type = 0x602, request_flags = 0x5;
	unsigned char bytes[128];
	int ack_error = -1;
	size_t length = make_ack(bytes, portid, sequence, request_type,
		request_flags, request_length, 0);
#define PARSE_ACK(data, size, family, pid, groups, expected_port, expected_seq, \
		request_t, request_f, request_l) \
	ker_ff_ingress_parse_verdict_ack(data, size, sizeof(struct lkl_sockaddr_nl), \
		family, pid, groups, expected_port, expected_seq, request_t, request_f, \
		request_l, &ack_error)
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == 1);
	CHECK(ack_error == 0);
	length = make_ack(bytes, portid, sequence, request_type, request_flags,
		request_length, -ECONNRESET);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == 1);
	CHECK(ack_error == -ECONNRESET);
	CHECK(PARSE_ACK(bytes, length - 1, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == -EPROTO);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 77, 0, portid, sequence,
		request_type, request_flags, request_length) == -EPROTO);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 1, portid, sequence,
		request_type, request_flags, request_length) == -EPROTO);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence + 1,
		request_type, request_flags, request_length) == 0);
	length = make_ack(bytes, portid, sequence + 1, request_type, request_flags,
		request_length, 0);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == 0);
	length = make_ack(bytes, portid, sequence, request_type + 1, request_flags,
		request_length, 0);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == -EPROTO);
	length = make_ack(bytes, portid, sequence, request_type, request_flags + 1,
		request_length, 0);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == -EPROTO);
	length = make_ack(bytes, portid, sequence, request_type, request_flags,
		request_length + 1, 0);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == -EPROTO);
	length = make_ack(bytes, portid, sequence, request_type, request_flags,
		request_length, 1);
	CHECK(PARSE_ACK(bytes, length, LKL_AF_NETLINK, 0, 0, portid, sequence,
		request_type, request_flags, request_length) == -EPROTO);
#undef PARSE_ACK
	return 0;
}

int main(void)
{
	CHECK(test_verdict_ack() == 0);
	const uint32_t local = htonl(0x0a000001);
	struct ker_ff_ingress_packet packet;
	struct wire_packet valid = make_packet(NF_INET_LOCAL_IN, 88, local, 0, 0);
	CHECK(ker_ff_ingress_parse_notification(valid.bytes, valid.length, 88,
		local, htons(8080), &packet) == 0);
	CHECK(packet.id == 77 && packet.local_address == local &&
		packet.remote_address == htonl(0x0a000002));
	/* Only the complete original headers are copied. TFO payload remains in
	 * the original skb and does not need to be reconstructed by this parser. */
	CHECK(ker_ff_ingress_parse_notification(valid.bytes, valid.length, 89,
		local, htons(8080), &packet) == -EPROTO);
	struct wire_packet wrong_hook = make_packet(NF_INET_LOCAL_OUT, 88, local, 0, 0);
	CHECK(ker_ff_ingress_parse_notification(wrong_hook.bytes, wrong_hook.length,
		88, local, htons(8080), &packet) == -EPROTO);
	struct wire_packet wrong_destination = make_packet(NF_INET_LOCAL_IN, 88,
		htonl(0x0a000003), 0, 0);
	CHECK(ker_ff_ingress_parse_notification(wrong_destination.bytes,
		wrong_destination.length, 88, local, htons(8080), &packet) == -EPROTO);
	struct wire_packet ack = make_packet(NF_INET_LOCAL_IN, 88, local, 1, 0);
	CHECK(ker_ff_ingress_parse_notification(ack.bytes, ack.length,
		88, local, htons(8080), &packet) == -EPROTO);
	struct wire_packet duplicate = make_packet(NF_INET_LOCAL_IN, 88, local, 0, 1);
	CHECK(ker_ff_ingress_parse_notification(duplicate.bytes, duplicate.length,
		88, local, htons(8080), &packet) == -EPROTO);
	CHECK(ker_ff_ingress_parse_notification(valid.bytes, valid.length - 1,
		88, local, htons(8080), &packet) == -EPROTO);
	return 0;
}
