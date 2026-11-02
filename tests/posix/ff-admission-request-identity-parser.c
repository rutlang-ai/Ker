#define _GNU_SOURCE
#include "ff-admission-request-identity.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "request identity parser:%d: %s\n", __LINE__, #condition); \
		return 1; \
	} \
} while (0)

extern int ker_ff_admission_request_identity_test_parse(
	uint32_t mark, const struct ker_ff_admission_ipv4_tuple *tuple,
	uint64_t listener_cookie, uint32_t sequence, uint32_t local_port_id,
	const void *bytes, size_t length,
	struct ker_tcp_request_revoke_request *request, bool *complete);

struct row_buffer {
	unsigned char bytes[4096];
	size_t length;
};

static int append_row(struct row_buffer *buffer,
	const struct ker_ff_admission_ipv4_tuple *tuple, uint32_t mark,
	uint32_t cookie_low, uint32_t cookie_high, bool add_info,
	bool wrong_tuple, bool malformed_mark)
{
	struct nlmsghdr header = {.nlmsg_type = SOCK_DIAG_BY_FAMILY,
		.nlmsg_flags = NLM_F_MULTI, .nlmsg_seq = 19, .nlmsg_pid = 29};
	struct inet_diag_msg message = {0};
	message.idiag_family = AF_INET;
	message.idiag_state = TCP_SYN_RECV;
	message.id.idiag_sport = tuple->local.sin_port;
	message.id.idiag_dport = tuple->remote.sin_port;
	message.id.idiag_src[0] = tuple->local.sin_addr.s_addr;
	message.id.idiag_dst[0] = tuple->remote.sin_addr.s_addr;
	if (wrong_tuple)
		message.id.idiag_dport = htons(htons(message.id.idiag_dport) + 1u);
	message.id.idiag_if = 7;
	message.id.idiag_cookie[0] = cookie_low;
	message.id.idiag_cookie[1] = cookie_high;
	unsigned char payload[sizeof(message) + 4 * 260] = {0};
	size_t used = sizeof(message);
	memcpy(payload, &message, sizeof(message));
	struct nlattr mark_attribute = {
		.nla_len = malformed_mark ? 2 : (uint16_t)(sizeof(struct nlattr) + sizeof(mark)),
		.nla_type = INET_DIAG_MARK};
	memcpy(payload + used, &mark_attribute, sizeof(mark_attribute));
	if (mark_attribute.nla_len >= sizeof(mark_attribute) + sizeof(mark))
		memcpy(payload + used + sizeof(mark_attribute), &mark, sizeof(mark));
	used += NLA_ALIGN(mark_attribute.nla_len);
	if (add_info) {
		struct nlattr info = {.nla_len = sizeof(info) + 248,
			.nla_type = INET_DIAG_INFO};
		memcpy(payload + used, &info, sizeof(info));
		used += NLA_ALIGN(info.nla_len);
	}
	header.nlmsg_len = (uint32_t)(sizeof(header) + used);
	size_t start = buffer->length;
	if (start + NLMSG_ALIGN(header.nlmsg_len) > sizeof(buffer->bytes))
		return -1;
	memcpy(buffer->bytes + start, &header, sizeof(header));
	memcpy(buffer->bytes + start + sizeof(header), payload, used);
	buffer->length = start + NLMSG_ALIGN(header.nlmsg_len);
	return 0;
}

static int append_done(struct row_buffer *buffer, int32_t status)
{
	struct nlmsghdr header = {.nlmsg_type = NLMSG_DONE,
		.nlmsg_flags = NLM_F_MULTI, .nlmsg_seq = 19, .nlmsg_pid = 29,
		.nlmsg_len = sizeof(header) + sizeof(status)};
	if (buffer->length + NLMSG_ALIGN(header.nlmsg_len) > sizeof(buffer->bytes))
		return -1;
	memcpy(buffer->bytes + buffer->length, &header, sizeof(header));
	memcpy(buffer->bytes + buffer->length + sizeof(header), &status, sizeof(status));
	buffer->length += NLMSG_ALIGN(header.nlmsg_len);
	return 0;
}

static int parse(const struct row_buffer *buffer,
	const struct ker_ff_admission_ipv4_tuple *tuple,
	struct ker_tcp_request_revoke_request *request, bool *complete)
{
	return ker_ff_admission_request_identity_test_parse(UINT32_C(0x415001),
		tuple, UINT64_C(0x1122334455667788), 19, 29,
		buffer->bytes, buffer->length, request, complete);
}

int main(void)
{
	struct ker_ff_admission_ipv4_tuple tuple = {
		.local = {.sin_family = AF_INET, .sin_port = htons(8080)},
		.remote = {.sin_family = AF_INET, .sin_port = htons(45123)}};
	CHECK(inet_pton(AF_INET, "198.18.0.2", &tuple.local.sin_addr) == 1);
	CHECK(inet_pton(AF_INET, "198.18.0.1", &tuple.remote.sin_addr) == 1);
	struct ker_tcp_request_revoke_request output;
	memset(&output, 0xa5, sizeof(output));
	struct ker_tcp_request_revoke_request sentinel = output;
	struct row_buffer buffer = {0};
	bool complete = true;
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415001), 123, 456,
		false, false, false) == 0);
	CHECK(parse(&buffer, &tuple, &output, &complete) == 0 && !complete);
	CHECK(!memcmp(&output, &sentinel, sizeof(output)));
	CHECK(append_done(&buffer, 0) == 0);
	CHECK(parse(&buffer, &tuple, &output, &complete) == 1 && complete);
	CHECK(output.version == KER_TCP_REQUEST_REVOKE_VERSION &&
		output.mark == UINT32_C(0x415001) && output.family == AF_INET &&
		output.local_port == tuple.local.sin_port &&
		output.remote_port == tuple.remote.sin_port && output.ifindex == 7 &&
		output.request_cookie[0] == 123 && output.request_cookie[1] == 456 &&
		output.listener_cookie[0] == UINT32_C(0x55667788) &&
		output.listener_cookie[1] == UINT32_C(0x11223344));
	CHECK(!memcmp(output.local_address, &tuple.local.sin_addr, 4));
	CHECK(!memcmp(output.remote_address, &tuple.remote.sin_addr, 4));
	for (size_t i = 4; i < 16; ++i)
		CHECK(output.local_address[i] == 0 && output.remote_address[i] == 0);

	buffer = (struct row_buffer){0};
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415001), 123, 456,
		false, true, false) == 0);
	CHECK(append_done(&buffer, 0) == 0);
	output = sentinel;
	CHECK(parse(&buffer, &tuple, &output, &complete) == 0 && complete);
	CHECK(!memcmp(&output, &sentinel, sizeof(output)));

	buffer = (struct row_buffer){0};
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415002), 123, 456,
		false, false, false) == 0);
	CHECK(append_done(&buffer, 0) == 0);
	CHECK(parse(&buffer, &tuple, &output, &complete) == -ESTALE);
	CHECK(!memcmp(&output, &sentinel, sizeof(output)));

	buffer = (struct row_buffer){0};
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415001), INET_DIAG_NOCOOKIE,
		INET_DIAG_NOCOOKIE, false, false, false) == 0);
	CHECK(append_done(&buffer, 0) == 0);
	CHECK(parse(&buffer, &tuple, &output, &complete) == -EPROTO);

	buffer = (struct row_buffer){0};
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415001), 123, 456,
		true, false, false) == 0);
	CHECK(append_done(&buffer, 0) == 0);
	CHECK(parse(&buffer, &tuple, &output, &complete) == -ESTALE);

	buffer = (struct row_buffer){0};
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415001), 123, 456,
		false, false, true) == 0);
	CHECK(parse(&buffer, &tuple, &output, &complete) == -EPROTO);

	buffer = (struct row_buffer){0};
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415001), 123, 456,
		false, false, false) == 0);
	CHECK(append_row(&buffer, &tuple, UINT32_C(0x415001), 789, 999,
		false, false, false) == 0);
	CHECK(parse(&buffer, &tuple, &output, &complete) == -EEXIST);

	puts("FF admission identity parser: complete-only output, tuple/mark/cookie, INFO and duplicate rejection passed");
	return 0;
}
