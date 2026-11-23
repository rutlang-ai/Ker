#include "ff-owner-requests-wire.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "owner request parser:%d: %s\n", __LINE__, #x); \
    return 1; } } while (0)

#define INFO_SIZE 248u
struct buffer { unsigned char bytes[2048]; size_t length; };

static void init(struct ker_ff_owner_requests_accumulator *s)
{
    memset(s, 0, sizeof(*s));
    s->mark = 0x1234;
    s->sequence = 73;
    s->local_port_id = 8181;
    s->family = 2;
}

static void append(struct buffer *b, const void *data, size_t n)
{
    memcpy(b->bytes + b->length, data, n);
    b->length += n;
}

static void append_attr(struct buffer *b, uint16_t type, const void *value,
    size_t value_len)
{
    struct ker_ff_owner_requests_nlattr a = {
        .length = (uint16_t)(sizeof(a) + value_len), .type = type};
    append(b, &a, sizeof(a));
    append(b, value, value_len);
    while (b->length & 3u) b->bytes[b->length++] = 0;
}

static void append_row(struct buffer *b, uint8_t family, uint32_t mark,
    bool info, uint32_t cookie)
{
    struct ker_ff_owner_requests_diag_msg m = {
        .family = family, .state = 3, .source_port = 0x3412,
        .destination_port = 0x7856, .cookie = {cookie, cookie + 1}};
    if (family == 2) m.source_address[0] = 0x0100007f;
    else m.source_address[3] = 0x01000000;
    append(b, &m, sizeof(m));
    append_attr(b, 15, &mark, sizeof(mark));
    if (info) {
        unsigned char tcp_info[INFO_SIZE] = {0};
        append_attr(b, 2, tcp_info, sizeof(tcp_info));
    }
}

static struct buffer message(uint16_t type, uint16_t flags,
    const void *payload, size_t payload_len)
{
    struct buffer b = {0};
    struct ker_ff_owner_requests_nlmsghdr h = {
        .length = (uint32_t)(sizeof(h) + payload_len), .type = type,
        .flags = flags, .sequence = 73, .port_id = 8181};
    append(&b, &h, sizeof(h));
    if (payload_len) append(&b, payload, payload_len);
    while (b.length & 3u) b.bytes[b.length++] = 0;
    return b;
}

static int consume(struct ker_ff_owner_requests_accumulator *s,
    struct buffer *b, uint64_t *count, bool *complete)
{
    return ker_ff_owner_requests_parse_datagram(s, b->bytes, b->length, 0,
        count, complete);
}

int main(void)
{
    uint64_t count = 999;
    bool complete = false;
    struct ker_ff_owner_requests_accumulator s;
    init(&s);
    struct buffer row = {0};
    append_row(&row, 2, s.mark, false, 100);
    struct buffer packet = message(20, 2, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == 0);
    REQUIRE(!complete && count == 999 && s.rows == 1 && s.requests == 1);
    int32_t done_status = 0;
    packet = message(3, 2, &done_status, sizeof(done_status));
    REQUIRE(consume(&s, &packet, &count, &complete) == 0);
    REQUIRE(complete && count == 1);

    init(&s); count = 999; complete = false;
    row = (struct buffer){0};
    struct buffer one_row = {0};
    append_row(&one_row, 2, s.mark, true, 200);
    struct buffer one_message = message(20, 2, one_row.bytes, one_row.length);
    append(&row, one_message.bytes, one_message.length);
    REQUIRE(consume(&s, &row, &count, &complete) == 0);
    REQUIRE(!complete && s.rows == 1 && s.requests == 0 && count == 999);
    packet = message(3, 2, &done_status, sizeof(done_status));
    REQUIRE(consume(&s, &packet, &count, &complete) == 0);
    REQUIRE(complete && count == 0);

    init(&s); s.family = 10; count = 999; complete = false;
    row = (struct buffer){0};
    append_row(&row, 10, s.mark, false, 300);
    packet = message(20, 2, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == 0);
    REQUIRE(!complete && s.rows == 1 && s.requests == 1 && count == 999);
    packet = message(3, 2, &done_status, sizeof(done_status));
    REQUIRE(consume(&s, &packet, &count, &complete) == 0);
    REQUIRE(complete && count == 1);

    init(&s); count = 999; complete = false;
    row = (struct buffer){0};
    append_row(&row, 2, s.mark, false, 400);
    packet = message(20, 2, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == 0);
    REQUIRE(consume(&s, &packet, &count, &complete) == -EAGAIN);
    REQUIRE(count == 999);

    init(&s); count = 999; complete = false;
    row = (struct buffer){0}; append_row(&row, 2, s.mark + 1, false, 500);
    packet = message(20, 2, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == -ESTALE);
    REQUIRE(count == 999 && !complete);

    init(&s); count = 999; complete = false;
    row = (struct buffer){0};
    struct ker_ff_owner_requests_diag_msg m = {.family = 2, .state = 3};
    append(&row, &m, sizeof(m));
    packet = message(20, 2, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == -EPROTO);
    REQUIRE(count == 999 && !complete);

    init(&s); count = 999; complete = false;
    row = (struct buffer){0}; append_row(&row, 2, s.mark, false, 600);
    packet = message(20, 0x12, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == -EPROTO);
    REQUIRE(count == 999 && !complete);

    init(&s); count = 999; complete = false;
    packet = message(3, 2, &done_status, sizeof(done_status));
    packet.bytes[6] |= 0x10;
    REQUIRE(consume(&s, &packet, &count, &complete) == -EPROTO);
    REQUIRE(count == 999 && !complete);

    init(&s); count = 999; complete = false;
    row = (struct buffer){0}; append_row(&row, 2, s.mark, true, 700);
    /* Corrupt the INFO attribute length so a short tcp_info cannot be
     * mistaken for a full TCP_SYN_RECV socket. */
    size_t attr = sizeof(struct ker_ff_owner_requests_diag_msg) + 8;
    struct ker_ff_owner_requests_nlattr short_info = {.length = 8, .type = 2};
    memcpy(row.bytes + attr, &short_info, sizeof(short_info));
    packet = message(20, 2, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == -EPROTO);
    REQUIRE(count == 999 && !complete);

    init(&s); count = 999; complete = false;
    struct ker_ff_owner_requests_diag_request expected = {
        .header = {.length = sizeof(expected), .type = 20, .flags = 0x301,
            .sequence = s.sequence, .port_id = 0},
        .request = {.family = 2, .protocol = 6, .extensions = 2,
            .states = UINT32_C(1) << 3},
        .mark_attribute = {.length = sizeof(expected.mark_attribute) + 12,
            .type = 1},
        .mark_instruction = {.code = 10, .yes = 12, .no = 16},
        .mark_condition = {.mark = s.mark, .mask = UINT32_MAX}};
    struct ker_ff_owner_requests_nlmsgerr error = {
        .error = -EINVAL, .request = expected.header};
    row = (struct buffer){0};
    append(&row, &error, sizeof(error));
    append(&row, (const unsigned char *)&expected + sizeof(expected.header),
        sizeof(expected) - sizeof(expected.header));
    packet = message(2, 0, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == -EINVAL);
    REQUIRE(count == 999 && !complete);

    row.bytes[sizeof(error) + sizeof(expected.request) + 8] ^= 1;
    packet = message(2, 0, row.bytes, row.length);
    REQUIRE(consume(&s, &packet, &count, &complete) == -EPROTO);
    REQUIRE(count == 999 && !complete);

    puts("owner request diagnostic parser cases passed");
    return 0;
}
