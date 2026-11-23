#include "member-census-diag-wire.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "member census parser:%d: %s\n", __LINE__, #test); \
    return 1; \
} } while (0)

/* Pinned Linux 7fdb include/uapi/linux/inet_diag.h attribute IDs/layouts. */
#define TEST_DIAG_SHUTDOWN 8u
#define TEST_DIAG_SOCKOPT 22u
#define TEST_DIAG_UNKNOWN 0x7ffeu
#define TEST_NLM_F_CAPPED 0x100u
#define TEST_NLM_F_ACK_TLVS 0x200u
#define TEST_COOKIE_SLOTS 64u

_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_SHUTDOWN == TEST_DIAG_SHUTDOWN,
    "wire SHUTDOWN ID must match pinned Linux UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_MARK == 15u,
    "wire MARK ID must match pinned Linux UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_PAD == 14u,
    "wire PAD ID must match pinned Linux UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_CLASS_ID == 17u,
    "wire CLASS_ID must match pinned Linux UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_CGROUP_ID == 21u,
    "wire CGROUP_ID ID must match pinned Linux UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_SOCKOPT == TEST_DIAG_SOCKOPT,
    "wire SOCKOPT ID must match pinned Linux UAPI");

static uint64_t test_seen_cookies[TEST_COOKIE_SLOTS];

struct test_attribute {
    uint16_t type;
    const void *data;
    size_t length;
};

struct request_wire {
    struct ker_member_census_nlmsghdr header;
    struct {
        uint8_t family;
        uint8_t protocol;
        uint8_t extensions;
        uint8_t pad;
        uint32_t states;
        struct {
            uint16_t source_port;
            uint16_t destination_port;
            uint32_t source_address[4];
            uint32_t destination_address[4];
            uint32_t interface_index;
            uint32_t cookie[2];
        } __attribute__((packed)) id;
    } __attribute__((packed)) request;
    struct ker_member_census_nlattr bytecode_attribute;
    struct { uint8_t code; uint8_t yes; uint16_t no; } __attribute__((packed)) instruction;
    struct { uint32_t mark; uint32_t mask; } __attribute__((packed)) condition;
} __attribute__((packed));

struct done_wire {
    struct ker_member_census_nlmsghdr header;
    int32_t status;
} __attribute__((packed));

static struct ker_member_census_accumulator initial_state(void)
{
    memset(test_seen_cookies, 0, sizeof(test_seen_cookies));
    return (struct ker_member_census_accumulator){
        .mark = 0x4312, .local_port = 45678, .sequence = 0x9942,
        .local_port_id = 77,
        .listener_cookie = UINT64_C(0x1122334455667788),
        .seen_cookies = test_seen_cookies,
        .seen_cookie_capacity = TEST_COOKIE_SLOTS};
}

static struct ker_member_census_diag_request expected_request(void)
{
    return (struct ker_member_census_diag_request){
        .header = {.length = sizeof(struct ker_member_census_diag_request),
            .type = KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST,
            .flags = KER_MEMBER_CENSUS_NLM_F_REQUEST | 0x300u,
            .sequence = 0x9942, .port_id = 0},
        .request = {.family = AF_INET, .protocol = IPPROTO_TCP,
            .states = UINT32_MAX,
            .id = {.source_port = htons(45678)}},
        .bytecode_attribute = {.length = sizeof(struct ker_member_census_nlattr) + 12,
            .type = 1},
        .mark_instruction = {.code = 10, .yes = 12, .no = 16},
        .condition = {.mark = 0x4312, .mask = UINT32_MAX}};
}

static size_t append_row(uint8_t *out, size_t capacity, uint8_t state,
    const struct test_attribute *attributes, size_t attribute_count)
{
    const size_t fixed = sizeof(struct ker_member_census_nlmsghdr) +
        sizeof(struct ker_member_census_diag_msg);
    if (capacity < fixed) return 0;
    struct ker_member_census_nlmsghdr header = {
        .type = KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST,
        .flags = KER_MEMBER_CENSUS_NLM_F_MULTI,
        .sequence = 0x9942, .port_id = 77};
    struct ker_member_census_diag_msg message = {
        .family = AF_INET, .state = state,
        .source_port = htons(45678), .cookie = {0x55667788, 0x11223344}};
    memcpy(out, &header, sizeof(header));
    memcpy(out + sizeof(header), &message, sizeof(message));
    size_t used = fixed;
    for (size_t i = 0; i < attribute_count; ++i) {
        const struct test_attribute *item = &attributes[i];
        size_t attr_length = sizeof(struct ker_member_census_nlattr) + item->length;
        size_t aligned = (attr_length + 3u) & ~(size_t)3u;
        if (attr_length > UINT16_MAX || aligned > capacity - used) return 0;
        struct ker_member_census_nlattr attr = {
            .length = (uint16_t)attr_length, .type = item->type};
        memcpy(out + used, &attr, sizeof(attr));
        if (item->length) memcpy(out + used + sizeof(attr), item->data, item->length);
        if (aligned > attr_length) memset(out + used + attr_length, 0, aligned - attr_length);
        used += aligned;
    }
    header.length = (uint32_t)used;
    memcpy(out, &header, sizeof(header));
    return used;
}

static size_t append_done(uint8_t *out, size_t capacity, int32_t status)
{
    if (capacity < sizeof(struct done_wire)) return 0;
    struct done_wire done = {
        .header = {.length = sizeof(done), .type = KER_MEMBER_CENSUS_NLMSG_DONE,
            .flags = KER_MEMBER_CENSUS_NLM_F_MULTI,
            .sequence = 0x9942, .port_id = 77},
        .status = status};
    memcpy(out, &done, sizeof(done));
    return sizeof(done);
}

static size_t append_error(uint8_t *out, size_t capacity, int32_t error,
    bool capped, bool ack_tlvs, bool echo_matches)
{
    struct ker_member_census_diag_request expected = expected_request();
    const size_t echo_length = capped ? 0 : sizeof(expected) - sizeof(expected.header);
    size_t payload_length = sizeof(struct ker_member_census_nlmsgerr) + echo_length;
    size_t total = sizeof(struct ker_member_census_nlmsghdr) + payload_length;
    if (total > capacity) return 0;
    struct ker_member_census_nlmsghdr header = {
        .length = (uint32_t)total, .type = KER_MEMBER_CENSUS_NLMSG_ERROR,
        .flags = (capped ? TEST_NLM_F_CAPPED : 0) |
            (ack_tlvs ? TEST_NLM_F_ACK_TLVS : 0),
        .sequence = 0x9942, .port_id = 77};
    struct ker_member_census_nlmsgerr body = {
        .error = error, .request = expected.header};
    memcpy(out, &header, sizeof(header));
    memcpy(out + sizeof(header), &body, sizeof(body));
    if (echo_length) {
        memcpy(out + sizeof(header) + sizeof(body),
            (const uint8_t *)&expected + sizeof(expected.header), echo_length);
        if (!echo_matches) out[sizeof(header) + sizeof(body)] ^= 1;
    }
    return total;
}

static int parse_expect(struct ker_member_census_accumulator *state,
    const void *bytes, size_t length, int expected_status,
    bool expected_complete, uint64_t expected_total,
    struct ker_socket_member_census_snapshot *snapshot)
{
    bool complete = !expected_complete;
    int status = ker_member_census_parse_datagram(state, bytes, length, 0,
        snapshot, &complete);
    if (status != expected_status || complete != expected_complete ||
        (expected_complete && snapshot->total != expected_total)) {
        fprintf(stderr, "member census parser: got status=%d complete=%d total=%llu, expected %d/%d/%llu\n",
            status, complete, (unsigned long long)snapshot->total,
            expected_status, expected_complete, (unsigned long long)expected_total);
        return 1;
    }
    return 0;
}

int main(void)
{
    CHECK(ker_member_census_receive_status(true, -EAGAIN) == 0);
    CHECK(ker_member_census_receive_status(false, -EAGAIN) == -EAGAIN);

    uint8_t packet[512];
    uint8_t shutdown = 0;
    uint8_t sockopt[2] = {0};
    uint32_t mark = 0x4312;
    uint32_t wrong_mark = 0x4313;
    const struct test_attribute full_attrs[] = {
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)},
        {TEST_DIAG_SHUTDOWN, &shutdown, sizeof(shutdown)},
        {TEST_DIAG_SOCKOPT, sockopt, sizeof(sockopt)}};
    const struct test_attribute full_attrs_reordered[] = {
        {TEST_DIAG_SOCKOPT, sockopt, sizeof(sockopt)},
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)},
        {TEST_DIAG_SHUTDOWN, &shutdown, sizeof(shutdown)}};
    const struct test_attribute request_attrs[] = {
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)}};
    const struct test_attribute unknown_extension[] = {
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)},
        {TEST_DIAG_UNKNOWN, sockopt, sizeof(sockopt)}};

    struct ker_socket_member_census_snapshot snapshot = {.total = 99,
        .listener_cookie = UINT64_C(0xaabbccddeeff0011)};
    struct ker_member_census_accumulator state = initial_state();
    size_t length = append_row(packet, sizeof(packet), 10, full_attrs,
        sizeof(full_attrs) / sizeof(full_attrs[0]));
    CHECK(length != 0);
    /* Pinned inet_diag_msg_attrs_fill() full-socket row shape. */
    CHECK(parse_expect(&state, packet, length, 0, false, 0, &snapshot) == 0);
    CHECK(state.total == 1 && state.state_counts[10] == 1 && snapshot.total == 99);

    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, full_attrs_reordered,
        sizeof(full_attrs_reordered) / sizeof(full_attrs_reordered[0]));
    CHECK(length != 0);
    CHECK(parse_expect(&state, packet, length, 0, false, 0, &snapshot) == 0);
    CHECK(state.total == 1 && state.state_counts[3] == 1);

    /* Unknown but structurally valid attributes do not alter the census. */
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, unknown_extension,
        sizeof(unknown_extension) / sizeof(unknown_extension[0]));
    CHECK(length != 0);
    CHECK(parse_expect(&state, packet, length, 0, false, 0, &snapshot) == 0);
    CHECK(state.total == 1 && state.state_counts[3] == 1);

    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs,
        sizeof(request_attrs) / sizeof(request_attrs[0]));
    CHECK(length != 0);
    CHECK(parse_expect(&state, packet, length, 0, false, 0, &snapshot) == 0);
    CHECK(state.total == 1 && state.state_counts[3] == 1);

    /* A complete multipart transaction publishes only after its DONE. */
    state = initial_state();
    length = append_row(packet, sizeof(packet), 10, full_attrs,
        sizeof(full_attrs) / sizeof(full_attrs[0]));
    size_t done_length = append_done(packet + length, sizeof(packet) - length, 0);
    CHECK(length && done_length);
    CHECK(parse_expect(&state, packet, length + done_length, 0, true, 1, &snapshot) == 0);
    CHECK(snapshot.listener_cookie == state.listener_cookie && snapshot.state_counts[10] == 1);

    /* A metadata capability outlives the listener, so an empty successful
     * dump and a dump containing only accepted/TIME_WAIT sockets are valid. */
    state = initial_state();
    done_length = append_done(packet, sizeof(packet), 0);
    CHECK(done_length && parse_expect(&state, packet, done_length,
        0, true, 0, &snapshot) == 0);
    CHECK(snapshot.total == 0 && snapshot.listener_cookie == state.listener_cookie);
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    done_length = append_done(packet + length, sizeof(packet) - length, 0);
    CHECK(length && done_length && parse_expect(&state, packet, length + done_length,
        0, true, 1, &snapshot) == 0);
    CHECK(snapshot.total == 1 && snapshot.state_counts[3] == 1 &&
        snapshot.listener_cookie == state.listener_cookie);

    /* Malformed later data after a good row must never publish a partial result. */
    state = initial_state();
    snapshot.total = 99;
    size_t row_length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    size_t malformed_done = append_done(packet + row_length,
        sizeof(packet) - row_length, 0);
    CHECK(row_length && malformed_done);
    packet[row_length + sizeof(struct ker_member_census_nlmsghdr)] = 1;
    CHECK(parse_expect(&state, packet, row_length + malformed_done,
        -EPROTO, false, 0, &snapshot) == 0);
    CHECK(snapshot.total == 99);

    /* Exact mark cardinality and value remain mandatory. */
    const struct test_attribute missing_mark[] = {
        {TEST_DIAG_SHUTDOWN, &shutdown, sizeof(shutdown)}};
    state = initial_state();
    length = append_row(packet, sizeof(packet), 10, missing_mark, 1);
    CHECK(length && parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    const struct test_attribute wrong_mark_attrs[] = {
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &wrong_mark, sizeof(wrong_mark)},
        {TEST_DIAG_SHUTDOWN, &shutdown, sizeof(shutdown)},
        {TEST_DIAG_SOCKOPT, sockopt, sizeof(sockopt)}};
    state = initial_state();
    length = append_row(packet, sizeof(packet), 10, wrong_mark_attrs, 3);
    CHECK(length && parse_expect(&state, packet, length, -ESTALE, false, 0, &snapshot) == 0);
    const struct test_attribute duplicate_mark[] = {
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)},
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)}};
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, duplicate_mark, 2);
    CHECK(length && parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);

    /* Structurally bad known and unknown attributes and truncated framing. */
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    struct ker_member_census_nlattr *attribute = (void *)(packet +
        sizeof(struct ker_member_census_nlmsghdr) + sizeof(struct ker_member_census_diag_msg));
    attribute->length = sizeof(*attribute) + 3; /* MARK must be a u32. */
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    const uint8_t short_data[2] = {0};
    const struct test_attribute malformed_known[] = {
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)},
        {TEST_DIAG_SHUTDOWN, short_data, sizeof(short_data)}};
    length = append_row(packet, sizeof(packet), 3, malformed_known, 2);
    CHECK(length);
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    const struct test_attribute malformed_unknown[] = {
        {KER_MEMBER_CENSUS_IN_DIAG_MARK, &mark, sizeof(mark)},
        {TEST_DIAG_UNKNOWN, short_data, sizeof(short_data)}};
    length = append_row(packet, sizeof(packet), 3, malformed_unknown, 2);
    CHECK(length);
    attribute = (void *)(packet + sizeof(struct ker_member_census_nlmsghdr) +
        sizeof(struct ker_member_census_diag_msg) + 8);
    attribute->length = 1;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length && parse_expect(&state, packet, length - 1, -EPROTO,
        false, 0, &snapshot) == 0);

    /* Full and capped initial NLMSG_ERROR replies bind to the original request. */
    state = initial_state();
    length = append_error(packet, sizeof(packet), -ENOENT, false, false, true);
    CHECK(length && parse_expect(&state, packet, length, -ENOENT, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_error(packet, sizeof(packet), -EINVAL, true, false, true);
    CHECK(length && parse_expect(&state, packet, length, -EINVAL, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_error(packet, sizeof(packet), -EINVAL, false, false, false);
    CHECK(length && parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_error(packet, sizeof(packet), -EINVAL, true, false, true);
    CHECK(length);
    struct ker_member_census_nlmsgerr *error_body = (void *)(packet +
        sizeof(struct ker_member_census_nlmsghdr));
    error_body->request.sequence++;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_error(packet, sizeof(packet), 1, true, false, true);
    CHECK(length && parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_error(packet, sizeof(packet), -4096, true, false, true);
    CHECK(length && parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_error(packet, sizeof(packet), -ENOENT, true, true, true);
    CHECK(length && parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_error(packet, sizeof(packet), -ENOENT, true, false, true);
    CHECK(length);
    packet[length++] = 0; /* No message may follow an initial request error. */
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);

    /* DONE errors/flags/TLV tails fail closed; this request does not negotiate EXT_ACK. */
    state = initial_state();
    length = append_done(packet, sizeof(packet), -EINTR);
    CHECK(length && parse_expect(&state, packet, length, -EINTR, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_done(packet, sizeof(packet), 0);
    CHECK(length && parse_expect(&state, packet, length - 1, -EPROTO,
        false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_done(packet, sizeof(packet), 0);
    CHECK(length);
    ((struct ker_member_census_nlmsghdr *)packet)->flags |= TEST_NLM_F_ACK_TLVS;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_done(packet, sizeof(packet), 0);
    CHECK(length);
    packet[length++] = 0; /* Unnegotiated/trailing extack bytes are rejected. */
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_done(packet, sizeof(packet), 0);
    CHECK(length);
    ((struct ker_member_census_nlmsghdr *)packet)->flags |=
        KER_MEMBER_CENSUS_NLM_F_DUMP_INTR;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);

    /* Header identity and accumulation overflow are rejected before publish. */
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    ((struct ker_member_census_nlmsghdr *)packet)->port_id++;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    ((struct ker_member_census_nlmsghdr *)packet)->sequence++;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    bool complete = false;
    CHECK(ker_member_census_parse_datagram(&state, packet, length, 5,
        &snapshot, &complete) == -EPROTO && !complete);
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    struct ker_member_census_diag_msg *message = (void *)(packet +
        sizeof(struct ker_member_census_nlmsghdr));
    message->source_port = htons(45679);
    CHECK(parse_expect(&state, packet, length, -ESTALE, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    ((struct ker_member_census_nlmsghdr *)packet)->flags |=
        KER_MEMBER_CENSUS_NLM_F_DUMP_INTR;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    ((struct ker_member_census_nlmsghdr *)packet)->flags = 0;
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);
    state = initial_state();
    state.rows = UINT64_MAX;
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length && parse_expect(&state, packet, length, -EOVERFLOW, false, 0, &snapshot) == 0);

    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length);
    struct ker_member_census_diag_msg *zero_cookie_message = (void *)(packet +
        sizeof(struct ker_member_census_nlmsghdr));
    memset(zero_cookie_message->cookie, 0, sizeof(zero_cookie_message->cookie));
    CHECK(parse_expect(&state, packet, length, -EPROTO, false, 0, &snapshot) == 0);

    /* Repeated Linux socket cookies in one dump are an ambiguous census. */
    state = initial_state();
    snapshot.total = 99;
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length && length * 2 <= sizeof(packet));
    memcpy(packet + length, packet, length);
    CHECK(parse_expect(&state, packet, length * 2, -EAGAIN, false, 0,
        &snapshot) == 0);
    CHECK(snapshot.total == 99);

    state = initial_state();
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length && parse_expect(&state, packet, length, 0, false, 0, &snapshot) == 0);
    length = append_row(packet, sizeof(packet), 3, request_attrs, 1);
    CHECK(length && parse_expect(&state, packet, length, -EAGAIN, false, 0,
        &snapshot) == 0);

    return 0;
}
