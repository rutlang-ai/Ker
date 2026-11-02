#include "member-census-diag-wire.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

static int remember_cookie(struct ker_member_census_accumulator *state,
    const struct ker_member_census_diag_msg *message)
{
    if (!state->seen_cookies || state->seen_cookie_capacity < 2 ||
        (state->seen_cookie_capacity & (state->seen_cookie_capacity - 1)))
        return -EINVAL;
    uint64_t cookie = ((uint64_t)message->cookie[1] << 32) | message->cookie[0];
    if (!cookie) return -EPROTO;
    uint64_t mixed = cookie;
    mixed ^= mixed >> 30;
    mixed *= UINT64_C(0xbf58476d1ce4e5b9);
    mixed ^= mixed >> 27;
    mixed *= UINT64_C(0x94d049bb133111eb);
    mixed ^= mixed >> 31;
    size_t slot = (size_t)mixed & (state->seen_cookie_capacity - 1);
    for (size_t probe = 0; probe < state->seen_cookie_capacity; ++probe) {
        uint64_t previous = state->seen_cookies[slot];
        if (!previous) {
            state->seen_cookies[slot] = cookie;
            return 0;
        }
        if (previous == cookie) return -EAGAIN;
        slot = (slot + 1) & (state->seen_cookie_capacity - 1);
    }
    return -E2BIG;
}

static struct ker_member_census_diag_request expected_request(
    const struct ker_member_census_accumulator *state)
{
    return (struct ker_member_census_diag_request){
        .header = {.length = sizeof(struct ker_member_census_diag_request),
            .type = KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST,
            .flags = KER_MEMBER_CENSUS_NLM_F_REQUEST | KER_MEMBER_CENSUS_NLM_F_DUMP,
            .sequence = state->sequence, .port_id = 0},
        .request = {.family = 2, .protocol = 6, .states = UINT32_MAX,
            .id = {.source_port = htons(state->local_port)}},
        .bytecode_attribute = {.length = sizeof(struct ker_member_census_nlattr) +
            4u + 8u, .type = KER_MEMBER_CENSUS_IN_DIAG_REQ_BYTECODE},
        .mark_instruction = {.code = KER_MEMBER_CENSUS_IN_DIAG_BC_MARK_COND,
            .yes = 12, .no = 16},
        .condition = {.mark = state->mark, .mask = UINT32_MAX}};
}

int ker_member_census_receive_status(bool would_block, int parse_status)
{
    return would_block ? 0 : parse_status;
}

static int validate_nested_attributes(const unsigned char *bytes, size_t length,
    unsigned depth)
{
    if (depth > 8) return -E2BIG;
    while (length) {
        if (length < sizeof(struct ker_member_census_nlattr)) return -EPROTO;
        struct ker_member_census_nlattr attribute;
        memcpy(&attribute, bytes, sizeof(attribute));
        if (attribute.length < sizeof(attribute) || attribute.length > length)
            return -EPROTO;
        uint16_t flags = attribute.type & (KER_MEMBER_CENSUS_NLA_F_NESTED |
            KER_MEMBER_CENSUS_NLA_F_NET_BYTEORDER);
        if (flags == (KER_MEMBER_CENSUS_NLA_F_NESTED |
                KER_MEMBER_CENSUS_NLA_F_NET_BYTEORDER)) return -EPROTO;
        size_t payload_length = attribute.length - sizeof(attribute);
        size_t aligned = KER_MEMBER_CENSUS_NLA_ALIGN(attribute.length);
        if (aligned > length) return -EPROTO;
        if ((flags & KER_MEMBER_CENSUS_NLA_F_NESTED) &&
            validate_nested_attributes(bytes + sizeof(attribute), payload_length,
                depth + 1)) return -EPROTO;
        bytes += aligned;
        length -= aligned;
    }
    return 0;
}

static int parse_attributes(const unsigned char *bytes, size_t length,
    uint32_t expected_mark, bool sparse_state)
{
    bool found_mark = false;
    bool found_shutdown = false;
    bool found_sockopt = false;
    bool found_class_id = false;
    bool found_cgroup_id = false;
    bool found_pad = false;
    while (length) {
        if (length < sizeof(struct ker_member_census_nlattr)) return -EPROTO;
        struct ker_member_census_nlattr attribute;
        memcpy(&attribute, bytes, sizeof(attribute));
        if (attribute.length < sizeof(attribute) || attribute.length > length) return -EPROTO;
        size_t payload_length = attribute.length - sizeof(attribute);
        uint16_t type = attribute.type & KER_MEMBER_CENSUS_NLA_TYPE_MASK;
        uint16_t flags = attribute.type & (KER_MEMBER_CENSUS_NLA_F_NESTED |
            KER_MEMBER_CENSUS_NLA_F_NET_BYTEORDER);
        if (flags == (KER_MEMBER_CENSUS_NLA_F_NESTED |
                KER_MEMBER_CENSUS_NLA_F_NET_BYTEORDER)) return -EPROTO;
        const unsigned char *payload = bytes + sizeof(attribute);
        switch (type) {
        case KER_MEMBER_CENSUS_IN_DIAG_SHUTDOWN:
            if (flags || found_shutdown || payload_length != sizeof(uint8_t))
                return -EPROTO;
            found_shutdown = true;
            break;
        case KER_MEMBER_CENSUS_IN_DIAG_MARK: {
            if (flags || found_mark || payload_length != sizeof(uint32_t))
                return -EPROTO;
            uint32_t mark;
            memcpy(&mark, payload, sizeof(mark));
            if (mark != expected_mark) return -ESTALE;
            found_mark = true;
            break;
        }
        case KER_MEMBER_CENSUS_IN_DIAG_SOCKOPT:
            if (flags || found_sockopt || payload_length != 2) return -EPROTO;
            found_sockopt = true;
            break;
        case KER_MEMBER_CENSUS_IN_DIAG_CLASS_ID:
            if (flags || found_class_id || payload_length != sizeof(uint32_t))
                return -EPROTO;
            found_class_id = true;
            break;
        case KER_MEMBER_CENSUS_IN_DIAG_CGROUP_ID:
            if (flags || found_cgroup_id || payload_length != sizeof(uint64_t))
                return -EPROTO;
            found_cgroup_id = true;
            break;
        case KER_MEMBER_CENSUS_IN_DIAG_PAD:
            if (flags || found_pad || payload_length != 0) return -EPROTO;
            found_pad = true;
            break;
        default:
            /* Future kernel attributes are ignored only after their outer
             * netlink framing has been validated. No payload escapes. */
            if (flags & KER_MEMBER_CENSUS_NLA_F_NESTED) {
                int nested_status = validate_nested_attributes(payload,
                    payload_length, 1);
                if (nested_status) return nested_status;
            }
            break;
        }
        size_t aligned = KER_MEMBER_CENSUS_NLA_ALIGN(attribute.length);
        if (aligned > length) return -EPROTO;
        bytes += aligned;
        length -= aligned;
    }
    if (!found_mark || found_shutdown != found_sockopt) return -EPROTO;
    return (found_shutdown && found_sockopt) || sparse_state ? 0 : -EPROTO;
}

int ker_member_census_parse_datagram(struct ker_member_census_accumulator *state,
    const void *bytes, size_t length, uint32_t sender_port_id,
    struct ker_socket_member_census_snapshot *complete_snapshot, bool *complete)
{
    if (complete) *complete = false;
    if (!state || !bytes || !complete_snapshot || !complete || !state->mark ||
        !state->local_port || !state->sequence || !state->local_port_id ||
        (!state->listener_cookie && !state->expect_no_listener) ||
        (state->listener_cookie && state->expect_no_listener) ||
        sender_port_id != 0 || !length) return -EPROTO;
    *complete = false;
    const unsigned char *cursor = bytes;
    size_t remaining = length;
    while (remaining) {
        if (remaining < sizeof(struct ker_member_census_nlmsghdr)) return -EPROTO;
        struct ker_member_census_nlmsghdr header;
        memcpy(&header, cursor, sizeof(header));
        if (header.length < sizeof(header) || header.length > remaining ||
            KER_MEMBER_CENSUS_NLA_ALIGN(header.length) > remaining ||
            header.sequence != state->sequence || header.port_id != state->local_port_id ||
            (header.flags & KER_MEMBER_CENSUS_NLM_F_DUMP_INTR)) return -EPROTO;
        size_t payload_length = header.length - sizeof(header);
        const unsigned char *payload = cursor + sizeof(header);
        size_t aligned_length = KER_MEMBER_CENSUS_NLA_ALIGN(header.length);

        if (header.type == KER_MEMBER_CENSUS_NLMSG_ERROR) {
            if (header.flags & ~(uint16_t)0x100 ||
                payload_length < sizeof(struct ker_member_census_nlmsgerr) ||
                aligned_length != remaining)
                return -EPROTO;
            struct ker_member_census_nlmsgerr error;
            memcpy(&error, payload, sizeof(error));
            struct ker_member_census_diag_request expected = expected_request(state);
            if (memcmp(&error.request, &expected.header, sizeof(error.request)) ||
                error.error >= 0 || error.error < -4095)
                return -EPROTO;
            size_t echo_length = (header.flags & 0x100) ? 0 :
                sizeof(struct ker_member_census_diag_request) -
                    sizeof(struct ker_member_census_nlmsghdr);
            if (payload_length != sizeof(error) + echo_length) return -EPROTO;
            if (echo_length && memcmp(payload + sizeof(error),
                    (const unsigned char *)&expected + sizeof(expected.header),
                    echo_length)) return -EPROTO;
            return error.error;
        }

        if (header.type == KER_MEMBER_CENSUS_NLMSG_DONE) {
            if (header.flags != KER_MEMBER_CENSUS_NLM_F_MULTI ||
                payload_length != sizeof(int32_t) || aligned_length != remaining)
                return -EPROTO;
            int32_t status;
            memcpy(&status, payload, sizeof(status));
            if (status > 0 || status < -4095) return -EPROTO;
            if (status) return status;
            if (state->total != state->rows ||
                (!state->listener_cookie && !state->expect_no_listener))
                return -EPROTO;
            struct ker_socket_member_census_snapshot result = {
                .total = state->total,
                .listener_cookie = state->listener_cookie};
            memcpy(result.state_counts, state->state_counts, sizeof(result.state_counts));
            *complete_snapshot = result;
            *complete = true;
            return 0;
        }

        if (header.type != KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST ||
            header.flags != KER_MEMBER_CENSUS_NLM_F_MULTI ||
            payload_length < sizeof(struct ker_member_census_diag_msg)) return -EPROTO;
        struct ker_member_census_diag_msg message;
        memcpy(&message, payload, sizeof(message));
        if (message.family != 2 /* AF_INET */ || message.state == 0 ||
            message.state >= KER_SOCKET_BROKER_TCP_STATES ||
            message.source_port != htons(state->local_port)) return -ESTALE;
        int attr_status = parse_attributes(payload + sizeof(message),
            payload_length - sizeof(message), state->mark,
            message.state == KER_MEMBER_CENSUS_TCP_SYN_RECV ||
                message.state == KER_MEMBER_CENSUS_TCP_TIME_WAIT);
        if (attr_status) return attr_status;
        int identity_status = remember_cookie(state, &message);
        if (identity_status) return identity_status;
        if (message.state == KER_MEMBER_CENSUS_TCP_LISTEN) {
            uint64_t cookie = ((uint64_t)message.cookie[1] << 32) | message.cookie[0];
            if (state->expect_no_listener || !state->listener_cookie ||
                cookie != state->listener_cookie || state->listener_seen)
                return -ESTALE;
            state->listener_seen = true;
        }
        if (state->rows == UINT64_MAX || state->total == UINT64_MAX ||
            state->state_counts[message.state] == UINT64_MAX) return -EOVERFLOW;
        ++state->rows;
        ++state->total;
        ++state->state_counts[message.state];
        cursor += aligned_length;
        remaining -= aligned_length;
    }
    return 0;
}
