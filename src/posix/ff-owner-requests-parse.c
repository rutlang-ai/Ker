#include "ff-owner-requests-wire.h"
#include <errno.h>
#include <string.h>

#define NLA_TYPE_MASK 0x3fffu
#define NLA_F_NESTED 0x8000u
#define NLA_F_NET_BYTEORDER 0x4000u
#define INET_DIAG_INFO 2u
#define INET_DIAG_MARK 15u
/* sizeof(struct tcp_info) in the pinned Linux 6.12/LKL UAPI. */
#define PINNED_TCP_INFO_SIZE 248u

static int check_mark_bytecode(const struct ker_ff_owner_requests_accumulator *s,
    const unsigned char *bytes, size_t length)
{
    const size_t attr_len = sizeof(struct ker_ff_owner_requests_nlattr) + 12u;
    if (length != attr_len) return -EPROTO;
    struct ker_ff_owner_requests_nlattr attr;
    memcpy(&attr, bytes, sizeof(attr));
    if (attr.length != attr_len || attr.type != 1u) return -EPROTO;
    uint8_t code, yes;
    uint16_t no;
    uint32_t mark, mask;
    memcpy(&code, bytes + 4, 1);
    memcpy(&yes, bytes + 5, 1);
    memcpy(&no, bytes + 6, 2);
    memcpy(&mark, bytes + 8, 4);
    memcpy(&mask, bytes + 12, 4);
    if (code != 10u || yes != 12u || no != 16u ||
        mark != s->mark || mask != UINT32_MAX) return -EPROTO;
    return 0;
}

static struct ker_ff_owner_requests_diag_request expected_request(
    const struct ker_ff_owner_requests_accumulator *s)
{
    return (struct ker_ff_owner_requests_diag_request){
        .header = {.length = sizeof(struct ker_ff_owner_requests_diag_request),
            .type = KER_FF_OWNER_REQUESTS_DIAG_FAMILY,
            .flags = KER_FF_OWNER_REQUESTS_NLM_F_REQUEST |
                KER_FF_OWNER_REQUESTS_NLM_F_DUMP,
            .sequence = s->sequence, .port_id = 0},
        .request = {.family = s->family, .protocol = 6, .extensions = 0x02,
            .states = UINT32_C(1) << 3},
        .mark_attribute = {.length = sizeof(struct ker_ff_owner_requests_nlattr) + 12u,
            .type = 1u},
        .mark_instruction = {.code = 10u, .yes = 12u, .no = 16u},
        .mark_condition = {.mark = s->mark, .mask = UINT32_MAX}};
}

static int parse_row(struct ker_ff_owner_requests_accumulator *s,
    const unsigned char *payload, size_t payload_len)
{
    if (payload_len < sizeof(struct ker_ff_owner_requests_diag_msg)) return -EPROTO;
    struct ker_ff_owner_requests_diag_msg msg;
    memcpy(&msg, payload, sizeof(msg));
    if (msg.family != s->family || msg.state != 3u)
        return -ESTALE;
    bool have_mark = false, have_info = false;
    const unsigned char *cursor = payload + sizeof(msg);
    size_t remain = payload_len - sizeof(msg);
    while (remain) {
        if (remain < sizeof(struct ker_ff_owner_requests_nlattr)) return -EPROTO;
        struct ker_ff_owner_requests_nlattr attr;
        memcpy(&attr, cursor, sizeof(attr));
        if (attr.length < sizeof(attr) || attr.length > remain) return -EPROTO;
        size_t attr_payload = attr.length - sizeof(attr);
        uint16_t type = attr.type & NLA_TYPE_MASK;
        uint16_t flags = attr.type & (NLA_F_NESTED | NLA_F_NET_BYTEORDER);
        if (flags == (NLA_F_NESTED | NLA_F_NET_BYTEORDER)) return -EPROTO;
        if (type == INET_DIAG_MARK) {
            uint32_t mark;
            if (flags || have_mark || attr_payload != sizeof(mark)) return -EPROTO;
            memcpy(&mark, cursor + sizeof(attr), sizeof(mark));
            if (mark != s->mark) return -ESTALE;
            have_mark = true;
        } else if (type == INET_DIAG_INFO) {
            if (flags || have_info || attr_payload < PINNED_TCP_INFO_SIZE)
                return -EPROTO;
            have_info = true;
        }
        size_t aligned = (attr.length + 3u) & ~3u;
        if (aligned > remain) return -EPROTO;
        cursor += aligned;
        remain -= aligned;
    }
    if (!have_mark) return -EPROTO;
    if (s->rows >= KER_FF_OWNER_REQUESTS_MAX_ROWS) return -E2BIG;
    /* A full TCP socket in SYN_RECV carries requested INET_DIAG_INFO. A
     * request_sock does not. Count only the latter, including both families. */
    for (size_t i = 0; i < s->rows; ++i) {
        if (s->seen[i].family == msg.family &&
            s->seen[i].source_port == msg.source_port &&
            s->seen[i].destination_port == msg.destination_port &&
            !memcmp(s->seen[i].source_address, msg.source_address,
                sizeof(msg.source_address)) &&
            !memcmp(s->seen[i].destination_address, msg.destination_address,
                sizeof(msg.destination_address)) &&
            s->seen[i].interface_index == msg.interface_index &&
            !memcmp(s->seen[i].cookie, msg.cookie, sizeof(msg.cookie)))
            return -EAGAIN;
    }
    s->seen[s->rows].family = msg.family;
    s->seen[s->rows].source_port = msg.source_port;
    s->seen[s->rows].destination_port = msg.destination_port;
    memcpy(s->seen[s->rows].source_address, msg.source_address,
        sizeof(msg.source_address));
    memcpy(s->seen[s->rows].destination_address, msg.destination_address,
        sizeof(msg.destination_address));
    s->seen[s->rows].interface_index = msg.interface_index;
    memcpy(s->seen[s->rows].cookie, msg.cookie, sizeof(msg.cookie));
    ++s->rows;
    if (!have_info) ++s->requests;
    return 0;
}

int ker_ff_owner_requests_parse_datagram(
    struct ker_ff_owner_requests_accumulator *s, const void *buffer,
    size_t length, uint32_t sender_port_id, uint64_t *result, bool *complete)
{
    if (!s || !buffer || !length || !result || !complete || !s->mark ||
        !s->sequence || !s->local_port_id || sender_port_id != 0) return -EPROTO;
    *complete = false;
    const unsigned char *cursor = buffer;
    size_t remain = length;
    while (remain) {
        if (remain < sizeof(struct ker_ff_owner_requests_nlmsghdr)) return -EPROTO;
        struct ker_ff_owner_requests_nlmsghdr h;
        memcpy(&h, cursor, sizeof(h));
        size_t aligned = KER_FF_OWNER_REQUESTS_NLA_ALIGN(h.length);
        if (h.length < sizeof(h) || h.length > remain || aligned > remain ||
            h.sequence != s->sequence || h.port_id != s->local_port_id ||
            (h.flags & KER_FF_OWNER_REQUESTS_NLM_F_DUMP_INTR)) return -EPROTO;
        const unsigned char *payload = cursor + sizeof(h);
        size_t payload_len = h.length - sizeof(h);
        if (h.type == KER_FF_OWNER_REQUESTS_NLMSG_ERROR) {
            if (h.flags & ~(uint16_t)0x100 || payload_len <
                    sizeof(struct ker_ff_owner_requests_nlmsgerr) || aligned != remain)
                return -EPROTO;
            struct ker_ff_owner_requests_nlmsgerr err;
            memcpy(&err, payload, sizeof(err));
            struct ker_ff_owner_requests_diag_request expected = expected_request(s);
            if (err.request.sequence != s->sequence ||
                memcmp(&err.request, &expected.header, sizeof(err.request)) || err.error >= 0 ||
                err.error < -4095) return -EPROTO;
            size_t echoed = (h.flags & 0x100u) ? 0 :
                sizeof(expected) - sizeof(expected.header);
            if (payload_len != sizeof(err) + echoed) return -EPROTO;
            if (echoed) {
                const unsigned char *echo = payload + sizeof(err);
                if (memcmp(echo, (const unsigned char *)&expected +
                        sizeof(expected.header), echoed) ||
                    check_mark_bytecode(s,
                        echo + sizeof(expected.request),
                        echoed - sizeof(expected.request))) return -EPROTO;
            }
            return err.error;
        }
        if (h.type == KER_FF_OWNER_REQUESTS_NLMSG_DONE) {
            if (h.flags != KER_FF_OWNER_REQUESTS_NLM_F_MULTI ||
                payload_len != sizeof(int32_t) || aligned != remain) return -EPROTO;
            int32_t status;
            memcpy(&status, payload, sizeof(status));
            if (status > 0 || status < -4095) return -EPROTO;
            if (status) return status;
            *result = s->requests;
            *complete = true;
            return 0;
        }
        if (h.type != KER_FF_OWNER_REQUESTS_DIAG_FAMILY ||
            h.flags != KER_FF_OWNER_REQUESTS_NLM_F_MULTI) return -EPROTO;
        int status = parse_row(s, payload, payload_len);
        if (status) return status;
        cursor += aligned;
        remain -= aligned;
    }
    return 0;
}
