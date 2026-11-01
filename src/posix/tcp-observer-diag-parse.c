#include "socket-broker-protocol.h"
#include "tcp-observer-diag-wire.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

static bool attributes_valid(const unsigned char *bytes, size_t length)
{
    while (length) {
        if (length < sizeof(struct ker_nlattr)) return false;
        struct ker_nlattr attribute;
        memcpy(&attribute, bytes, sizeof(attribute));
        if (attribute.length < sizeof(attribute) || attribute.length > length) return false;
        size_t aligned = KER_TCP_OBSERVER_NLA_ALIGN(attribute.length);
        if (aligned > length) return false;
        bytes += aligned;
        length -= aligned;
    }
    return true;
}

int ker_tcp_observer_parse_reply(const void *bytes, size_t length,
    uint32_t sender_port_id, uint32_t local_port_id,
    const void *expected_request, size_t expected_request_length,
    const struct ker_inet_diag_sockid *expected_identity,
    struct ker_sb_tcp_observer_snapshot *snapshot)
{
    if (!bytes || !expected_request || !expected_identity || !snapshot ||
        !local_port_id || sender_port_id != 0 ||
        expected_request_length < sizeof(struct ker_nlmsghdr) ||
        expected_request_length > UINT32_MAX || length < sizeof(struct ker_nlmsghdr))
        return -EPROTO;
    struct ker_nlmsghdr request_header;
    memcpy(&request_header, expected_request, sizeof(request_header));
    if (request_header.length != expected_request_length ||
        request_header.type != KER_TCP_OBSERVER_SOCK_DIAG_BY_FAMILY ||
        request_header.flags != KER_TCP_OBSERVER_NLM_F_REQUEST || !request_header.sequence ||
        request_header.port_id != 0) return -EPROTO;

    struct ker_nlmsghdr header;
    memcpy(&header, bytes, sizeof(header));
    if (header.sequence != request_header.sequence || header.port_id != local_port_id ||
        header.length != length || header.length < sizeof(header) ||
        KER_TCP_OBSERVER_NLA_ALIGN(header.length) != length) return -EPROTO;
    const unsigned char *payload = (const unsigned char *)bytes + sizeof(header);
    size_t payload_length = header.length - sizeof(header);

    if (header.type == KER_TCP_OBSERVER_NLMSG_ERROR) {
        if (header.flags & ~(KER_TCP_OBSERVER_NLM_F_CAPPED |
                KER_TCP_OBSERVER_NLM_F_ACK_TLVS) ||
            payload_length < sizeof(struct ker_nlmsgerr)) return -EPROTO;
        struct ker_nlmsgerr error;
        memcpy(&error, payload, sizeof(error));
        if (error.request.length != request_header.length ||
            error.request.type != request_header.type ||
            error.request.flags != request_header.flags ||
            error.request.sequence != request_header.sequence ||
            error.request.port_id != request_header.port_id) return -EPROTO;
        size_t echo_length = (header.flags & KER_TCP_OBSERVER_NLM_F_CAPPED) ? 0 :
            expected_request_length - sizeof(request_header);
        if (payload_length < sizeof(error) + echo_length) return -EPROTO;
        if (echo_length && memcmp(payload + sizeof(error),
                (const unsigned char *)expected_request + sizeof(request_header), echo_length))
            return -EPROTO;
        size_t attributes_length = payload_length - sizeof(error) - echo_length;
        if (header.flags & KER_TCP_OBSERVER_NLM_F_ACK_TLVS) {
            if (!attributes_valid(payload + sizeof(error) + echo_length, attributes_length))
                return -EPROTO;
        } else if (attributes_length) return -EPROTO;
        if (error.error == -ENOENT) {
            *snapshot = (struct ker_sb_tcp_observer_snapshot){
                .cookie = ((uint64_t)expected_identity->cookie[1] << 32) |
                    expected_identity->cookie[0], .present = 0};
            return 0;
        }
        if (error.error >= 0 || error.error < -4095) return -EPROTO;
        return error.error;
    }

    if (header.type != KER_TCP_OBSERVER_SOCK_DIAG_BY_FAMILY || header.flags ||
        payload_length < sizeof(struct ker_inet_diag_msg)) return -EPROTO;
    struct ker_inet_diag_msg message;
    memcpy(&message, payload, sizeof(message));
    if (!attributes_valid(payload + sizeof(message), payload_length - sizeof(message)))
        return -EPROTO;
    if (message.family != AF_INET || message.state < 1 || message.state > 13 ||
        message.id.cookie[0] != expected_identity->cookie[0] ||
        message.id.cookie[1] != expected_identity->cookie[1] ||
        message.id.sport != expected_identity->sport ||
        message.id.dport != expected_identity->dport ||
        message.id.src[0] != expected_identity->src[0] ||
        message.id.src[1] || message.id.src[2] || message.id.src[3] ||
        message.id.dst[0] != expected_identity->dst[0] ||
        message.id.dst[1] || message.id.dst[2] || message.id.dst[3]) return -ESTALE;
    *snapshot = (struct ker_sb_tcp_observer_snapshot){
        .cookie = ((uint64_t)expected_identity->cookie[1] << 32) |
            expected_identity->cookie[0],
        .receive_queue = message.receive_queue,
        .send_queue = message.send_queue,
        .state = message.state,
        .present = 1};
    return 0;
}
