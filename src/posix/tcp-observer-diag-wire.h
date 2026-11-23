#ifndef KER_TCP_OBSERVER_DIAG_WIRE_H
#define KER_TCP_OBSERVER_DIAG_WIRE_H

/* Fixed-width Ker namespaced copy of the pinned Linux INET_DIAG v2 UAPI
 * records. Layout is checked against the unmodified pinned headers by the
 * tcp-observer-diag-layout fixture. */
#include <stdint.h>
#include <stddef.h>

#define KER_TCP_OBSERVER_SOCK_DIAG_BY_FAMILY 20
#define KER_TCP_OBSERVER_PROTOCOL_TCP 6
#define KER_TCP_OBSERVER_NETLINK_PROTOCOL 4
#define KER_TCP_OBSERVER_NLM_F_REQUEST 0x01
#define KER_TCP_OBSERVER_NLM_F_MULTI 0x02
#define KER_TCP_OBSERVER_NLM_F_CAPPED 0x100
#define KER_TCP_OBSERVER_NLM_F_ACK_TLVS 0x200
#define KER_TCP_OBSERVER_NLMSG_ERROR 2
#define KER_TCP_OBSERVER_NLA_ALIGN(value) (((value) + 3u) & ~3u)

struct ker_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} __attribute__((packed));

struct ker_nlmsgerr {
    int32_t error;
    struct ker_nlmsghdr request;
} __attribute__((packed));

struct ker_nlattr {
    uint16_t length;
    uint16_t type;
} __attribute__((packed));

struct ker_inet_diag_sockid {
    uint16_t sport;
    uint16_t dport;
    uint32_t src[4];
    uint32_t dst[4];
    uint32_t interface_index;
    uint32_t cookie[2];
} __attribute__((packed));

struct ker_inet_diag_req_v2 {
    uint8_t family;
    uint8_t protocol;
    uint8_t extensions;
    uint8_t pad;
    uint32_t states;
    struct ker_inet_diag_sockid id;
} __attribute__((packed));

struct ker_inet_diag_msg {
    uint8_t family;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmits;
    struct ker_inet_diag_sockid id;
    uint32_t expires;
    uint32_t receive_queue;
    uint32_t send_queue;
    uint32_t uid;
    uint32_t inode;
} __attribute__((packed));

struct ker_sb_tcp_observer_snapshot;
int ker_tcp_observer_parse_reply(const void *bytes, size_t length,
    uint32_t sender_port_id, uint32_t local_port_id,
    const void *expected_request, size_t expected_request_length,
    const struct ker_inet_diag_sockid *expected_identity,
    struct ker_sb_tcp_observer_snapshot *snapshot);

#endif
