#ifndef KER_MEMBER_CENSUS_DIAG_WIRE_H
#define KER_MEMBER_CENSUS_DIAG_WIRE_H

#include <ker/socket-broker.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST 20u
#define KER_MEMBER_CENSUS_TCP_SYN_RECV 3u
#define KER_MEMBER_CENSUS_TCP_TIME_WAIT 6u
#define KER_MEMBER_CENSUS_TCP_LISTEN 10u
#define KER_MEMBER_CENSUS_NETLINK_PROTOCOL 4
#define KER_MEMBER_CENSUS_NLM_F_REQUEST 0x01u
#define KER_MEMBER_CENSUS_NLM_F_MULTI 0x02u
#define KER_MEMBER_CENSUS_NLM_F_DUMP 0x300u
#define KER_MEMBER_CENSUS_NLM_F_DUMP_INTR 0x10u
#define KER_MEMBER_CENSUS_NLMSG_ERROR 2u
#define KER_MEMBER_CENSUS_NLMSG_DONE 3u
#define KER_MEMBER_CENSUS_NLA_ALIGN(value) (((value) + 3u) & ~3u)
#define KER_MEMBER_CENSUS_IN_DIAG_REQ_BYTECODE 1u
#define KER_MEMBER_CENSUS_IN_DIAG_SHUTDOWN 8u
#define KER_MEMBER_CENSUS_IN_DIAG_PAD 14u
#define KER_MEMBER_CENSUS_IN_DIAG_MARK 15u
#define KER_MEMBER_CENSUS_IN_DIAG_CLASS_ID 17u
#define KER_MEMBER_CENSUS_IN_DIAG_CGROUP_ID 21u
#define KER_MEMBER_CENSUS_IN_DIAG_SOCKOPT 22u
#define KER_MEMBER_CENSUS_IN_DIAG_BC_MARK_COND 10u
#define KER_MEMBER_CENSUS_NLA_F_NESTED 0x8000u
#define KER_MEMBER_CENSUS_NLA_F_NET_BYTEORDER 0x4000u
#define KER_MEMBER_CENSUS_NLA_TYPE_MASK 0x3fffu
#define KER_MEMBER_CENSUS_MAX_ROWS 65536u
#define KER_MEMBER_CENSUS_COOKIE_HASH_SLOTS 131072u

struct ker_member_census_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} __attribute__((packed));

struct ker_member_census_nlmsgerr {
    int32_t error;
    struct ker_member_census_nlmsghdr request;
} __attribute__((packed));

struct ker_member_census_nlattr {
    uint16_t length;
    uint16_t type;
} __attribute__((packed));

struct ker_member_census_diag_msg {
    uint8_t family;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmits;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t source_address[4];
    uint32_t destination_address[4];
    uint32_t interface_index;
    uint32_t cookie[2];
    uint32_t expires;
    uint32_t receive_queue;
    uint32_t send_queue;
    uint32_t uid;
    uint32_t inode;
} __attribute__((packed));

struct ker_member_census_diag_request {
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
    struct { uint8_t code; uint8_t yes; uint16_t no; } __attribute__((packed)) mark_instruction;
    struct { uint32_t mark; uint32_t mask; } __attribute__((packed)) condition;
} __attribute__((packed));

struct ker_member_census_accumulator {
    uint32_t mark;
    uint16_t local_port;
    uint32_t sequence;
    uint32_t local_port_id;
    uint64_t listener_cookie;
    bool expect_no_listener;
    uint64_t rows;
    uint64_t total;
    uint64_t state_counts[KER_SOCKET_BROKER_TCP_STATES];
    bool listener_seen;
    uint64_t *seen_cookies;
    size_t seen_cookie_capacity;
};

/* Consume one complete kernel-originated datagram. `snapshot` is written only
 * after a valid NLMSG_DONE; partial counts stay private on every error. */
int ker_member_census_parse_datagram(struct ker_member_census_accumulator *state,
    const void *bytes, size_t length, uint32_t sender_port_id,
    struct ker_socket_member_census_snapshot *complete_snapshot, bool *complete);

/* Only an actual nonblocking receive with no datagram is pending. A parser
 * error such as duplicate-cookie -EAGAIN must remain a query failure. */
int ker_member_census_receive_status(bool would_block, int parse_status);

#endif
