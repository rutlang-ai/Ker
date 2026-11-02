#ifndef KER_FF_OWNER_REQUESTS_WIRE_H
#define KER_FF_OWNER_REQUESTS_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KER_FF_OWNER_REQUESTS_DIAG_FAMILY 20u
#define KER_FF_OWNER_REQUESTS_NLMSG_ERROR 2u
#define KER_FF_OWNER_REQUESTS_NLMSG_DONE 3u
#define KER_FF_OWNER_REQUESTS_NLM_F_REQUEST 0x01u
#define KER_FF_OWNER_REQUESTS_NLM_F_MULTI 0x02u
#define KER_FF_OWNER_REQUESTS_NLM_F_DUMP 0x300u
#define KER_FF_OWNER_REQUESTS_NLM_F_DUMP_INTR 0x10u
#define KER_FF_OWNER_REQUESTS_NLA_ALIGN(n) (((n) + 3u) & ~3u)
#define KER_FF_OWNER_REQUESTS_MAX_ROWS 4096u
#define KER_FF_OWNER_REQUESTS_MAX_BYTES (1024u * 1024u)

struct ker_ff_owner_requests_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} __attribute__((packed));

struct ker_ff_owner_requests_nlmsgerr {
    int32_t error;
    struct ker_ff_owner_requests_nlmsghdr request;
} __attribute__((packed));

struct ker_ff_owner_requests_nlattr {
    uint16_t length;
    uint16_t type;
} __attribute__((packed));

struct ker_ff_owner_requests_diag_msg {
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

struct ker_ff_owner_requests_diag_request {
    struct ker_ff_owner_requests_nlmsghdr header;
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
    struct ker_ff_owner_requests_nlattr mark_attribute;
    struct { uint8_t code; uint8_t yes; uint16_t no; } __attribute__((packed)) mark_instruction;
    struct { uint32_t mark; uint32_t mask; } __attribute__((packed)) mark_condition;
} __attribute__((packed));

struct ker_ff_owner_requests_accumulator {
    uint32_t mark;
    uint32_t sequence;
    uint32_t local_port_id;
    uint8_t family;
    uint64_t rows;
    uint64_t requests;
    struct {
        uint8_t family;
        uint16_t source_port;
        uint16_t destination_port;
        uint32_t source_address[4];
        uint32_t destination_address[4];
        uint32_t interface_index;
        uint32_t cookie[2];
    } seen[KER_FF_OWNER_REQUESTS_MAX_ROWS];
};

int ker_ff_owner_requests_parse_datagram(
    struct ker_ff_owner_requests_accumulator *state, const void *bytes,
    size_t length, uint32_t sender_port_id, uint64_t *complete_count,
    bool *complete);

#endif
