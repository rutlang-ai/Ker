#ifndef KER_SOCKET_BROKER_PROTOCOL_H
#define KER_SOCKET_BROKER_PROTOCOL_H
#include <ker/socket-broker.h>
#include <netinet/in.h>
#include <stdint.h>

#define KER_SB_MAGIC UINT32_C(0x4b534252)
#define KER_SB_VERSION 2
#define KER_SB_MAX_PACKET (KER_SOCKET_BROKER_IO_MAX + 512)
#define KER_SB_MAX_RIGHTS 2
#define KER_SB_CLIENTS 32
#define KER_SB_OBJECTS 256
#define KER_SB_PATH_MAX 107

enum ker_sb_operation {
    KER_SB_SOCKET = 1, KER_SB_BIND, KER_SB_CONNECT, KER_SB_LISTEN,
    KER_SB_ACCEPT4, KER_SB_READ, KER_SB_WRITE, KER_SB_SHUTDOWN,
    KER_SB_GETSOCKNAME, KER_SB_GETPEERNAME, KER_SB_SETSOCKOPT,
    KER_SB_GETSOCKOPT, KER_SB_EPOLL_CREATE1, KER_SB_EPOLL_CTL,
    KER_SB_EPOLL_WAIT, KER_SB_DESCRIBE, KER_SB_DUP, KER_SB_GETFL,
    KER_SB_SETFL, KER_SB_FIONBIO, KER_SB_FIONREAD, KER_SB_SEND, KER_SB_RECV,
    KER_SB_REUSEPORT_GROUP_CREATE, KER_SB_REUSEPORT_GROUP_MEMBER,
    KER_SB_REUSEPORT_GROUP_SELECT,
    KER_SB_TCP_OBSERVER_CREATE = 32,
    KER_SB_TCP_OBSERVER_SNAPSHOT = 33,
    KER_SB_MEMBER_CENSUS_CREATE = 40,
    KER_SB_MEMBER_CENSUS_SNAPSHOT = 41,
    KER_SB_MEMBER_PAYLOAD_SNAPSHOT = 42,
    KER_SB_FF_OWNER_CREATE = 43,
    KER_SB_FF_OWNER_SOCKET = 44,
    KER_SB_FF_OWNER_MATCH = 45,
    KER_SB_FF_OWNER_PAYLOAD = 46,
    KER_SB_FF_OWNER_REQUESTS = 47,
    KER_SB_FF_OWNER_ADMISSION_PREPARE = 48,
    KER_SB_FF_OWNER_ADMISSION_RETIRE = 49,
    KER_SB_FF_OWNER_ADMISSION_REARM = 50,
    KER_SB_FF_OWNER_ADMISSION_STATUS = 51,
    KER_SB_FF_OWNER_GROUP_PLAN = 52,
    KER_SB_FF_OWNER_GROUP_SLOT = 53,
    KER_SB_FF_OWNER_GROUP_CLAIM = 54,
    KER_SB_FF_OWNER_GROUP_PUBLISH = 55,
    KER_SB_FF_OWNER_GROUP_MEMBER = 56,
    KER_SB_FF_OWNER_GROUP_STAGED_PLAN = 57,
    KER_SB_FF_OWNER_GROUP_PUBLISH_INITIAL = 58,
    KER_SB_FF_OWNER_GROUP_PUBLISH_CANDIDATE = 59,
    KER_SB_FF_OWNER_GROUP_ACTIVATE_INITIAL = 60,
    KER_SB_FF_OWNER_GROUP_CONTROL = 61,
    KER_SB_FF_OWNER_GROUP_CONTROL_AFTER_EXIT = 62
};

struct ker_sb_header {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t payload_length;
    uint16_t rights_count;
    uint16_t flags;
    uint64_t sequence;
    int64_t result;
} __attribute__((packed));

struct ker_sb_socket_args { int32_t domain, type, protocol; } __attribute__((packed));
struct ker_sb_address { uint32_t length; unsigned char bytes[128]; } __attribute__((packed));
struct ker_sb_integer { int32_t value; } __attribute__((packed));
struct ker_sb_option { int32_t level, option; uint32_t length; } __attribute__((packed));
struct ker_sb_epoll_create { int32_t flags; } __attribute__((packed));
struct ker_sb_epoll_ctl { int32_t operation; uint32_t has_event; struct epoll_event event; } __attribute__((packed));
struct ker_sb_epoll_wait { int32_t maxevents; } __attribute__((packed));
struct ker_sb_describe { int32_t kind, flags; } __attribute__((packed));
struct ker_sb_io { int32_t flags; uint32_t length; } __attribute__((packed));
struct ker_sb_reuseport_group_create { unsigned char address[sizeof(struct sockaddr_in)]; int32_t backlog; } __attribute__((packed));
struct ker_sb_reuseport_group_member { uint32_t index; } __attribute__((packed));
struct ker_sb_tcp_observer_snapshot {
    uint64_t cookie;
    uint32_t receive_queue;
    uint32_t send_queue;
    uint8_t state;
    uint8_t present;
    uint8_t reserved[2];
} __attribute__((packed));
struct ker_sb_member_census_create { uint32_t index; } __attribute__((packed));
enum ker_sb_member_census_flags {
    KER_SB_MEMBER_CENSUS_EXPECT_NO_LISTENER = 1u << 0
};
struct ker_sb_member_census_snapshot {
    uint64_t total;
    uint64_t state_counts[KER_SOCKET_BROKER_TCP_STATES];
    uint64_t listener_cookie;
    uint32_t flags;
    uint32_t reserved;
} __attribute__((packed));
struct ker_sb_member_payload_snapshot {
    uint64_t payload_bytes;
    uint64_t sampled_sockets;
} __attribute__((packed));
struct ker_sb_ff_owner_requests { uint64_t request_count; } __attribute__((packed));
/* Private owner-control attachment response. `registration_id` is a one-use
 * broker registration, not a mark or a caller-selected identity. */
struct ker_sb_ff_owner_admission_prepare {
    char endpoint_path[KER_SOCKET_BROKER_PATH_MAX + 1];
    uint64_t registration_id;
    uint32_t reserved;
} __attribute__((packed));
struct ker_sb_ff_owner_admission_window {
    uint32_t state;
    uint32_t reserved;
    uint64_t queue_lease;
    uint64_t epoch;
    int32_t status;
    uint32_t reserved2;
} __attribute__((packed));
struct ker_sb_ff_owner_group_plan {
    unsigned char address[sizeof(struct sockaddr_in)];
    int32_t backlog;
    uint32_t group_rights;
} __attribute__((packed));
struct ker_sb_ff_owner_group_slot {
    uint32_t index;
    uint32_t reserved;
} __attribute__((packed));
#define KER_SB_MAX_REQUEST (KER_SOCKET_BROKER_IO_MAX + sizeof(struct ker_sb_io))

#endif
