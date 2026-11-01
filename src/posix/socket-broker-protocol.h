#ifndef KER_SOCKET_BROKER_PROTOCOL_H
#define KER_SOCKET_BROKER_PROTOCOL_H
#include <ker/socket-broker.h>
#include <stdint.h>

#define KER_SB_MAGIC UINT32_C(0x4b534252)
#define KER_SB_VERSION 1
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
    KER_SB_EPOLL_WAIT
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

#endif
