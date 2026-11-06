#ifndef KER_MPTCP_SOCKET_WIRE_H
#define KER_MPTCP_SOCKET_WIRE_H
#include <stdint.h>
/* Private same-host fixture ABI. No protocol decisions cross this channel. */
#define MS_MAGIC 0x4b4d5331U
#define MS_MAX 131072U
enum ms_operation { MS_SOCKET = 1, MS_BIND, MS_LISTEN, MS_ACCEPT, MS_CONNECT,
    MS_SETOPT, MS_GETOPT, MS_READ, MS_WRITE, MS_IOCTL, MS_RECVMSG, MS_STOP, MS_NAME, MS_PEER,
    MS_FCNTL, MS_POLL, MS_SHUTDOWN, MS_SENDMSG, MS_NEWNS, MS_DELNS, MS_UP, MS_SYSCTL,
    MS_FILE, MS_PIDS, MS_STATUS, MS_LISTNS, MS_NS_FD, MS_IFINDEX, MS_FILE_CHUNK, MS_SENDFILE };
struct ms_io { uint32_t data, control, name, flags; };
_Static_assert(sizeof(struct ms_io) == 16, "private message wire layout");
struct ms_message {
    uint32_t magic, operation, length, a, b, c;
    int64_t result;
};
_Static_assert(sizeof(struct ms_message) == 32, "private socket wire layout");
#endif
