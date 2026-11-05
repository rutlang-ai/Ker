#ifndef KER_MPTCP_SOCKET_WIRE_H
#define KER_MPTCP_SOCKET_WIRE_H
#include <stdint.h>
/* Private same-host fixture ABI. No protocol decisions cross this channel. */
#define MS_MAGIC 0x4b4d5331U
#define MS_MAX 16384U
enum ms_operation { MS_SOCKET = 1, MS_BIND, MS_LISTEN, MS_ACCEPT, MS_CONNECT,
    MS_SETOPT, MS_GETOPT, MS_READ, MS_WRITE, MS_IOCTL, MS_RECVMSG, MS_STOP, MS_NAME, MS_PEER };
struct ms_message {
    uint32_t magic, operation, length, a, b, c;
    int64_t result;
};
_Static_assert(sizeof(struct ms_message) == 32, "private socket wire layout");
#endif
