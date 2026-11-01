#include "socket-broker-protocol.h"
#include "tcp-observer-diag-wire.h"
#include <stddef.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>

_Static_assert(sizeof(struct ker_inet_diag_sockid) == sizeof(struct inet_diag_sockid),
    "sockid must match the pinned Linux UAPI");
_Static_assert(offsetof(struct ker_inet_diag_sockid, cookie) ==
    offsetof(struct inet_diag_sockid, idiag_cookie), "cookie offset must match");
_Static_assert(sizeof(struct ker_inet_diag_req_v2) == sizeof(struct inet_diag_req_v2),
    "request must match the pinned Linux UAPI");
_Static_assert(offsetof(struct ker_inet_diag_req_v2, id) ==
    offsetof(struct inet_diag_req_v2, id), "request identity offset must match");
_Static_assert(sizeof(struct ker_inet_diag_msg) == sizeof(struct inet_diag_msg),
    "message must match the pinned Linux UAPI");
_Static_assert(offsetof(struct ker_inet_diag_msg, receive_queue) ==
    offsetof(struct inet_diag_msg, idiag_rqueue), "receive queue offset must match");
_Static_assert(offsetof(struct ker_inet_diag_msg, send_queue) ==
    offsetof(struct inet_diag_msg, idiag_wqueue), "send queue offset must match");
_Static_assert(SOCK_DIAG_BY_FAMILY == KER_TCP_OBSERVER_SOCK_DIAG_BY_FAMILY,
    "request type must match the pinned Linux UAPI");
_Static_assert(sizeof(struct ker_nlmsghdr) == sizeof(struct nlmsghdr),
    "netlink header must match the pinned Linux UAPI");
_Static_assert(offsetof(struct ker_nlmsghdr, sequence) ==
    offsetof(struct nlmsghdr, nlmsg_seq), "netlink sequence offset must match");
_Static_assert(offsetof(struct ker_nlmsghdr, port_id) ==
    offsetof(struct nlmsghdr, nlmsg_pid), "netlink port offset must match");
_Static_assert(sizeof(struct ker_nlmsgerr) == sizeof(struct nlmsgerr),
    "netlink error must match the pinned Linux UAPI");
_Static_assert(offsetof(struct ker_nlmsgerr, request) ==
    offsetof(struct nlmsgerr, msg), "netlink error request offset must match");
_Static_assert(sizeof(struct ker_nlattr) == sizeof(struct nlattr),
    "netlink attribute header must match the pinned Linux UAPI");
_Static_assert(sizeof(struct sockaddr_nl) == 12,
    "netlink socket address must match the pinned Linux UAPI");

int main(void) { return 0; }
