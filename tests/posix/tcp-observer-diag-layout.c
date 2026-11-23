#include "socket-broker-protocol.h"
#include "tcp-observer-diag-wire.h"
#include "member-census-diag-wire.h"
#include <stddef.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <net/tcp_states.h>

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
_Static_assert(sizeof(struct ker_member_census_nlmsghdr) == sizeof(struct nlmsghdr),
    "member census netlink header must match pinned UAPI");
_Static_assert(sizeof(struct ker_member_census_nlattr) == sizeof(struct nlattr),
    "member census attribute header must match pinned UAPI");
_Static_assert(sizeof(struct ker_member_census_diag_msg) == sizeof(struct inet_diag_msg),
    "member census TCP row must match pinned UAPI");
_Static_assert(offsetof(struct ker_member_census_diag_msg, state) ==
    offsetof(struct inet_diag_msg, idiag_state), "TCP state offset must match");
_Static_assert(offsetof(struct ker_member_census_diag_msg, source_port) ==
    offsetof(struct inet_diag_msg, id.idiag_sport), "local port offset must match");
_Static_assert(offsetof(struct ker_member_census_diag_msg, cookie) ==
    offsetof(struct inet_diag_msg, id.idiag_cookie) &&
    sizeof(((struct ker_member_census_diag_msg *)0)->cookie) ==
        sizeof(((struct inet_diag_msg *)0)->id.idiag_cookie),
    "socket cookie identity must match");
_Static_assert(offsetof(struct ker_member_census_diag_msg, inode) ==
    offsetof(struct inet_diag_msg, idiag_inode), "inode offset must match");
_Static_assert(KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST == SOCK_DIAG_BY_FAMILY,
    "member census request type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_NETLINK_PROTOCOL == NETLINK_SOCK_DIAG,
    "member census netlink protocol must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_NLM_F_REQUEST == NLM_F_REQUEST &&
    KER_MEMBER_CENSUS_NLM_F_MULTI == NLM_F_MULTI &&
    KER_MEMBER_CENSUS_NLM_F_DUMP == NLM_F_DUMP &&
    KER_MEMBER_CENSUS_NLM_F_DUMP_INTR == NLM_F_DUMP_INTR,
    "member census dump flags must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_NLMSG_ERROR == NLMSG_ERROR &&
    KER_MEMBER_CENSUS_NLMSG_DONE == NLMSG_DONE,
    "member census terminal message types must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_TCP_SYN_RECV == TCP_SYN_RECV &&
    KER_MEMBER_CENSUS_TCP_TIME_WAIT == TCP_TIME_WAIT &&
    KER_MEMBER_CENSUS_TCP_LISTEN == TCP_LISTEN,
    "sparse TCP row states must match pinned UAPI");
#define KER_CENSUS_STATE_EQ(public_state, linux_state) \
    ((int)(public_state) == (int)(linux_state))
_Static_assert(KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_ESTABLISHED, TCP_ESTABLISHED) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_SYN_SENT, TCP_SYN_SENT) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_SYN_RECV, TCP_SYN_RECV) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_FIN_WAIT1, TCP_FIN_WAIT1) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_FIN_WAIT2, TCP_FIN_WAIT2) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_TIME_WAIT, TCP_TIME_WAIT) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_CLOSE, TCP_CLOSE) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_CLOSE_WAIT, TCP_CLOSE_WAIT) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_LAST_ACK, TCP_LAST_ACK) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_LISTEN, TCP_LISTEN) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_CLOSING, TCP_CLOSING) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_NEW_SYN_RECV, TCP_NEW_SYN_RECV) &&
    KER_CENSUS_STATE_EQ(KER_SOCKET_TCP_STATE_BOUND_INACTIVE, TCP_BOUND_INACTIVE),
    "public TCP census indexes must match the pinned original state enum");
#undef KER_CENSUS_STATE_EQ
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_REQ_BYTECODE == INET_DIAG_REQ_BYTECODE,
    "bytecode attribute type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_MARK == INET_DIAG_MARK,
    "mark attribute type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_SHUTDOWN == INET_DIAG_SHUTDOWN,
    "shutdown attribute type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_PAD == INET_DIAG_PAD,
    "padding attribute type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_CLASS_ID == INET_DIAG_CLASS_ID,
    "class id attribute type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_CGROUP_ID == INET_DIAG_CGROUP_ID,
    "cgroup id attribute type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_SOCKOPT == INET_DIAG_SOCKOPT,
    "socket options attribute type must match pinned UAPI");
_Static_assert(KER_MEMBER_CENSUS_NLA_F_NESTED == NLA_F_NESTED &&
    KER_MEMBER_CENSUS_NLA_F_NET_BYTEORDER == NLA_F_NET_BYTEORDER &&
    KER_MEMBER_CENSUS_NLA_TYPE_MASK == (uint16_t)NLA_TYPE_MASK,
    "attribute flags/mask must match pinned netlink UAPI");
_Static_assert(KER_MEMBER_CENSUS_IN_DIAG_BC_MARK_COND == INET_DIAG_BC_MARK_COND,
    "mark filter instruction must match pinned UAPI");
_Static_assert(sizeof(((struct ker_member_census_diag_request *)0)->request) ==
    sizeof(struct inet_diag_req_v2), "member census request body must match pinned UAPI");
_Static_assert(offsetof(struct ker_member_census_diag_request, request) ==
    sizeof(struct nlmsghdr), "member census request body offset must match");
_Static_assert(sizeof(((struct ker_member_census_diag_request *)0)->mark_instruction) ==
    sizeof(struct inet_diag_bc_op), "mark instruction size must match pinned UAPI");
_Static_assert(sizeof(((struct ker_member_census_diag_request *)0)->condition) ==
    sizeof(struct inet_diag_markcond), "mark condition size must match pinned UAPI");

int main(void) { return 0; }
