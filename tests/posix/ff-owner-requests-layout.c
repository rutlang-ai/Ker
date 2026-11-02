#include "ff-owner-requests-wire.h"
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

_Static_assert(sizeof(struct ker_ff_owner_requests_nlmsghdr) ==
    sizeof(struct nlmsghdr), "netlink header layout must match pinned UAPI");
_Static_assert(sizeof(struct ker_ff_owner_requests_diag_msg) ==
    sizeof(struct inet_diag_msg), "inet_diag_msg layout must match pinned UAPI");
_Static_assert(sizeof(struct ker_ff_owner_requests_diag_request) ==
    sizeof(struct nlmsghdr) + sizeof(struct inet_diag_req_v2) +
        sizeof(struct nlattr) + sizeof(struct inet_diag_bc_op) +
        sizeof(struct inet_diag_markcond),
    "mark-filter request layout must match pinned UAPI");
_Static_assert(sizeof(struct tcp_info) == 248,
    "INFO minimum must match pinned Linux 6.12 tcp_info ABI");
_Static_assert(INET_DIAG_INFO == 2 && INET_DIAG_MARK == 15 &&
    INET_DIAG_REQ_BYTECODE == 1 && INET_DIAG_BC_MARK_COND == 10,
    "diagnostic extension identifiers must match pinned Linux UAPI");

int main(void) { return 0; }
