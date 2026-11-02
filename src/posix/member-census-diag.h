#ifndef KER_MEMBER_CENSUS_DIAG_H
#define KER_MEMBER_CENSUS_DIAG_H

#include "member-census-diag-wire.h"
#include <stdatomic.h>

struct ker_member_census_identity {
    uint32_t mark;
    uint16_t local_port;
    uint64_t listener_cookie;
    bool expect_no_listener;
};

struct ker_member_census_diag_state {
    bool started;
    int fd;
    uint32_t local_port_id;
    uint64_t start_ns;
    uint64_t bytes_total;
    unsigned datagrams;
    struct ker_member_census_identity identity;
    struct ker_member_census_accumulator accumulator;
};

int ker_member_census_diag_require_net_admin(void);

/* Query state is advanced only by the single ker-posix census worker. Each
 * step consumes at most one bounded nonblocking netlink datagram. The direct
 * LKL path requires existing effective NET_ADMIN and never changes creds. */
int ker_member_census_diag_begin(struct ker_member_census_diag_state *state,
    const struct ker_member_census_identity *identity);
int ker_member_census_diag_step(struct ker_member_census_diag_state *state,
    const atomic_bool *cancel, struct ker_socket_member_census_snapshot *snapshot);
void ker_member_census_diag_close(struct ker_member_census_diag_state *state);

#endif
