#ifndef KER_FF_OWNER_REQUESTS_DIAG_H
#define KER_FF_OWNER_REQUESTS_DIAG_H

#include "ff-owner-requests-wire.h"
#include <stdatomic.h>

struct ker_ff_owner_requests_state {
    bool started;
    int fd;
    uint32_t local_port_id;
    uint32_t sequence;
    unsigned family_index;
    uint64_t rows_total;
    uint64_t requests_total;
    uint64_t started_ns;
    uint64_t bytes;
    unsigned datagrams;
    struct ker_ff_owner_requests_accumulator accumulator;
};

/* The mark must come from the authenticated owner context. This private
 * primitive does not authorize or expose arbitrary caller-selected marks. */
int ker_ff_owner_requests_begin(struct ker_ff_owner_requests_state *state,
    uint32_t owner_mark);
/* Returns 0 while pending, 1 after a complete valid dump, or negative errno.
 * The output is written only after a valid kernel NLMSG_DONE. */
int ker_ff_owner_requests_step(struct ker_ff_owner_requests_state *state,
    const atomic_bool *cancel, uint64_t *request_count);
void ker_ff_owner_requests_close(struct ker_ff_owner_requests_state *state);

#endif
