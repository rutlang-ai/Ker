#ifndef KER_MEMBER_CENSUS_RUNTIME_H
#define KER_MEMBER_CENSUS_RUNTIME_H

#include "member-census-diag.h"

/* Private broker-to-ker-posix runtime calls. Global mark allocation and the
 * bounded query worker live in the single original-Linux runtime, not in a
 * broker archive that may be linked by more than one server. */
int ker_member_census_mark_allocate(uint32_t *mark);
int ker_member_census_server_claim(uint64_t *lease);
int ker_member_census_server_release(uint64_t lease);
int ker_member_census_query_submit(const struct ker_member_census_identity *identity,
    uint64_t *ticket);
int ker_member_census_query_poll(uint64_t ticket,
    int *query_status, struct ker_socket_member_census_snapshot *snapshot);
int ker_member_census_query_cancel(uint64_t ticket);
int ker_member_payload_query_submit(uint32_t mark, uint64_t *ticket);
int ker_member_payload_query_poll(uint64_t ticket, int *query_status,
    struct ker_socket_member_payload_snapshot *snapshot);
int ker_member_requests_query_submit(uint32_t mark, uint64_t *ticket);
int ker_member_requests_query_poll(uint64_t ticket, int *query_status,
    uint64_t *request_count);
void ker_member_census_runtime_shutdown(void);

#endif
