/* A private admission window must not change Nginx's FF configuration or
 * share the process-global flow table used by its eventual generation FSM. */
#ifndef KER_NGINX_CANDIDATE_MAP_NAMESPACE_H
#define KER_NGINX_CANDIDATE_MAP_NAMESPACE_H
#define ff_global_cfg ker_nginx_candidate_config
#define ff_flow_map_active ker_nginx_candidate_map_active
#define ff_flow_map_admit ker_nginx_candidate_map_admit
#define ff_flow_map_revoke ker_nginx_candidate_map_revoke
#define ff_flow_map_open ker_nginx_candidate_map_open
#define ff_flow_map_close ker_nginx_candidate_map_close
#define ff_flow_map_lookup ker_nginx_candidate_map_lookup
#define ff_flow_map_insert ker_nginx_candidate_map_insert
#define ff_flow_map_stats ker_nginx_candidate_map_stats
#define ff_flow_map_stats2 ker_nginx_candidate_map_stats2
#define ff_flow_map_cap_set ker_nginx_candidate_map_cap_set

/* ngx_core.h may already have included the ordinary FF headers, so declare
 * the private entry points even when their upstream header guards are set. */
#include <stdint.h>
struct ff_flow_key;
int ff_flow_map_active(void);
int ff_flow_map_admit(const struct ff_flow_key *, int *);
int ff_flow_map_revoke(const struct ff_flow_key *);
void ff_flow_map_open(void);
void ff_flow_map_close(void);
int ff_flow_map_lookup(const struct ff_flow_key *);
int ff_flow_map_insert(const struct ff_flow_key *);
void ff_flow_map_stats(uint64_t *, uint64_t *, uint64_t *);
void ff_flow_map_stats2(uint64_t *, uint64_t *, uint64_t *, uint64_t *,
    uint64_t *, uint64_t *, uint32_t *, uint64_t *);
void ff_flow_map_cap_set(uint32_t);
#endif
