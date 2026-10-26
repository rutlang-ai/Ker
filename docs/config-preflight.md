# Configuration validation before worker queries

`ker-run.py` validates the final CLI/INI configuration before running the
selected worker for its `--dpdk-limits` capability response. The query still
runs exactly once for a valid typed bond, and its positive `max_numa_nodes`
value bounds `socket_id`; there is no fixed replacement NUMA limit.

Previously the INI reader queried bond limits before `parse_arguments` checked
auxiliary interface MTU, queues, RSS, addresses and cross-interface ownership.
A malformed interface paired with a valid bond could execute the worker and
report a capability error instead of the configuration error. The CLI now
defers only that query until all pure checks, including CLI overrides, finish.
Standalone reader calls keep their existing selected-worker bounds check.

`native-fstack-interface-section-validation` adds22 rejection combinations:
eleven semantic errors alone or after another valid interface. A process marker
must remain absent, and the CLI must report the relevant configuration error.
A separate executable implements only the capability response protocol to check
one query for valid configurations, main CLI correction precedence, selected
NUMA bounds and corrected-load recovery. That executable supplies no PMD or
network evidence. Existing typed-bond tests also query the actual built worker.

This is a Ker configuration-ordering fix and does not complete another pinned
F-Stack scenario. Source inventory counts remain218 adapted,18 partial,
127 blocked,15 architecture-specific and55 harness-only, with145 behavioral
cases incomplete. Upstream Linux and DPDK code are unchanged.
