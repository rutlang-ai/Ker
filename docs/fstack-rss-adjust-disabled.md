# RSS disabled reverse-adjustment qualification

This checkpoint qualifies three exact cases from the pinned F-Stack
`tests/unit/test_ff_dpdk_if.c`:

- `test_ff_rss_adjust_sport_thash_adjust_off`
- `test_ff_rss_adjust_sport6_thash_adjust_off`
- `test_ff_rss_thash_ctx_init_thash_adjust_off`

The importer verifies the pinned implementation hash and retains the complete
original function bodies and shared test helpers. The first two bodies run in
the original unit profile (default key, RETA BSS zero, no contexts) and again
after real primary DPDK thash contexts are built with adjustment enabled; the
unchanged source test body then sets `thash_adjust` to zero. The context-init
body runs in both profiles. In the two adjustment cases, the original
test functions themselves change the bound configuration flag to zero before
calling the original helpers. With `FF_RSS_DIAG` disabled,
`ff_rss_thash_ctx_init` has no adjustment-disabled branch: its body returns zero
without creating or reporting a usable context. Readiness is established from
the original build-key/context state, not that return value.

The caller example is intentionally narrower than F-Stack's PCB allocator. It
uses the original reverse-adjustment helpers as optional hints for synthetic,
application-generated UDP reply tuples. The real primary EAL caller builds the
original key and IPv4/IPv6 contexts, tries bounded candidate ranges, and accepts
only candidates whose final tuple independently hashes to the caller's own
software queue under the published key and RETA. The original software
`ff_rss_check` predicates choose the queue; the independent Toeplitz calculation
checks that choice. Accepted and fallback records traverse real DPDK `net_ring`
devices with exact bytes and pool ownership checks. The observed run accepted
200/200 candidates in each family; this is a measured result, not a required
success-rate threshold.

After the caller disables adjustment while retaining ready contexts, the
original helper declines and leaves the candidate output unchanged. The
synthetic IPv4 and IPv6 fallback records retain their original tuple bytes and
route through the original software predicates. This demonstrates fallback for
this caller only.

This qualification does not alter Linux socket source ports, implement a
TCP/UDP allocator or port scan, exercise original Linux collision semantics,
test a secondary EAL process, observe physical NIC RSS queue landing, or claim
F-Stack PCB integration. Ker leaves automatic socket-port selection with
original Linux. The broader table, ready guard/range, recheck and hardware RSS
contracts remain tracked under issue #220.

Run the focused checks from a configured build with DPDK available:

```sh
ctest --test-dir BUILD --output-on-failure -R '^fstack-rss-adjust-'
ctest --test-dir BUILD --output-on-failure -R '^fstack-rss-(table|thash)-'
```

`fstack-rss-adjust-source` also proves two build/reset/build/reset cycles in one
primary EAL process. It verifies that the original context names disappear from
the DPDK thash registry after each reset. The adjustment importer checks the
exact pinned source blocks; the caller test checks real PMD transfer and packet
pool recovery.
