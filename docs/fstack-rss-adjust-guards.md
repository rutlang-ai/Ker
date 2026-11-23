# RSS reverse-adjustment guard and range qualification

This batch completes the unchanged pinned source assertions for:

- `test_ff_rss_adjust_sport_null`
- `test_ff_rss_adjust_sport_degraded`
- `test_ff_rss_adjust_sport_single_queue`
- `test_ff_rss_adjust_sport6_guard`
- `test_ff_rss_adjust_sport_range_params`
- `test_ff_rss_adjust_sport6_range_params`

The source importer checks the complete function bodies and shared helpers
against the pinned F-Stack snapshot. All six source functions execute in the
original BSS profile with RETA size zero. This preserves the source's actual
assertions, including cases where an earlier unready-context guard masks the
named later branch. The caller softc adapter safely accepts NULL because the
original helper may convert the opaque pointer before its explicit NULL guard.

Separate ready-context controls exercise the later branches. The test fixture
builds both original primary DPDK thash contexts, verifies readiness, creates
the original caller configuration, explicitly sets `thash_adjust=1`, and
provides the original four-queue test configuration before testing inverted and
sub-RETA ranges. It also changes
the configured queue count to one to reach the single-queue guard while the
context is ready. Each decline must preserve a sentinel output port. The
unchanged source bodies themselves remain byte-for-byte intact and are not
modified to force these branches.

The real caller then repeats inverted and sub-RETA rejection for IPv4 and IPv6
with both contexts ready and adjustment enabled. It checks that the original
tuple bytes and output sentinel remain unchanged, routes each fallback record
using the original software `ff_rss_check` predicate through real `net_ring`,
then applies a valid successor advisory and sends that record through the same
caller. An independent Toeplitz calculation checks classifier results against
the actual published key and RETA. These are synthetic UDP reply records; Ker
does not use the advisory to allocate Linux socket ports or implement a port
scan. No physical RSS queue, Linux collision behavior, TCP integration, or
secondary EAL context is claimed.

The importer, source fixture, real caller, previous software-table consumer,
and standalone thash regression profiles are registered with CTest. Run the
focused set from a DPDK-configured build:

```sh
ctest --test-dir BUILD --output-on-failure -R '^fstack-rss-'
```

The separate disabled-adjustment qualification is documented in
[fstack-rss-adjust-disabled.md](fstack-rss-adjust-disabled.md). The original
microbenchmark’s BSS skip remains a control, while its ready timing fixture is
qualified separately; see the [RSS contract matrix](fstack-rss-contracts.md).
