# RSS reverse-adjustment recheck qualification

This batch qualifies the four exact pinned source cases:

- `test_ff_rss_adjust_sport_recheck_off`
- `test_ff_rss_adjust_sport_recheck_on`
- `test_ff_rss_adjust_sport6_recheck_off`
- `test_ff_rss_adjust_sport6_recheck_on`

The importer byte-checks all four complete source functions, their shared
helpers, the unchanged source wrapper block, and `RD_RECHECK_N=100`. The exact
100-iteration loops execute with original BSS RETA size zero. They assert that
the unready adjustment path makes no own-queue predicate calls. The `recheck=1`
source cases then call the predicate directly as a wrapper wiring sanity check;
that direct call is separate from the 100 adjustment calls, each of which returns early before reaching recheck.

The fixture also builds genuine primary IPv4 and IPv6 DPDK thash contexts and
uses a private test-only copy of the caller policy library. Only references to
the own-queue predicate inside the imported adjustment helper are redirected
to the unchanged source counter wrappers. The production library and original
helper bodies stay unchanged. Ready controls explicitly set `thash_adjust=1`
and perform 64 calls per family for each recheck mode. Observed accepted counts
were 64/64 with recheck off and 64/64 with recheck on for both families; the
helper-boundary call counts were 0/64 for IPv4 and 0/64 for IPv6. These are
fixture observations, not a timing claim.

Every accepted candidate is checked against the original requested port range,
independent Toeplitz over the final reply tuple using the published DPDK key and
RETA, and the original software own-queue predicate. Every accepted candidate in either mode must be owned by the selected queue. A valid synthetic UDP reply
caller separately runs both flags through the original software predicate and
real `net_ring` packet transfer; the independent calculation checks the
classifier's chosen queue and the PMD sink verifies exact bytes and pool
recovery.

This demonstrates the original helper's caller-side recheck contract. It does
not qualify Linux socket allocation, TCP behavior, physical RSS queue landing,
or Linux allocation or hardware RSS. The microbenchmark’s unchanged BSS profile
still skips and remains only a control; its separate ready fixture and strict
N=10000 timing are qualified in the [overall RSS contract matrix](fstack-rss-contracts.md).
