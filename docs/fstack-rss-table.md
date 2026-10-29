# Caller-side software RSS table qualification

This example consumes the original F-Stack table/hash functions as application
metadata policy. It uses `ker::packet_dispatcher` to classify caller-owned
synthetic UDP-shaped L3 fixtures into application rings. It neither chooses
Linux socket ports nor configures a device RSS key or RETA. The imported Linux
port allocator and protocols are unchanged. Hardware RSS landing and the
missing native allocation extension point remain separate requirements.

The complete pinned source already retained under `third_party/fstack-pools`
supplies unchanged table structures, hash key and whole table/hash functions.
`fstack-rss-table-import` checks the full source digest and literal fragments.
The original configuration/memory layouts are retained. The caller's metadata
handles allocate real storage, borrow an exact context, and release it; they
are not a FreeBSD veth or protocol implementation. Diagnostic messages are
forwarded to stderr. There are no table-success or hash-success stubs.

The original Toeplitz initializer relies on two's-complement signed shifts.
Only this example object is compiled with `-fwrapv`; the source stays unchanged.
GCC/Clang results and UBSan with `halt_on_error=1` are checked against an
independent bit-window hash implementation.

`ker-rss-table-router` is a bounded, single-threaded caller example. It copies
fixed-size parsed rules for port0, validates a software queue/key model, builds
both address-family tables and restricts their candidate intervals. The caller
explicitly registers the classifier. Configuration/reset require quiescent
callbacks. Success from route transfers the packet to the selected caller
ring; errors retain caller ownership. Unsupported/scattered metadata is
explicitly rejected. No protocol state is inferred from the fixture bytes.

The transport has **one original ring-PMD queue**. Four software classification
buckets are an explicitly configured model, not observed hardware queues.
The example sends and receives128 IPv4/IPv6 fixtures through the original PMD,
then invokes the public dispatcher and the real table lookup. Independent hash
results predict32 local and96 other classifications. Exact original pointers,
bytes, both PMD counters and complete unique pool511/511 recovery are checked.
Detached routing retains caller ownership and fails explicitly.

Repository GCC shared, Clang static and ASan/UBSan builds run the source
contract and this consumer. A separately built consumer links the newly built
caller archive to previously installed, unchanged public Ker packet-dispatcher
libraries/headers. Its128-packet result matches. A classifier forced to return
only the local bucket fails at the expected destination-ring assertion.
No unavailable EAL initialization is treated as a successful skip.

Exactly the source case named by each PR is qualified. Original guard/smoke
assertions retain their weaker meaning; the common enabled consumer supplies a
real use and positive lifecycle. Neither the table tests nor this software
classifier qualify original Linux PCB allocation hooks, reverse adjustment,
physical NIC RSS, real TCP/UDP interoperability or full F-Stack reload.

| Source case added by this PR | Source CTest |
|---|---|
| `test_ff_rss_tbl_set_portrange_no_cfg` | `fstack-rss-table-no-config` |
| `test_ff_rss_tbl_set_portrange_disabled` | `fstack-rss-table-test_ff_rss_tbl_set_portrange_disabled` |
| `test_ff_rss_tbl_set_portrange_inverted_range` | `fstack-rss-table-test_ff_rss_tbl_set_portrange_inverted_range` |
| `test_ff_rss_tbl_get_portrange_no_cfg` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_no_cfg` |
| `test_ff_rss_tbl_get_portrange_disabled` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_disabled` |
| `test_ff_rss_tbl_get_portrange_smoke` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_smoke` |
| `test_ff_rss_tbl_get_portrange_hit` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_hit` |
| `test_ff_rss_tbl_get_portrange_rotation` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_rotation` |
| `test_ff_rss_tbl_get_portrange_miss` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_miss` |
| `test_ff_rss_check6_landing` | `fstack-rss-table-test_ff_rss_check6_landing` |
