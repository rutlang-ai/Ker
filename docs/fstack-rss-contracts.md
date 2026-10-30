# Exact RSS source contracts and qualification boundaries

[Issue #220](https://github.com/rutlang-ai/Ker/issues/220) originally tracked31
source cases at `646a641cfff77f4815e1e29829a09e1ed15a2999`. The two
standalone IPv4/IPv6 thash equivalence cases are now scenario-adapted;
29 remain in that issue (one partial,28 blocked). The table below preserves
all31 exact contracts and identifies those two qualifications. It records
actual assertions, not promises of future real-machine acceptance.

## Three different kinds of evidence

1. Source helper/configuration tests exercise candidate-table lookup, flags,
   guard behavior and software arithmetic. Many do not require a physical RSS
   device. They still need an actual corresponding Ker consumer to qualify;
   an unused helper added solely to make their assertions pass is insufficient.
2. Ker's existing `native-fstack-rss-control` configures an original null PMD,
   preserves its key, restores all128 RETA entries after independent poisoning,
   checks readback and rejects a successfully queried but corrupted table. It
   uses `no-rx=1`. This is control-plane evidence, not flow distribution.
   Original null-PMD RX implementations generate dummy packets or no packets;
   their queue functions do not perform an RSS tuple-to-queue dispatch.
3. Data-plane RSS acceptance requires actual packets with independently chosen
   IPv4/IPv6 tuples, original PMD hash/queue observations, queried key/algorithm
   and RETA, and agreement with independent hash computation. Ordinary packet
   delivery on queue0, successful RETA readback and explicitly alternating
   vhost backend queues do not establish it. Existing `rx-lcores.py` deliberately
   injects alternating queues and must not be relabeled as RSS evidence.

In particular the source tests' BSS `rss_reta_size[] == 0` is a unit setup,
not a legitimate runtime capability query. Its software predicate uses the
resulting mask0xffff. Several adjustment guards run before the branches their
names suggest. Their exact assertions are useful, but do not prove those later
branches. The microbench calls `skip()` on unready context; it supplies no timing
result on that path. When their EAL initialization succeeds, the IPv4/IPv6
equivalence tests create real DPDK thash contexts and require200/200 full-loop
software landing at RETA128 and512. An EAL-init skip reaches neither the context
creation nor those assertions and is not a pass. They report first-candidate
rates rather than imposing the same threshold on those rates. Neither observes
hardware queues.

## Original kernel allocation boundary

The pinned original
[in_pcb.c](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/freebsd/netinet/in_pcb.c#L862)
calls the F-Stack IPv4/IPv6 candidate table and adjustment functions from its
PCB port allocator, then checks local port conflicts and falls back to scanning.
Later it calls the own-queue predicates while continuing that search. These
are consumers inside the F-Stack FreeBSD allocation path, not merely NIC RETA
configuration routines. Calling standalone DPDK hash functions or pre-binding a
port in a test cannot qualify this caller integration.

Ker keeps automatic port selection and collisions in original Linux. Before
implementing a source-port steering adaptation, identify an original Linux
extension point with equivalent lifecycle, routing, conflict, range and
fallback semantics. Document a concrete missing hook if none can express it;
do not write a Ker TCP source-port/state machine or patch imported Linux merely
because a unit helper can compute a port. Preserve kernel choices when the
optimization is disabled or unavailable. RSS input steering and original Linux
socket allocation are separate integration requirements.

## Source assertion matrix

`test_ff_config.c` and `test_ff_dpdk_if.c` refer to the unchanged retained files
under [tests/upstream/fstack/tests/unit](../tests/upstream/fstack/tests/unit).
Every original #220 exact ID appears once below. Only the two explicitly
qualified equivalence rows have new pass mappings; the existing partial
range-validation mapping remains partial.

| Source file | Exact case | Assertion and remaining boundary |
| --- | --- | --- |
| `test_ff_config.c` | `test_rss_check_cfg_handler_no_port_no_vlan` | Section appears before port configuration; the original source only asserts rss_check_cfgs stays NULL and discards the loader result. The caller-side source test now separately confirms the retained `rss_check.enable` callback ran and returned 0 with the NULL port list, while the production inspector still rejects the unsafe document before upstream loading. This proves the original missing-port guard only; Ker has no equivalent ordered RSS-table loader contract. |
| `test_ff_config.c` | `test_rss_tbl_cfg_handler_bad_tuple` | Malformed three-token rule leaves nb_rss_tbl zero if the source RSS block exists; loader result is discarded. Generic unknown-section rejection does not prove rule-parser behavior. |
| `test_ff_config.c` | `test_rss_check_thash_adjust_off_parses` | Valid source configuration succeeds with RSS enabled and thash_adjust=0. Ker has no corresponding source-port optimization toggle; rejecting the field is not this positive contract. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_set_portrange_no_cfg` | Source table setter declines with -1 when rss_check_cfgs is NULL. An absent Ker table API or rejected INI section is not a demonstrated setter guard. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_set_portrange_disabled` | Source table setter declines with -1 for enable=0; the surrounding enabled table contract is still required. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_set_portrange_inverted_range` | Source enabled-table setter rejects first>last. Existing original-Linux ephemeral-range validation is partial evidence only; no Ker RSS candidate table update or queue ownership contract is implemented. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_get_portrange_no_cfg` | Source lookup declines with -1 when configuration is NULL. No corresponding real Ker lookup consumer is qualified. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_get_portrange_disabled` | Source lookup declines with -1 when configuration is disabled. No matching enabled/disabled candidate-table lifecycle is qualified. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_get_portrange_smoke` | Source invokes lookup against uncontrolled table state and discards its return value; the assertion is only that this actual path does not crash, not hit/miss correctness or packet landing. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_get_portrange_hit` | Source hit returns0, a non-NULL candidate array and a nonempty index interval; sampled candidates agree with the independent software hash and own-queue check. Ker has no such source-port candidate table. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_get_portrange_rotation` | Consecutive lookups preserve the same index interval and array pointer; rotation is performed by the caller, and two different candidate ports pass the own-queue check. Lookup must not be described as advancing the cursor itself. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl_get_portrange_miss` | A different source address misses the configured three-tuple, returns -ENOENT and leaves the candidate pointer NULL. No Ker equivalent table/miss path is qualified. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport_null` | Source rejects NULL softc or output pointer with -1 before dereference. Guarding a different RSS control API does not implement this source-port-selection consumer. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport_degraded` | With BSS RETA size0, context initialization succeeds but leaves ports unready; adjustment declines -1 for native/software fallback. This is degraded readiness, not working reverse calculation. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport_single_queue` | Source sets one queue but the earlier unready-context guard already returns -1 in this unit environment. It does not isolate the one-queue branch or prove traffic landing. |
| `test_ff_dpdk_if.c` | `test_ff_rss_thash_equivalence_hitrate` | On a non-skipped run (EAL initialization must succeed), standalone real DPDK thash contexts use RETA128/512 and deterministic seeds for200 IPv4 tuples each. First-candidate rates are reported; adjustment success must be positive and the full retry loop must land200/200 with independent software verification. An EAL-init skip does not reach these assertions. Qualified by `fstack-rss-thash-ipv4` and the repeat/failure controls; see [evidence](fstack-rss-thash.md). This is not observed PMD queue landing. |
| `test_ff_dpdk_if.c` | `test_ff_rss_check6_landing` | Source IPv6 own-queue verdicts match an independent software Toeplitz replica over64 destination ports and include at least one hit. Source BSS RETA0 implies mask0xffff; it is not a queried device RETA. |
| `test_ff_dpdk_if.c` | `test_ff_rss_check6_single_queue` | Source own-queue predicate returns1 for a fixed IPv6 tuple with one queue. Ordinary single-queue TCP delivery does not invoke or establish a corresponding Ker predicate ABI. |
| `test_ff_dpdk_if.c` | `test_ff_rss_tbl6_set_get` | IPv6 rule initialization and lookup return a candidate array whose sampled ports pass the source own-queue predicate; missing tuples must miss. Ker has no IPv6 candidate table consumer. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport6_guard` | Source IPv6 adjustment rejects NULL softc/output and declines after initialization with RETA0/unready context. Neither disabled device RSS nor zero packet counters proves these guards. |
| `test_ff_dpdk_if.c` | `test_ff_rss_thash6_equivalence_hitrate` | On a non-skipped run (EAL initialization must succeed), standalone thash contexts use36-byte IPv6 tuples and a16-bit helper at bit256 with RETA128/512; each deterministic200-tuple full loop must land200/200 in independent software verification. An EAL-init skip does not reach these assertions. Qualified by `fstack-rss-thash-ipv6` and the repeat/failure controls; see [evidence](fstack-rss-thash.md). No device RX queue is observed. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport_recheck_off` | Source makes100 IPv4 adjustments with recheck=0, all declining at the unready-context guard, and asserts zero wrapped own-queue checks. The recheck branch is not reached. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport_recheck_on` | Source makes100 IPv4 adjustments with recheck=1 but the unready-context guard still prevents rechecks; zero wrapper calls plus a direct predicate-call sanity check are asserted. It does not demonstrate enabled runtime rechecking. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport6_recheck_off` | Source makes100 IPv6 adjustments with recheck=0; RETA0/unready initialization causes -1 and no wrapped predicate calls. No ready recheck branch is exercised. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport6_recheck_on` | Source makes100 IPv6 adjustments with recheck=1; all still decline before rechecking. A direct predicate call checks wrapper wiring, not the ready adjustment branch. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_microbench` | Source probes context readiness and calls skip() when RETA0 leaves adjustment unavailable. Only a ready context times10000 calls for each recheck mode and asserts off<on. A skipped run provides no performance result. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport_thash_adjust_off` | With the source optimization disabled, IPv4 adjustment declines -1 so its original PCB caller can perform the fallback scan. Ker must preserve original Linux allocation rather than invent a TCP port scan. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport6_thash_adjust_off` | With thash_adjust=0, IPv6 adjustment declines -1 for the original PCB caller fallback. No Ker equivalent optimization lifecycle or caller is implemented. |
| `test_ff_dpdk_if.c` | `test_ff_rss_thash_ctx_init_thash_adjust_off` | Source initialization returns0 when optimization is disabled. This is a deliberate disabled-path result, not evidence that a usable reverse-hash context exists. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport_range_params` | Source IPv4 adjustment declines for an inverted range and a two-port sub-RETA range, but RETA0/unready context may reject earlier. The unit does not independently reach ready-context range validation. |
| `test_ff_dpdk_if.c` | `test_ff_rss_adjust_sport6_range_params` | Source IPv6 adjustment similarly declines inverted and too-small ranges with the earlier unready guard active. Original Linux range checks alone do not qualify reverse-hash candidate selection. |

## Next implementation gates

First establish the original Linux allocation extension point and its real
consumer; independently qualify an actual PMD/input profile for RSS landing.
Use actual disabled/degraded/enabled control states with valid positive paths.
Then qualify candidate-table updates and lifetime, hit/miss, caller-owned
rotation, both address families and queue landing without changing upstream
protocol semantics. Ready-context branch tests must explicitly demonstrate
readiness before measuring recheck/range behavior or timing. Keep the source's
weaker guard assertions distinct from this stronger runtime acceptance.

The current catalog is305 scenario-adapted,4 partial,54 blocked,
15 architecture-specific and55 harness-only out of433. All58 blocked/partial
cases remain unfinished. The two standalone tests already consume DPDK directly
in the original source; their unchanged arithmetic contracts need no new Ker
production helper. This qualification does not satisfy the remaining table,
source-port allocation or data-plane RSS gates above.
