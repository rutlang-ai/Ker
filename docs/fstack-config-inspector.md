# Legacy configuration inspection and unload contract

`ker-fstack-config-inspect -c legacy.ini [-t primary|secondary] [-p ID]`
parses a legacy F-Stack document and displays its original EAL argument plan.
It is a caller-side migration aid, built with the examples/tests when DPDK is
enabled. It never executes that plan, starts EAL, or configures Ker networking.
FreeBSD, KNI, RSS, threading and reload settings still need explicit runtime
adaptation. Parsing a setting successfully does not claim runtime support.

The original `lib/ff_config.c` at revision
`646a641cfff77f4815e1e29829a09e1ed15a2999` is retained byte-for-byte under
`third_party/fstack-config`, with its original configuration layout, parser and
reload headers. The caller adapter namespaces its globals and entry points;
the original INI parser has a separate namespace and DPDK supplies the actual
`rte_strsplit`. There are no replacement parser, log or allocation success
stubs. The log filename prefix is caller-owned data read by the parser.
Nothing from this example is exported or linked into Ker libraries.

The example is single-threaded. Its snapshot and argument pointers are borrowed
until the next load/unload. Load first frees the prior document, clears remaining
scalars and resets `getopt`, so documents do not inherit unrelated flags.
Call unload after success or failure. This adapter does not change the original
configuration structures or parser semantics.

Because the retained parser writes its EAL plan into fixed-size storage without
bounds checks, the adapter preflights each document with the same unchanged INI
parser and rejects oversized plans before calling upstream load. The preflight
counts every argument source against `DPDK_CONFIG_NUM`, checks each formatted
argument against `DPDK_CONFIG_MAXLEN`, bounds port, lcore, slave-port and
VLAN-filter list expansion, and rejects port ids outside `RTE_MAX_ETHPORTS`
(since those ids index a fixed-size allocation). It also rejects negative port
section ids and a listed port that has no `[portN]` section, so the retained
parser can neither index `port_cfgs[-1]` nor dereference the unallocated
`port_cfgs` array in `ff_check_config`. VLAN sections are inspected too:
negative parent-port ids and repeated attachments beyond
`DPDK_MAX_VLAN_FILTER` per port are rejected, attachments that precede the
first `[portN]` section are rejected (that section allocates `port_cfgs`), a
lcore mask enabling more than `DPDK_MAX_LCORE` cores is rejected, list range
endpoints that cannot fit the retained parser's `int` loop variable (or whose
upper endpoint is `INT_MAX`) are rejected, a KNI `owner_proc_id` outside
`[0, RTE_MAX_LCORE)` is rejected, `primary_slim`/`kni.enable` without an
`lcore_mask` is rejected (that mask allocates `proc_lcore`), a negative or
out-of-range `-p` process id is rejected, and the
preflight resolves the
configuration filename with the same option table as `ff_parse_args` so `--`
and other `getopt` behavior cannot make the two parsers select different
documents. A parse error does not turn a
partially inspected oversized plan into permission to run the retained parser:
an unsafe partial plan is still rejected. This is a caller-side policy: the
pinned parser source and its manifest hash stay unchanged, and a document that
would exceed the parser's capacities produces an error instead of memory
corruption.

Exactly one source case is newly qualified here:
`tests/unit/test_ff_config.c::test_ff_unload_config_zeroes_state`.
The full original function is retained in `tests/fstack-config-unload-source.inc`.
Its assertions call the upstream unload function directly, checking every
original ownership pointer and the second, idempotent unload. The adapter's
extra scalar reset cannot mask a missing upstream cleanup operation.

Validation includes 100 complete load/unload cycles, GCC release, Clang static and GCC
ASan/UBSan builds with leak detection, an actual CLI invocation with the pinned
minimal fixture, and source/hash checks. A linked no-op replacement of upstream
unload fails at the original `proc_lcore == NULL` assertion. The existing
`ker::ini` target still builds from its original, separately namespaced object.
The original snapshot and historical 50-case completion ledger are unchanged.

This source unit case requires pointer cleanup, not traffic. The other legacy
schema, startup, hardware, allocation and runtime cases are not promoted by
this import. In the new request for 50 additional cases, this is case 1; prior
migration batches are excluded from that count.

## Additional source contracts

Each row is added in its own PR. All rows qualify document parsing only.

| Source case | CTest |
|---|---|
| `test_ff_load_config_valid_minimal_ini` | `fstack-config-source-test_ff_load_config_valid_minimal_ini` |
| `test_ff_load_config_unknown_section` | `fstack-config-source-test_ff_load_config_unknown_section` |
| `test_ff_load_config_all_sections` | `fstack-config-source-test_ff_load_config_all_sections` |
| `test_ff_load_config_dpdk_full` | `fstack-config-source-test_ff_load_config_dpdk_full` |
| `test_ff_load_config_portlist_nonint` | `fstack-config-source-test_ff_load_config_portlist_nonint` |
| `test_rss_check_cfg_handler_no_port_no_vlan` | `fstack-config-source-test_rss_check_cfg_handler_no_port_no_vlan`; a test-only callback proxy verifies the retained `rss_check.enable` handler runs and returns 0 after the production preflight separately rejects the same unsafe fixture. |
| `test_rss_tbl_cfg_handler_bad_tuple` | `fstack-config-source-test_rss_tbl_cfg_handler_bad_tuple` |
| `test_rss_check_thash_adjust_off_parses` | `fstack-config-source-test_rss_check_thash_adjust_off_parses` |
| `test_vlan_cfg_handler_id_not_in_filter_returns_one` | `fstack-config-source-test_vlan_cfg_handler_id_not_in_filter_returns_one` |
