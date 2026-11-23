# Caller-owned flow-map metadata qualification

This batch adapts exactly five pure metadata-table cases from F-Stack
`646a641cfff77f4815e1e29829a09e1ed15a2999`:

| Original case in `tests/unit/test_ff_dpdk_if.c` | CTest | Retained contract |
| --- | --- | --- |
| `test_ut_nr_23_flow_map` | `fstack-flow-map-basic` |40-byte key; disabled, unattached and closed gates; v4/v6 identity; insert/lookup/duplicate; reversible window |
| `test_a1_flow_map_single_phase` | `fstack-flow-map-single-phase` | Immediate visibility, duplicate admission and independent records |
| `test_a1_flow_map_admission_rule` | `fstack-flow-map-admission` | Untracked windows admit without recording; live room records; saturation refuses and leaves tuple absent |
| `test_a1_flow_map_revoke` | `fstack-flow-map-revoke` | Removal preserves colliding probe chains; reinsertion; duplicate creation flag; absent revoke |
| `test_p3_flow_map_bounded_growth` | `fstack-flow-map-growth` | At most4 doublings from64 to1024; full counter after bound; invalid capacity ignored |

The complete original assertion bodies are unchanged. The test adapter
translates original shared-block attachment into actual `ker_reload_bind_state`
and unbind operations. The existing layout validation still runs; no fake
attachment result is supplied. Every source test finishes detached.

`third_party/fstack-flow-map/ff_flow_map.c` and `.h` are byte-identical pinned
upstream files, with their license and source hashes retained. The import
CTest checks their hashes and all five complete source excerpts. The original
configuration layout and reload header come from existing pinned dependencies.
Neither imported Linux nor the existing F-Stack runtime is modified.

## Application boundary

The table is linked only into `ker-example-flow-map` and its caller example,
never into or exported by Ker libraries. Its enabled flag belongs to the caller;
its attached-state gate reads actual `ker::reload` observations. It remains a
single-thread, process-local table. Callers must serialize all accesses and
quiesce before close, capacity changes or unbind. No locking or shared table
semantics are claimed.

The table's original comments describe FreeBSD syncache/SYN consumers. This
example does not port those consumers. Application metadata admission is an
explicit caller decision. Original Linux retains socket allocation, handshake,
ACK processing and connection lifetime. No Ker TCP state or source-port
allocator is introduced.

`ker-flow-map-router` consumes the table for bounded IPv4/IPv6 UDP L3 fixtures:
closed tracking selects the local output; during tracking, recorded metadata
selects local and a miss selects peer. It is an application policy example,
not an IP validator or a general packet dispatcher. TCP, IPv4 options/fragments
and IPv6 extension chains are outside this profile. Errors retain the mbuf for
the caller; only successful enqueue transfers it.

## Real execution

The router uses real primary EAL, original net_ring RX queues, a63-object
mbuf pool and synchronous `ker_reload_poll`. Both address families complete two
close/open/admit/duplicate/revoke/reinsert/reopen sequences. Queue identity is
checked independently of the routing function, and every received pointer,
length and byte string matches the original packet. A denied production poll
leaves its input queued and invokes no callback; restored ownership processes
it. A full peer ring preserves caller ownership of the rejected packet.
Unsupported TCP also preserves caller ownership. Every stage restores63/63
objects; final state, PMD, rings, pool and EAL are released.

The normal run completes30 deliveries,30 callbacks and60 original PMD receives
(input plus selected output). This is ring-PMD transport, not physical hardware,
external network traffic or a live TCP connection. No hardware RSS queue
steering, cross-master generation transport, half-open classification, Linux
PCB hook, TCP continuity or full graceful reload is qualified. Those remaining
source integration cases remain under issue218.

Validation on unprivileged UID1002 with DPDK26.11.0-rc0:

- GCC Release/shared and Clang Release/static: all7 focused CTests pass with no
  skips. The example, policy and source-test targets explicitly require strict
  C11 with extensions disabled and `-Wall -Wextra -Werror`.
- A separate private mutation forces every routing decision to local while
  retaining the original table. The actual consumer fails its expected peer
  queue assertion; the normal executable passes30/30 afterward.
- Catalog integrity:106 pinned files,433 cases;21 catalog regression/mutation
  tests pass. Only the five named entries move from blocked to adapted.
- Counts change272/12/79 to277/12/74 (adapted/partial/blocked);86 behavioral
  cases remain unfinished. All remaining non-adapted cases retain issue links.

The local evidence manifest
`/home/hurricane/.local/state/ker-compat-work/fstack-flow-map-evidence/qualification-manifest.json`
(SHA-256 `4b72866c378658eafcde815006a84a6ad6552af70a288e0d780a3cf5f38ec4c2`)
binds source/test hashes, both normal builds, private mutation, raw PMD output
and build/CTest logs to baseline `69a0bf91d9d51fc6714bebb44952708f8f3e895e`.
EAL uses one allowed CPU, a PID-specific namespace,64MiB with `--no-huge`,
`--no-pci`, `--no-shconf`, VA IOVA and no telemetry; host hugepages are unchanged.

## Reproduce

Configure with `BUILD_TESTING=ON`, `KER_WITH_DPDK=ON` and supported DPDK, then:

```sh
cmake --build build --target ker-fstack-flow-map-test ker-flow-map-router
ctest --test-dir build --output-on-failure -R '^fstack-flow-map-'
python3 tests/fstack_migration.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_fstack_migration.py
```
