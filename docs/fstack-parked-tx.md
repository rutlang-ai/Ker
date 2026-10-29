# Parked TX transport and burst guards

This batch adapts exactly four cases from
`tests/integration/test_ff_reload_integration.c` at F-Stack
`646a641cfff77f4815e1e29829a09e1ed15a2999`:

| Source case | CTest | Retained source judgment |
| --- | --- | --- |
| `test_it_a09_tx_divert_no_hw` | `fstack-parked-tx-divert` |8 copied +4 owned/raw packets divert while parked, zero PMD calls/drops,12 queued; owner sends12 in one burst |
| `test_it_a09_drain_ring_tx_watermark` | `fstack-parked-tx-watermark` |4x64 packets,8 bursts;255-entry capacity plus one overflow, exactly one full/divert drop and zero owner drop;16 cumulative bursts/511 packets |
| `test_it_a09_send_burst_guard` | `fstack-parked-tx-guard` |32 RESPONSE packets reach defensive flush while parked: no PMD call,32 drops, staging empty, pool512 restored |
| `test_it_a09_main_loop_parked_pass` | `fstack-parked-tx-pass` |Five packets staged before handover are diverted by one parked TX pass; no PMD call or drain dequeue until the owner handles them |

The original source cases run a single-process role simulation with bridge
stubs for non-DPDK dependencies. This adaptation uses actual public Ker reload
control and original DPDK rather than pretending to supply the FreeBSD global,
veth/config or main-loop ABI. The caller owns its event loop and ring/queue
selection. No Linux protocol implementation or imported upstream file changes.
Boot/veth assertions, native PCB hooks, concurrent/cross-master takeover,
physical NIC behavior and full application reload remain unqualified.

## Optional adapter

`ker::reload_tx` supplies an opaque per-caller TX context. The caller owns a
configured, started PMD queue, mbuf pool and its selected generation TX ring,
and keeps them alive until packets are reclaimed. Calls, stats and reload
control are serialized; all callbacks have completed before control changes.
The selected worker comes from `ker::reload`.

- `owned` consumes a valid caller mbuf. An owner stages up to32; a parked
  worker diverts into its own ring. A full ring frees/counts the rejected
  object. `copy` provides the contiguous borrowed-buffer entry point.
- `reply` stages an already selected single-segment RESPONSE, with bounded
  length trimming. It generates no response or protocol state and performs no
  VLAN/checksum/offload fixup. Callback selection remains caller policy.
- `flush` runs hardware TX only inside `ker_reload_poll`. A denied guard
  drops/counts staging. `pass` instead diverts parked staging residue; owner
  passes may flush. `drain` processes at most32 objects through the same gate
  and never dequeues when denied.
- PMD shortfalls release/count the unsent suffix separately from producer
  ring-full drops. Reentry from a PMD callback returns `-EBUSY`; empty-only
  destruction and FIFO cancellation make ownership recovery explicit.

Accepted ownership is recorded separately from actual PMD transmission and
all drop categories. After a valid owned/reply acceptance, `*packet` is NULL
for queued, staged and dropped outcomes. Prevalidation errors retain input;
a negative poll error after acceptance drops/counts the batch and is returned
and recorded. Copied input remains borrowed. Oversized copies and unsupported
multi-segment replies fail explicitly.

The bridge owns each burst admission. Run these TX entrypoints outside an
existing `ker_reload_poll` callback; nested gate errors are returned and an
already accepted batch is dropped/counted. This is an explicit TX-pass adapter,
not an implicit replacement for native Linux netdev hooks. Ring/port/queue
identity, peer selection and all synchronization requirements of the reload
runtime remain caller responsibilities. Directory-less role switching is the
profile qualified here.

## Actual execution

Real primary EAL creates one original net_ring PMD, a255-entry drain ring,
a255-entry output ring and a512-object pool. A DPDK TX callback independently
counts actual burst calls and submitted packets. The adapter's sent counters
must also match original driver `opackets`. Every output packet is checked
for length, all64 bytes and its single reference, in FIFO order.

Observed source-phase records:

| Phase | Actual PMD calls | Submitted | Ring / drops |
| --- | ---: | ---: | --- |
| Parked diversion |0|0|12 queued, zero drops |
| Sustained4x64 owner drains |8|256|zero full/drop |
| One producer overflow |8|256|255 queued, full1/divert drop1, owner drop0 |
| Final watermark owner drain |16|511|empty drain, owner drop0 |
| Parked RESPONSE guard |0|0|32 guard drops, staged0, pool512 |
| Parked residue pass |0|0|5 queued, staged0 |

The guard test then uses the same response path as owner and verifies32
actual transmissions. The parked-pass test similarly lets the owner send its
five retained packets. `fstack-parked-tx-ownership` adds real PMD shortfall
accounting, cancellation/destruction, unsupported-length/chain rejection and
PMD-callback reentry checks. It is extra adapter evidence, not another source
case. Every mode allocates all512 objects afterward, checks unique pointers
and exact exhaustion, returns them, and cleans up contexts/state, callback,
PMD, rings, pool and EAL.

GCC Release/shared and Clang Release/static each pass all5 strict-C11 tests,
with extensions disabled, warnings as errors and no skips. An independent
external CMake consumer repeats all5 modes using the installed
`ker::reload_tx` and public headers/libraries. Fourteen new/related reload,
PEER and callback tests plus the separate park-barrier test pass. The
106-file/433-case audit and21 catalog regression/mutation tests pass.

Two private negative builds retain all test assertions: bypassing the burst
gate fails the zero-PMD-call guard; suppressing the full-ring free fails pool
conservation. Neither mutation is installed or linked into normal libraries.
Normal and installed runs retain their actual phase/counter output in JSON.

Qualified implementation: `b771c0c3df25d38564c04bbfcff62878a9f1dd0b`.
Manifest:
`/home/hurricane/.local/state/ker-compat-work/fstack-parked-tx-evidence/qualification-manifest.json`,
SHA-256 `c377c2eb7a8580e9721dd7a68384d7b2e78a5757e9cbf6aad65a43ff69f25932`.
It binds implementation/test hashes, both builds, regression/negative results,
installed header/library/target and the external consumer. Runs use unprivileged
UID1002, one allowed CPU, no PCI and no hugepages. Host settings are unchanged.

## Integration and inventory

PR390 merged into PR389's feature branch after PR389 had already merged into
the integration branch. This branch preserves that merged PEER implementation
and brings it into integration alongside these four new cases. Relative to
PR390's merged tree,278/12/73 becomes282/12/69 (adapted/partial/blocked),
leaving81 behavioral cases incomplete. Only the four cases above gain new
status here. The earlier PEER case is carried forward, not counted again.
Boot state, half-open/PCB integration, foreign-epoch cleanup and all other
incomplete cases retain their issue links and classifications.

## Reproduce

Configure `KER_WITH_DPDK=ON`, `BUILD_TESTING=ON` and supported DPDK:

```sh
cmake --build build --target ker-fstack-parked-tx-test
ctest --test-dir build --output-on-failure -R '^fstack-parked-tx-'
python3 tests/fstack_migration.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_fstack_migration.py
```

External consumers use `find_package(ker CONFIG REQUIRED)` and link
`ker::reload_tx`. The test consumer additionally links the original ring PMD
and `ker::packet_dispatcher` for the borrowed RESPONSE callback.
