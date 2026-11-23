# PEER dispatch ownership boundary

Exactly `tests/unit/test_ff_dpdk_if.c::test_ut_nr_27_dispatch_peer_boundary`
from F-Stack `646a641cfff77f4815e1e29829a09e1ed15a2999` is scenario-adapted.
The original case asserts three ownership paths: forwarding retains an owned
mbuf in the peer ring; a full ring frees the rejected mbuf and increments the
full counter; a closed reload window frees instead of enqueueing. The original
callback receives borrowed data and never enqueues or frees the mbuf itself.

The optional `ker::peer_dispatcher` component composes the existing borrowed
callback registry with actual `ker::reload` round observations and original
DPDK ring/mbuf operations. It adds no transport protocol, PCB lookup or peer
selection policy. Existing `ker::packet_dispatcher` behavior and dependencies
are unchanged. All imported upstream source files remain unchanged.

The caller supplies and validates the selected peer ring's generation, epoch,
port and queue, and keeps the ring alive for the operation. Calls, reload
control and stats access must be serialized. The bridge does not authenticate
or create rings, discover peers, consult USR2 draining-peer mirrors, or
implement cross-master routing. A live bound round permits the PEER path;
without one the packet is dropped. No physical NIC, Linux SYN/PCB integration,
TCP continuity or full graceful reload is qualified.

## API ownership

`ker_packet_dispatch_peer()` returns a negative errno for invalid inputs and
otherwise reports one of these outcomes. `decision` preserves the callback's
original result; `length` is the callback's local length output.

| Callback/window result | Return | `*packet` | Owner afterward |
| --- | --- | --- | --- |
| PEER, open round, enqueue succeeds | `KER_PEER_FORWARDED` | NULL | Peer ring |
| PEER, open round, full ring | `KER_PEER_DROPPED` | NULL | Freed once |
| PEER, closed/unbound round | `KER_PEER_DROPPED` | NULL | Freed once |
| Any non-PEER callback result | `KER_PEER_PASSTHROUGH` | Original pointer | Caller |
| Invalid input | Negative errno | Original pointer | Caller |

As in the original PEER branch, callback length edits do not change mbuf
metadata. Non-PEER queue/error/response decisions remain caller policy. Drop
accounting counts segments; forwarding/full/closed counters count outcomes.
The ordinary borrowed dispatcher API never gains implicit ownership.

## Execution and failure controls

`fstack-peer-dispatch-ownership` uses real primary EAL, an original net_ring
PMD, a63-entry peer ring and a127-object mbuf pool. It checks:

- Original pointer,32-byte payload and reference count after forwarding.
- Full-ring rejection preserves63 queued packets, exact FIFO payloads and pool
  availability. `full` increments exactly once.
- Closed-window drop makes no enqueue attempt or extra full count, even while
  the peer ring remains full; an unbound-state drop is also checked.
- Queue/error/response callback results retain caller ownership. Invalid
  queue/missing-ring arguments invoke no callback and retain the packet.
- A two-segment dropped chain releases both objects. Final counters are
  `forwarded=1`, `full=1`, `closed=3`, `dropped_segments=5`.
- Original PMD RX observes64 packets. Allocating all127 pool objects afterward
  requires unique pointers and exact exhaustion; every object is returned.
  State, PMD, rings, pool and EAL are cleaned up.

GCC Release/shared and Clang Release/static each pass the new strict-C11 test
with warnings as errors and no skips. The seven-test GCC regression set also
passes existing callback source import, lifetime, PMD, plain/context and
unregister checks. A separate external CMake consumer uses the installed
`ker::peer_dispatcher` target and installed headers/libraries to repeat the
same EAL/PMD contract; its test helpers are copied into its own source folder.
A private negative build suppresses the rejected-packet free and fails the
source-shaped pool-conservation assertion. The normal executable then passes.
The runtime uses one allowed CPU, no PCI and no hugepages; host settings are
unchanged.

Qualified implementation commit: `c73ce1ce492a680f31cdace20dd5f71e0c887be7`.
Local manifest:
`/home/hurricane/.local/state/ker-compat-work/fstack-peer-dispatch-evidence/qualification-manifest.json`,
SHA-256 `dd46f18ad41becefc1c05a4fef738969d3084dc5aef945ee02f75bb9c99c12b5`.
It binds implementation/test hashes, both normal builds, regression logs,
installed target/header/library and consumer, private negative control and raw
normal/failure results.

This batch is stacked on PR389. Only this source case changes status:
277/12/74 becomes278/12/73 (adapted/partial/blocked), leaving85 behavioral
cases incomplete. The106-file/433-case audit and21 catalog regression/mutation
tests pass. Issue218 retains all other incomplete generation contracts.

## Foreign-epoch drain source case

The complete unchanged `test_p1_drain_foreign_epoch_tx` helper/assertion set
now runs against the exact pinned `ff_drain_ring.c` implementation and the
original reload/generation-directory runtime. Its mode-3 profile leaves the
epoch-1/generation-0 TX ring queued while the directory names epoch-2/generation-0
as hardware owner. A bounded same-process caller checks the original
`ff_no_hw_mode()` ownership predicate, confirms that the packet remains queued
before ownership, then makes epoch 2 the selected owner. The unchanged original
`ff_drain_ring_tx_drain()` sends the exact retained mbuf and bytes through queue
1 of a real two-queue `net_ring` PMD; source teardown restores all 64 pool
objects. The original `ff_drain_ring_unregist()` is detach-only: named rings
and pointer arrays persist until EAL/process cleanup. The test cleans its PMD
endpoint and pool without claiming manual drain-bank destruction.

This qualifies the source ring cleanup behavior and a trusted same-process
primary caller. It does not execute the secondary-only F-Stack main loop,
authenticate two coexisting masters, adapt the Ker resident's one-identity-per-
generation bank, or qualify full reload. Epoch-isolated resident admission and
cleanup remain open; changing detach authorization alone is insufficient.
See [source and reproduction](fstack-drain-foreign-epoch.md).

## Reproduce

```sh
cmake --build build --target ker-fstack-peer-dispatch-test
ctest --test-dir build --output-on-failure -R '^fstack-peer-dispatch-'
python3 tests/fstack_migration.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_fstack_migration.py
```

Configure `KER_WITH_DPDK=ON` and `BUILD_TESTING=ON` with the supported DPDK.
External consumers use `find_package(ker CONFIG REQUIRED)` and link
`ker::peer_dispatcher`; no private Ker headers or runtime substitution is
required.
