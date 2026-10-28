# Exact live-slot admission and continued owner service

`test_p1_directory_live_slot` requires rejecting the original derived epoch
slot when its owner remains alive, even if another slot is free. Advancing to
another slot would disagree with the epoch-derived IPC/drain ring names.
The original `ff_reload_gendir.c` backend is compiled unchanged by Ker's
directory adapter; no alternate-slot scan or successful fallback is added.

The complete original `p1_directory_conflict(0)` helper and source test are
retained unchanged in `fstack-reload-live-slot-source.inc`. The private test
compiles the actual production TU with test-only EAL-role, memzone lookup and
fatal-exit interception. It performs both original attempts and verifies:
directory absent, prior epoch9 retained, no reset pending, disabled mirror,
unchanged RX word and primary slot, and alternate slot2 still unowned. Import
guards compare the entire helper/test bytes against the pinned source. The
interception hooks are never compiled into or installed with `ker::reload`.

The real multiprocess consumer uses the existing exported directory adapter,
original EAL, original net_ring and original typed IPC. Four distinct master
parents create four actual EAL secondary lifetimes. A receives epoch2/slot2;
B receives epoch3/slot3, then exits and is reaped with its master. C receives
epoch4/slot1. D's next epoch5 maps exactly to A's live slot2 and must terminate
with the original admission diagnostic and status1. B's alternate slot remains
reclaimable. Only the new test plan expects this exact worker exit; all existing
fixture plans continue to require status0. Every child/master is reaped.

Before and after the failed admission, A processes one exact PMD frame and one
original typed QUERY roundtrip, with address/nonce/cookie/pointer and pool checks.
Its public owner view remains unchanged, C cannot poll its hardware, and all88
original FF-named rings remain associated with A's epoch. End state requires
PMD RX/TX2/2, two IPC roundtrips, empty queues, no in-flight callbacks and both
pools63/63, followed by original EAL/primary cleanup. The failed secondary has
not reached caller pool allocation or polling. This is a positive preservation
proof as well as a failed-admission test.

Actual secondary EAL requires shared hugepages. A host skip77 is not completion.
Qualification must run both repository and independently installed public-API
consumers in the networkless isolated guest with private hugepages, preserve
all existing shared-runtime profiles after the fixture change, and record
source/binary/image/serial hashes and normal power-down. The qualification below completes the50th distinct baseline-incomplete source ID.

## Qualified evidence

Candidate `e821e67ab9749cab4c8cc3cd55cd16c30f0d46fc` passed fresh isolated
guest14 on its first attempt. Both repository and independently installed P1
consumers pass the exact admission/continued-service contract above. All prior
11 runtime profiles and two existing examples also pass after the expected-exit
fixture extension; the guest powers down normally and QEMU exits0. The host
shared-hugepage skip is not used as evidence.

`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest14/actual-result-attempt1.json`
has SHA256
`12c7514d4ce66d7c88b6f43368f2a13130d3619941239fb61b60b8def3819168`.
The package/result bind source, actual executable, independently installed
source/CMake/link/library, image, serial and command hashes. Separate source
and import CTests pass in Debug/static and Release/shared. Host final relevant
suites pass14/static and15/shared tests with one explicit shared-hugepage
MPskip each; the actual MP acceptance above supplies the required evidence.

The objective is **50/50**:44 previously blocked and6 previously partial IDs,
verified against actual baseline commit `7f46febca`. The full catalog changes
from218 to268 adapted,127 to83 blocked and18 to12 partial; these remaining
catalog entries are not claimed complete. Every eligible completed ID and its
assertion/runtime tests is recorded in `tests/fstack-unfinished-completed.json`.
