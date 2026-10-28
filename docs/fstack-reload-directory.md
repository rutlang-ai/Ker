# Cross-master directory and user proof

Five baseline-incomplete source cases are now qualified through unchanged
upstream runtime, complete source assertions and real EAL/net_ring repository
and independently installed consumers. The baseline-to-current completion
count is **36/50**, with 14 still required. Only the five cases below are newly
complete; remaining directory naming/arbitration and application reload cases
retain their prior status.

`ker::reload` now builds the pinned original `lib/ff_reload_gendir.c`, alongside
the already imported `lib/ff_reload.c`. Both sources, the original configuration
layout and `ff_log.h` remain byte-for-byte unchanged. `UPSTREAM.json` records
GitHub-verified original Git blobs and SHA256 hashes. The compatibility layer
maps original logging to the registered `ker.reload.directory` DPDK log category;
it does not suppress or simulate logging.

The explicit APIs in `ker/reload-directory.h` borrow the caller's initialized
EAL and state storage. Primary reserves the original directory memzone;
secondaries look it up. The original backend derives secondary identity from
the real parent PID, assigns an epoch-derived slot, and retains fatal startup
refusal for missing/incompatible directories and conflicting slots. Primary
cannot poll hardware through this adapter. Attach fixes the generation and
worker slot for that process; detach releases both original local pointers.

Every secondary starts with an original STOPPED registration, so an attached
worker that has not polled is also tracked during orphan retirement. Polling
registers an original ACTIVE hardware-user lease before entering the
original ownership gate. A denied pass acknowledges STOPPED only after the
previous callback returns. Callback return alone leaves the lease ACTIVE.
Explicit stop/release require the caller to keep hardware work quiescent.
Release is terminal for the attachment; subsequent poll/transfer/reclaim/new
ring admission are refused until detach and a fresh attachment. Stop alone
permits a later poll.
Foreign ownership moves through the original proof-bearing release/reclaim
operations; implicit mirroring is suppressed while a foreign coordinate owns
RX. The adapter continues the original peer observation and liveness stamping
while that mirror is suppressed. Concurrent first claimants use the original
CAS reclaim operation before any mirror publishes. No protocol implementation
or automatic process supervisor is added.

Ring registration, census and purge locking expose the original runtime
operations. The application still owns resource initialization and purge:
serialize recycled-slot startup, hold the purge lock across census and dequeue,
leave slots with live users alone, drain all old objects before admitting a
recycled slot, and return every mbuf/message to its original pool. The recycled
flag in the view is observational and is not consumed by the view operation.
These primitives do not themselves prove that a ring has been drained.

Detach refuses this process's remaining registrations or purge lock. Departing
orphans preserve LIVE epoch state while other registered processes still borrow
that epoch. Destroy is primary-only and additionally refuses visible live
foreign masters and users. The caller must first prove that **all** other EAL
participants have exited, including unregistered observers. After detaching,
destroy frees the original memzone; a failed free reports an error and leaves
the local attachment detached. EAL cleanup and all other resources stay caller
owned. The component exposes 44 public APIs including the previous 28; original
helpers remain hidden.

The private fixture compiles the actual production translation unit for raw
source preconditions. `fstack-reload-directory-source.inc` is an unchanged
excerpt containing all original P2/RX-15 assertions, compared byte-for-byte
with the pinned `test_ff_config.c` by `fstack-reload-import`. Only cmocka's
assertion host is mapped to CHECK; runtime helpers are the original implementation.
Raw field mutation exists only in this noninstalled fixture. Each source case
has its own executable selector and CTest:

| Source case | Independent CTest |
|---|---|
| `test_p2_hw_user_proof` | `fstack-reload-directory-hw-users` |
| `test_p2_reclaim_needs_user_proof` | `fstack-reload-directory-reclaim` |
| `test_p2_release_epoch_needs_proof` | `fstack-reload-directory-release` |
| `test_p2_orphan_workers_keep_epoch_live` | `fstack-reload-directory-orphans` |
| `test_rx15_ring_user_census_and_purge_lock` | `fstack-reload-directory-ring-census` |

The extra primary-probe assertions do not qualify
`test_ut_nr_m5_probe_epoch_fallback`; its actual routed IPC consumer is still
required. The primary-EAL create/destroy test and lifecycle guards are extra
regressions, not additional source cases.

## Actual distinct-master consumer

`fstack-reload-directory-multiprocess` creates two real master parents, each
with two actual EAL secondary children. A Unix socket transfers duplicate stdin
and stdout pipe descriptors to the top-level test process. That process enables
Linux child-subreaper handling and retains exact pidfds, so killing/reaping one
master leaves its actual workers alive, adopted and controllable. No fabricated
parent identity or shared-memory PID mutation is used in this profile.

The original net_ring PMD, two caller-owned shared state blocks and a cache0
63-mbuf pool remain caller-owned. A real RX callback is held before its burst;
a foreign worker cannot consume the pending packet. Release refuses after the
unchanged production5s budget, rolls back local park state and increments the
original refusal counter. Callback return without STOPPED still refuses. Proven
STOPPED allows epoch/generation release and claim; reversal repeats the proof.
All four original RX/TX records validate their exact mbuf identity, nonce,
sequence and payload. Repeated polls retain one registration per actual PID.

After actual master death, four orphan polling passes keep its epoch live.
When those passes cease, the original timestamp really becomes stale. Neither
ordinary foreign polling nor explicit reclaim can displace its still-ACTIVE
workers. An actual crashed/reaped worker ceases to block, but its surviving peer
still blocks until STOPPED. Reclaim then succeeds. A separate live master
remains protected after a measured2300ms no-poll interval. Three bounded release
refusals and two user-proof reclaim refusals produce counter5; success and
live-master/fresh-orphan refusals leave that count unchanged.

Actual ring users demonstrate idempotent attach, live-holder timeout with
registration rollback, nonowner unlock refusal, dead-holder takeover and
per-slot live/dead census. Purge preserves a dead marker and both queued mbufs
while another real user is alive. That user receives the exact two-object FIFO.
After detach, purge reclaims the next two actual mbufs and clears idle markers;
a repeated purge frees nothing. Re-admission consumes another two-object FIFO
on the same ring. Every record checks original pool identity, exact object
identity, nonce, sequence and payload. Final queues are empty and pool63/63.
The source-only128-entry capacity and cross-generation/cross-slot marker
assertions also run unchanged; four actual workers validate the consumer path.

The installed program is built outside the repository using `find_package(ker)`
and `ker::reload`, plus the original net_ring driver. Its application/check
sources equal the repository bytes, and its CMake, link command, installed
library and executable hashes are recorded. It uses only public Ker and DPDK
interfaces. Both profiles finish with callbacks `[6,1,2,0]`, received
`[1,1,2,0]`, PMD RX/TX4/4, no in-flight work and pool63/63. Every owned worker is
reaped before primary resource destruction; the deliberately crashed secondary
exits0 without EAL cleanup to supply the real dead-user proof, and its remaining
shared resources are reclaimed by the primary. Other EAL lifetimes exit cleanly.

## Evidence and limits

Debug/static and Release/shared run all five source selectors, the source-import
checks and primary-EAL lifetime test. Host shared-hugepage skip77 is never
completion evidence. Fresh isolated guest10 at candidate
`fff309ac0118683cc848e7d086aa5bca132e97ab` reruns the prior five runtime profiles,
both prior examples and both new directory profiles. Every profile passes,
followed by normal guest power-down and QEMU exit0.

Artifacts are retained outside worktrees at
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest10`:

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `ebeb8e2e05f69e30934434572f1c1d0118f631b13183d1af9d710187bbdf4d5a` |
| `package-manifest.json` | `ae3201eb24b49f9836bd7243c0caaff98164e35c541fcc6db60b7d8f1ae9e213` |
| `initramfs.cpio.gz` | `a6d695337dce97aa4597ce94c3904350b159ead1c772a2ace7610900237a7314` |
| `serial-attempt1.log` | `639a80a0be1e7357f5be25002734fcba851818fd9af98cea856382db32eead50` |
| `qemu-command-attempt1.json` | `fb361af6cca8a719678de0c4cf86a3c9344fa67ef07d0d4c434f6e8775bbf12b` |
| `qemu-host-attempt1.log` | `659fbea079cc86b145595394d5604d207a193b5bca774bb3a53bf6c144753757` |

This proves the named cooperative runtime contracts with the original software
PMD. It does not qualify physical NIC DMA, imported-Linux traffic through this
component, TCP continuity, the full cross-master name/handover sweep, recycled
resource orchestration or complete application reload. The caller still owns
queue assignment, all packet work, purge policy and process supervision.
