# Generation reload ownership contract

This is the implementation prerequisite for [issue #218](https://github.com/rutlang-ai/Ker/issues/218),
not a claim of full reload support. Of its 79 actionable cases, 18 have bounded
scenario adaptations: four A4 cases (complete primary precreation, namespace
recycling, own-slot secondary lookup/device claim and epoch liveness), NR-19
generation-ring ownership, the narrow TC-3 same-generation observer, the TC-5
live-coordinate/ring-name query, TC-7 drain-peer semantics, three P1 configured-ring detach
cases, the empty-queue-configuration cleanup case, the F-M4-1 TX full-ring visibility case, and five directory admission cases (full,
missing, invalid, primary-slot-busy and success). Directory success observes default-off and
generation-rings-enabled configurations in the same production adapter domain,
including real secondary attach replay; it does not claim a literal graceful_reload
switch or F-Stack ABI equivalence. The TC-5 adapter uses Ker's authenticated internal typed
control command; it does not implement the original FF_RELOAD_CMD_QUERY/ff_ipc ABI or
packet/flow migration. F-M4-1 adapts only actual enqueue-full visibility, caller ownership of the rejected object, FIFO drain/cleanup, and typed full/drop/peak counters; it does not claim hardware NIC behavior or broader TX semantics. Another 61 cases remain incomplete, all blocked.
The two page-array build assertions are separately excluded in #232. The source
pin is `646a641cfff77f4815e1e29829a09e1ed15a2999`.
The retained tests are authoritative; proposed Ker mechanisms below still need
implementation and runtime qualification.

The first executable prerequisite now exists as a separate
[resident EAL registration stage](fstack-session-registration.md): it precreates
bounded shared rings and attaches real secondaries under live master epochs.
It also exchanges authenticated shared control mbufs with the parked resident,
including resident-journaled leases recovered after exact borrower death,
even when a worker exits before enqueue or after reply dequeue.
The optional [original ring-PMD stage](fstack-session-pmd.md) now supplies an
actual secondary consumer grant and a live standby that samples the owner and
takes over in the same PID/EAL/epoch after exact borrower death. Epoch liveness
comes from the resident pidfd census, including surviving/frozen orphans and
stale-epoch rejection after slot reuse. The [directional packet stage](fstack-session-packets.md)
also transports real IPv4/IPv6 TCP/UDP frames into an original imported-Linux instance through a
granted EAL secondary, without a primary packet relay. Cross-generation
dispatch/drain and exception-owner agreement, physical PMD handover and full
application reload remain unimplemented.

## Existing boundary and implementation choice

At baseline `6c032bb42c3286faeafee7940fe900d38ba472b9`,
[ker-run.py](../tools/ker-run.py) creates packet/control channels for one
application and independent primary workers. [io-worker.c](../src/posix/io-worker.c)
rejects secondary EAL processes after initialization; the launcher also rejects
explicit secondary arguments before execution. Closing a launcher's control
pipe drains its worker and ends that device session.
[tx-ring.h](../src/runtime/tx-ring.h) explicitly promises same-process SP/SC
only. [flow.h](../src/runtime/flow.h) borrows in-process worker/context pointers
and fixes bucket ownership during quiescent setup. Neither adapter provides a
shared generation directory, transferable admission, or process-death proof.
The existing flow parser and hash do not establish Linux connection ownership.

The target topology is one resident DPDK primary, two generation slots per
master epoch, and generation I/O processes attached as real EAL secondaries.
Each application generation retains its own original Linux instance. The
primary creates the shared pools, directory and bounded rings before admitting
secondaries; it remains available for control/probe and orphan reclamation
while parked from application packet consumption. Generation I/O processes
must use the same original DPDK memory namespace and compatible device profile.
This requires a distinct supervised session lifecycle; removing the existing
secondary rejection alone is unsafe and does not implement this topology.

A permanently active primary relaying bytes to independent application kernels
is a possible different architecture, but would not prove the source hardware
handover, secondary lookup or shared-ring contracts. It must not silently
replace this design or qualify those tests. Actual secondary support for the
chosen original PMD is a prerequisite: start with a no-PCI virtual-device
profile that demonstrably supports the required operations, then qualify each
additional driver. No Linux or DPDK source modifications are assumed.

Application-specific HUP/USR2 orchestration, nginx worker counts, listener policy
and business readiness belong to the caller/test application. Ker supplies
registration, quiescence, device ownership and packet transport. The nginx FSM
in the retained config tests is an application contract; a standalone copy of
that table in an unused Ker helper cannot qualify it.

## Identities, bounds and publication

A session identity identifies one resident primary lifetime. Every message,
registration, packet envelope and query reply carries that session plus
`epoch`, `generation`, `process index` and a monotonically increasing operation
sequence. An epoch identifies one master lifetime; generation is 0 or 1 within
that epoch. A recyclable directory slot is storage, never an identity. Reusing
a slot must not make delayed traffic or acknowledgements valid again.
Epoch/sequence exhaustion rejects new admission rather than wrapping into a
live identity. Process identity must include a stable lifetime reference
(for example a pidfd), not just a numeric PID that can be reused.

Before accepting any client, the primary publishes a validated directory
header (magic, ABI version, size, slot/process/ring bounds, session identity)
and all ring/pool descriptors for the configured finite topology. Publish the
ready state last. An attaching process validates the complete geometry and
looks up its own descriptors; it never creates a missing shared ring or
falls back to epoch zero. Missing, invalid, full or initializing directories
produce distinguishable failures and no application execution. A bounded wait
may handle a legitimate initialization window; timeout leaves ownership intact.

Keep separate registrations for hardware users and ring users. A process may
stop touching the device while still receiving or draining generation rings.
Registration is idempotent for the same process lifetime and coordinate;
conflicting registration fails. Every queue producer/consumer is identified,
including remote EAL RX lcores. Admission cannot double the configured hardware
queue count just because two generations coexist.

## Ownership and handover

The device owner is one atomically published `(session, epoch, generation,
operation)` coordinate. All hardware queues in the handover domain use the same
coordinate; the RX owner and host-exception owner must agree. Within that
coordinate, retain each queue's single-consumer assignment. A successful claim
is not permission for every process of a generation to poll the same queue.

Only a process with a current hardware-user registration and queue grant may
enter RX/TX bursts or device control. Every poller acknowledges parking after
its last in-flight device call returns. A stale heartbeat, master exit or
control-channel EOF alone is not a parking acknowledgement. Device changes
such as MTU rebuild, port stop, queue setup and bond changes must not race
handover; serialize them under the session's device operation or reject busy.

The caller drives this lifecycle:

| Phase | Required evidence before advancing | Failure behavior |
| --- | --- | --- |
| Serving old generation | Current queue grants, live ring users and original Linux instance | Preserve its ownership until explicit quiescence/death proof. |
| Preparing new generation | Complete lookup/registration, Linux/netdev readiness and live processes for every configured participant | Roll back only the new preparation; old keeps serving. No overlapping reload transaction. |
| Parking old hardware users | Matching operation ACK from every poller; no device calls in flight | Deadline reports busy; never steal from a stalled live user. |
| Publishing new owner | Compare-and-swap against the exact old coordinate after all parking proofs | A mismatched owner/operation aborts publication. Never accept a delayed ACK. |
| Draining old generation | New owner transmits old queued TX; RX transport reaches the correct old Linux instance | Keep old kernel, ring registrations and transport live. A queue-empty sample alone is insufficient. |
| Retiring old generation | Caller reports drain completion, all ring borrowers detach, queue/pool accounting reconciles, old processes exit | Remain non-reusable on incomplete proof; surface failure instead of reporting success. |

An owner publication and an acknowledgement to its requester are separate
operations. Retrying a lost reply must return the recorded operation result,
not perform a second transfer. Before publication, preparation can be cancelled
without disturbing the old owner. After publication, restoring an old owner
requires a new park/prove/publish transaction against the actual current owner;
resetting a state variable cannot implement rollback.

The retained nginx FSM has 12 legal transitions over seven states and 11
events: idle/HUP, spawn/all-ready, handover/ack, drain/done, drain-done/quit,
old-exited/idle; spawn timeout/death and abort during handover/drain/drain-done
enter error, whose only exit is reset. Those table checks remain separate from
proof that the runtime actions above actually occurred. Caller reset is allowed
only after ownership and cleanup have reached a known state.

## Liveness, recovery and reclamation

A live master protects its epoch. If the master exits, live orphan workers and
ring users still protect that epoch while draining. Hardware takeover additionally
requires every displaced hardware user to acknowledge stopped or have proven
process death. Heartbeat timeout indicates a suspect peer; it does not grant
permission to free memory or run a second consumer. An unresponsive live worker
therefore blocks takeover until it cooperates or its exact process lifetime ends.

Primary death invalidates the session; do not reconnect secondaries to a new
same-name primary and resume old pointers. End the affected session with an
infrastructure failure and reconcile each surviving process/reference before
recreating shared objects. Client death must not destroy a resident session or
unrelated generations. Master replacement must use a new epoch even when a
numeric PID or directory slot is reused.

Purge requires an exclusive reclaim operation with a fresh census, serialized
against registration and slot reset. A missing directory is absence of proof,
not permission to purge. A never-attached coordinate may still be starting.
A recorded dead RX consumer allows purging its RX ring, but its TX ring may
still have a live hardware consumer from another generation. Preserve that TX
ring until its borrowers are quiescent too. Never purge solely because the
master died or the ring is momentarily empty. A new registration after the last
dead marker was consumed must not inherit permission to discard new packets.

Slot reuse waits for that census, transport shutdown, queue reclamation and all
remaining references; then reset storage and publish the new identity last.
The number of slots, rings, mempools, user registrations and outstanding packets
must remain bounded through repeated master replacement. Exhaustion is an
explicit admission failure, never a fallback into the primary's slot.

## Packet and IPC ownership

Every successful enqueue transfers one complete mbuf-chain reference; failure
preserves producer ownership. Partial bursts account accepted prefix and
retained/dropped suffix exactly once. A non-owner sends TX through bounded
transport to the current granted hardware consumer and never calls the PMD
itself. Epoch, session and operation checks apply before accepting redirected
traffic. Define observable full/drop/retry counters and budgets; no unbounded
retry loop or allocation growth. Draining must include queued, retained and
in-flight chains plus original Linux/application lifetime evidence.

A control request has a unique client-lifetime/sequence tag and an explicit
coordinate or a non-destructive live-coordinate query. Pointer equality is not
reply identity. One client's receive cannot return or free another live
client's reply; no pending request means no reply can match. A provably dead
client's orphan reply can be reclaimed once. Probes must neither consume nor
free unrelated replies, and a parked primary must still answer with the live
worker coordinate rather than its own epoch zero. Malformed or stale messages
must not modify state or optional output arguments. Exact legacy string/ring
names in the source IPC tests require a separate compatibility decision; a
new wire envelope does not automatically pass those ABI assertions.

## Original Linux connection ownership prerequisite

The retained half-open/admission tests depend on actual kernel flow ownership,
including SYN-ACK failure rollback and surviving lookup probe chains. A tuple
hash or SYN-bit observer alone cannot establish this. Before implementing the
reload dispatcher, identify an original Linux lookup/lifetime interface that
covers request sockets, established sockets and their removal, then expose it
through Ker adapters with the kernel's required synchronization and references.
Prove routing across two original Linux instances with actual packets during
handover, including retransmission and failure. Ker must not implement its own
TCP handshake, ACK/window, retransmission, congestion or teardown state machine.

If the pinned Linux interface cannot express a required admission/rollback
point without an upstream patch, document the concrete missing hook and why an
adapter cannot solve it before considering a minimal isolated patch. Until
that proof exists, half-open routing, admission/revoke and end-to-end graceful
reload remain unsupported. No always-successful flow callback or configuration
flag may conceal the boundary. Existing connection ownership must survive a
reload; routing every packet to the newest generation is insufficient.

## Qualification sequence and evidence

The source files below are unchanged. Each qualification must retain exact
source IDs in the migration manifest and name its actual executable evidence.
This design supplies no pass/provenance entry for any of them.

| Source cases | Required independent evidence |
| --- | --- |
| Generation-directory integration (7 in `test_ff_gendir_mp_integration.c`) | Real original-EAL primary and secondaries under two distinct, simultaneously live masters; precreated/lookup-only rings; distinct epochs and packet tokens; exactly one queue consumer; live-coordinate probe; orphan drain; repeated slot recycle. Use a memory mode actually supporting secondaries; no-huge independent primaries do not qualify. |
| Reload integration (7 in `test_ff_reload_integration.c`) | Boot/parked control progress, non-owner TX diversion, watermark drain and burst guard; actual original Linux half-open packets routed to the correct kernel. |
| Config lifecycle/directory tests in `test_ff_config.c` | Valid/invalid real topology configuration, finite geometry, complete legal/illegal lifecycle table, delayed operation/epoch rejection, owner/user proof, orphan liveness and census-locked purge. Schema rejection without a valid positive configuration is insufficient. |
| Page-array build tests (2 in `test_ff_config_pa.c`) | The source build with `FF_USE_PAGE_ARRAY` must reject graceful reload while continuing to accept the minimal reload-off configuration. Ker has no same build mode; generic unsupported-key rejection does not prove this conditional positive/negative contract. The explicit exclusion is recorded in [the page-array audit](fstack-page-array-contracts.md) under #232. |
| DPDK glue tests in `test_ff_dpdk_if.c` | Original shared pool/cache and SP/SC rings, exact queue ownership, full-ring visibility, peer/foreign-epoch TX, missing/full/transient directory behavior, bounded flow admission and growth, dead-user purge returning the pool to baseline. |
| IPC tests (12 in `test_ff_ipc.c`) | Coordinate parser/serialization compatibility plus two live clients, delayed/foreign replies, dead-client reclamation and non-destructive probe under concurrent real control traffic. |
| `test_graceful_reload.sh::entrypoint` | A caller-owned server on original Linux, external traffic across repeated HUP/USR2, continued existing streams and new connections, explicit fault/timeout scenarios, process ownership and complete resource cleanup. Parse-only/harness self-tests do not qualify. |

## Explicit architecture exclusions

The following source assertions are outside #218's qualification sequence. They remain
architecture-specific exclusions under #232, with no Ker pass or test mapping:

- `tests/unit/test_ff_config_pa.c::test_page_array_rejects_graceful_reload` requires
  the optional `FF_USE_PAGE_ARRAY` source build to reject reload because staged TX
  carries process-private FreeBSD `bsd_m_table` references.
- `tests/unit/test_ff_config_pa.c::test_page_array_keeps_graceful_off` is the paired
  assertion that the same build accepts minimal reload-off configuration; Ker has
  no equivalent build mode or process-private FreeBSD mbuf-table representation.

Both assertions are from F-Stack revision `646a641cfff77f4815e1e29829a09e1ed15a2999`.
See [the page-array audit](fstack-page-array-contracts.md) for the source boundary and
rationale. These exclusions add no passes. The current branch catalog records 61 remaining #218 cases
(all blocked); the three bounded P1 detach-retention cases, the empty-queue-
configuration adaptation and five directory-admission adaptations are mapped separately,
while broader drain and reload behavior remains open. The added non-owner case covers a live
generation-1 PMD/RX owner while generation 0 is detached under the same authenticated master
epoch: only RX q0/g0 is reclaimed, while TX q1/g0 and the six other ring entries remain owned.

The current integrated candidate `0ac28b8973b1f79e5fdbb9a86335531d9f71fd14` passed all 13 suites in one fresh guest image. The actual-result manifest is `/home/hurricane/.local/state/ker-compat-work/fstack-followups/session-directory-modes-integrated-guest2/actual-result-attemptmodes-integrated1.json` (SHA-256 `30f449b0762efa5fd0f953103aed2ee3c7f11368cf72b4ec624b9cef67e51571`); it binds package manifest SHA-256 `4d87ed42fe94ed1c45736a62701779fe2683511dd933115105c5d07d4bd45cbb`, image SHA-256 `32750d8b2c2648edf6abe56287d18723b030cad79a7879ebf954d2a9ed5d6149`, and serial SHA-256 `d2c258cc7feedca27e0becc0a83d17bf901dcb29763fef6e93106898b6022d44`. The run includes current default-off and enabled generation-directory registration, TC-3 observer, live coordinate, USR2 drain-peer, P1 detach, empty-mask retention and invalid-entry fail-closed profiles. All suite exits were zero, all 511 pool objects were restored with zero outstanding, and QEMU exited 0 after normal power-down. Earlier guest6 and split runs remain historical evidence; the current manifest is the latest combined qualification.

Begin implementation with the resident-session lifecycle and real secondary
attachment/lookup, integrated with process supervision rather than a detached
unit-only directory. The first integration gate must create two real master
chains, synchronize both participants' samples before either exits, prove one
consumer with packet delivery and leave no processes or mbufs behind. Next add
park/publication and crash/recycle evidence; qualify the Linux connection hook
before enabling application reload or attempting the flow-map cases. Keep
hardware-dependent PMD profiles explicit and unqualified profiles unsupported.

The current branch catalog records 204 scenario-adapted, 12 partial, 147 blocked,
15 architecture-specific and 55 harness-only (433 total).
The 159 blocked/partial cases, including the 61 remaining here, remain unfinished;
`--require-complete` must continue to fail.

For the actual local EAL attachment precondition and its observed failure, see
[the environment investigation](fstack-reload-environment.md). This environment
limitation does not waive any of the implementation or packet-delivery gates.
