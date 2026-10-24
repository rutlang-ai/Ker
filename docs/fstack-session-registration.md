# Resident EAL registration and shared control

[Issue #218](https://github.com/rutlang-ai/Ker/issues/218) requires a resident
primary and actual secondary processes before generation handover can be
qualified. `ker-io-session` and `ker-session` implement registration and shared control
using original DPDK EAL, memzones, mbuf pools and rings. The existing packet worker and
`ker-run` secondary admission boundary remain unchanged. Optional device admission
and live standby are documented separately in [the ring-PMD stage](fstack-session-pmd.md);
the shared-control commands below do not enable them.

## Running the shared-control stage

Build the `ker-io-session` target with the native Linux configuration. The
installed `ker-session` tool locates that executable beside itself; from a
checkout use `python3 tools/ker-session.py` with an explicit `--worker` path.
Linux must provide `SO_PEERPIDFD` (introduced in Linux 6.5), and the original
EAL shared-memory profile needs writable hugetlbfs and sufficient free hugepages.
The program checks peer pidfd support before initializing EAL.

Start the resident from a terminal, keeping its standard input open:

```sh
ker-session serve --socket "$SESSION_DIR/control.sock" \
  --eal '--lcores=0@0 --no-telemetry --iova-mode=va -m 64 --file-prefix=ker-session'
```

Choose an allowed CPU and a unique EAL file prefix; `SESSION_DIR` must be a
private directory owned by the current user. The tool creates a missing parent
with mode 0700. Each master uses the same socket and EAL options in another
terminal, also keeping standard input open:

```sh
ker-session lease --socket "$SESSION_DIR/control.sock" --generation 0 --process 0 \
  --eal '--lcores=0@0 --no-telemetry --iova-mode=va -m 64 --file-prefix=ker-session'
ker-session status --socket "$SESSION_DIR/control.sock"
```

`serve` executes a real primary. `lease` remains the master and starts a direct
child running original EAL secondary initialization and shared-object lookup.
Readiness reports `shared-control`; no application command is accepted.
The tool selects `--proc-type`, adds `--no-pci`, and rejects device admission.
The compiled worker independently requires no PCI and rejects virtual-device
and allow-list options. No network PMD, network device or original Linux application
instance is created at this stage.

The lease supervisor relays caller input through a private control pipe. `P`
requests one configured batch; non-`P` input or EOF requests graceful stop.
During a batch the secondary checks the pipe between allocations, publications
and reply waits. A queued `P` is deferred until the current batch finishes; it
is not consumed as a stop. EOF, other input, SIGINT or SIGTERM cancels the
active batch. Cancellation before publication leaves the resident's leased
mbuf untouched; after publication the ring reference remains resident-owned
until exact secondary death permits journal reclamation. The one-shot `probe`
action completes its requested batch even when caller stdin is empty. The
supervisor closes its private control writer on signal, waits up to five seconds
for original secondary EAL cleanup, then sends SIGTERM and uses SIGKILL only
after a further timeout. Graceful SIGTERM exits 143 (SIGINT 130); any escalation
reports failure. Stop leases before stopping the resident for normal cleanup.

## Geometry and process lifetime

The resident precreates the directory and all 128 bounded original DPDK rings
before publishing readiness: four epoch slots (slot zero reserved), two
generations, four process indices and control/RX/TX/reply rings per coordinate.
A 511-object original mbuf pool with no per-lcore cache is created before
readiness; secondaries only look it up. The internal ABI is now version 3.
Each ring has capacity 64 and declares single-producer/single-consumer use.
The authenticated secondary is the sole request producer and reply consumer
for its coordinate; the resident consumes control requests and produces replies.
RX/TX rings remain unused, and no network-device consumer is granted.

A private local seqpacket connection authenticates the same UID and obtains
an original kernel peer pidfd. Master registrations receive a monotonically
increasing epoch and a random ticket. Slots are storage rather than identity.
A secondary reserves its coordinate **before** borrowing EAL memory; it must
be a direct child of the registered live master. After EAL initialization it
validates the directory ABI, resident identity, session, epoch and complete
geometry, looks up its four rings, shared pool and resident-assigned mbuf lease, and acknowledges attachment. Duplicate
coordinates and stale or foreign identities are rejected. Exact request
replays return the cached result; changed or older sequence numbers fail.

Socket EOF alone never proves an EAL borrower dead. The resident retains its
pidfd, including after master loss, until actual process death. An epoch can
be recycled only after all registered borrowers have died and all its rings
are empty. A stopped secondary therefore blocks release. There is no timeout
that frees live references, no discard of a live borrower's traffic to manufacture an empty ring,
and no fallback to an independent primary.

Resident shutdown publishes stopping and allows five seconds for borrower
exit. If any remains alive, it exits 125 without freeing shared objects or
calling EAL cleanup. This preserves the failed namespace and backing files;
production crash recovery and operator reclamation are not implemented yet.
A secondary treats resident process death as fatal. Normal secondary exit
performs original EAL cleanup before the master releases its epoch.

## Shared control probes and mbuf ownership

Run `ker-session probe` with the same socket and EAL options as `lease` to
create a real temporary master/secondary chain, exchange a shared control
message and exit after cleanup. `--probe-count N` requests 1..4096 roundtrips.
A long-lived `lease --probe-count N` performs a batch when its standard input
receives `P`; each later batch advances its sequence. Other input or EOF stops
it. This permits independent master chains to be fully attached before their
probes run concurrently. `status` reports registered EAL users, available
message-pool objects and outstanding objects without initializing EAL itself.

Each request publishes the resident-assigned original mbuf carrying a fixed
envelope and 64 bytes of coordinate/sequence-derived payload. Ring enqueue
transfers the shared reference while the allocation remains under the resident's
private coordinate journal. The resident validates session, epoch, generation,
process, slot, request state and increasing sequence, then returns the same
object through that coordinate's reply ring. The requester verifies the full
returned envelope, resident PID and all payload bytes before reusing its leased
mbuf; the secondary never frees the allocation. This is a transport health probe, not the source tools' hardware-owner
query: no hardware-owner word exists yet. Replies are not synthesized in the
requesting process or returned through the registration socket.

Enqueue transfers ownership. A request timeout cannot free the published mbuf,
because the resident may still own it. When the exact borrower is dead, the
resident reclaims its queued control requests/replies before recycling the
epoch. A full reply ring leaves requests queued rather than discarding them. A cancelled
request is not freed by its secondary; if it was already published, the exact
borrower must die before the resident drains the request/reply ring references
and clears the journal. Cleanup requires all EAL borrowers dead, every ring empty
and zero outstanding message objects. The resident allocates and records exactly one original
control mbuf per coordinate before acknowledging RESERVE, then publishes its
pointer in the shared directory with release/acquire ordering. The secondary
never allocates or frees control mbufs; it reuses the assigned object only
after validating each reply. The resident verifies that every queued object
matches that coordinate's private lease record. After exact borrower death it
removes queued references, verifies the shared lease agrees, clears it and
returns the mbuf exactly once, including when neither ring contains it. This
covers death before first enqueue and after reply dequeue. A live borrower,
foreign/duplicated reference, lease mismatch or unexplained balance prevents
cleanup; packet-pool journals and resident-crash recovery remain unqualified.

`status` counts the original pool's live allocations: three registered EAL
borrowers hold three control leases even while idle, so 508 of 511 objects are
available. After their exact deaths and reclamation, all 511 must be available.
A slot cannot recycle while any directory lease remains nonzero.

## Acceptance and remaining work

`native-fstack-session-registration` runs the production tool and compiled
worker. It requires the real shared-memory EAL profile and skips with code 77
when free writable hugepages are unavailable. A skip is not a runtime pass.
The isolated guest profile in [the environment investigation](fstack-reload-environment.md)
provides those prerequisites without changing host hugepages or global settings.

The test covers a resident and three simultaneously live master/secondary
chains, distinct epochs and ring lookup, retry/identity rejection, duplicate
coordinates, failed EAL initialization, master death with a surviving borrower,
slot recycling, cancellation of non-borrowing queries and active 4096-probe
batches through non-`P` input and supervisor-only SIGTERM, normal cleanup, and
refusal to free a stopped live borrower. It gates three live chains before
concurrent shared-mbuf exchanges, checks monotonic second-batch sequences,
runs the production one-shot probe, and freezes the resident until a published
request times out. After borrower death the resident must recover all 511
objects and continue admitting a new probe. The test owns and reaps its exact
children; only after proving borrower death does it reclaim its own unchanged
hugepage backing files left by the intentional failed shutdown.

The source A4 case `test_it_a14_usr2_chain_slot_recycle` is now scenario-adapted:
three plain masters occupy all reusable slots and are killed without RELEASE;
their live EAL secondaries still protect the slots. After those secondaries
leave original EAL, a fourth master and real secondary must receive a fresh
nonzero epoch/slot and validate shared-object lookup through actual control
roundtrips. This qualifies only namespace recycling, not application USR2 or
packet handover. Precreation, own-slot lookup and cross-master isolation source
cases remain partial because their fixed network dispatch and hardware-owner
assertions are missing. Issue #218 retains 78 incomplete cases: 74 blocked and
4 partial (including the pre-existing local SP/SC partial case).

Shared packet envelopes,
packet-pool ownership journals, generation admission and grants, PMD secondary compatibility,
single-consumer enforcement, packet delivery into original Linux, draining,
hardware handover and caller-managed graceful reload still require real
implementation and source-case acceptance. This registration stage is an
implementation prerequisite, not a replacement for those contracts.
