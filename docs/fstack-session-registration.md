# Resident EAL session registration

[Issue #218](https://github.com/rutlang-ai/Ker/issues/218) requires a resident
primary and actual secondary processes before generation handover can be
qualified. `ker-io-session` and `ker-session` implement this registration stage
using original DPDK EAL, memzones and rings. The existing packet worker and
`ker-run` secondary admission boundary remain unchanged.

## Running the registration stage

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
Readiness reports `registration-only`; no application command is accepted.
The tool selects `--proc-type`, adds `--no-pci`, and rejects device admission.
The compiled worker independently requires no PCI and rejects virtual-device
and allow-list options. No PMD, network device or original Linux application
instance is created at this stage.

Input or EOF requests each process to stop. Stop the leases before stopping
the resident for normal cleanup. Signal handling also requests shutdown.

## Geometry and process lifetime

The resident precreates the directory and all 96 bounded original DPDK rings
before publishing readiness: four epoch slots (slot zero reserved), two
generations, four process indices and control/RX/TX rings per coordinate.
Each ring has capacity 64 and declares single-producer/single-consumer use.
That declaration does not yet prove data ownership: this stage only looks up
rings, without enqueueing packets or granting a consumer.

A private local seqpacket connection authenticates the same UID and obtains
an original kernel peer pidfd. Master registrations receive a monotonically
increasing epoch and a random ticket. Slots are storage rather than identity.
A secondary reserves its coordinate **before** borrowing EAL memory; it must
be a direct child of the registered live master. After EAL initialization it
validates the directory ABI, resident identity, session, epoch and complete
geometry, looks up its three rings, and acknowledges attachment. Duplicate
coordinates and stale or foreign identities are rejected. Exact request
replays return the cached result; changed or older sequence numbers fail.

Socket EOF alone never proves an EAL borrower dead. The resident retains its
pidfd, including after master loss, until actual process death. An epoch can
be recycled only after all registered borrowers have died and all its rings
are empty. A stopped secondary therefore blocks release. There is no timeout
that frees live references, no packet discard to manufacture an empty ring,
and no fallback to an independent primary.

Resident shutdown publishes stopping and allows five seconds for borrower
exit. If any remains alive, it exits 125 without freeing shared objects or
calling EAL cleanup. This preserves the failed namespace and backing files;
production crash recovery and operator reclamation are not implemented yet.
A secondary treats resident process death as fatal. Normal secondary exit
performs original EAL cleanup before the master releases its epoch.

## Acceptance and remaining work

`native-fstack-session-registration` runs the production tool and compiled
worker. It requires the real shared-memory EAL profile and skips with code 77
when free writable hugepages are unavailable. A skip is not a runtime pass.
The isolated guest profile in [the environment investigation](fstack-reload-environment.md)
provides those prerequisites without changing host hugepages or global settings.

The test covers a resident and three simultaneously live master/secondary
chains, distinct epochs and ring lookup, retry/identity rejection, duplicate
coordinates, failed EAL initialization, master death with a surviving borrower,
slot recycling, cancellation of non-borrowing queries, normal cleanup, and
refusal to free a stopped live borrower. The test owns and reaps its exact
children; only after proving borrower death does it reclaim its own unchanged
hugepage backing files left by the intentional failed shutdown.

The 79 actionable source cases in #218 remain blocked. Packet envelopes,
shared pools, generation admission and grants, PMD secondary compatibility,
single-consumer enforcement, packet delivery into original Linux, draining,
hardware handover and caller-managed graceful reload still require real
implementation and source-case acceptance. This registration stage is an
implementation prerequisite, not a replacement for those contracts.
