# Same-master polling and park confirmation

The optional `ker::reload` component now provides a synchronous polling adapter
around the unchanged original F-Stack runtime's generation gate and park
markers. It supports cooperating processes that borrow the same original shared
state block under one master. It does not install a cross-master directory or
change original Linux networking or DPDK code.

The caller owns state storage, EAL, devices, queues, packet work and process
coordination. Initialize the original block once, map/borrow it in each worker,
then select that worker's generation and slot with `ker_reload_worker_select`.
Serialize API calls within each process. `ker_reload_poll` calls the application's
callback only when the original runtime permits RX, and forwards its result.
The callback retains ownership of all its packet operations. A denied pass
acknowledges the current park epoch after the previous callback has returned.

The controller must park the current owner, arm a fresh epoch, and wait for
**every old worker's exact acknowledgement** before releasing ownership. Callback
return alone is insufficient; an old epoch is insufficient. The new generation
claims only after release; the original claim primitive provides a bounded
non-stealing wait and idempotent reacquisition. The caller must prevent multiple
workers in one generation from concurrently accessing an SC queue. The adapter
gates generations, not per-worker queue assignment.

Marker restoration and manual acknowledgement preserve the original low-level
semantics. They require already-quiescent callbacks and do not themselves prove
quiescence. Normal workers use the denied poll pass. Configure legacy enabled=0
before the first poll; that mode deliberately provides no generation exclusion.
The library rejects changes after polling starts, missing state/worker selection,
and recursive polling/control. Unbind requires complete quiescence; attempting
it inside a callback aborts. The library owns no worker process, queue or device
and must never release the caller's state or EAL.

These twelve poll/control APIs extend the six existing message/lifetime APIs.
The shared component exports only the eighteen documented Ker symbols; imported
runtime helpers remain hidden. A typical caller runs its actual RX/TX function
through the gate:

```c
int result = ker_reload_poll(application_rx_tx, application_context);
/* A denied pass returns0 without invoking application_rx_tx. */
```

## Exact source contracts

Both cases are in the pinned `tests/unit/test_ff_config.c`:

| Source case | Independent CTest |
|---|---|
| `test_ut_nr_26_rx_handover_markers` | `fstack-reload-markers` |
| `test_ut_nr_11_handover_barrier` | `fstack-reload-barrier` |

The marker case checks unbound defaults, both generation gates, invalid
arguments, bounded non-stealing timeout, parked release, claim/unpark, repeated
claim, reverse markers and legacy mode. The barrier case checks monotonic park
epochs, exact slot/epoch correlation, stale-epoch rejection, out-of-range slots,
park-before-transfer and the single-generation gate at each stage. Both use the
same exported functions consumed by the actual polling fixture. Reentry and
configuration-lifetime checks are extra regressions, not additional source cases.

## Actual PMD and installed-consumer acceptance

`fstack-reload-multiprocess` creates an original EAL primary, shared state/identity
memzones, an actual original net_ring port and a cache0 pool of 63 mbufs. Four
independent EAL secondary lifetimes exercise two old worker slots, a new
generation and a same-slot successor. They validate the actual primary identity
and nonce, shared block and original driver in their own process.

The old owner enters a real packet callback and waits before its original RX
burst. While it is in flight, the controller parks and arms a new epoch; the
other old worker and standby acknowledge, but release fails. The held callback
then performs its actual RX/TX pass. Release still fails until that worker runs
a denied pass and acknowledges. Only after all old acknowledgements does the
controller release, preserving the parked flag until the new worker claims.
Old-generation denied passes cannot consume the next packet.

A second epoch rejects all prior acknowledgements. The controller then reverses
ownership with the same proof sequence. A fresh same-slot secondary subsequently
uses the same PMD and pool. Each profile checks the identical queued mbuf and
all 96 raw payload bytes, original PMD `ipackets=4` and `opackets=4`, callback
counts `[2,1,1,0]`, no in-flight work, empty RX/TX rings and 63/63 objects returned.
Every secondary exits before primary port, ring, memzone, pool and EAL teardown.

The repository Debug/static program and a separately configured installed
consumer each ran this entire profile. The latter includes only installed Ker
and DPDK headers, links `ker::reload` plus the caller's original net_ring PMD,
and uses no private Ker symbols. Its copied C/check sources were checked against
the candidate source bytes. Release/shared exact source CTests also passed.
The existing 15 IPC/naming/message source phases and both examples were rerun.

This is raw software-PMD/runtime ownership evidence. It does not establish
physical-NIC DMA, hardware-user journals, cross-master arbitration, crash
recovery, imported-Linux packet delivery, TCP continuity or complete reload.

## Bound evidence

Candidate `a1a1a2ffdd63032341bd4f601a8982063ea511e5` passed in the isolated
networkless guest with 64 guest-only 2-MiB hugepages. Artifact directory:
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest4`.

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `6807f34ae165833ea81b8f30958aa3d0ef48ca91eacbc3dca772e3195b4cb426` |
| `package-manifest.json` | `eaa49ace5658ece0f835c69d2bd5cdc13a8064e4195f198bf075e9278c56d660` |
| `initramfs.cpio.gz` | `7f2a355dd9f4577d99a1700fa48c37ed42d4641e7e00570d280781098ac9dbcb` |
| `serial-attempt1.log` | `d5cbb2909dd6d02434215184d8c7347a2d347a9347be306d9b6dc8ecc6e6e36c` |

The package binds source/executable hashes, including the installed consumer.
Actual-result validation requires all 15 existing source phases, the two new
source markers in both polling programs, each profile's independent secondary
PIDs, both examples, exact PMD/pool/callback counters, normal power-down and
QEMU exit 0. A host lacking shared hugepages returns skip77, never completion.

Exactly two baseline-blocked cases are newly complete. Repeating the installed
profile adds no source IDs. The baseline-to-completed total is 26/50; 24 remain.
