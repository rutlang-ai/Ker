# Original packet callback dispatch

`ker::packet_dispatcher` exposes registration/unregistration for plain and
context callbacks plus borrowed-mbuf dispatch in `<ker/packet-dispatcher.h>`.
The caller owns EAL, devices, packets, queues and all routing/drop/response
policy. Dispatch never transfers ownership, changes mbuf metadata, enqueues,
frees or transmits. It forwards callback output length and result unchanged;
the caller validates length before changing packet metadata. With no callback
the result is the input queue. Legacy error/response/peer results are forwarded
as -1/-2/-3; no FreeBSD peer-routing implementation is imported.

Callback signatures and the context layout are literal unchanged declarations
from pinned `ff_api.h`, given public Ker names by private preprocessor aliases.
Original globals, registration/unregistration functions and the callback
invocation block from `ff_dpdk_if.c` are compiled unchanged. Full source files
are shared with the address-policy/pool imports. The import guard verifies
complete blob/SHA256 identities and reconstructs every compiled excerpt and
all three complete original source tests. No original Linux/DPDK source changes
or FreeBSD protocol functions are involved.

Original behavior is preserved: plain wins when both callbacks are registered;
the callback borrows first-segment data, a writable local length, input queue
and queue count. The context carries VLAN stripped=1 and network-order TCI when
`RTE_MBUF_F_RX_VLAN_STRIPPED` is set; otherwise both fields are0. A callback
cannot retain the borrowed storage past dispatch.

Replacement/unregister quiesces all active callbacks before changing either
pointer. New outer calls wait for a pending update, while nested calls can
complete against the same registration. Reentrant updates return `EDEADLK`.
Deferred cancellation releases the dispatch lease; registration defers
cancellation until its update finishes. Callbacks must not longjmp out. Fork
only with quiescent callers; the API is not async-signal-safe.

| Original case | Independent source CTest |
|---|---|
| `test_ff_regist_packet_dispatcher_smoke` | `fstack-packet-dispatcher-plain` |
| `test_ff_regist_packet_dispatcher_context_smoke` | `fstack-packet-dispatcher-context` |
| `test_ut_nr_24_unregist_dispatcher` | `fstack-packet-dispatcher-unregister` |

The actual public-API caller uses the original net_ring PMD with two RX and
two TX queues. Twelve inputs verify data identity/bytes, queue/count arguments,
plain-over-context precedence, VLAN metadata including stripped/unstripped,
output length without premature mbuf metadata mutation, callback replacement,
repeated unregister and NULL-registration recovery. Caller policy produces
nine PMD TX completions, two drops and one caller-owned peer-queue transfer.
The latter is an explicit application queue, not FreeBSD graceful-reload
forwarding. Each frame restores pool127/127 and empties all queues; final PMD
statistics are RX12/TX9. The source/lifetime tests additionally check both
callback kinds with held-call replacement/unregister barriers, nested calls,
reentrant refusal and deferred cancellation. Extra regressions and installed
reruns add no source-case count.

The PMD consumer needs no host shared hugepages: it uses private EAL with
`--no-huge --no-shconf`. Its harness fails on absent/broken dependencies and
optionally writes a non-overwriting evidence record of the exact command,
application/hash, stdout and stderr. Qualification requires Debug/static,
Release/shared and a separately configured `find_package(ker)` consumer linked
to installed `ker::packet_dispatcher` and the original net_ring PMD. This proves
callback/device adaptation, not imported-kernel delivery or physical NIC DMA.
