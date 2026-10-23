# Host Linux exception TAP

The primary Ethernet worker can divert a selected outer Ethernet type to a
separate host Linux TAP, while other valid frames continue to the imported
Linux instance. The TAP is an actual host interface, distinct from a DPDK TAP
used as the wire PMD. Host-originated frames on the exception TAP return through
the original wire PMD. The worker transports Ethernet; original Linux performs
all TCP/UDP and other protocol processing.

```ini
[dpdk]
exception_iface=kerexcept0
exception_type=34997
exception_queue=256
exception_rate=0
```

The same options are available as `--exception-iface`, `--exception-type`,
`--exception-queue` and `--exception-rate`. They apply to the primary worker,
not additional interfaces. `34997` is experimental EtherType `0x88b5`; values
are decimal,1536..65535. The selector compares only the **outer** Ethernet type,
including across mbuf segments. It does not implement F-Stack TCP/UDP port
bitmaps, accept/reject policy inversion, IPv4 tunnel recursion, or NDP/OSPF
classification. These remain tracked under [#219](https://github.com/rutlang-ai/Ker/issues/219).

The worker creates a new, nonpersistent, exclusive TAP with no PI/vnet headers
and no offloads. It applies/reads back the actual wire PMD MAC so unicast frames
are classified as host traffic by Linux, sets its startup MTU and brings it up.
Existing interfaces are never attached or changed; an occupied name fails
before application entry. The process needs permission to create a TAP in its
network namespace. IP addresses/routes and application services on the host
interface belong to the caller. Closing the owning worker descriptor removes
the interface. Until a two-device transaction is implemented, changing the
native MTU while this bridge is enabled explicitly fails EOPNOTSUPP; querying
the unchanged MTU remains supported.

## Ownership and bounded work

A power-of-two ring size4..65536 provides size-1 usable entries. A single EAL
worker owns the queue and TAP. Enqueue consumes and NULLs a selected mbuf,
including freeing it on a full-queue drop. An invalid/non-owner call retains
caller ownership. Each iteration processes at most32 queued frames and32
host-originated frames. TAP writes use the complete mbuf chain with writev;
Linux copies the frame before the adapter frees its mbufs. A short/nonblocking
host write ends the accepted prefix and frees the remaining owned suffix.
Malformed/oversized frames are dropped without forwarding. Other device errors
fail the session and use normal worker cleanup.

Host reads become owned mbuf chains using the worker's pool, then the original
ethdev TX API transfers only the accepted prefix. Unaccepted suffixes are freed
exactly once. The host TAP has offloads disabled, so host Linux supplies complete
frames/checksums. No Ker protocol state machine or upstream Linux/DPDK patch is
introduced. Native TX retains its existing original-Linux/offload path.

`exception_rate` is a per-worker, one-second monotonic **batch gate**, matching
the pinned source processing policy. Zero disables it. When the prior dequeued
count is below the limit, the whole current burst can pass; a burst can overshoot
the limit. Once exhausted, subsequent dequeued bursts are dropped until the
window resets. The counter advances by dequeued packets, including limited
ones, rather than only by accepted writes. This is not strict packet pacing or
F-Stack's separate general/console enqueue limits.

Stopping discards any queued suffix with an explicit shutdown counter, closes
the TAP and ring before the wire PMD/pool, and requires zero outstanding mbufs.
PCAP RX includes selected wire frames; PCAP TX includes host-originated frames
before original PMD ownership transfer. Capture failure still fails the session.

## Evidence and counters

`native-fstack-exception-tap` uses an actual Linux TAP/AF_PACKET pair and original
net_ring PMD. It adapts the eight pinned integration scenarios: primary interface
allocation, host-bound forwarding, active/exhausted kernel batch limits,
partial host writes, host-to-wire forwarding, partial wire acceptance and a
full enqueue ring. Initialization checks the real TAP kind, UP/MTU/MAC, live
ring and zeroed counters. The selected EAGAIN write failures are injected;
every successful write reaches the real TAP. No successful PMD/TAP operation is
mocked. Multi-segment payloads, a reset rate window, over-MTU drops and shutdown
with a queued suffix also exercise real ownership and reclamation.

A separate production-worker run uses original net_tap wire traffic through
veth. It verifies exact broadcast/unicast frames in both directions, original
Linux PACKET_HOST classification for unicast, non-selected frame isolation,
complete RX/TX PCAP records and original native UDP with an independent host
peer. An existing persistent TAP must reject startup without changing its
flags, MTU or MAC. These are Linux-TAP scenario adaptations, not ff_kni_alloc
ABI, original virtio_user hotplug, shared generation ownership or F-Stack
private-global-layout equivalence.

Existing `tx`/`rx`/byte/drop counters continue to describe the native-channel
path. Separate `exception_*` counters describe this bridge:

- `selected = to_host + to_host_dropped + shutdown_dropped + queued`.
- `enqueued` excludes full-ring drops; `rate_dropped` is a subset of
  `to_host_dropped`.
- `host_received = from_host + wire_dropped`; accepted `from_host` packets are
  owned by the PMD, and rejected packets have been freed.
- `malformed` counts geometry drops. `outstanding` still covers the entire
  shared mempool and must be zero after both paths stop.

For RX queue accounting, add `exception_selected` to the existing identity:
`sum(rx_by_queue) = rx + rx_dropped + exception_selected + rx_shutdown_discarded - rx_startup_discarded`.
The remaining30 KNI/configuration/ownership source cases stay incomplete;
passing these eight integration scenarios does not complete issue219.
