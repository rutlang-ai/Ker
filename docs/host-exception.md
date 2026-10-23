# Host Linux exception TAP

The primary Ethernet worker can divert selected Ethernet traffic to a
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
are decimal, 1536..65535. The default selector compares the **outer** Ethernet
type, including across mbuf segments. Destination-port mode below adds original-DPDK classification
and accept/reject dispatch. Remaining ownership and encapsulation gaps are
tracked under [#219](https://github.com/rutlang-ai/Ker/issues/219).

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

For RX queue accounting, shared copies must be subtracted (zero in outer-type mode):
`sum(rx_by_queue) = rx + rx_dropped + exception_selected - exception_shared_selected + rx_shutdown_discarded - rx_startup_discarded`.
At the initial TAP milestone, 30 KNI/configuration/ownership source cases
remained incomplete. The destination-port milestone below further qualifies
17 scenarios; issue219 remains open with 13 source cases plus the documented
service-ownership/encapsulation gaps.

## Destination-port mode

```ini
[dpdk]
exception_iface=kerexcept0
exception_mode=ports
exception_policy=accept
exception_tcp_ports=80,443,8000-8002
exception_udp_ports=53,5060
```

Use `ports` without `exception_type`. Lists contain decimal ports or inclusive
ranges within 0..65535; NULL/empty lists select no services. Invalid lists fail
before worker startup. CLI equivalents are `--exception-mode`,
`--exception-policy`, `--exception-tcp-ports` and `--exception-udp-ports`.
The default `ethertype` mode retains its earlier behavior.

Ker owns the port sets and ownership policy. Original DPDK
`rte_net_get_ptype` / `rte_net_skip_ip6_ext` supply header geometry, including
reads across actual mbuf segments. Minimum TCP/UDP headers must exist before a
port lookup. Original Linux still validates checksums, lengths and protocol
state. No F-Stack parser mirror or Ker TCP/UDP implementation is used.

With `accept`, a selected local destination port goes to host Linux; other
services go to imported Linux. With `reject`, selected ports go to imported
Linux and other services go to the host. This follows the pinned F-Stack
accept/reject dispatch policy. OSPF has a distinct classification and follows
the non-service policy. NDP types 133..137 are distinct from ordinary ICMPv6.
IPv4 ICMP error types 3, 4, 5, 11 and 12, and IPv6 ICMPv6 error types 1..4,
are deep-copied to the host while their original frames continue to imported
Linux. Echo, other informational and unknown ICMP messages retain the selected
service policy. The classifier reads only the bounded outer ICMP header;
original Linux validates checksums and quotations and owns error-queue and PMTU
processing. ARP and NDP retain their existing shared-copy behavior. Both
stacks' addresses and service bindings must be configured by the caller; the
bridge does not assign host IPs.

A retained native RX suffix is marked after its first shared-copy attempt,
so channel backpressure cannot repeatedly clone the same ARP/NDP or ICMP error
frame. Clone allocation failure is counted; the original native frame remains
owned by its existing path. A full host queue consumes only its clone, leaving
the original native delivery intact.

Live acceptance covers unicast TCP/UDP service ownership; full F-Stack
multicast data/generation fanout remains unqualified.

The selector is static destination-port ownership, not connection tracking.
Outgoing clients need coordinated local port bindings/ownership; automatic
cross-stack ephemeral-port discovery is not implemented. IP-in-IP classification
uses the one inner-header level exposed by original DPDK, not arbitrary F-Stack
recursion. IPv6 extension handling has the original DPDK bounds and recognized
header set; opaque/deeper encapsulations are not qualified as service steering.

**Port mode rejects IPv4/IPv6 fragments explicitly** with
`exception_fragment_dropped` and the existing RX-drop counter. Fragment ownership
cannot be inferred reliably from every fragment's port fields. An original-Linux
reassembly/flow-ownership adapter is still needed; no Ker reassembly substitute
is introduced. This restriction does not affect disabled/outer-EtherType mode
or the original Linux stacks' normal fragmentation APIs. These gaps remain
under issue219 and are not waived by the source-case counts.

`native-fstack-exception-filter` requires 15 exact source classification markers
from actual original-DPDK mbuf parsing and then starts a separate original Linux
peer namespace. For both accept and reject policies, host and imported Linux
serve independent IPv4/IPv6 TCP and UDP sockets on one wire MAC/address. Replies
identify their actual stack and preserve full nonperiodic payloads. The native
kernel must record exactly two passive opens and one UDP receive per family.
Three actual native-channel ARP sends and one each of IPv4 frag-needed and
IPv6 Packet Too Big are forced to EAGAIN. The TAP capture and independent RX
PCAP must each contain exactly one copy of both ICMP errors under both
policies; ARP RX counts must still equal the host-copy count. Two actual wire
fragments exercise explicit rejection. The test verifies delivery and ownership,
not completion of a PMTU update. Every shared/selected mbuf must be reclaimed.

The same CTest validates accepted `reject` configuration and rejected invalid
policy before application entry. Source adaptation covers 15 classification /
port-initialization scenarios and two method-validation scenarios, not the
F-Stack global layout, primary-lcore configuration or generation-owner ABI.

Additional counters are `exception_shared_selected`, `exception_shared_arp`,
`exception_shared_failed` and `exception_fragment_dropped`. Shared copies are a
subset of `exception_selected`; the physical RX identity in port mode is:

`sum(rx_by_queue) = rx + rx_dropped + exception_selected - exception_shared_selected + rx_shutdown_discarded - rx_startup_discarded`.

The earlier eight source integration scenarios remain adapted. Thirteen KNI
cases still need enqueue-time console/general budgets, primary-lcore or IPFW
configuration, and generation/non-owner/allocation contracts.
