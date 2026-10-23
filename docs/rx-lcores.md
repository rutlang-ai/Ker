# Port RX lcore ownership

The native Ethernet worker can assign its RX queues to selected original DPDK
EAL lcores. Protocol processing remains in the original Linux instance; lcores
transport complete mbufs without implementing TCP/UDP behavior.

```ini
[network]
address=198.18.0.2/24
[dpdk]
port=net_tap0
queues=2
rx_lcores=0,1
eal=--lcores=0@4,1@5 --main-lcore=0 --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 --vdev=net_tap0,iface=kerwire
```

Choose CPU mappings permitted by the caller's actual affinity. The example maps
logical EAL cores0/1 to host CPUs4/5; `rx_lcores` names **logical EAL IDs**, not
physical CPUs. The CLI equivalent is `--rx-lcores 0,1`; it replaces the INI list.
Omitting the option retains existing main-only polling of every active queue.
An additional `[interface.NAME]` may specify its own `rx_lcores` against that
worker's own `eal` arguments. It does not inherit the primary port's list.

Lists contain unique decimal IDs separated by commas. Empty lists, duplicates,
ranges and more selected cores than active queues are rejected. Original EAL
must enable every selected core, and each receives at least one active queue:
queue q belongs to selection[q modulo count]. The active queue count remains
separate from the PMD's advertised capacity. Invalid assignments fail before
application entry; the main lcore may be any original EAL main ID.

When an exception TAP is enabled, its owner is the original EAL main, which
must belong to the port's RX list. Missing main membership is rejected even if
that main is enabled in EAL. Without an exception TAP, all RX may run on remote
selected cores while main handles channel/TX/control work. This is a Ker
scenario adaptation of F-Stack's per-port primary-lcore inclusion constraint;
it does not reproduce F-Stack process-per-core globals or generation tables.

## Ownership, pressure and shutdown

Each queue has exactly one RX poller. Remote EAL pollers call original ethdev
RX only for their assigned queues and hand accepted mbufs to main through
original DPDK SP/SC rings with256 entries (255 usable). A partial enqueue
transfers only the accepted prefix; the producer retains the FIFO suffix and
retries it before polling that queue again. Other queues assigned to that core
continue receiving bounded visits. No successful ring enqueue is fabricated.

Remote producers use an eventfd to wake main; notifications coalesce without
changing packet ownership. Main is the sole native-channel, exception TAP,
PCAP, application TX and device-control owner. Remote handoffs preserve packet
bytes, chains and original PMD metadata. The pool budget includes descriptor
rings, handoff capacity and producer bursts. Dedicated remote cores actively
poll; `idle_sleep_us` controls main's existing idle wait, not remote pacing.

Stopping first signals and joins every launched EAL poller, including partial
startup failure. Main then captures/frees accepted handoff entries followed by
the producer's retained suffix in per-queue FIFO order. Shutdown-only RX frames
therefore still appear once in enabled RX PCAP. Capture errors fail the session
while owned mbufs are freed. The device and pool close only after all producer
and consumer suffixes have been reclaimed. Packets still owned by unpolled PMD
descriptors remain the original driver's shutdown responsibility.

Live MTU changes pause/join remote pollers before original PMD stop, RX queue
rebuild and restart. Queued and retained handoffs are captured and freed before
rebuild. The same core assignment resumes after success or successful rollback,
with lifetime counters preserved. Failed rollback or failed poller resumption
fails the whole session and reclaims its buffers. An exception TAP still rejects
MTU mutation until its separate two-device transaction is supported. Main-only
live MTU retains its existing path.

Large-buffer storage includes the original PMD's reported RX overhead, including
virtio's device header, so the configured maximum remains usable after queues
exist. No upstream driver is patched. RSS is separate; core assignment does not
configure RSS or guarantee flow affinity across queues.

## Evidence

`rx_pollers` in final worker statistics records each queue's configured owner,
observed `rte_lcore_id`, actual host CPU, physical packet count, poll count,
handoff stalls, shutdown/reconfiguration discards and starts of that queue's
polling session. Fields are read only after joining producers. A pause/resume
keeps these counters rather than recreating the plan. `rx_reconfigure_discarded`
is a subset of `rx_dropped`; `rx_shutdown_discarded` remains separate. `rx_by_queue` counts physical RX, including remote handoff shutdown
suffixes, and retains the existing native/exception/shutdown accounting identity.

`native-fstack-rx-lcores-ownership` uses original EAL cores and net_ring PMD,
real chained mbufs and bounded rings. It requires exact512-frame FIFO recovery
after a full handoff, actual two-CPU execution, shutdown capture/reclamation,
partial startup cleanup after a real ring-name collision and reclamation after
an actual `/dev/full` capture failure. Neither the collision nor ordinary pool
cleanup proves F-Stack future-generation statistics/slot allocation contracts.

`native-fstack-rx-lcores` uses original virtio-user/vhost/TAP. The independent
backend explicitly alternates incoming bursts across two queues, qualifying
actual queue landing rather than hardware RSS. Main0, main1 and remote-only
profiles require real original-Linux IPv4/IPv6 TCP/UDP payloads, observed queue
owners/CPUs, exact exception frames, full physical RX PCAP counts and zero
outstanding mbufs. Remote-only profiles change MTU, reject and roll back failures
before/after actual PMD mutation, then complete the same TCP/UDP traffic. Test
observers require all non-main EAL cores to be WAIT before device stop, RX queue
setup or MTU set. Actual rollback/resume failures must terminate with zero mbufs. Missing actual main membership and a disabled selected core
must reject before app entry. The two pinned source membership cases qualify;
generation/non-owner/allocator and other exception gaps remain in
[#219](https://github.com/rutlang-ai/Ker/issues/219).


`native-fstack-rx-lcores-mtu` additionally runs original TAP over two remote RX
queues through 1500 → 9000 → 1500, in large and scatter modes. Independent host
and native IPv4/IPv6 ICMP require full-size Ethernet frames, exact payloads and
checksums, and DF on all nine captured IPv4 echo requests in each direction.
Pre/post-mutation rollback, fatal rollback and ceiling rejection are covered.
This extends the existing MTU source evidence; it adds no new pinned source IDs.
