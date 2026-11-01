# F-Stack KNI owner activation and nonowner

This batch adapts exactly `test_p1_future_kni_owner` and
`test_p1_kni_nonowner` from F-Stack revision
`646a641cfff77f4815e1e29829a09e1ed15a2999`. The complete unchanged source
helpers and both test bodies are retained and checked against the pinned test
snapshot by `tests/fstack-kni-owner-import.py`. The unchanged original
`ff_kni_inject_process` implementation is added to the audited KNI excerpt.

## Retained source contracts

The source fixture runs the exact owner and nonowner bodies and complete
`p1_cold_*` setup/teardown. Its EAL process-type wrapper exists only in this
fixture to reach the original secondary ring-lookup branch. It binds the
source-shaped reload block through Ker's existing `ker::reload` adapter;
activation calls the adapter's original begin/complete functions, and the new
`ker_reload_kni_owner_matches` observation delegates directly to pinned
`ff_reload_kni_owner_match`. The test checks the owner predicate while
generation1 is pending and after activation, statistics allocation before
activation, no hotplug, both named ring lookups, exact three-packet TX, the
source pool census, and the nonowner's null statistics and shared ring
pointers. The source fixture has no generation directory.

The actual EAL primary caller separately initializes original KNI statistics,
rings, TAP and kernel-vhost `virtio_user` devices. It binds selected generation1
while generation0 is active, receives an exact frame into the original KNI RX
ring, and reports that queued state before activation. The owner gate holds the
frame with no PMD TX. Original reload begin/complete activates generation1;
the caller then exchanges exact Ethernet frames in both directions through
the original PMDs, restores the exact packet counters and returns all 2047
mbufs. A generation0 mismatch and `proc_id=2` are denied while active1, then
restored and allowed again. The installed consumer repeats this path.
The original primary-slim RX path increments `tx_packets` when it queues the
host frame and `ff_kni_inject_process` increments it again on PMD transmit;
the final `tx_packets=2` is those two stage-accounting increments for one
host-to-wire frame.

The bypass control removes the caller's owner check around the original KNI
processing pass. A queued wire-to-host frame then escapes through the paired
virtio device before activation, proving that the pending queue is sensitive
to the owner gate.

## Scope

This is same-process caller integration. The TAP/vhost caller is an actual EAL
primary with a bound original reload state; it does not claim to be a genuine
secondary future-owner process. The source fixture's process-type wrapper is
not part of the caller. This batch does not establish cross-process reload,
cross-master directory ownership, FreeBSD KNI ABI, physical NIC behavior,
complete graceful reload. Short-TX backpressure and full RX-ring ownership
are covered separately in [short-TX scope](fstack-kni-short-tx.md) and
[full-ring scope](fstack-kni-full-ring.md).

## Build and reproduce

Build `ker-kni-owner-source-test` and run its importer and source CTests:

```sh
ctest --test-dir BUILD --output-on-failure \
  -R '^(fstack-kni-owner-original-import|fstack-kni-owner-source)$'
```

The source fixture uses the pinned DPDK `net_ring` PMD. In the native CI
profile, also run `native-fstack-kni-host-consumer`,
`native-fstack-kni-host-installed-consumer`, and
`native-fstack-kni-owner-bypass-control`. Those tests require Linux network
namespaces, `/dev/net/tun`, `/dev/vhost-net`, and the original TAP and virtio
PMDs. The installed profile installs `ker-reload` and `ker-ipc` with the
example so it can run without build-tree libraries.
