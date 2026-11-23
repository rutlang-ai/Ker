# F-Stack KNI full RX-ring ownership

This batch adapts the unchanged `test_p1_future_kni_full_ring` from F-Stack
revision `646a641cfff77f4815e1e29829a09e1ed15a2999`. The original
`p1_cold_init` helper and full-ring source test body remain byte-for-byte in
the imported fixture and are verified by `tests/fstack-kni-owner-import.py`.

## Executable boundary

The source case fills the original KNI RX ring to its actual capacity of15,
tries one more enqueue, requires `-1`, exactly one `rx_dropped` increment and
the precise pool count showing that the rejected mbuf was freed. The test
fixture's allocator wrapper seeds distinct payload bytes and records each
admitted mbuf before the unchanged source overflow runs. Afterward it verifies
that those same pointers and bytes remain in FIFO order, so freeing an older
queued object or retaining the rejected object fails the check.

The fixture then restores the real PMD operations and points the original KNI
statistics at a real capacity-one `net_ring` sink. Unchanged
`ff_kni_process` drains the first retained object; its pointer and payload are
checked at the sink and freeing it restores one pool object and one RX-ring
slot. A fresh packet is enqueued behind the retained suffix. The remaining
original objects and retry packet drain through the same PMD in exact FIFO
order, with exact RX/drop counters and complete pool recovery.

This qualifies bounded source-fixture ring ownership and software-PMD drain
behavior. It does not establish an independently installed caller, a genuine
EAL secondary, cross-master directory ownership, physical NIC behavior,
protocol behavior or complete graceful reload.

## Build and reproduce

Build `ker-kni-owner-source-test`, then run the exact source importer and
full-ring fixture:

```sh
ctest --test-dir BUILD --output-on-failure \
  -R '^(fstack-kni-owner-original-import|fstack-kni-full-ring-source)$'
```

The test uses the pinned DPDK `net_ring` PMD. It makes no claim about
kernel-vhost/TAP installation paths or protocol behavior.
