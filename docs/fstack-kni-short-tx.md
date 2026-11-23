# F-Stack KNI short-TX backpressure

This batch adapts the unchanged `test_p1_future_kni_short_tx` from F-Stack
revision `646a641cfff77f4815e1e29829a09e1ed15a2999`. The original
`p1_cold_tx_check(1)` helper and source test body are retained byte-for-byte and
verified against the pinned snapshot by `tests/fstack-kni-owner-import.py`.
The fixture runs the original `ff_kni_inject_process` implementation.

## Executable boundary

The unchanged source contract requires a TX limit of one, exactly one accepted
packet, two dropped packets and complete pool recovery. A second fixture
exercise configures an actual `net_ring` PMD sink with capacity one and restores
the original PMD operations before calling the unchanged inject function. It
places three distinct packet mbufs in the original inject ring. The real PMD
accepts the first packet; the test checks its pointer, FIFO position and exact
payload, while the original function releases the two rejected packets. TX and
drop counters must increase by exactly one and two. The pool census is checked
before and after dequeuing the accepted mbuf. A fresh packet is then accepted
and reclaimed with no extra drops.

This is bounded caller TX backpressure through the real software PMD in the
source fixture. It does not qualify an independently installed short-TX caller,
a genuine EAL secondary, the separate full RX-ring source fixture, protocol behavior or
physical NIC behavior. The separate owner activation and nonowner caller scope
is documented in [KNI ownership](fstack-kni-ownership.md).

## Build and reproduce

Build `ker-kni-owner-source-test`, then run the source importer and short-TX
fixture:

```sh
ctest --test-dir BUILD --output-on-failure \
  -R '^(fstack-kni-owner-original-import|fstack-kni-short-tx-source)$'
```

The fixture uses the pinned DPDK `net_ring` PMD and the original test pool. It
makes no claim about kernel-vhost/TAP installation paths or protocol behavior.
