# Foreign-epoch drain source case

`tests/unit/test_ff_dpdk_if.c::test_p1_drain_foreign_epoch_tx` is scenario-adapted
through `fstack-drain-foreign-epoch`. The fixture byte-audits the unchanged
`p1_setup`, `p1_teardown`, `p1_drain_check` and source test body. It also imports
the exact pinned `lib/ff_drain_ring.c` and `.h` at F-Stack revision
`646a641cfff77f4815e1e29829a09e1ed15a2999`; the original reload and
generation-directory implementation is compiled in the same private caller
fixture. No Linux or upstream implementation is patched.

The retained source test seeds all eight epoch-1 rings and sets the original
directory's RX owner to epoch 2, generation 0. Its unchanged mode-3 assertions
verify that configured RX q0/g0 is reclaimed while TX q1/g0 and the other ring
entries remain queued. The source teardown verifies that the 64-object mbuf
pool is restored.

The caller extension uses source-shaped live directory records for
`(epoch 1, generation 0)` and `(epoch 2, generation 0)`. It first checks the
original `ff_no_hw_mode()` predicate and confirms that the retained TX packet
does not reach the PMD while epoch 1 is not the hardware owner. It then selects
epoch 2/generation 0 and invokes the unchanged TX-drain function through a
bounded caller gate. A real two-queue `net_ring` PMD accepts the exact original
mbuf pointer and payload on queue 1. The original source teardown returns all
64 pool objects. As in the original implementation, `ff_drain_ring_unregist()`
only detaches the persistent pointer arrays; named drain rings and arrays live
until EAL/process cleanup. The test explicitly stops/closes the PMD and frees
its endpoint rings and mbuf pool, but does not claim manual destruction of all
original drain rings.

This fixture runs one real EAL primary and invokes the original source ring
routine from a trusted same-process caller. It does not claim a real secondary,
two coexisting masters, F-Stack's secondary-only main loop, or authentication
through Ker's resident admission bank. The resident still permits only one
identity per generation; cross-process epoch-isolated admission and cleanup
remain unqualified. No TCP continuity, external traffic or full reload is
claimed.

## Reproduce

Configure with `KER_WITH_DPDK=ON` and `BUILD_TESTING=ON`, then run:

```sh
cmake --build build --target ker-fstack-drain-source-test
ctest --test-dir build --output-on-failure -R '^fstack-drain-(import|foreign-epoch)$'
python3 tests/fstack-drain-import.py
```
