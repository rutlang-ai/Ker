# RX-15 orphan-purge source case

`tests/unit/test_ff_dpdk_if.c::test_rx15_primary_purges_orphaned_rings` is
scenario-adapted through `fstack-drain-rx15-orphans`. The fixture byte-audits
the unchanged `p1_dead_pid`, ring helpers and complete source test body. It
executes them with the pinned original `ff_drain_ring.c` and original reload /
generation-directory runtime in a real one-queue DPDK primary EAL. The original
`create_ring` helper is also imported and audited. No upstream implementation
is patched.

The source assertions exercise rings created and looked up by the original
drain implementation. They verify that no directory and a live but unattached
user do not justify purging RX; a real forked-and-reaped child PID permits
selective RX reclamation while live RX and TX remain; an externally held purge
lock refuses work; a slot reset times out while that lock is held; clearing the
live marker retires the dead marker but preserves fresh traffic for an
unregistered consumer; and a later unlocked slot reset empties the slot. The
original final pool assertion requires all 64 mbufs back. The fixture then
frees that pool and exits EAL.

The upstream source itself uses PID 1 as a stand-in live identity. That
assertion is preserved and is not described as a real service or secondary.
This fixture does not establish secondary-EAL visibility, an authenticated
resident bank, or a full reload/crash matrix. The original drain pointer arrays
and named rings persist until EAL/process teardown, as the source implementation
specifies. The separate foreign-epoch fixture covers actual original TX-drain
delivery through a real `net_ring` PMD.

## Reproduce

Configure with `KER_WITH_DPDK=ON` and `BUILD_TESTING=ON`, then run:

```sh
cmake --build build --target ker-fstack-drain-orphans-source-test
ctest --test-dir build --output-on-failure -R '^fstack-drain-(import|rx15-orphans)$'
python3 tests/fstack-drain-import.py
```
