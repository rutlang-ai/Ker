# Reload caller boot state

This qualifies exactly
`tests/integration/test_ff_reload_integration.c::test_it_a09_boot_state` at
F-Stack revision `646a641cfff77f4815e1e29829a09e1ed15a2999`. The complete original
assertion function is retained unchanged and checked by
`fstack-reload-boot-original-import`. The original stub suite is not compiled.
The existing `ker::reload` component already preserves the original reload
implementation; no upstream implementation or Ker exported API changes here.

The source host translates its boot observations to actual public Ker APIs and
original DPDK resources:

| Original assertion | Actual boundary |
| --- | --- |
| State attached | `ker_reload_runtime_view().attached` after real state initialization/binding |
| RX owner 0 and no hardware denial | Actual owner observation and `ker_reload_rx_allowed()` for selected generation0 |
| Drain rings ready | Four original DPDK ring lookups agree with the caller's actual RX/TX resources |
| Four named ring lookups | Actual `drain_{rx,tx}_p0_q0_g{0,1}` objects; names are caller labels, not a shared FreeBSD ABI |
| One device port | Actual `rte_eth_dev_count_avail()` |
| Context registration succeeds | Creation of real `ker_reload_tx` contexts against the pool, rings, port and queue |
| Interface activation succeeds | Actual original PMD start and `rte_eth_add_tx_callback` |
| One TX hook per configured port | Successful callback registration count against the actual single-port configuration |
| Initial TX calls/packets are zero | Actual live TX callback counters, also checked against original PMD counters |

Source `sc`/`ifp` tokens are validated by the host registration adapter; they do
not become FreeBSD veth/kernel pointers. Activation binds the actual DPDK device,
not a successful veth stub. Source registration checks success only; no argument
forwarding or FreeBSD interface layout equivalence is inferred.

## A consumer for all four rings

`ker-reload-frame-forwarder [EAL options] -- input.bin output.bin` is a caller
composing the existing state, polling gate, parked-TX and original-PMD APIs.
It owns one original net_ring loopback port and four actual drain rings.
Input chains come from the unchanged production `ker_worker_mbuf_from_bytes`.
One EAL lcore serializes two logical workers in the same process; all callbacks
have returned before control changes ownership.

The actual data cycle is:

1. The independent file frame enters the PMD's backing input ring. A permitted
   generation0 polling callback receives it through original PMD RX into RX0.
2. The caller arms a park epoch, marks RX stopped and runs the denied generation0
   pass. The callback must not run; its exact slot/epoch acknowledgement must be
   present before release to generation1 and claim.
3. Generation0 consumes RX0 into its parked TX0 ring. Its denied drain makes no
   dequeue or TX call. Generation1 drains that ring through the actual PMD.
4. Generation1 receives that frame into RX1. The equivalent park proof transfers
   ownership back to generation0. Parked generation1 queues TX1; only generation0
   drains it. Final generation0 PMD RX passes through RX0 to the output file.

All four rings participate in actual ownership transfer. The output must be the
same mbuf pointer with reference count1 and exact bytes. One complete cycle has
PMD TX2/RX3, exactly two live TX callback invocations and no residual queue or
pool ownership. Tests use independent 64/4096/9014-byte experimental-EtherType
frames, checking all bytes and chain segment counts. This is software-PMD frame
I/O, not physical RSS, Linux socket traffic or TCP continuity.

The installed executable repeats all three exchanges from an independent prefix
with the original reload license. The default build links the existing Ker
components into that executable. For shared-library builds the same install
component includes reload-TX, reload and IPC DSOs; the test points the loader
at that installation library directory and the selected DPDK prefix, with no
Ker build-directory library path.

## Startup and lifecycle controls

The complete source function runs five times in one actual EAL lifetime. Each
cycle starts with a fresh bound state, all four rings, one real port, its TX
contexts and hook, and zero PMD traffic. It then performs the real transfer,
restores all511 mbufs, removes the hook and releases contexts, port/vdev, rings,
pool and state. The next cycle recreates those same names successfully. Original
`rte_vdev_uninit` releases the caller-created vdev; merely closing the ethdev or
unplugging its driver leaves a bus object that prevents identical-name creation.
No DPDK source patch is needed.

Two test-only linker controls must fail exact original assertions:

- Returning NULL from real-hook allocation makes actual activation fail and
  rejects the original `ff_dpdk_if_up() == 0` assertion.
- Performing one actual PMD TX immediately after activation makes the original
  zero-TX-call assertion fail. These counters cannot pass as inactive observers.

Normal teardown is empty-only. A staged/queued/caller-held packet causes EBUSY
and leaves resources alive. After input enqueue, unexpected later transfer errors
may retain queue-owned packets; no general rollback/crash-recovery matrix is
claimed. The example's successful bounded cycle performs complete cleanup.

## Scope and checks

This qualifies only the source boot contract through caller composition. It is
isolated from authenticated resident sessions: no distinct master/epoch banks,
cross-process admission proof, FreeBSD veth ABI, graceful service reload,
connection handover or protocol implementation is supplied. The remaining
foreign-epoch, orphan and full reload cases stay open. Original Linux/F-Stack/
DPDK implementations and Ker's borrowed packet callbacks remain unchanged.

GCC passed the six dedicated checks and eight existing reload-marker/barrier,
parked-TX and import regressions. A separate shared-library build passed all six
dedicated checks, including the installed executable and its installed Ker DSOs. Clang with ASan/UBSan passed all six dedicated
checks using `ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1`; the
intentional early-failing mutation processes do not perform orderly cleanup.
Normal profiles independently require complete queue/pool/port/state restoration.
All21 catalog mutation/regression tests pass, and completion still fails while
22 blocked plus1 partial source case remain.

```sh
cmake --build build --target ker-reload-frame-forwarder ker-reload-boot-source-test \
  ker-reload-boot-no-hook-test ker-reload-boot-dirty-start-test \
  ker-fstack-parked-tx-test ker-fstack-reload-poll-test
ctest --test-dir build --output-on-failure \
  -R '^fstack-(reload-boot-|parked-tx-|reload-(markers|barrier|import)$)'
python3 tests/fstack_migration.py
```

Missing EAL, PMD, source integrity, callback or installation is a failure, not a
skip. Native Linux/LKL startup and host hugepage changes are not required for
this bounded component/caller contract.
