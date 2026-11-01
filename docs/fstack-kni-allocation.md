# F-Stack KNI named allocation contracts

This batch adapts exactly `test_p1_kni_stats_oom` and
`test_p1_kni_slot_oom` from F-Stack revision
`646a641cfff77f4815e1e29829a09e1ed15a2999`. The complete source functions,
assertions, implementation excerpts, statistics layout and license are retained
byte-for-byte. `tests/fstack-kni-allocation-import.py` audits their hashes and
exact extraction. The full implementation snapshot is audit input; only the
listed memory/device helpers are compiled under a private example namespace.

## Executable boundary

The caller owns a real ordinary EAL primary. The original `ff_kni_init` and
`ff_kni_alloc` select live statistics storage. The test linker forwards every
allocation to original DPDK except the exact `kni:stat` or `kni:stat_lcore`
label selected by the unchanged source body. Five independent allocation/reset
cycles require exactly one failed allocation, the source NULL assertion and
zero hotplug attempts. Source-level fatal interception exists only in the test
harness; separate subprocesses forward the actual `rte_exit(1)` and
`rte_panic`/SIGABRT and verify the NULL state and exact fatal diagnostics.
A negative control bypasses the table fault and must fail the original expected
fatal assertion.

The positive caller uses original `net_tap` and kernel-vhost `virtio_user` PMDs,
with the original KNI allocation, enqueue and bidirectional processing functions.
Inside a private user/network namespace, AF_PACKET peers send exact 128-byte
experimental Ethernet frames in both directions. The original statistics must
record RX1/TX2 with no drops (the primary-slim path accounts the host packet
when it enters the inject ring and again when the owner transmits it). Both named rings are empty, both real devices and
host interfaces disappear, and all 2047 mbufs return before EAL cleanup. A
separately installed executable repeats the same exchange without a source-tree
runtime dependency. No TCP/UDP parser or protocol implementation is imported.

The source suite's synthetic future-owner setup is replaced only for these two
allocation assertions by the actual primary's supported statistics ownership.
These allocation cases cover ordinary-primary named allocation only. A
separate scoped adaptation covers owner activation and nonowner selection;
the full RX-ring case remains blocked. Neither batch qualifies
cross-process secondary ownership, generation banks, FreeBSD KNI ABI, physical
NIC behavior, rate-limit policy or a Ker protocol stack. The example exports
no KNI API and does not route Ker application traffic automatically.

## Build and reproduce

Configure a DPDK/native test build with the repository's pinned DPDK and Linux
build paths. Build targets `ker-kni-host-bridge` and `ker-kni-allocation-test`,
then run:

```sh
ctest --test-dir BUILD --output-on-failure \
  -R '^(native-fstack-kni-|fstack-kni-allocation-original-import)'
python3 tests/fstack_migration.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_fstack_migration.py
```

Runtime tests require Linux user/network namespaces, accessible `/dev/net/tun`
and `/dev/vhost-net`, `ip`, and the original null/TAP/virtio PMDs. The native CI
profile provisions these devices before its full test graph; other DPDK builds
still compile both targets. There is no skip-as-pass. Tests use `--no-huge`,
`--no-pci`, `--no-shconf`, private runtime directories and namespace-local IPv6
settings. Deliberate panic tests disable core dumps in their subprocess only.
No host network configuration or hugepage reservation is changed.

GCC and Clang builds use strict warnings. Two existing upstream diagnostics
(unused variable and GCC format truncation for unrestricted port IDs) are
suppressed only around the unchanged excerpt; the caller admits only port0,
whose ring name fits the original fixed bound.

The catalog now records345 scenario-adapted,1 partial and17 blocked out of433.
The remaining18 behavioral contracts remain unfinished; `--require-complete`
continues to fail.
