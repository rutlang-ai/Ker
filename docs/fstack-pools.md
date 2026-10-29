# Original generation pools and cache policy

Two baseline-blocked source cases now complete the original memory contracts.
The objective is **42/50**, with 8 still required. `ker::pools` adds 8 exported C
APIs; original helper symbols remain private. The caller owns EAL, every pool,
packet/reference/message object, device, queue and application control policy.

| Source case | Independent source CTest |
|---|---|
| `test_ut_nr_18_gen_pool_config` | `fstack-pool-generation` |
| `test_ut_nr_21_shared_pool_cache_size` | `fstack-pool-cache` |

## Preserve original memory code

Full pinned `lib/ff_dpdk_if.c` and `lib/ff_memory.h` are retained byte-for-byte in
`third_party/fstack-pools`, with Git blob/SHA256 provenance. The original file
contains FreeBSD packet integration that must not become Ker's protocol path.
The build therefore compiles only literal memory constants, cache/name helpers,
pool-selection globals and `ff_app_mbuf_pool`/`ff_app_mbuf_set_gen` bodies, using
the unchanged private configuration layout. `pool-import.py` reconstructs those
exact excerpts from the complete sources and compares their bytes. No upstream
source is patched. Git attributes retain original CRLF/trailing whitespace;
blob and excerpt guards provide the stronger source integrity check.

The Ker layer creates actual DPDK mbuf pools, typed original-layout ff_msg pools
and caller-defined opaque reference pools using the original cache policy. The
reference role is useful per-packet ownership metadata; it does not implement
the FreeBSD page-array reference structure or callbacks. No FreeBSD packet or
protocol function from the full source file is compiled or linked.

The original process-global bank preserves gen0/gen1 and socket0..7 selection.
Legacy mode returns the shared RX pool. Generation mode returns exactly the
selected generation, including NULL/ENOENT before creation, and never falls
back to a populated shared pool. Invalid generation selection is ignored.
Selection and allocation are serialized by the caller. New processes may borrow
already-used shared pools; rebinding/detaching existing bindings refuses
outstanding mbufs. Detach frees no caller resource. In shared mode all bound
mbuf pools require cache0.

`tests/fstack-pool-source.inc` preserves both complete original test functions,
including names for sockets0/3, bad generation/truncation, exact gen count2,
legacy/missing-generation/invalid-selection behavior, all three cache roles and
the reserved positive FREE_RING_SIZE constant. The private test compiles the
actual production TU for raw source preconditions. Only the cmocka assertion
host is mapped to CHECK; no fixture entry point is installed.

## Real legacy and shared consumers

`fstack-pool-legacy-consumer` starts a private real EAL and original net_ring
with `--no-huge --no-shconf`. Its three actual pools have caches256/16/256.
Four frames traverse original PMD RX/TX: an original typed message and an opaque
reference record accompany each packet, the bank allocates its response, and
completion returns all three object types. Each cache is observed nonempty,
then explicitly flushed, and every pool restores1023/1023 objects. Generation
selection1 still chooses the legacy RX pool as required.

`fstack-pool-multiprocess` uses a real primary and two real EAL secondaries,
all configured with lcore0. The fixed shared RX pool, original-named gen0/gen1
application pools, typed messages and per-packet reference journals all have
cache0. Before generation pools exist, real allocation returns NULL/ENOENT
while the shared RX pool is available. Once created, each response allocation
uses the selected original generation pool.

The first worker allocates a gen0 TX response and leaves it, its message and
reference record outstanding. It selects gen1, then invalid2/-1 preserve gen1.
Only then does the second actual EAL process start, borrow the already-used
pools and return that gen0 response while selecting gen1. Further frames reverse
selection and return objects from a different process/current selection. Every
stage checks the exact five-pool census; buffers are returned to their original
pool rather than the current allocation bank. Both mbuf pointer identity and
all payload bytes, typed message nonce/sequence/generation and the actual
reference-record identity are checked. A bank detach is refused while its TX
output remains outstanding.

The application owns control/completion queues and the simple packet transform;
Ker supplies memory adaptation and original selection only. Each profile ends
with actual PMD RX/TX4/4, four completed records, no in-flight work, empty queues,
all five shared pools63/63 and both secondaries reaped before primary cleanup.
The independently installed consumer uses `find_package(ker)`, `ker::pools`,
`ker::ipc` for its public message layout, and the original net_ring driver.
Its source/check bytes equal the repository consumer, and its CMake, link,
library and executable inputs are hashed in the package manifest.

## Qualification evidence

Debug/static and Release/shared pass both complete source selectors, the import
guard and the real legacy consumer. The host shared-hugepage skip77 is not
completion evidence. Fresh isolated guest13 at candidate
`b0f065706fdc65eae52dad2adec0d00bc01f0bde` passes all 11 runtime profiles,
including both new pool consumers and all prior 9 profiles. Both old examples
also pass, followed by normal guest power-down and QEMU exit0. Artifacts remain
outside worktrees at
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest13`:

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `a263b40da4ccba8006c813d9a29e7b40db67fd409cdb94ad2c287f590a844917` |
| `package-manifest.json` | `45566df1c661997497eb11303229f0fbb760a9abb6a8f81f28df26e3d734123b` |
| `initramfs.cpio.gz` | `2598361e059091f463766b31bdd3139497944cb13eafd037693a82ee46c8d43e` |
| `serial-attempt1.log` | `3a85e30bee8b7eabf953c06bfd282b2d3ca2b62e53729ccc39caeeab6e010175` |
| `qemu-command-attempt1.json` | `65703b9d8cd1f772cab2ad1c52399a218a1be1229ea0182e25ae6729cd502b47` |
| `qemu-host-attempt1.log` | `659fbea079cc86b145595394d5604d207a193b5bca774bb3a53bf6c144753757` |

The named memory contracts are complete. This does not qualify the FreeBSD
page-array reference ABI, physical NIC DMA, original-Linux packet delivery
through this consumer, TCP continuity or full application reload. The reserved
fallback free-ring constant is preserved; the default cache0 path does not
implement an additional cross-generation fallback ring.
