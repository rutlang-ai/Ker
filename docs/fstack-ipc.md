# Caller-owned shared-message IPC

`ker::ipc` exports a C adapter around the unchanged F-Stack transport pinned at
`646a641cfff77f4815e1e29829a09e1ed15a2999`. It requires DPDK. A caller initializes
original EAL, creates or looks up the shared pool/rings, attaches the client,
handles its own commands, waits for all accepted requests to return, detaches,
then destroys its resources and shuts EAL down. The
[`ipc-channel.c`](../examples/ipc-channel.c) example shows this lifetime; installed consumers
use `find_package(ker CONFIG REQUIRED)` and link `ker::ipc`.

The public message layout and ring naming come from the pinned upstream sources.
The adapter does not implement FreeBSD sysctl, ioctl or reload operations. The
example provider explicitly returns `-EOPNOTSUPP` while preserving caller bytes
and reply identity. This component is separate from the authenticated resident
session protocol and accepts only cooperating trusted EAL peers. Pointer-bearing
messages are not an authentication boundary. Original Linux protocol code is
unchanged.

Calls must be serialized: the pinned client has one process-global pending
request. Process/generation/epoch parsing preserves AUTO and unspecified epoch;
transport requires explicit generation unless an actual proc0 legacy input ring exists.
AUTO then uses the original legacy detector; its address snapshot stays unspecified.
The bounded probe currently requires process0. An accepted timed-out request is
still owned by the queue/provider. Detach returns `-EBUSY` until the entire typed
cache0 pool is quiescent. The caller must coordinate reclamation after receiver
completion; timeout does not cancel another process's work. Exact PID/cookie
matching protects reply ownership. Orphan reclamation must not free a dead peer's
private allocation. The C-only upstream message layout is retained.

## Source assertions

All IDs below are in `tests/unit/test_ff_ipc.c`. Each has an independent
`fstack-ipc-<suffix>` CTest plus the shared `fstack-ipc-multiprocess` acceptance.

| Source case | CTest suffix |
|---|---|
| `test_ff_ipc_proc_id_plain` | `process` |
| `test_ff_ipc_proc_id_gen` | `generation` |
| `test_ff_ipc_proc_id_gen_epoch` | `generation-epoch` |
| `test_ff_ipc_proc_id_full_coordinate` | `coordinate` |
| `test_ff_ipc_gen_str_epoch` | `generation-option-epoch` |
| `test_ff_ipc_gen_str_plain` | `generation-option` |
| `test_ff_ipc_rejects_malformed` | `malformed` |
| `test_p4_recv_own_reply` | `own-reply` |
| `test_p4_recv_foreign_live_owner` | `foreign-live` |
| `test_p4_recv_foreign_without_send` | `foreign-no-send` |
| `test_p4_recv_orphan_dead_owner` | `orphan` |
| `test_p4_probe_is_non_destructive` | `probe` |

The fixture verifies actual original-EAL secondary roles, the primary's shared
memzone identity/nonce, source coordinate and literal ring names, shared-pool
objects, PID/cookie ownership and payload identity. Plain AUTO parsing remains
AUTO; it is not counted as resolved transport. Live foreign replies survive
unrelated receives and probes, and their rightful owner retrieves them. An exact
reaped secondary supplies the orphan case, including an inaccessible private
buffer. Two actual QUERY candidates remain owned until the probing caller returns;
only then does fixture-provider cleanup reclaim them. Each ownership phase admits
a new secondary. All secondary lifetimes end before the primary destroys rings,
the memzone and the fully reclaimed 64-object pool and calls EAL cleanup.

## Qualification evidence

Debug/static and Release/shared source CTests passed. A separate installed CMake
consumer linked only `ker::ipc` and completed the example's actual EAL/pool/ring
lifetime. `fstack-ipc-import` verifies original Git blobs and SHA256 values;
the adapter carries no upstream patches.

The shared-hugepage acceptance ran in an isolated, networkless QEMU guest using
64 guest-only 2-MiB hugepages. Candidate commit
`dbdfd324d5ef18d6eb5ded186d8ba9ea1fd59994` passed all 12 source phases with one
original EAL primary and 20 distinct secondary PIDs, reclaimed 64/64 objects,
completed the exported example, then powered down normally. Artifact directory:
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest1`.

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `9c82301736dc6f197adacd8403b41a59f49503dc959d645dce50ac52a4aa940f` |
| `package-manifest.json` | `8e2398a0f8fccd06f129be58100bcac4a6628325155a16b8d983885e38c8d319` |
| `initramfs.cpio.gz` | `1b6fa41175782c7f8b98dc0da2f484c5920c279448eb38d0a8788a86bf427062` |
| `serial-attempt1.log` | `223e9f66f7c0d7fc548a791c03c313f3517fdc1abbcbe72ab39a8a15aa346b4c` |

The package manifest binds source and executable hashes. Actual result validation
requires every source marker, distinct secondary identities, full reclamation,
example exit 0, normal power-down and QEMU exit 0. The inherited guest root does not
imply that unrelated historical suites were rerun. On hosts without usable shared
hugepages the CTest returns skip77; that result is never counted as completion.

These twelve cases move from baseline blocked to scenario-adapted. They do not
complete remaining generation/reload contracts, physical NIC handover, control
command semantics or TCP continuity. The initial batch baseline-to-completed total was 21/50; the extension below brings it to 23/50.


## Provider names and legacy transport extension

`ker_ipc_format_ring` lets a caller construct its actual provider rings without
changing the process-global client selection. It uses the unchanged imported
naming implementation. With generation-aware names disabled, every epoch and
generation yields the exact legacy name. A client with AUTO may attach when an
actual legacy proc0 input ring exists; the original client then discovers the
unsuffixed ring namespace. Other unresolved AUTO configurations remain explicit
unsupported boundaries.

`test_ut_nr_m5_epoch_slot_and_ring_name` and
`test_ut_nr_m5_graceful_zero_epoch_invariance` in `test_ff_config.c` map to
`fstack-ipc-epoch-names` and `fstack-ipc-legacy-names`, plus the multiprocess test.
They cover source slot0/NONE/1/2/3/4 mapping, exact names, longest source coordinate,
truncation, and the full six-epoch/four-process/two-generation/type matrix.
Invalid buffers return a negative Ker errno; upstream truncation remains -1.
The original EAL primary now creates both namespace layouts with the exported
builder. An actual secondary discovers legacy mode, sends to the unsuffixed
proc1 queue, receives its exact payload and permits full reclamation.

The extension passed Debug/static, Release/shared and an independently installed
consumer. Guest2 candidate `5340a307` passed all 14 source phases, including the
original 12, with 21 distinct secondary PIDs, 64/64 reclaimed objects, example exit 0
and normal power-down. It does not qualify directory arbitration or handover.
Artifact directory: `/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest2`.

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `038cc08da07417ae3ae0b02116de4b1fc8196dd5591375dc7049a283805a2eba` |
| `package-manifest.json` | `060603e86960833b27da6ef6c03759160c881a45ebdf9c9bb9537599a95289e6` |
| `initramfs.cpio.gz` | `eac3433dd8c5e9f9004af7a8155d24c30574c9f84eb1ecfc2a1063c99e039152` |
| `serial-attempt1.log` | `902c1dc4670b013aa01aa4ea4925a2771125a7ddc7fe13634511f479fef21855` |

The extension completes exactly two additional baseline-blocked source cases.
At naming qualification the baseline-to-completed total was 23/50. Current
progress is tracked in [the migration summary](fstack-migration.md).
