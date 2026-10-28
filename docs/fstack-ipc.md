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
transport requires explicit generation rather than silently resolving AUTO.
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
example exit0, normal power-down and QEMU exit0. The inherited guest root does not
imply that unrelated historical suites were rerun. On hosts without usable shared
hugepages the CTest returns skip77; that result is never counted as completion.

These twelve cases move from baseline blocked to scenario-adapted. They do not
complete remaining generation/reload contracts, physical NIC handover, control
command semantics or TCP continuity. The baseline-to-completed total is21/50.
