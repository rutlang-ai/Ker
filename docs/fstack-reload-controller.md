# Caller-owned reload controller

[`reload-controller.c`](../examples/reload-controller.c) is an application caller
of the installed Ker runtime APIs and original EAL/net_ring. Its
[`policy component`](../examples/reload-controller-policy.c) uses the unchanged
pinned nginx pure transition header. Application policy remains in the example;
Ker libraries retain their 28 documented APIs and contain no nginx FSM code.
Original Linux/DPDK code is unchanged. The example builds with testing disabled,
and its sources can also be compiled against an independently installed package.

The controller supports four cooperating worker slots under one master. The
caller owns each worker PID and pidfd, EAL, state storage, queues, polling
callbacks and the policy object. Control is serialized. The example exposes
explicit events and individual worker poll commands so each ordering requirement
can be observed. Worker callbacks remain subject to the original runtime gate.

The original table chooses every legal next state; additional runtime evidence
determines when that transition can actually commit:

| Event | Application evidence/action |
|---|---|
| HUP | Open the original Ker round and obtain target generation/round epoch. |
| ALL_READY | Every registered target PID must publish READY under that exact round; park the old owner and arm a fresh park epoch. |
| handover command | Every old worker must acknowledge that park epoch or be proven dead by its pidfd; no callback may remain in flight. Release preserves the stopped flag until the target claims. |
| HANDOVER_DONE | The target must have claimed, the parked flag must be clear, and old-worker proof must still hold. |
| DRAIN_DONE | The example's raw-record workload has empty RX/TX queues, no callback in flight and all 63 mbufs returned. |
| QUIT_GOLD | Request cooperative old-worker retirement. Workers verify the request and denied RX gate, then clean up their EAL attachment. |
| GOLD_EXITED | All exact old pidfds must report death before original round completion; close their watches and retain the target as the next active worker set. |
| Failure / RESET | First park and obtain fresh proof from all affected workers, then abort/restore the active generation. Retire failed targets and require their exact deaths before RESET. |

Missing proof returns `-EAGAIN` without advancing policy state. Illegal table
transitions return `-EINVAL`. A pending rollback blocks other advancement.
Repeated handover release records its prior completion and does not repark an
already claimed owner. The application closes pidfds only after their associated
workers have died; the caller must retire all workers before final destruction.

These are workload-specific application decisions. The example's raw-record
drain condition does not establish nginx connection drain, TCP continuity,
cross-master ownership, physical-device crash recovery or full application
reload. In-flight crash recovery remains fail-closed when quiescence cannot be
proved.

## Four exact source cases

The pinned `tests/unit/test_ff_config.c` registers four pure-policy tests:

| Source case | CTest |
|---|---|
| `test_ut_nr_10_reload_fsm_transitions` | `fstack-reload-fsm-transitions` |
| `test_ut_nr_10_all_legal_transitions` | `fstack-reload-fsm-legal` |
| `test_ut_nr_10_illegal_combinations_exhaustive` | `fstack-reload-fsm-illegal` |
| `test_ut_nr_10_error_recovery_and_abort` | `fstack-reload-fsm-recovery` |

The tests call the same policy function consumed by the real controller. They
cover the full happy chain, all 12 legal transitions, two consecutive rounds,
the 7-state×11-event matrix, all source out-of-range states, re-entry/jump
rejection, all five failure entries, RESET-only recovery and state names. The
pure source tests do not assert every operational side effect of nginx.

`fstack-reload-controller` adds actual consumer evidence. It runs two complete
original-EAL/net_ring rounds plus a safely parked READY-timeout abort/reset.
It rejects missing READY, premature handover, pending RX and TX records,
re-entry and premature old-exit events. A held old callback completes its
original RX/TX pass before its new park acknowledgement permits handover.
Exact old worker deaths are verified through pidfds before commit. Target
generation alternates 1 then 0; a same-slot successor continues actual packet work.

Repository and independently installed programs each used four distinct actual
EAL secondary PIDs and ended with original PMD `ipackets=4`, `opackets=4`,
callbacks `[3,0,1,0]`, no in-flight work, empty queues and 63/63 reclaimed mbufs.
All secondary/EAL cleanup precedes primary device, queue, pool and state teardown.
The installed consumer's application/policy/header bytes were checked against
the candidate sources. Both profiles record their complete event traces.

Debug/static and Release/shared source CTests passed. The example also builds
with `BUILD_TESTING=OFF`. `fstack-reload-controller-import` checks original policy,
root/nginx licensing and separation from Ker implementation. Kernel runtime
exports remain 28; this batch adds application sources rather than Ker APIs.

## Qualification record

Candidate `5f606d513c90fcf4113b7b9f7ab9db28416fb6ca` passed in a fresh networkless
shared-hugepage guest, alongside all 18 earlier runtime source phases and both
previous examples. All five multiprocess profiles, both controller programs,
normal power-down and QEMU exit 0 passed. Host skip77 is never completion.
The earlier failed guest6 is retained separately; its QEMU exit 0 is not a pass.

Artifact directory:
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest7`.

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `ff9ce3cbf8a88140ab7fdd98d27b25b5e8b096a030fd8a8805e4a4486583d80e` |
| `package-manifest.json` | `f3531233fbbee24e8cc360dad091c0712800de23d705ba28dab41ce6a942615a` |
| `initramfs.cpio.gz` | `574c7112df8d750ce03fe205193301985f5f4f51417f09afe6048131e864bb4d` |
| `serial-attempt1.log` | `ba6f317f43f6783582fe80d4cafa13fe1fa798a61931636c36410b0b6ab5a08e` |

The result binds candidate source, executables, installed application sources,
package and serial/event traces. Unit tests cover all five failure-table entries;
the integrated controller demonstrates the shared rollback mechanism with an
actual READY-timeout, without claiming every operational fault permutation.
Exactly four baseline-blocked source cases are newly complete. The current
baseline delta is 31/50; 19 remain.
