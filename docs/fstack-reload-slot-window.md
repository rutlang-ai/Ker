# Transient reload slot admission

This batch completes two pinned upstream cases previously marked blocked:

| Source case | Source assertion CTest | Real EAL profile |
|---|---|---|
| `test_p2_slot_transient_window` | `fstack-reload-slot-window` | production-linked and independently installed consumers |
| `test_p2_slot_transient_exhausted` | `fstack-reload-slot-exhausted` | private production-TU consumer with original 50 ms test budget |

The source is `tests/unit/test_ff_dpdk_if.c` at F-Stack
`646a641cfff77f4815e1e29829a09e1ed15a2999`. Complete original helper and
assertion bodies are retained in `fstack-reload-slot-window-source.inc`;
`reload-live-slot-import.py` compares their exact bytes against the pinned
snapshot. The source assertion host replaces only CMocka assertions, EAL role,
memzone lookup and fatal-exit reporting. It does not replace slot selection,
PID liveness, clocks, sleeps, retry budgets, counters or ownership CAS.

The actual EAL test uses separate real parent/master processes and secondary
workers, original shared hugepages, and `net_ring`. The resident primary owns
the original shared directory. Four actual master/worker lifetimes advance
the epoch counter: old A gets epoch 2/slot 2, then epochs 3/4 depart and leave
both alternative slots reclaimable. A polls once to refresh its original
slot timestamp and explicitly stops its hardware lease. Its master is killed
and reaped, leaving A alive and adopted by the test subreaper.

The new secondary finishes EAL initialization before an explicit barrier
allows its directory attachment. Only then does the fixture refresh A's
stamp, reap its master, and release attachment. This separates the actual
admission wait from EAL setup time. Read-only observations of the pinned
layout record slot fields; no test writes directory timestamps, slot contents
or the mint counter.

With the original production budget, epoch 5 waits until the remaining
2000 ms stale interval expires and takes exactly slot 2. It must not select an
otherwise available alternative slot or increment the refusal counter.
Explicit proof-bearing hardware reclaim is separate from slot admission.
The old orphan's subsequent poll cannot enter its callback; the new worker
serves one exact frame through original PMD RX/TX. All 63 pool buffers and
queues are reclaimed, and every participant is reaped before primary cleanup.

For exhaustion, a separate noninstalled executable compiles the same
production reload translation unit and sets only the original upstream
`ff_reload_reclaim_timeout_set(50)` test knob. It uses actual EAL roles,
memzones, fatal termination, clocks and PID checks. The source implementation
must exit 1 with its original isolation diagnostic, increment refusals exactly
once, and preserve old slot epoch/master/stamp, ownership and both alternative
slots. No production timeout override is added; the production-linked and
installed consumers keep the original default budget. No test hook is added
to the production runtime or installed libraries.

## Validation

Strict Release/shared builds and both source assertion CTests pass. The full
catalog audit and its mutation tests pass. A fresh two-CPU, no-NIC guest with
64 guest-only 2 MiB pages passes repository success/exhaustion profiles and an
independently installed production success profile. Host hugepage settings
are unchanged. The guest shuts down normally with QEMU status 0.

Qualified test implementation: `fad9912c7e3804a019261e0dc6326a07535bed89`.
Evidence: `/home/hurricane/.local/state/ker-compat-work/fstack-directory-boundaries-evidence/guest2/actual-result-attempt1.json`,
SHA-256 `0cdc60ade1540aa38300e847b37e47a8c8b8395a5f443cee8dfb9ef0d8433ae6`.
The record binds source Git blobs, binary/library and standalone-consumer
inputs, guest image, serial output and QEMU command/status. Guest1 is retained
as a failed timing-fixture attempt, not accepted qualification.

Only these two source cases change status. Baseline merge
`9206b9d48d3c33c6742d7e384d0e39797527e03a` has 268 adapted, 12 partial, 83 blocked;
this batch has 270 adapted, 12 partial, 81 blocked. The105 upstream test files,
LICENSE, production Ker runtime, Linux/DPDK dependencies and prior 50-case
completion ledger remain unchanged. This does not qualify physical NIC I/O,
application reload/TCP continuity, generation packet diversion or other
remaining cases.
