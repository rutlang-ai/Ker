# Worker process modes and F-Stack compatibility boundaries

Each Ker I/O worker must be an original DPDK primary and own its selected
device. The launcher rejects an explicit `--proc-type=secondary` or
`--proc-type secondary` in the effective main EAL arguments and every
additional interface's EAL arguments. Rejection is a configuration error2,
before any worker query/exec, EAL attachment or application startup. A raw
EAL suffix after the first `--` is preserved and not interpreted as a mode.

CLI `--eal` overrides the whole main INI EAL string before this validation.
Thus a CLI primary can replace an obsolete INI secondary. This does not add
F-Stack `-t`/`-p`, `proc_id`, `proc_mask` or `thread_mode` fields. Unknown mode
values still reach the original EAL parser and retain its real rejection.
Explicit auto remains governed by original EAL selection; the actual process
must still pass the worker's post-init primary check. The new preflight is
only a guarantee for explicit secondary requests, not a replacement EAL mode
parser or a general guarantee about automatic secondary selection.

## Runtime acceptance

`native-fstack-eal-file-prefix` keeps an actual same-prefix primary alive,
requests secondary mode for both main and auxiliary interfaces in both forms,
and requires error2 without executing a PID-recording wrapper that would exec
the real worker. No app marker or stats may exist. The original primary must
remain alive and subsequently complete original Linux TCP/UDP with zero owned
mbufs. This is not a successful secondary attachment test.

The same test retains original EAL same-prefix primary-lock rejection,
concurrent independent-prefix acceptance, literal prefix selection and CLI
precedence. New successful profiles verify actual original EAL auto selection
as primary in an isolated namespace and a CLI primary replacing INI secondary.
Every successful profile requires the observed worker process type primary,
actual namespace selection, original Linux TCP/UDP counters and cleanup.
Independent primary instances are not F-Stack secondary or generation owners.

## Exact remaining source contracts

The unchanged pinned
[test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c)
asserts the following under [issue #227](https://github.com/rutlang-ai/Ker/issues/227):

| Source case | Actual source assertion | Remaining Ker boundary |
| --- | --- | --- |
| `test_ff_load_config_argv_t_override` | `-t secondary -p0` loads successfully and stores secondary/proc_id0. | Ker rejects explicit secondary; successful CLI primary overriding INI secondary does not satisfy the reverse source request. |
| `test_parse_lcore_mask_proc_id_in_range` | Mask0x3 permits proc_id1 and synthesizes a non-NULL proc_mask. | Ker has no global process-index-to-core table. EAL core membership/RX ownership is a different contract. |
| `test_parse_lcore_mask_proc_id_over_count_fails` | proc_id5 with a two-core table fails load. | Rejecting an unsupported proc_id field cannot prove this conditional index check or its in-range positive counterpart. |
| `test_ff_load_config_thread_mode_enabled` | Mode1 derives4threads, collapses nb_procs to1, forces primary and retains full proc_mask0xf. | The fixture describes single-process multi-thread multi-stack operation. Four Ker RX pollers feeding one original Linux instance do not implement those global stack/process semantics. No same-name no-op mode is added. |
| `test_ff_load_config_thread_mode_default_off` | Absent mode has0threads and4processes for mask0xf. | Ker does not automatically launch a process per mask bit. One worker enabling four EAL cores is not four application stacks. |
| `test_ff_load_config_thread_mode_secondary_conflict` | Mode1 plus secondary rejects while valid primary mode1 succeeds. | Generic secondary rejection does not complete the conditional source mode contract without the valid mode1 implementation. |

All six remain blocked with no pass or partial mapping. A real adaptation must
first define shared device ownership, application/kernel instance lifetime,
process-index/core mapping and how multiple original Linux stacks execute.
Preserve upstream Linux/DPDK and protocol semantics; do not emulate these
contracts with independent namespaces, idle threads or invented global fields.

The catalog remains179 scenario-adapted,19partial,167blocked,
13architecture-specific and55harness-only out of433. The complete gate must
still fail for186blocked/partial cases. This primary-only boundary and its
runtime evidence improve the real adapter without claiming those cases passed.
