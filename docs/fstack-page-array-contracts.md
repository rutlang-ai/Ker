# F-Stack page-array build exclusions

Two retained source cases test a F-Stack build restriction tied to FreeBSD
mbuf ownership. They are architecture-specific exclusions under
[issue #232](https://github.com/rutlang-ai/Ker/issues/232), not Ker test passes.
They do not describe a missing generic Linux page-array allocator.

The unchanged [test_ff_config_pa.c](../tests/upstream/fstack/tests/unit/test_ff_config_pa.c)
is compiled with `FF_USE_PAGE_ARRAY`. It loads two real source fixtures:

| Exact source case | Assertion | Disposition |
| --- | --- | --- |
| `test_page_array_rejects_graceful_reload` | `valid_graceful_reload.ini` fails with -1 in the page-array build. | F-Stack/FreeBSD build restriction; excluded, no Ker test mapping. |
| `test_page_array_keeps_graceful_off` | `valid_minimal.ini` succeeds and leaves the source global reload flag zero in the same build. | The positive half of that build restriction; excluded, no Ker test mapping. |

At the same pinned revision, the original
[ff_config.c guard](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_config.c#L1573)
explains the restriction: handing staged TX mbufs to another process cannot
release the originating process's `bsd_m_table` references. The original
[ff_memory.c staging path](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_memory.c#L518)
stores both the DPDK mbuf head and the source BSD mbuf in parallel arrays.
The exclusion is specific to those references and that build form.

Ker's [packet device](../src/posix/packet-device.c) transports frame bytes over
a connected Unix socket into/out of original Linux. The separate
[TX export adapter](../src/runtime/tx-export.h) transfers copied DPDK chains
only after sink acceptance, preserving the original skb while queued/retried.
Neither path exports a process-private FreeBSD mbuf table or implements the
`FF_USE_PAGE_ARRAY` build ABI. This does not establish cross-process reload
safety: the real generation transport still needs the ownership and lifetime
proof in [the reload contract](fstack-reload-ownership.md).

Adding an unused build define or a `graceful_reload` boolean solely to reproduce
these two loader results would invent a mode with no actual consumer. Generic
unsupported-key rejection also cannot qualify the positive reload-off case.
Preserve the source tests and fixtures unchanged, with no fabricated FreeBSD
mbuf table and no upstream Linux/DPDK modifications. Revisit the exclusion only
if a real supported integration introduces these source-specific borrowed
references; general generation reload remains implementation work in #218.

This audit transfers exactly these two IDs from #218 to #232, leaving 79
reload cases actionable and 12 cases in the FreeBSD-internals exclusion group.
The fixed denominator is 433: 179 scenario-adapted, 19 partial, 165 blocked,
15 architecture-specific and 55 harness-only. The two exclusions add no passes;
184 blocked/partial cases still require work.
