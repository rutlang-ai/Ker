# F-Stack thread contracts and Linux architecture exclusions

The source is the retained, unchanged F-Stack revision
`646a641cfff77f4815e1e29829a09e1ed15a2999`,
[tests/unit/test_ff_thread.c](../tests/upstream/fstack/tests/unit/test_ff_thread.c).
[Issue #231](https://github.com/rutlang-ai/Ker/issues/231) records the explicit
incompatibilities. None of the three exclusions below is a Ker test pass.

| Exact source case | Actual source assertion | Ker/Linux disposition |
| --- | --- | --- |
| `test_ff_pthread_create_basic` | Set a parent `struct thread` placeholder in `pcurthread`; after real create/join, require the child to observe that exact pointer. | FreeBSD context inheritance is outside the original Linux task model. Ker preserves independent pthread TLS and lets original LKL manage Linux task context. Creating/joining a thread alone does not satisfy this assertion. |
| `test_ff_pthread_join_retval` | Return `0xDEAD` from a `void *` routine; require the F-Stack start wrapper to discard it so join writes NULL into the caller's result slot. | Pinned LKL uses `thread_create(void (*f)(void *), void *arg)` and `thread_join(lkl_thread_t)`. The start result and join output slot do not exist. An argument object containing completion data is not an equivalent return-value test. |
| `test_ff_pthread_create_failfast` | Clear `pcurthread` and `pcpup`; touch `curcpu` through the test-local `ff_pcpu_get`/`PCPU_GET` mirror, which calls wrapped panic. | No thread is created in this body. No malloc fault is injected. The FreeBSD PCPU accessor is not a Linux API, and a generic Ker panic test does not execute it. |

The callback signatures come from the pinned Linux LKL
`arch/lkl/include/uapi/asm/host_ops.h`. The actual adapter is
[src/posix/host-thread.c](../src/posix/host-thread.c): it invokes a void routine,
returns NULL from its internal pthread trampoline and calls pthread_join with a
NULL result destination. The internal trampoline's NULL is not an externally
observable LKL join-result slot. Copying a parent FreeBSD pointer into host TLS
or adding unused source-shaped wrappers would manufacture the tested ABI rather
than adapt an actual original-Linux consumer.

The unchanged [runtime acceptance](../tests/posix/fstack-thread-runtime.c)
still qualifies two portable source scenarios: real argument delivery and
wrapper allocation failure without invoking a thread. Default, DEBUG and NDEBUG
variants also verify real thread completion, distinct argument objects, TLS
isolation/destructors, synchronization, failure cleanup and original Linux
boot/halt using the callbacks. Those extensions remain useful executable
boundary evidence, without being relabeled as the excluded assertions.

The fixed 433-case inventory now has 175 scenario-adapted, 19 partial,
171 blocked, 13 architecture-specific and 55 harness-only entries. The three
reclassifications add no passing scenario. The complete-migration gate must
continue to fail for the remaining 190 blocked/partial cases. Preserve the
source snapshot and reopen this disposition if a real consumer requires a
compatible FreeBSD thread ABI; no upstream Linux changes are justified merely
to emulate these tests.
