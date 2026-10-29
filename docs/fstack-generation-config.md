# Generation-independent configuration mapping

The complete original `test_ut_nr_12_generation_mapping` is retained without
changing its assertions. The caller-side legacy inspector supplies the parsed
process/lcore map. Real `ker::reload` borrowed state selects generations0/1,
and the existing public `ker::ipc` formatter supplies the original names,
including legacy disabled mode, distinct processes, typed output rings and
truncation failure. Invalid generation selections leave the previous selection
unchanged. No source state or name result is replaced with a test constant.

`ker_reload_selected_generation()` observes the actual process generation from
the unchanged runtime. It is distinct from `ker_reload_runtime.worker_generation`,
whose upstream meaning is the open round's target or the active generation.
Observation grants no RX ownership. The usual caller serialization rules apply.

The `ker-config-generation-plan` example uses this observer while switching its
own borrowed state and printing the same parsed process/lcore map for both
roles. It does not start EAL, run traffic, or apply FreeBSD startup options.
Configuration snapshots remain caller data; the Ker runtime never reads or
rewrites their lcore arrays.

Validation covers the original complete assertions, actual example execution,
the source import checker, GCC/Clang and sanitizer builds. An independently
built consumer uses freshly installed public libraries/headers; replacing the
observer with a constant0 fails the original generation1 assertion. All prior parser
cases are rerun with the current optional coexistence layout enabled. This is
the generation/name/mapping unit contract, not reload traffic or TCP continuity.
