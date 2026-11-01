# Graceful-reload shell migration boundary

The remaining blocked source entry is
[`tests/integration/test_graceful_reload.sh`](../tests/upstream/fstack/tests/integration/test_graceful_reload.sh)
(`::entrypoint`). The original script is
an operational F-Stack/nginx test, not just a reload-policy unit test. It
requires a running nginx/F-Stack service, sends reload signals, keeps remote
TCP probes active through the transition, checks reload/drain state and
fault-path results, and verifies process and DPDK-resource cleanup. Its remote
client, build manifest and configured test host are part of the test contract.
Running the F-Stack service by itself is an upstream baseline, not evidence of
Ker migration.

Ker's native Linux backend currently isolates its initialized kernel from
post-init process creation. [`lkl-channel.c`](../src/posix/lkl-channel.c)
registers an at-fork child handler that exits with status 125;
[`posix-process.c`](../src/posix/posix-process.c) rejects `posix_spawn`,
`system` and `popen` after initialization. The documented native boundary also
requires each process to start through its own `ker-run` and does not support
passing native descriptors to a replacement through `exec` or `SCM_RIGHTS`
([native TCP limits](native-tcp.md)). Thus the original daemon/re-exec service
lifecycle and inherited live connections are not currently available to a Ker
caller.

The existing [`ker::reload` controller](fstack-reload-controller.md) consumes
the unchanged nginx FSM policy, but its caller demonstrates raw-record queue
drain, worker readiness and pidfd retirement. It explicitly does not establish
nginx connection drain or TCP continuity. The [packet-session
runtime](fstack-session-packets.md) grants one packet consumer for its worker;
it does not provide replacement-service process handoff. These are distinct
runtime limits, not missing test-host setup.

## Path to meaningful qualification

Keep packet and connection behavior in one authoritative original Linux kernel
socket runtime. A future adapter needs an authenticated supervisor and an
explicit replacement-process boundary that transfers or reopens authenticated
handles to the same socket and epoll state; it must not recreate TCP state in
Ker. The real nginx caller must run its signal-driven FSM while workers change.
Qualification must observe actual FSM transitions, nginx/runtime logs, counters,
live connection results and cleanup side effects, rather than fabricated
oracle text or a raw-record queue substitute.

Run the original script's applicable cases explicitly in a disposable Linux
guest with independent remote clients, build/source identity, fault-injection
builds, and verified worker, descriptor, DPDK and kernel cleanup. The complete
applicable set is `precheck,baseline,rt01,rt02,rv9,gr0,rt12,rt20,rt20b,rt21,rt22,rt23,rt24,rt25,rt26,rt30,rt31`; `rt13` is permanently excluded. The built-in
`--cases all` alias only selects `precheck,baseline,rt01,rt02,rv9,gr0,rt12,rt13`,
so it omits `rt20`, `rt20b`, `rt21`-`rt26`, and performance cases `rt30`/`rt31`.
Do not treat that alias as the full matrix, and do not count `LIMITED` or `SKIP` as a pass. Preserve the
original result artifacts and distinguish failed or skipped profiles from
passes.

Until that process and socket handoff exists, the source entry remains
`blocked`. Neither an F-Stack-only run, the pure nginx FSM tests, nor the
single-process caller controller completes it.
