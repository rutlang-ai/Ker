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

The in-process `ker-posix` API still isolates its initialized kernel from
post-init process creation. [`lkl-channel.c`](../src/posix/lkl-channel.c)
registers an at-fork child handler that exits with status 125;
[`posix-process.c`](../src/posix/posix-process.c) rejects `posix_spawn`,
`system` and `popen` after initialization. A separate authenticated
[native socket broker](native-socket-broker.md) and its
[POSIX caller adapter](native-socket-preload.md) now transfer selected original
Linux TCP socket/epoll capabilities across frontend fork/exec. The verified
no-FF Nginx lifecycle exercises that bounded caller path. It does not initialize
the F-Stack Nginx module or provide its full application runtime.

Ker's [`ker::fstack-socket-bridge` leaf adapter](fstack-socket-bridge.md) can
route selected unchanged `ff_api.h` TCP socket calls through the original-Linux
broker. The opt-in [bounded FF-enabled Nginx runtime profile](fstack-nginx-runtime.md)
now binds those leaves to the pinned executable's detached `graceful_reload=0`
caller path, restores its FF fd offset, and demonstrates a one-worker
HUP/USR2/WINCH lifecycle over original Linux TCP. It explicitly rejects
secondary-worker initialization; multiworker `reuseport` clone ownership
remains unsupported. The profile does not implement generation reload or
census behavior.

The `native-socket-broker-generation-handoff` caller test exercises the
broker's fixed two-member original-Linux reuseport selector with two old and
two replacement SDK workers. It holds twelve old TCP streams open, verifies
nonce-specific payloads before and after selector change, and overlaps fresh
no-retry connections with the change. Every connection initiated after the
successful selector operation must identify a replacement worker. Accept-only
barriers prove both workers in each generation serve a connection. After the
selector changes and tracked pre-selector connection attempts finish, the old
workers stop accepting, remain alive while their streams transfer payload,
and exit after those streams half-close. Among broker capabilities, the
supervisor retains the group control capability and metadata-only TCP
observers; the broker owns the base listeners, and workers own accepted socket
capabilities. Observer snapshots verify the original Linux socket identity
reaches TIME_WAIT or absence after worker teardown.

This is a bounded process and selector handoff primitive test. It does not run
the F-Stack nginx executable or its generation FSM, does not implement its
drain/census hooks, and does not establish a zero-TCP-state claim. It does not
change the blocked source inventory entry.

The separate [`native-socket-broker-member-census` test](native-socket-broker.md)
now samples raw original-Linux TCP states for two managed IPv4 reuseport
members. It observes a real old-member `SYN_RECV` across selector change, then
closes every native accepted descriptor while the host pauses reads, verifies
queued native-to-host bytes and orderly EOF, and observes closing/TIME_WAIT
rows after worker exit. A separate kind-4 observer provides the send-queue
measurement; the kind-5 census result itself contains only raw state counts
and listener identity. This validates the broker's bounded member-census
primitive, not F-Stack per-process FD aliases, `so_snd`, syncache or source FSM
counters. It is not the original shell's complete census, fault or lifecycle
matrix and does not change the blocked inventory entry.

The existing [`ker::reload` controller](fstack-reload-controller.md) consumes
the unchanged nginx FSM policy, but its caller demonstrates raw-record queue
drain, worker readiness and pidfd retirement. It explicitly does not establish
nginx connection drain or TCP continuity. The [packet-session
runtime](fstack-session-packets.md) grants one packet consumer for its worker;
it does not provide replacement-service process handoff. These are distinct
runtime limits, not missing test-host setup.

## Path to meaningful qualification

Keep packet and connection behavior in the one authoritative original Linux
kernel socket runtime already used by the broker. The remaining adapter work
must connect the FF-enabled Nginx caller to that runtime, restore its executable
FD offset at the right boundaries, and provide real caller-side FF lifecycle,
event and drain behavior. The real Nginx caller must run its signal-driven FSM
while workers change. Qualification must observe actual FSM transitions,
Nginx/runtime logs, counters, live connection results and cleanup side effects,
rather than fabricated oracle text or a raw-record queue substitute.

Run the original script's applicable cases explicitly in a disposable Linux
guest with independent remote clients, build/source identity, fault-injection
builds, and verified worker, descriptor, DPDK and kernel cleanup. The complete
applicable set is `precheck,baseline,rt01,rt02,rv9,gr0,rt12,rt20,rt20b,rt21,rt22,rt23,rt24,rt25,rt26,rt30,rt31`; `rt13` is permanently excluded. The built-in
`--cases all` alias only selects `precheck,baseline,rt01,rt02,rv9,gr0,rt12,rt13`,
so it omits `rt20`, `rt20b`, `rt21`-`rt26`, and performance cases `rt30`/`rt31`.
Do not treat that alias as the full matrix, and do not count `LIMITED` or `SKIP` as a pass. Preserve the
original result artifacts and distinguish failed or skipped profiles from
passes.

Until the FF generation-reload service, its per-process descriptor/census
interfaces, original runtime counters, drain behavior, fault cases and cleanup
are exercised end to end, the source entry
remains `blocked`. Neither an F-Stack-only run, pure Nginx FSM tests, the no-FF
Nginx lifecycle, the bounded graceful-off Nginx profile, nor the single-process
caller controller or bounded two-member broker census completes it.
