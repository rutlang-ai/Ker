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
`system` and `popen` after initialization. The separate authenticated
[native socket broker](native-socket-broker.md) and its
[POSIX caller adapter](native-socket-preload.md) support selected original
Linux TCP socket/epoll capabilities across frontend fork/exec. The verified
no-FF Nginx lifecycle exercises that bounded caller path. It does not initialize
the F-Stack Nginx module or provide its full application runtime.

Ker's [`ker::fstack-socket-bridge` leaf adapter](fstack-socket-bridge.md) can
route selected unchanged `ff_api.h` TCP socket calls through the original-Linux
broker. The opt-in [bounded FF-enabled Nginx runtime profile](fstack-nginx-runtime.md)
now binds those leaves to the pinned executable's detached `graceful_reload=0`
caller path, restores its FF fd offset, and demonstrates a one-worker
HUP/USR2/WINCH lifecycle over original Linux TCP. The validated worker shim
also supports one- and two-worker `reuseport` listener ownership across HUP,
USR2, and WINCH while retaining `graceful_reload=0`. This caller profile does
not implement the F-Stack generation reload FSM.

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
primitive, not F-Stack per-process FD aliases, `so_snd`, or source FSM counters.
A separate op-47 owner hook now reports a bounded original-Linux request_sock
count for `ff_syncache_count`; it excludes full `SYN_RECV` sockets and
stateless cookies, and does not establish full source-counter equivalence. The
tests keep the listener live through zero. This is not the original shell's
complete census, fault or lifecycle matrix and does not change the blocked
inventory entry.

The private C16 fixture attaches one authenticated FF owner and one IPv4
listener to an independently running original-Linux broker. It arms the
broker's marked NFQUEUE admission task before `listen`, pumps the unchanged
flow-map callback on the FF event-loop owner thread, holds real TAP SYN-ACKs
until a map verdict, and rejects a real full-map request through the original
kernel. Its cases include exact owner request revocation, a stopped owner with
independent broker progress and deadline enforcement, duplicate SYNs,
authenticated endpoint rejection, and owner/listener cleanup. Errors remain
quarantined and fail-closed; this fixture does not prove healthy recovery.
It does not bind the production Nginx dispatcher or generation FSM, and does
not enable public `graceful_reload=1`; all six C16 controls are narrower than
the original shell matrix and leave this source entry blocked.

The C17 fixture adds private retirement and rearm of the marked admission
queue while preserving the same listener. The controller disables the old
lease, drains notifications while the owner map remains open, then asks the
owner thread to close that map. Rearm revalidates the retained listener and
uses a fresh lease before the owner reopens the map. A real connection during
the retired interval exercises the unchanged map's outside-window
allow-without-record behavior. Three windows are tested; this bounded profile
does not establish production Nginx generation/FSM integration, arbitrary
kernel hook quiescence, or recovery from an uncertain accepted verdict. The
public graceful-reload path remains unsupported and the source entry remains
blocked.

This retirement ordering is qualified only for the configured native artifact
`399c02b3aa05a7ee2a35c13fca64a279198c0d0675a8dc218eddc07399525b8d`, whose
config is UP, `PREEMPT_NONE`, and `TINY_RCU`. The pinned LKL syscall holds its
single CPU through synchronous `LOCAL_OUT` NFQUEUE enqueue, whose callback uses
atomic allocation and nonblocking netlink delivery. Disabling the exact mark
and lease serializes behind any hook already executing on that CPU; the broker
then drains queued/deferred notifications before the FF owner closes the map.
The CMake profile guard rejects other scheduling/RCU configurations; this is
not a generic kernel quiescence guarantee.

The bounded FF runtime now implements `ff_socket_drain_count` over authenticated
broker capabilities registered in the current process. It counts application
FD aliases individually and queries live `SO_ACCEPTCONN`, so an inherited
listener that starts listening after fork is excluded. The tests exercise
broker-created UDP inherited through exec as well as registered TCP sockets,
host descriptor exclusion, descriptor reuse pruning and live TCP traffic
through both the leaf bridge and `libfstack.so`, plus fail-closed broker errors
through the leaf bridge.
This hook is not the pinned source's whole process FD-table walk: raw or
unregistered descriptors are outside its view, and the public FF/POSIX socket
creation adapters still reject UDP. The graceful-off caller profile does not
invoke the generation FSM. The bounded authenticated `ff_syncache_count()`
hook observes original-Linux request sockets only; flow-map, dispatcher, and
generation FSM hooks remain unsupported. The source inventory entry remains
blocked.

The bounded FF bridge now supports `ff_dup` for registered TCP descriptors via
the existing namespaced `F_DUPFD` adapter. Tests cover lowest-free slot reuse,
shared socket identity and status, close-on-exec behavior, independent alias
closure, fork/exec inheritance, resource-exhaustion rollback and live TCP
traffic through the duplicate. Host and private broker descriptors are rejected
by the FF bridge. This leaf does not add `ff_dup2` or establish full F-Stack FD
table equivalence; the broader drain, lifecycle and blocked source inventory
status are unchanged. The pinned [`ff_dup` implementation](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_syscall_wrapper.c#L2167-L2189)
routes F-Stack descriptors through `sys_dup`.

The opt-in runtime now provides `ff_socket_snd_pending` for ordinary
ready-copy TCP sockets created through the authenticated FF owner context. Each
process receives a distinct broker-owned mark bound to its host PID, process
start time, and pidfd; accepted children and duplicated aliases retain that
owner. The hook reports original-Linux queued payload bytes, including
descriptorless full sockets, and clamps to the upstream `int` result range.
Generic, inherited, or foreign registered sockets cause the query to fail
closed, even after those descriptors close. Sticky history is stored by the
broker against the authenticated PID, process start time, and pidfd, so it
survives session reconnect and `exec`; owner marks remain stable for the live
process. The same-process native broker is within the trusted boundary. The
check does not defend against privileged code with direct access to sockets in
the same LKL instance and the ability to set their marks. The
profile excludes sendfile and does not enable graceful reload. The private
C16 fixture exercises one bounded admission window but is not production Nginx
generation binding. The source still requires end-to-end generation admission,
dispatcher/FSM integration, healthy recovery, the remaining fault matrix and
cleanup before a zero result can drive promotion; the source inventory entry
remains blocked.

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
must bind the production FF-enabled Nginx caller to broker-owned admission and
generation services, restore its executable FD offset at the right boundaries,
and provide real caller-side FF lifecycle, event and drain behavior. The real
Nginx caller must run its signal-driven FSM while workers change. Qualification
must observe actual FSM transitions,
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
