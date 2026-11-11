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

The SDK now has a deferred owner-aware fixed two-member IPv4 reuseport-group
constructor. Its five calls reserve the tuple (`owner_group_plan`), issue one
index-scoped slot (`owner_group_slot`), authenticate the owner (`ff_owner_group_claim`),
create both listeners (`owner_group_publish`), and retrieve aliases for the
owner's member (`owner_group_member`). The claim capability is a one-use,
phase-checked receipt that can be reused only to retrieve aliases for that
same owner, index, group incarnation, and member cookie. It grants neither
group selection nor delegation. The coordinator retains separate group
CONTROL authority; each worker gets only its owner CONTROL capability and
claimed receipt.

Both distinct live owners must claim before publication. The listeners receive
their respective immutable owner marks from creation; those same marks
authorize owner payload snapshots and member READ censuses. Fresh FF TCP
creation is rejected while an owner is associated with this group, so another
socket cannot pollute the member census. Publication fails if either owner is
dead or has acquired sticky owned/unowned network history after claiming;
repeated claims and publication return `EALREADY`. The native TAP test checks
owner isolation, these lifecycle failures, selector changes, and TCP exchanges
accepted by both owners. An old accepted stream remains usable after selection
moves to the second listener, including a descriptorless pending-payload
snapshot checked against a real ACK-drop capture.

This SDK leaf supports one fixed two-member IPv4 group. It does not bind Nginx
generation startup, worker dispatcher behavior, repeated generations, or the
graceful-reload FSM; the source inventory entry remains blocked.

The C21 SDK leaf adds an opt-in activation path for the initial member of a
staged owner group. The claimed owner receives one unbound original-Linux TCP
socket tagged with its immutable owner mark; only that actor may set the small
prebind option allowlist and perform the reserved-tuple `bind` and real
`listen`. The broker publishes the member cookie and selector-0 group only
after `listen` succeeds, and the coordinator can retrieve group CONTROL after
that point. Owner history is checked before every activation operation, and
the socket cookie and mark are revalidated against the native descriptor.
Admission-prepared initial owners, repeated replacement, Nginx worker/module
binding, and the graceful-reload FSM remain outside this initial-member leaf.
The TAP fixture exercises a real accepted TCP exchange, sticky-history refusal
without bind/listen effects, capability cleanup, and reuse of the released
tuple by a fresh non-reuseport listener. This is an SDK prerequisite, not a
graceful-reload qualification; the source inventory entry remains blocked.

The C25 candidate-activation leaf extends this sequence to a single slot-1
candidate in the same fixed IPv4 group. Only its authenticated claimed owner
can request the unbound marked socket, and only after the existing admission
task reports READY. The owner then uses the ordinary bind/listen path for the
reserved tuple. The broker pins a stable duplicate into the task after bind
and before listen, and publishes the candidate cookie/member only after the
original Linux `listen` succeeds. Candidate validation and failure cleanup
remain scoped to slot 1; selector zero and the initial listener stay available
until a separate coordinator selection. Published member aliases share the
candidate activation lifetime, including when the original activation fd is
closed. The real TAP fixture checks the pre-listen census, off-tuple bind
rejection, task registration before listen, alias closure, selector change,
candidate TCP/map admission, and a held old stream after selection. This does
not bind the pinned Nginx worker lifecycle or qualify graceful reload; repeated
generations and the full FSM remain unsupported.

The opt-in C23 source baseline runs unchanged pinned `m4_lc.py` against the
installed C22 Nginx runtime on `198.18.0.2:80`: 24 persistent connections plus
one fresh-request worker, 330 seconds, 0.5-second intervals, and a 2-second
timeout. The source oracle passed with 15,840 persistent requests, 660 fresh
requests, and zero failures or reconnects. This is a baseline qualification
only. The separate manual `gr0` mode runs unchanged 25-second `m4_outage.py`,
sends the real Nginx HUP at the source harness's five-second anchor, and applies
the unchanged oracle and zero-FSM-log check. In the recorded run it observed
one 0.028-second refusal window, below the source oracle's 0.3-second minimum;
`gr0` was therefore unqualified at that checkpoint. The evidence records exact probe
arguments and hashes, the installed Ker manifest, Nginx/module/runtime hashes,
probe logs, and original-Linux broker statistics. The config preserves the
source probe's `/` index response and 300-second keepalive settings. The
baseline CTest is opt-in because it takes more than five minutes; manual `gr0`
and composite modes return nonzero when the unchanged oracle rejects a run.
This work does not advance the source-case inventory or qualify graceful reload.

## Private Linux RX decision lease (C31)

The private `ker-run --rx-decision` profile gives the trusted original-Linux
application a bounded, authenticated decision for each retained Ethernet RX
mbuf. Private wire version 2 carries the complete flattened frame while
retaining the original first-segment, offset, queue, and offload metadata. The
callback receives a read-only full-frame view and a first-segment alias for the
duration of the callback; a deferred callback must copy all bytes it needs.
The consumer may choose `LOCAL` (inject the unchanged frame once into
that application's original Linux instance) or `DROP`; it cannot provide
replacement bytes, a target, or a file descriptor. Worker settlement waits
until every decision lease is resolved. The implementation does not enable
F-Stack dispatcher registration, PEER/RESPONSE actions, or a graceful-reload
profile.

The private callback may defer one lease only after copying any bytes it needs;
the snapshot is valid only during the callback. The exact packet ID can then be
completed once on the registered owner thread, before the original worker
deadline, after fresh worker and supervisor pidfd/start-time checks. Pumping
while a lease is pending does not read another packet or invoke the callback.
Expiration or send failure leaves the packet unresolved, so a later `SETTLED`
cannot claim that packet was handled. Callers must finish a pending lease and
switch to their own bounded synchronous `LOCAL`/`DROP` policy before stopping
their app loop; otherwise native shutdown cannot service another deferred
callback. The physical TAP case exercises this caller-owned drain transition.
The full-frame snapshot does not transfer mbuf ownership: the worker retains
the original chained mbuf until the one result and uses that same object for
the existing LOCAL/DROP ownership path. The supported producer cap remains
MTU plus Ethernet and VLAN headers (9018 bytes at MTU 9000); the private wire
frame ceiling is 9022 bytes, and both endpoints reject excess or non-exact
payload lengths. This remains a private prerequisite: source callback
integration, authenticated cross-generation `PEER` routing, and the original
same-master graceful-reload matrix are still unsupported.

The TAP qualification uses real original-Linux TCP: normal echo, an injected
packet-channel EAGAIN followed by same-ID retry and one actual send, immediate
application stop with RX decision progress during native send-queue drain,
and a post-PREPARED SYN answered by DROP without a SYNACK. A separate retry
case proves cleanup-only `EBUSY` continuation and retained native drain error.
Actual-worker negative cases also exercise an expired lease, a replayed stale
RESULT, wrong sender credentials, and consumer death with a lease outstanding;
each must fail closed with `ETIMEDOUT` or `EPROTO`, inject no packet on the
local packet channel, and return the worker pool to zero outstanding buffers.
These cases qualify the private lease and shutdown ownership boundary only;
they do not invoke the pinned Nginx callback, transfer packets between Nginx
generations, qualify PEER routing, or complete the original graceful-reload
entrypoint. They do not change the source-case inventory.

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

## Packet-channel retirement and worker control lifetime

The standalone I/O worker now treats a retired native packet endpoint as a
data-path retirement, independently of its control owner's lifetime. A failed
RX send with `ECONNREFUSED`, `EPIPE`, or `ENOTCONN` stops RX pollers, releases
retained RX mbufs, and drains already accepted TX using the existing bounds.
Once quiescent, the worker waits for its control command or control EOF before
exiting. Signals and genuine drain failures retain their existing failure and
cleanup behavior. No Linux or DPDK protocol implementation changes.

`native-worker-packet-retirement-command` and
`native-worker-packet-retirement-eof` use a real DPDK TAP PMD in an isolated
network namespace. They first verify a received Ethernet frame, close the
packet endpoint while more frames arrive, require the worker to remain alive
beyond the existing drain bound, and then stop it through the independent
control channel. Final statistics must show explicit control retirement,
discarded retired-path RX, and zero outstanding mbufs. The old worker fails
this regression by exiting before control retirement.

These worker-only tests qualify the lifetime prerequisite only. They do not qualify the
original 25-second `gr0` outage oracle, `gr1`, or the complete reload matrix;
the source migration entry remains `blocked` until those run end to end.

## Original gr0 probe across a serial runtime cycle

The private serial-cycle fixture now has an explicit `--source-gr0` mode. It
runs the unchanged pinned `m4_outage.py` against `198.18.0.2:80` for 25 seconds
with a 0.5-second timeout, sends the real Nginx reload at the five-second
anchor, and invokes the unchanged `reload_checks.py summary outage` oracle.
The oracle still requires a nonempty success sample and outage window with a
longest outage between 0.3 and 2.5 seconds. Source hashes are checked before
and after the probe, and the Nginx error log must contain no graceful-reload
FSM completion or transition lines.

The original master remains alive while the old worker retires, the old
runtime settles, and the successor runtime becomes READY. Distinct worker,
nonce and epoch identities, descriptor isolation, event order, final companion
shutdown and zero outstanding mbufs retain the existing fixture checks. A
rejected source oracle produces a nonzero result after normal runtime cleanup;
a runtime error is never recorded as a qualified probe.

Enable the optional test with `-DKER_ENABLE_NGINX_SERIAL_GR0=ON` in a build
already configured with the pinned FF-enabled Nginx executable, source tree,
generated headers and runtime module. Run:

```sh
ctest --test-dir build -R '^native-nginx-fstack-serial-gr0$' --output-on-failure
```

The fixture prints `C39_EVIDENCE <path>/result.json`. Preserve that directory:
it contains the probe log, Nginx logs, both runtime logs/statistics and ordered
lifecycle evidence. The result records source and executable hashes, and the
installed native-Linux manifest when run using installed artifacts.

On the worker-lifetime repair, the build-tree run passed with 1,822 successful
requests and one 1.678-second outage. An independent installed-artifact run
passed with 1,859 successes and one 1.754-second outage, with both runtime
settlements reporting zero outstanding mbufs. These qualify this bounded
original `gr0` probe over the serial caller path, not the complete original
shell entrypoint or `graceful_reload=1`. The migration catalog remains
362 scenario-adapted, zero partial and one blocked entry.

## Bounded repeated serial cycles

The private `SerialGenerationController` accepts an explicit
`max_generations` between two and nine; its default remains two. Each advance
must refer to the current generation and consumes that generation's original
broker retirement and runtime settlement proofs exactly once. Old broker,
worker and launcher pidfds must all report death before the next launch.
Successor artifact directories are distinct (`new`, `new-2`, and so on), and
reaching the configured limit rejects further launches. Terminal companion
shutdown still cannot authorize a successor.

The real Nginx fixture accepts `--reloads 1..8`; the original `--source-gr0`
mode continues to require exactly one reload. The registered
`native-nginx-fstack-repeated-serial-cycle` test performs three HUPs through
four runtimes under the same Nginx master. Each cycle verifies HTTP service,
distinct worker PID and runtime nonce/epoch, inherited-descriptor isolation,
old runtime settlement before successor READY, rejection of consumed proofs,
and final zero-outstanding-buffer settlement. The configured generation cap
is also checked without launching another runtime.

```sh
ctest --test-dir build -R '^native-nginx-fstack-repeated-serial-cycle$' --output-on-failure
```

This extends the serial lifetime adapter only. It does not qualify upstream
`rv9`: that case requires the production `graceful_reload=1` FSM, its original
counters, continuous fresh traffic and resource-trend gates over the original
round count. Serial runtime replacement still has an outage and does not
preserve active TCP streams across kernel-instance retirement. The complete
shell entrypoint therefore remains blocked.

## Real Nginx candidate admission leaf

The pinned owner-activation module accepts an explicit private
`KER_NGINX_CANDIDATE_SLOT_FD` for one delegated staged slot-1 capability. The
validated one-worker IPv4/TCP Nginx child claims that slot after authenticated
FF-owner preflight. After normal runtime initialization, it attaches the
broker admission channel on its event-loop thread and prepares the candidate
socket before Nginx's unchanged socket/bind/listen sequence. The broker still
requires a READY admission task, registers the exact listener before listen,
and leaves selector zero unchanged. Nginx receives no coordinator plan or
selector authority. Its listener tuple and backlog must match the delegated
plan, and a wrong capability fails before socket activity.

The original Nginx shared-state allocator initializes the inherited reload
block. The private admission window compiles the pinned original
`ff_flow_map.c` in a separate namespace and owns a separate configuration
object. It does not change Nginx's `graceful_reload=0` configuration or bypass
the original master's configuration-consistency check. Original flow-map
admit/revoke callbacks are pumped by the existing authenticated owner loop;
original Linux remains the TCP and SYN-ACK authority. This does not register
Nginx's generation packet dispatcher or start its graceful-reload FSM.

`native-nginx-candidate-admission-tap` verifies a real SDK initial owner and
a real pinned Nginx candidate in the same original-Linux broker. A live
ordinary descriptor is rejected as a slot capability; an early candidate
publication remains rejected and the valid slot can still be used. After
candidate publication, fresh traffic still reaches the initial owner until
the separate coordinator selects member one. Nginx then serves an exact HTTP
response through a recorded original-map admission, while a TCP connection
established with the initial SDK owner before selection continues exchanging
bytes. Nginx shutdown must remove the candidate listener, restore selector
zero through the coordinator, and leave zero outstanding worker buffers.
The test writes hashes, ordered events, native statistics and logs to
`nginx-candidate-evidence.json` in the build directory.

This leaf is one-shot. Candidate HUP/respawn, USR2 qualification, repeated
candidate slots, same-master old/new Nginx orchestration and production FSM
integration remain unsupported. The complete source shell entrypoint and
its `rt01`/`rt02`/`rv9`/fault matrix remain blocked.


### Real old/new Nginx overlap qualification

The candidate leaf now has a separate two-real-Nginx qualification:
`native-nginx-overlapping-owner-cutover-tap`. It exercises the existing C28
queued-SYN transaction, preserves an old established HTTP connection, retires
the dead old owner's listener pin through a pidfd-gated typed API, and proves
new HTTP after old LISTEN=0. See the [runtime profile and exact limits](fstack-nginx-runtime.md#two-real-nginx-owners-and-a-committed-cutover).
This advances the overlap prerequisite; the original shell entrypoint remains
blocked and the source matrix is not counted as migrated.


### Original source stream probe over explicit overlap

`native-nginx-overlap-source-streams-tap` runs the unchanged original twelve
stream probe and summary oracle over the two real Nginx callers. It retains
the source 8 MiB/120-second shape and requires each worker's response to span
the real cutover, followed by later waves after old-owner exit. A mark-scoped
old-owner ESTABLISHED census anchors the handoff, and old LISTEN=0 plus new HTTP
anchor retirement. See [configuration, evidence and limits](fstack-nginx-runtime.md#original-twelve-stream-probe-across-real-nginx-overlap).
This adds source traffic qualification but does not execute the original
shell's generation FSM or its signal/transition assertions; the source matrix
and migration inventory entry remain blocked.


### Real Nginx abort continuity

The two real Nginx profile now covers explicit C28 ABORT with a retained SYN:
`native-nginx-overlap-abort-tap` requires the queued connection to reach old
Nginx, then proves existing and fresh old-owner HTTP after the candidate's
confirmed exit and LISTEN=0. Its companion
`native-nginx-overlap-abort-source-streams-tap` runs the unchanged source
stream probe and summary oracle across the abort and candidate retirement.
See [abort scope and reproduction](fstack-nginx-runtime.md#queued-syn-abort-with-real-nginx-owners).
This qualifies the abort prerequisite before the selector changes. It does not execute
the original FSM's failure policy or certify post-commit rollback, repeated
attempts or the complete shell matrix; the migration entry remains blocked.


### Original keepalive probe over explicit overlap

The real old/new Nginx profile now consumes the unchanged 180-second original
LC probe and summary oracle in both commit and abort modes. It preserves the
source progress anchor, the perf oracle's bounded closure rule for handover,
and the stricter zero-failure/reconnect rule for abort. This workload also
exposed the single-packet admission queue limit and interrupted identity checks;
the host adapters now retain a bounded notification FIFO and an unverified
received record until identity validation finishes. See [LC scope and runtime
qualification](fstack-nginx-runtime.md#original-keepalive-probe-through-commit-and-abort).
The original same-master FSM, performance comparison and complete shell matrix
remain unqualified; inventory remains 362 scenario-adapted, 0 partial, 1 blocked.

### Original rt24 LC traffic over acknowledged abort recovery

`native-nginx-abort-retry-source-lc-tap` now runs the original rt24 30-second LC
probe through the native abort/retry adapter. It preserves 12 connections,
0.1-second requests, 0.5-second fresh connects, two-second timeout, the observed
three-second progress anchor and at least five seconds of zero-failure source
progress after abort before replacement startup. The original perf summary
oracle accepts the bounded old-connection closures after successful retry.

This is source traffic qualification over three explicit Nginx callers, not a
completed `case_rt24`: its original `flip_fail_once` fault, same-master two-HUP
sequence and original FSM completion/drain assertions are not claimed. See
[evidence and exact limits](fstack-nginx-runtime.md#original-rt24-traffic-probe-across-abort-and-retry).

### READY candidate death is not an acknowledged abort

Native pinned-Nginx profiles now distinguish worker death before cutover from
worker death after a SYN is frozen. The first preserves fresh old-owner HTTP;
the second must reach kernel-confirmed QUARANTINED with zero accepted packets,
reject retry and retain the fail-closed ingress gate. An asynchronous COMMIT
request may have returned success before that terminal failure. Existing old
keepalive remains usable, but this is not fresh-service recovery. See
[the death profiles and exact limits](fstack-nginx-runtime.md#ready-does-not-survive-candidate-worker-death).
These are native fault qualifications, not completion of an original source
case. Quarantined-cutover recovery and the same-master original generation FSM
remain gaps; the source entrypoint remains blocked.

### Pre-BEGIN missing-READY recovery

The native caller can now explicitly abandon a live published candidate before
any cutover begins, wait for its actual map-close ACK, and obtain a fresh plan
preserving the original listener. The unready owner and all its listener aliases
must disappear before another candidate slot is delegated. Two real-Nginx tests
suppress the test module's READY message, observe a one-second caller timeout and
complete a later queued-SYN cutover. See
[the abandon API and boundaries](fstack-nginx-runtime.md#abandon-an-unready-candidate-before-ingress-freeze).
This is caller recovery before ingress freeze, not original `ready_never` fault
or same-master FSM integration. Dead candidates and quarantined cutovers remain
outside this recovery contract; inventory remains 362 adapted, 0 partial, 1 blocked.

### Pre-BEGIN published-candidate death recovery

A separate typed recovery API now preserves the original live owner/listener
after a published, never-selected candidate dies before BEGIN. Recovery waits
for exact pidfd death, joined task release and complete owner socket/alias/pin
closure, then compare-and-clears only the dead admission mark/lease. A fresh
plan can delegate a replacement candidate and complete a queued-SYN cutover.
Published cookie/claim metadata survives death cleanup. Real-Nginx plain/alias
profiles and a selection-history rejection profile qualify this path; see
[proofs and limits](fstack-nginx-runtime.md#recover-a-dead-never-selected-candidate-before-begin).
This does not recover started/quarantined ingress transactions or candidates
that had been selected, and it does not implement the original master FSM.
The source shell entrypoint remains blocked; migration counts are unchanged.
