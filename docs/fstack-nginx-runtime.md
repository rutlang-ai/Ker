# Bounded FF-enabled Nginx runtime profile

The opt-in `ker-fstack-nginx-runtime` DSO provides a caller runtime for the
pinned F-Stack Nginx module at commit
[`646a641cfff77f4815e1e29829a09e1ed15a2999`](https://github.com/F-Stack/f-stack/tree/646a641cfff77f4815e1e29829a09e1ed15a2999).
The Nginx subtree is `2cd18ae3bcc055a9d7bfb9c492297ec2f6ae3916`; the tested
1.28.0 executable SHA-256 is
`d8910d7ad11e9ae93766abbf01a01f19bedbfaac4e077839c66bd938999b9f7d`. It was
built unchanged with `--with-ff_module --with-debug
--without-http_rewrite_module --without-http_gzip_module`, linked to this
runtime DSO and exported its original Nginx boundary symbols with `-Wl,-E`.
It uses the unchanged imported `ff_reload.c` for the real detached reload-state
helpers and the `ker::fstack-socket-bridge` leaf calls for TCP sockets in the
original Linux kernel owned by the broker. Its strict profile parser uses the
existing `ker-ini` adapter over the unchanged imported inih parser, and the
runtime install component includes that target artifact and its provenance.
An optional worker-ownership shim is compiled only against the same pinned
Nginx source headers and generated configuration as the executable. Its
installed build manifest records the executable hash/build ID and generated
configuration hashes.
It does not initialize EAL or a second Linux kernel. Build it with
`KER_BUILD_FSTACK_NGINX_RUNTIME=ON`; set
`KER_FSTACK_NGINX_BINARY` to an unchanged `--with-ff_module` Nginx executable
to register the one-worker lifecycle CTest. To build the two-worker shim, also
set `KER_FSTACK_NGINX_SOURCE_ROOT` to the clean pinned F-Stack checkout and
`KER_FSTACK_NGINX_BUILD_DIR` to that executable's `objs` directory. Configuration
fails if the source revision, source-header cleanliness, generated headers, or
binary hash differ from the validated artifact. This opt-in adds separate
two-worker positive and unsupported-listener-option negative CTests.

To reproduce the linked Nginx build, first configure Ker with the matching
native Linux manifest and DPDK installation, then build the runtime target. Put
the unchanged imported FF headers and resulting DSO in an `FF_PATH` prefix as
shown; `PKG_CONFIG_PATH` must point to the same DPDK installation used by Ker.

```sh
cmake -S "$KER_SOURCE" -B "$KER_BUILD" \
  -DKER_WITH_NATIVE_TCP=ON \
  -DKER_NATIVE_LINUX_BUILD="$KER_NATIVE_LINUX_BUILD" \
  -DKER_BUILD_FSTACK_NGINX_RUNTIME=ON
cmake --build "$KER_BUILD" --target ker-fstack-nginx-runtime
cmake --install "$KER_BUILD" --component fstack-nginx-runtime --prefix "$KER_INSTALL"

mkdir -p "$FF_PREFIX/lib"
ln -s "$KER_SOURCE/third_party/fstack-address-policy/ff_api.h" "$FF_PREFIX/lib/ff_api.h"
ln -s "$KER_SOURCE/third_party/fstack-address-policy/ff_event.h" "$FF_PREFIX/lib/ff_event.h"
ln -s "$KER_SOURCE/third_party/fstack-address-policy/ff_errno.h" "$FF_PREFIX/lib/ff_errno.h"
ln -s "$KER_SOURCE/third_party/fstack-flow-map/ff_flow_map.h" "$FF_PREFIX/lib/ff_flow_map.h"
ln -s "$KER_SOURCE/third_party/fstack-ipc/ff_reload.h" "$FF_PREFIX/lib/ff_reload.h"
ln -s "$KER_SOURCE/third_party/fstack-ipc/ff_msg.h" "$FF_PREFIX/lib/ff_msg.h"
ln -s "$KER_SOURCE/third_party/fstack-reload/ff_config.h" "$FF_PREFIX/lib/ff_config.h"
ln -s "$KER_SOURCE/third_party/fstack-reload/ff_log.h" "$FF_PREFIX/lib/ff_log.h"
ln -s "$KER_BUILD/libfstack.so" "$FF_PREFIX/lib/libfstack.so"

cd "$PINNED_FSTACK_SOURCE/app/nginx-1.28.0"
FF_PATH="$FF_PREFIX" PKG_CONFIG_PATH="$DPDK_PKGCONFIG" ./configure \
  --with-ff_module --with-debug --without-http_rewrite_module \
  --without-http_gzip_module --prefix="$NGINX_PREFIX" \
  --with-ld-opt="-L$KER_BUILD -Wl,-rpath,$KER_BUILD"
make -j"$JOBS"
```

Run the broker under `ker-run`; only that process starts the original Linux
kernel. Nginx is a client-only frontend and does not load `libker-posix.so`.
For the FF profile, set `KER_SOCKET_BROKER_PATH` to the broker's Unix endpoint
and preload the runtime before the POSIX socket adapter, using installed paths:

```sh
KER_SOCKET_BROKER_PATH="$BROKER_SOCKET" \
LD_PRELOAD="$KER_INSTALL/lib64/libfstack.so:$KER_INSTALL/lib64/libker-socket-preload.so" \
  "$NGINX_PREFIX/sbin/nginx" -p "$NGINX_PREFIX/" -c "$NGINX_CONFIG"
```

For the validated two-worker profile, the config must use `worker_processes 2`
and the installed shim must be loaded before the runtime and POSIX adapter:

```sh
KER_SOCKET_BROKER_PATH="$BROKER_SOCKET" \
LD_PRELOAD="$KER_INSTALL/lib64/libker-fstack-nginx-worker-shim.so:$KER_INSTALL/lib64/libfstack.so:$KER_INSTALL/lib64/libker-socket-preload.so" \
  "$NGINX_PREFIX/sbin/nginx" -p "$NGINX_PREFIX/" -c "$NGINX_CONFIG"
```

Use this shim only with the exact Nginx binary and generated configuration
recorded in `share/ker/fstack-nginx-runtime/nginx-worker-shim-build.json`.

The supported profile accepts only `[ker_socket_broker] version=1` with a
broker `path` equal to `KER_SOCKET_BROKER_PATH`, and `[dpdk] graceful_reload=0`.
It rejects `FF_FAULT`, unsupported configuration keys, unreachable brokers,
and nonzero process IDs unless the build-matched two-worker shim validates the
secondary role and listener ownership. That validation handshake is cooperative
same-process DSO coordination, not a security boundary. Nginx's `ff_global_cfg` retains its
configuration filename after the caller frees its argument strings. Reload
state remains genuinely detached and inactive; no synthetic generation block
is installed. The FF `ff_socket_drain_count` hook counts registered application
descriptor aliases by querying original Linux `SO_DOMAIN` and `SO_ACCEPTCONN`
through their broker capabilities; live listeners are excluded. It returns a
count only when every registered descriptor query succeeds, and aborts with an
errno diagnostic on failure because the FF hook has no error result channel.
This bounded adapter census covers registered INET/INET6 descriptors, including
inherited broker UDP capabilities, while host sockets and private broker
metadata are excluded. The public FF/POSIX socket-creation adapters still reject
UDP; this does not claim complete equivalence with the pinned F-Stack process
fd-table census. The pinned [`ff_socket_drain_count`](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/freebsd/kern/uipc_syscalls.c#L185)
walks the whole process fd table, counts each IPv4/IPv6 socket alias including
UDP, and excludes sockets whose live `SO_ACCEPTCONN` is set. Ker's adapter only
counts authenticated broker capabilities registered in this process; direct
FF/POSIX UDP creation and raw, unregistered fd bypasses remain unsupported.
Reload state remains unsupported. `ff_syncache_count()` now queries the
authenticated process owner's original-Linux request sockets through bounded
sequential IPv4/IPv6 INET_DIAG dumps. It is a non-atomic request_sock profile,
not a complete F-Stack syncache equivalence: full `SYN_RECV` sockets and
stateless syncookies are excluded. Flow-map, dispatcher, and generation FSM
hooks still abort with an explicit diagnostic if reached. The runtime supplies
a bounded `ff_socket_snd_pending` adapter for ordinary ready-copy TCP sockets created
through its authenticated per-process FF owner context. The broker binds a
unique owner mark to the caller's authenticated PID, process start time, and
pidfd; duplicated sockets retain that owner and accepted sockets inherit it.
The owner record survives session close and `exec` while that process remains
alive, so reinitialization cannot rotate the mark and forget descriptorless
queues. Owner initialization refuses any earlier generic/unowned network
socket history; later generic, inherited, or foreign broker sockets make the
pending query fail closed, even after their descriptors close. Failures abort
with an errno diagnostic because the upstream hook has no error result
channel. Successful byte counts are clamped to the upstream `int` range. This
reports the C9 original-Linux ready-copy payload snapshot; sendfile is outside
the profile, and the hook does not enable graceful promotion. See the
[remaining graceful-reload limits](fstack-graceful-reload-gap.md).

The C16 native fixture qualifies a private opt-in admission attachment for one
IPv4 listener and one authenticated FF owner. The owner attaches before creating
any broker-owned socket; the broker derives the mark from its authenticated
owner record, arms the original-Linux queue before allowing `listen`, and runs
the admission deadline independently of the FF owner loop. The FF fixture pumps
the unchanged imported flow-map operations on its own event-loop thread. Tests
cover real TAP SYN/SYN-ACK ordering, map-full rejection and request revocation,
owner stalls while unrelated broker RPC continues, duplicate SYNs, endpoint
authentication, and owner/listener teardown. Failures quarantine the opt-in
owner and remain fail-closed; this does not qualify healthy recovery.

This is a private fixture boundary, not a production Nginx generation binding.
It does not add an Nginx dispatcher or FSM callback, enable public
`graceful_reload=1`, or implement packet dispatch. The runtime DSO now links
the unchanged upstream `ff_flow_map.c`, so its map lifecycle and lookup/admit
symbols resolve in the same DSO as the original reload context and
`ff_global_cfg`. The table remains process-local and single-threaded by the
upstream contract. It is active only when the caller attaches a valid original
reload block and enables graceful reload; the supported Nginx runtime profile
still sets graceful reload to zero and leaves reload state detached. The
original dispatcher registration hooks remain fail-closed. The DSO map test
and C16 app do not compile duplicate map, reload, or configuration definitions
into the executable; they verify the actual DSO symbol ownership.

The default Nginx runtime remains detached and graceful reload remains
unsupported.
The C16 test-only pump-failure and received-FD trace hooks are compiled only
with `BUILD_TESTING`; they are absent from tests-off installs. When the optional
product runtime is disabled, native testing builds an uninstalled fallback DSO
from the same runtime sources and shared CMake helper; the installed
product runtime remains opt-in. The six C16 tests run with either runtime
target, including `BUILD_TESTING=ON` plus the default runtime option `OFF`.
Run the fixture set with `ctest -R '^native-c16-'`; it includes
`native-c16-broker-owner-admission-tap`, `native-c16-owner-pump-failure`,
`native-c16-owner-auth-negative`, `native-c16-owner-hello-fd-negative`,
`native-c16-owner-death-cleanup`, and `native-c16-listener-close-cleanup`.

The C17 private window-cycle fixture retires the marked queue while retaining
the same live listener, closes the imported flow map only after the old queue
drains, serves an outside-window connection through the original map's
allow-without-record behavior, and rearms with a fresh queue lease. It verifies
three real admission windows and two retirement/rearm transitions. This is
limited to the guarded UP/PREEMPT_NONE/TINY_RCU IPv4 profile and does not prove
production Nginx generation binding, generic queue quiescence, or healthy
recovery after an uncertain verdict. Public `graceful_reload=1` remains
unsupported.

The serialization guard is tied to the configured native artifact, not a
general Linux claim: manifest fingerprint
`399c02b3aa05a7ee2a35c13fca64a279198c0d0675a8dc218eddc07399525b8d` has
`CONFIG_SMP` unset, `CONFIG_PREEMPT_NONE=y`, and `CONFIG_TINY_RCU=y`. In that
profile the LKL syscall owns its single CPU while the synchronous IPv4
`LOCAL_OUT` hook runs through `nf_hook_slow`, `nf_queue`, and the NFQUEUE
enqueue callback; the queue copy uses atomic allocation and nonblocking
netlink delivery. Returning from the mark-disable ioctl therefore serializes
after any hook already running on that LKL CPU. C17 then consumes deferred and
queued notifications before it asks the FF owner thread to close the map. The
source audit is against the pinned original tree at
`/dev/shm/ker-c15-native-full/source-399c02b3aa05a7ee`: `arch/lkl/kernel/syscalls.c`
holds the LKL CPU from syscall entry through interrupt processing before
`lkl_cpu_put()`, implemented in `arch/lkl/kernel/cpu.c`; the IPv4 `LOCAL_OUT`
hook runs through `net/ipv4` and `net/netfilter/core.c`, `net/netfilter/nf_queue.c`,
and `net/netfilter/nfnetlink_queue.c`. A different scheduling/RCU profile is
rejected at configure time. This proof does not establish a generic network
quiescence barrier for another kernel build.

`native-c17-retire-pending-cancellation` requests retirement while a real SYN's
PREPARED reply is pending. A test-only nonblocking delay keeps the owner
response pending while the outer event loop acknowledges RETIRE_BEGIN. After
the packet decision deadline, the broker revokes the exact request, completes
the known-unsent cancellation, and only then invokes the map-close callback;
that callback verifies the map is still active with one insertion and one
revoke and that the key is absent. DROP acknowledgement has a separate bounded
cleanup deadline. The delayed-response hook exists only in testing builds.

The bounded FF socket bridge implements `ff_dup` for registered application
INET/INET6 sockets by dispatching to the namespaced preload `F_DUPFD` path. It
preserves the shared original-Linux open-file description, returns a descriptor
with `FD_CLOEXEC` clear, and retains the broker descriptor's lowest available
host slot when it already satisfies the requested minimum. `F_DUPFD` relocates
only when its minimum requires it; `F_DUPFD_CLOEXEC` keeps close-on-exec in both
paths. This is scoped to the adapter's registered descriptors and Linux host
descriptor table; it does not claim equivalence with F-Stack's process-wide
descriptor numbering because Ker's host and private broker descriptors share
that table. `ff_dup2` remains unsupported. The pinned
[`ff_dup`](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_syscall_wrapper.c#L2167-L2189)
delegates to `sys_dup` for F-Stack descriptors.

The lifecycle profile supports its existing one-worker control and an opt-in
two-worker TCP `reuseport` profile. In this pinned FF-enabled caller, unchanged
worker startup opens every `reuseport` clone in each worker, while the event
initializer registers only the clone assigned to that worker. The exact-build
shim validates the executable build ID and Nginx module ABI before reading
Nginx globals, then validates both listener clones and all FD-affecting options
before runtime preflight. After broker/config/descriptor-offset preflight
succeeds, it marks only the unowned clone ignored and clears its `listen` flag
before the original open/configure loops. Unsupported listener options or
unexpected live descriptors fail before any listener mutation. One-worker
mode makes no listener changes. This bounded profile does not cover arbitrary
listener layouts, UDP/QUIC, or general F-Stack graceful reload.

The Nginx-specific adapter restores the original executable's FF descriptor
offset only for descriptors selected by Nginx's exported classifier. It sends
both host and FF epoll registrations through the composite preload adapter.
This pinned FF build selects kqueue event constants ahead of the Linux epoll
constants; the adapter fault-safely copies the event and maps `EV_CLEAR` (`0x20`)
to Linux `EPOLLET`, preserving the event data and other flags. Nginx's real
`timer_resolution 1ms` signal path services host control events; the adapter
does not synthesize readiness or shorten arbitrary waits.

The opt-in lifecycle tests run the unchanged `--with-ff_module` Nginx binary over the
TAP-backed original Linux TCP runtime. It sends twelve concurrent 8 MiB static
responses and verifies each length and SHA-256 while exercising Nginx HUP,
USR2, WINCH, idle control handling, replacement workers, a fresh request after
each transition, and socket/pool cleanup. `sendfile` is off in this caller
profile. After each transition, the test retries a fresh service-readiness
probe for at most 30 seconds and reports the number of connection/readiness
retries; it does not treat a refused probe as successful fresh-traffic
continuity. The twelve active streams still require exact complete bodies and
hashes. The trace names actual FF leaf invocations and the epoll adapter;
initialization records broker reachability probe start, success, or failure
with preserved errno, and records the reported descriptor limit and Nginx
offset so a worker-start failure is attributable. Original Linux TCP and DPDK
counters remain separately reported authorities.

The two-worker run proves both original and replacement worker PIDs serve
requests across HUP, USR2, and WINCH; a separate negative run sets `rcvbuf` and
requires the shim to reject the configuration before runtime commit or socket
creation. The source/build manifest is installed with the shim. The worker
ownership shim is only a build-specific adapter for the pinned executable.

This qualifies bounded one- and two-worker, `graceful_reload=0` Nginx caller
paths. It does not qualify the F-Stack generation-reload state machine, UDP,
fault injection, the original shell matrix, or shell cleanup oracle. Those requirements remain in
[`fstack-graceful-reload-gap.md`](fstack-graceful-reload-gap.md).

The C22 owner-activation module adds one narrower opt-in profile for a single
IPv4 TCP `reuseport` listener and exactly one worker. The master validates the
pinned runtime configuration and reserves a staged plan plus slot zero before
fork. The child inherits only that slot, closes its plan and master RPC copies,
then the existing F-Stack shim claims and activates the unbound member after
the authenticated owner starts and before Nginx's original socket/bind/listen
sequence. Ker does not replace those Nginx or Linux calls. The broker validates
the exact address, socket cookie, mark, role, and listen backlog; it allows the
pinned caller's second same-backlog `listen()` invocation without changing the
published selector.

Both initial and HUP cycles require the Nginx dynamic module to be loaded. The
module verifies the running executable's GNU build ID before reading any
build-specific Nginx structure. It parses the bounded path from the actual
`fstack_conf` directive and requires `KER_FSTACK_NGINX_INI` to name that same
`graceful_reload=0` file. `nginx -t` validates the profile but creates no
broker plan; `nginx -s reload` follows the original signaller path without
creating broker state. Unsupported listener layouts/options fail closed. Negative tests
cover the wrong worker count, extra or missing listeners, IPv6, forbidden
listener options, `graceful_reload=1`, a mismatched INI environment path, and a
missing worker shim; they require rejection before plan creation and TCP
socket opens. The C22 TAP test proves
HTTP before and after the pinned legacy HUP path, authenticates the old worker's
exit through the broker's pidfd-gated admin receipt, and waits for a mark-scoped
census to show `LISTEN=0` and no queued payload before reserving a new mark.
Original-Linux TIME_WAIT rows may remain and are not forcibly cleared. The test
also repeats HUP, checks the master's socket descriptor count does not grow,
proves each cycle receives a distinct listener cookie, and waits for each
mark-scoped census to reach `LISTEN=0` at cleanup.

The pinned shim also recognizes only the reaped worker-respawn `fork()` callsite
in the exact Nginx ELF build. It drains the dead worker's mark, releases the old
plan/slot, and creates a fresh slot before the original fork; the child then
uses the same authenticated prepare path. The TAP test kills the serving worker
twice with `SIGKILL`, verifies a new listener cookie and original-Linux HTTP
service each time, and checks every respawn mark reaches `LISTEN=0` at shutdown.
The old census capability is retained if a bounded drain attempt times out, but
the shim refuses that fork rather than reuse a stale claim. A later explicit
cycle attempt can retry the retained census. Automatic retry after a failed
respawn attempt and recovery when the worker dies before publishing its
listener are not claimed.

This Nginx HUP path intentionally has an outage while the old worker exits and
the new cycle starts. It does not claim active-stream preservation, does not
override Nginx signal handling, and does not qualify `graceful_reload=1` or a
second worker. Build and install the module only with the same clean pinned
source, generated configuration, and executable inputs required by the worker
shim; the installed `nginx-owner-activation-build.json` records that boundary.
Run `ctest -R 'native-nginx-fstack-owner-activation|fstack-nginx-worker-shim-build-id-boundary'`
for the positive TAP cycle, unsupported-profile matrix, and wrong-main-build-ID
guard.

An explicit private `KER_NGINX_CANDIDATE_SLOT_FD` profile now binds a delegated
slot-1 listener to a real Nginx worker and the existing broker admission
channel. It retains `graceful_reload=0`, uses a separately namespaced original
flow map for that private admission window, and gives Nginx no coordinator
plan or selector authority. Run `native-nginx-candidate-admission-tap` for the
invalid-capability boundary, candidate HTTP after selection, surviving old
SDK TCP stream and cleanup qualification. This is a one-shot candidate leaf;
candidate HUP, respawn, USR2 and the complete generation FSM remain outside
the profile. See [qualification details](fstack-graceful-reload-gap.md#real-nginx-candidate-admission-leaf).


### Two real Nginx owners and a committed cutover

`native-nginx-overlapping-owner-cutover-tap` replaces the old SDK actor with
another unchanged pinned Nginx executable. A test-only coordinator reserves
one staged group and delegates slot zero through `KER_NGINX_INITIAL_SLOT_FD`
and slot one through `KER_NGINX_CANDIDATE_SLOT_FD`. Each Nginx master forks one
broker-authenticated worker; neither receives the plan or selector authority.
Both use the existing restricted IPv4/reuseport, `graceful_reload=0` profile.
Delegated initial and candidate masters reject HUP and worker respawn; this
one-shot overlap profile does not change the existing serial-cycle path.

The coordinator begins the existing broker cutover, waits for PREPARED, and
observes a real host SYN retained before requesting commit. The original Linux
stack accepts that connection on the new Nginx after COMMITTED. A previously
established keepalive connection still returns the old Nginx body. Response
length, MD5 and requested EOF are checked by the unchanged upstream
`reload_probes/http_probe.py` response helper; this is not the complete shell
matrix or its stream-duration oracle.

After graceful exit and pidfd-confirmed death of the old worker, the new typed
`ker_socket_client_owner_group_retire_initial_listener` operation releases only
the initial listener pin. It requires a CONTROL plan, a settled committed
cutover to member one, no remaining initial application listener aliases,
exact owner identities and validated original-Linux listener cookies/marks.
Premature calls return EAGAIN; a slot capability is rejected, and successful
retirement is idempotent. Linux compacts the surviving reuseport member to
physical index zero, and the adapter reattaches the existing native selector
accordingly. A selector-attachment failure marks the group failed and poisons
the remaining listener instead of reporting success. Accepted TCP sockets and
protocol state remain under original Linux ownership; listener retirement does
not certify that all accepted sockets have drained.

The test requires old LISTEN=0 before fresh new-owner HTTP, then new LISTEN=0
and broker outstanding=0 at shutdown. The build directory's
`nginx-overlap-evidence.json` records both Nginx logs, runtime traces and events.
The full same-master F-Stack generation FSM, repeated overlap,
failure/rollback matrix and shell cleanup contract remain unqualified.
A separate original twelve-stream qualification is described below. Migration inventory remains 362 scenario-adapted,0 partial,1
blocked (`test_graceful_reload.sh::entrypoint`).

### Original twelve-stream probe across real Nginx overlap

`native-nginx-overlap-source-streams-tap` adds the unchanged imported
`m4_stream.py`/`http_probe.py` process and `reload_checks.py` stream oracle to
the two-real-Nginx profile. Both static roots contain the original shell's
8 MiB zero payload. The host client uses twelve streams, 16384-byte chunks,
0.1-second gaps, a five-second socket timeout, a three-second stall threshold
and a 120-second duration. It completes the wave in flight at that duration,
within the original 300-second probe budget. The only network adaptation is
the existing TAP destination and port 4108. No FF runtime is preloaded into
the host probe.

Before handoff, the profile preserves the source shell's three-second delay
and additionally requires the old member's original-Linux census to contain
at least thirteen ESTABLISHED sockets: twelve probe streams and the separately
held keepalive connection. It verifies that census again before asking old
Nginx to quit. The existing cutover retains a real SYN and commits it to the
new Nginx while every probe worker's first response remains in flight. Old
Nginx handles SIGQUIT through its original graceful shutdown path while those
responses drain; the probe must still be alive after the authenticated old
worker exits. Old LISTEN=0 and a fresh new-owner HTTP response are required
before the profile waits for the remaining source waves.

Success requires the unchanged probe exit status and stream-summary oracle,
exact 8 MiB bodies, all twelve worker IDs spanning cutover in flight, and later
waves from every worker completing after old-owner exit. Each completed
response must retain MD5 and clean EOF; the source stall threshold is not
relaxed. The JSON evidence records the actual probe command, source SHA-256
values, complete stream output, monotonic transition events, both Nginx logs
and broker cleanup counters. Run the long case separately from the quick
checks; CTest allows 360 seconds for startup, the bounded source probe and
cleanup:

```sh
ctest --test-dir <build> -R '^native-nginx-overlap-source-streams-tap$' --output-on-failure
```

This qualifies the original traffic probe over an explicit two-master broker
cutover. It does not run the source shell's same-master HUP/USR2 generation FSM,
its transition-log assertions, repeated reloads or fault matrix. The source
`rt02`/`rt23` cases and the complete shell entrypoint therefore remain blocked;
the migration inventory remains 362 scenario-adapted, 0 partial, 1 blocked.


The recorded Debug run completed 36 responses (288 MiB) across three waves in
about 155.5 seconds. All 36 MD5 and EOF counters passed, the source reported zero
stalls and zero worker errors, and old Nginx drained for 47.917 seconds after
SIGQUIT. The original-Linux broker reported outstanding=0 and worker_exit_code=0
at final cleanup. A separate negative control changed only one byte of the new
Nginx's payload; the unchanged source probe rejected the resulting responses.

### Queued-SYN abort with real Nginx owners

`native-nginx-overlap-abort-tap` exercises the other decision of the existing
C28 transaction with both unchanged pinned Nginx callers. It waits for a real
SYN to be retained in PREPARED, proves the host connection has not completed,
requests ABORT and waits for ABORTED. The ingress freeze precedes socket and
flow-map admission; the retained SYN must be replayed to the old selector.
The queued connection must return the old Nginx's distinct body with the
unchanged original HTTP helper's length, MD5 and EOF checks. This path does
not expect the candidate's flow map to admit the frozen SYN.

The candidate then quits through original Nginx SIGQUIT handling. Its exact
worker pidfd must report death and its mark-scoped LISTEN census must reach
zero. The old worker must remain alive, its established keepalive must still
return the old body, and fresh HTTP must still reach that same old service.
Premature initial-listener retirement remains rejected after abort and after
candidate exit. At final shutdown the controller releases its plan/slot/group
and terminal transaction handles; the independent old census must then show
LISTEN=0 before broker shutdown and outstanding=0.

`native-nginx-overlap-abort-source-streams-tap` adds the same unchanged
12-stream, 8 MiB, 120-second source probe and original summary oracle used by
the commit qualification. Every source worker must have a response in flight
across PREPARED and must complete later waves after the candidate has exited.
The probe must still be alive after candidate retirement. All old-owner HTTP
checks, twelve-worker census, exact bodies, MD5/EOF, stall limits and final
cleanup remain required. It uses the production activation module; the alias
regression module is not involved. JSON evidence records outcome=abort and the
candidate retirement separately from old-owner shutdown.

Run the quick abort boundary or the full long-stream qualification separately:

```sh
ctest --test-dir <build> -R '^native-nginx-overlap-abort-tap$' --output-on-failure
ctest --test-dir <build> -R '^native-nginx-overlap-abort-source-streams-tap$' --output-on-failure
```

This is one explicit abort before the selector changes. It does not qualify
rollback after a committed handover, retrying this single-attempt group, the
same-master generation FSM, fault-injection builds or the original shell
matrix. Those remain open, and the source inventory stays at 362
scenario-adapted, 0 partial, 1 blocked.


The recorded abort/source run completed 36 correct responses (288 MiB), with
all 12 workers active and complete, zero integrity failures, zero stalls and
zero worker errors; broker outstanding was zero. A wrong-decision negative
control replaced only the coordinator's ABORT request with COMMIT. The queued
HTTP response then came from the candidate, and the unchanged response helper
rejected its digest because the abort profile requires the old owner's body.
The mutation was restored before the normal regression suite.


### Admission channel interruptions

A real commit/source-stream regression exposed an additional runtime fault:
the candidate worker aborted when its owner pump returned -EINTR. This caused
all twelve second-wave clients to fail after the first wave had completed.
The failed trace is retained separately from successful qualification.

The Ker admission channel now treats EINTR from nonblocking sendmsg/recvmsg
before any record transfer as retryable -EAGAIN. The caller yields to its next
bounded step, preserving the original command ID, pending response and
deadline. No record is resent after successful transfer, authentication still
runs on received records, and other errors retain their existing fail-closed
handling. Nginx signal handling, timers and all upstream sources are unchanged.

`admission-channel-eintr` injects EINTR at eleven syscall sites in the exact
channel source, including empty receive, command send, request receive,
result/PREPARED response send, controller receive, FINALIZE receive and
cancellation reply. Uninterrupted operations use real credential-checked
SOCK_SEQPACKET I/O. Its callbacks count effects rather
than implementing protocol behavior: two admits and one revoke occur exactly
once, and repeated interruptions yield once per step. The test fails at its
first owner receive without the fix. The existing original flow-map ownership
and original-LKL admission tests retain the independent runtime semantics
coverage.


With the channel fix, all eight focused native checks passed, including both
complete commit/source and abort/source runs. Each long profile completed 36
responses with zero integrity failures, stalls and worker errors, and both
brokers ended with outstanding=0. The deterministic channel test also passed
GCC and Clang with C11, -Wall -Wextra -Werror; the existing original-map channel
and original-LKL admission checks passed unchanged.
