# Native socket broker

The native socket broker lets a separate frontend process use selected
original-Linux sockets without loading `libker-posix`. The broker process runs
under `ker-run`, creates original-Linux sockets and epoll instances through the
usual POSIX calls, and adopts those descriptors with
`ker_socket_broker_server_adopt()`. It transfers returned capability FDs to
frontends over a host Unix socket using `SCM_RIGHTS`. A frontend links only
`ker::socket-client`; each explicit `ker_socket_client_*` call is one bounded
request to the broker.

The first API supports `AF_INET` and `AF_INET6` stream and datagram sockets,
plus epoll control and polling. Network sockets are nonblocking. The broker
always calls original Linux `epoll_wait()` with timeout zero, so callers decide
their own scheduling and retry policy. This API is a selected operation
surface; it does not interpose libc or turn the capability into a general
POSIX descriptor. A host transport failure after sending a request can leave
the original-Linux operation's completion unknown. The client never retries
requests automatically; a caller must reconcile that state before retrying a
mutating operation.

Socket-option RPCs accept only explicitly supported flat values. Both
`getsockopt` and `setsockopt` support `SOL_SOCKET` `SO_REUSEADDR`,
`SO_REUSEPORT`, `SO_KEEPALIVE`, `SO_RCVBUF`, `SO_SNDBUF`, `SO_RCVLOWAT`,
`SO_SNDLOWAT`, `SO_LINGER`, `SO_RCVTIMEO`, and `SO_SNDTIMEO`; get-only options
are `SO_TYPE`, `SO_ERROR`, `SO_DOMAIN`, `SO_PROTOCOL`, `SO_ACCEPTCONN`, and
`SO_COOKIE`. `SO_COOKIE` requires an exact `uint64_t` buffer and cannot be set.
Both directions also support `IPPROTO_TCP` `TCP_NODELAY`, `TCP_CORK`,
`TCP_DEFER_ACCEPT`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`,
`TCP_FASTOPEN`, and `IPPROTO_IPV6` `IPV6_V6ONLY`. Unknown options and options
whose values contain pointers or descriptor numbers (including packet-filter
programs and reuse-port BPF descriptors) return `EOPNOTSUPP` before original
Linux is called. The dedicated two-member reuseport group API below is the
only exception for classic reuseport cBPF: its server constructs the fixed
selector locally; callers cannot supply instructions, pointers, or native
descriptor values. For supported options, original Linux still validates the
value length and contents. `SO_LINGER` is restricted to disabled mode or
enabled mode with zero duration; enabled nonzero durations return
`EOPNOTSUPP` before changing original Linux state because the broker's final
descriptor close must not block its request loop.

## Capability and session lifetime

Place the broker's `SOCK_SEQPACKET` path in a directory inaccessible to
untrusted users. The broker creates the path with mode `0600`, accepts only its
effective UID, checks peer credentials and pidfd, and validates kernel-supplied
per-message credentials against the PID/UID/GID captured when the RPC session
connected. Requests have a versioned bounded header, monotonic sequence, exact
payload and rights counts. Invalid sessions are closed after all received
rights are closed.

Each socket or epoll capability is an opaque host pipe write end. The broker
retains the matching read end and records its device/inode identity. The
request must carry a write-only FIFO with that identity; numeric descriptor
values are never authority. Duplicating, transferring, or inheriting a
capability keeps the same broker object alive. When the final write reference
closes, the broker closes the adopted original-Linux descriptor. Bytes
accidentally written to the pipe are discarded; the pipe does not carry
network data. `shutdown()` on it returns `ENOTSOCK`.

The frontend client context is caller-serialized. After `fork()`, its next API
call closes the inherited RPC session and authenticates a fresh one for the
child. Capabilities can be inherited or passed to the replacement with normal
host FD operations. Host `dup(cap_fd)` adds a reference to the same
broker-owned descriptor. The explicit `ker_socket_client_dup()` operation
instead calls original Linux `F_DUPFD_CLOEXEC`, then returns a capability for
that distinct descriptor. The duplicate shares its open file description and
status flags while retaining original Linux's separate epoll registration key.
The returned host capability has `FD_CLOEXEC` cleared like POSIX `dup()`;
the broker's private native duplicate remains close-on-exec.

The descriptor SDK exposes `DESCRIBE` for socket/epoll kind and original
`F_GETFL` flags, `DUP`, and `GETFL`/restricted `SETFL`. `SETFL` requires
`O_NONBLOCK` to remain set and rejects changes to all other status flags.
`ioctl` is limited to enabling `FIONBIO` and reading `FIONREAD`; clearing
nonblocking mode and all other requests return `EOPNOTSUPP`. `SEND` accepts
only `MSG_DONTWAIT`, `MSG_MORE`, and `MSG_NOSIGNAL`; the broker always adds
`MSG_NOSIGNAL`. `RECV` accepts only `MSG_PEEK` and `MSG_DONTWAIT`. Other flags
are rejected before original Linux. Reads, writes, option values, and epoll
readiness continue to be supplied by original Linux.

## Fixed two-member IPv4 reuseport group

`ker_socket_client_reuseport_group_create()` asks the broker to create two
original-Linux IPv4 TCP listeners on one fixed, nonzero port. The broker sets
`SO_REUSEPORT`, binds and listens on member 0, attaches a locally constructed
single-instruction `BPF_RET | BPF_K` selector returning 0, and only then binds
and listens on member 1. This order prevents initial traffic from selecting a
listener that has not joined the group. `..._member(group, 0|1)` returns a
managed listener capability; `..._select(group, 0|1)` atomically replaces the
original-Linux group's selector. Invalid indices and unauthorized or
wrong-kind capabilities fail before selection changes.

The group capability reports kind `REUSEPORT_GROUP` and has control authority.
The pre-run server factory accepts an explicit rights mask so fixtures can
exercise a group capability without control rights. SDK `ker_socket_client_dup`
is unsupported for a group cap; ordinary host `dup`, `SCM_RIGHTS`, or inherited
FD references retain the same group capability. Create/member APIs return
`FD_CLOEXEC` capabilities by default; callers must explicitly clear the flag
or pass the descriptor when inheritance is intended. Managed member SDK duplicates
are distinct original-Linux descriptors and retain their group/member identity.
Managed members support accept, I/O, names, options reads, and readiness, but
cannot bind, connect, listen, shut down, or change socket options. Generic
broker socket binds cannot claim a port reserved by a live group, and generic
`SO_REUSEPORT` listeners cannot join one. Existing broker bindings prevent
group creation on their port.

The trusted broker caller must keep group membership exclusive: it must not
create native listeners outside this API on the reserved tuple or create
outside aliases that bind or mutate these listener descriptions. The broker
guards its own generic operations and known bindings, but cannot prevent
trusted code from bypassing it through direct original-Linux syscalls.

The server owns both base listener descriptors while any group capability or
managed member capability remains. Accepted sockets are independent and do
not extend group lifetime. After the final group/member reference closes, the
broker closes both listeners; an already accepted connection remains governed
by its separate original-Linux socket descriptor. This is a bounded broker
API for two-member IPv4 TCP selection, not arbitrary cBPF support or general
reuseport-group adoption.

## Staged owner-group publication

`ker_socket_client_owner_group_staged_plan()` creates a separate immutable
plan mode while preserving the atomic `owner_group_plan()`/`owner_group_publish()`
contract. After slot 0 is claimed by a fresh owner,
`owner_group_publish_initial()` creates a real original-Linux listener and a
selector fixed to member 0. It can serve traffic before a slot-1 owner exists.
Slot 0 is sealed at this point; slot 1 can be delegated and claimed later.
`owner_group_publish_candidate()` joins its fresh listener without changing
selection. A caller must explicitly select member 1. Existing member-0 streams
remain ordinary original-Linux TCP streams across that selection.

Missing claims and an unpublished initial listener return `EAGAIN` without
consuming the candidate attempt. Once a claimed candidate reaches preflight, a
rejection is terminal: the candidate cannot be replaced or retried. Failures
close only the candidate listener and preserve member 0. The initial listener
identity, mark, bound tuple, and `SO_ACCEPTCONN` state are revalidated before
candidate socket effects.

Initial publication requires an unprepared actor. A prepared candidate returns
`EAGAIN` before socket effects while its admission task is starting or in a
retryable window transition; this does not consume the candidate attempt. Once
the task is `READY`, the broker sets the candidate mark, binds it, registers
that exact native listener with the admission task, and only then calls
`listen()`. Terminal or quarantined task states fail closed and consume the
attempt, preserving member 0 and its selector. These SDK controls do not
qualify Nginx `graceful_reload=1`, a full F-Stack lifecycle, or a graceful-reload
FSM.

## Reuseport member census

`ker_socket_client_member_census_create(group, index)` creates a read-only
metadata capability for one managed member. Each managed listener receives a
unique, nonzero `SO_MARK` before publication. The broker attaches a fixed local
`INET_DIAG_BC_MARK_COND` filter and issues bounded original-Linux
`SOCK_DIAG_BY_FAMILY` multipart dumps. Callers cannot supply a mark, bytecode,
netlink request, pointer, or descriptor. Snapshot results contain raw TCP
state counts, the immutable listener cookie, and no queue metrics or F-Stack
syncache/syncounter aliases.

For a claimed staged member 1 that is not published yet, census creation is
also permitted. Its snapshot uses the already reserved member mark with
`listener_cookie=0`; a successful snapshot must have zero `LISTEN` rows. Any
unexpected listener under that mark fails the snapshot. This lets callers
verify the candidate has not begun listening while its owner is still starting.

The kind-5 census capability has no TCP descriptor, group reference, or member
handle. It remains valid after all group/member handles close: snapshots may
then report no `LISTEN` row while previously marked accepted, closing, or
`TIME_WAIT` rows remain. Listener cookie metadata remains the original cookie;
it does not keep the listener open. A dump publishes only after a valid
terminal `NLMSG_DONE`; truncation, interrupted dumps, duplicate socket
identities, malformed rows, and incomplete/error replies fail without
publishing partial counts. Rows are sampled during a non-atomic interval, not
a linearizable snapshot.

One `ker-posix` runtime permits one live broker server instance. This keeps
member marks and group-port reservations global to the original Linux runtime;
the nonwrapping mark allocator is not reset when a broker is destroyed and a
later one is created. The broker uses one bounded census worker and a global
four-query queue. Submission requires the caller already to hold effective
`CAP_NET_ADMIN`; the worker rechecks its own authority and never elevates or
changes credentials. Generic public `AF_NETLINK` restrictions are unchanged.
The worker checks cancellation and bounded byte, datagram, row, and elapsed
time budgets between nonblocking kernel calls; no hard bound is claimed for a
single original-Linux syscall.

`native-socket-broker-member-census` uses a real host TCP connection and a
temporary nftables rule inside its isolated network namespace to drop the
connection's ordinary final ACK. It observes the original-Linux `SYN_RECV`
row on member 0, changes selection to member 1, then removes the rule so the
real handshake completes on the original member. A later connection reaches
member 1. On both accepted streams, the native sender fills the real original-
Linux send queue until `EAGAIN` while the host delays reads. A separate
existing TCP observer capability records a positive send-queue value; it is
not added to the census result. The native worker then closes its accepted,
member, and group descriptors and exits before the host drains the queued
bytes. The host verifies every byte and orderly FIN while retaining only
metadata capabilities; the census observes closing/TIME_WAIT states and
confirms both listener rows disappear. The test does not synthesize TCP
packets or claim a full-table census outside this bounded two-member group.

Adding these typed operations advances the private broker wire protocol to
version 2; client and broker must be built from compatible API versions.

`native-socket-broker-reuseport-group` runs the selector 0→1→0 over real TAP
traffic. It verifies exact payloads and listener-specific readiness, rights
and type failures, reserved-port guards, managed-member restrictions, and an
accepted stream across selector changes and final listener close. A fresh
connection is refused after all group/member capabilities close, while the
accepted stream completes and original-Linux buffer accounting returns to
zero. The test does not claim IPv6 group selection, arbitrary BPF programs,
Nginx/F-Stack lifecycle behavior, or Ker-owned TCP behavior.
## TCP observer

Protocol version 2 adds a typed, read-only TCP observer capability through
`ker_socket_client_tcp_observer_create()` and
`ker_socket_client_tcp_observer_snapshot()`. Creation requires both `NAME` and
`OPTION` rights on a socket capability, then accepts only a connected IPv4
`SOCK_STREAM` using `IPPROTO_TCP`. It records the original Linux `SO_COOKIE`
and local/peer IPv4 tuple. The returned observer has `READ` rights, describes
as kind 4 with zero status flags, and cannot be duplicated through the SDK.
Ordinary host `dup()` still only adds another reference to that observer pipe.

An observer stores metadata only. It holds no TCP descriptor, open-file
description, or group reference, so closing the final TCP capability follows
the socket's ordinary Linux close and FIN behavior while the observer remains
available. Each snapshot opens a temporary broker-owned original-Linux
`NETLINK_SOCK_DIAG` socket and sends one non-dump `SOCK_DIAG_BY_FAMILY`
request keyed by that stored cookie and tuple. The returned `state`, receive
queue, and send queue are instantaneous `inet_diag_msg` values. This operation
does not modify the socket or count generations, SYN-received requests, or all
TCP connections.

A validated exact kernel `NLMSG_ERROR` with `-ENOENT` reports `present=0`.
Cookie mismatch (`ESTALE`), unavailable netlink results, truncation, and
malformed replies remain errors; none is treated as an empty census. This
initial observer surface is limited to connected IPv4 TCP sockets and is not a
per-generation or full-table F-Stack graceful-reload census.

## Scope

The broker caller must quiesce socket users while adopting descriptors and
before the `ker_posix_run()` loop stops. Adoption requires an exact Ker
descriptor-table socket or epoll kind; host descriptors are rejected. Socket
adoption accepts only INET stream/datagram descriptors with nonblocking close
behavior; an existing socket with enabled nonzero `SO_LINGER` is rejected.
Because socket options apply to a shared open file description, the trusted
caller must not mutate an adopted socket through an outside alias. Capabilities are
transferred by the trusted caller; this API does not implement an application
supervisor, daemonization, generic file descriptor forwarding, or a complete
POSIX compatibility layer.

`native-socket-broker-fork-exec` runs a real TAP-backed original-Linux TCP
listener and external host peers. It verifies active traffic before fork,
authenticates a fresh child RPC session, execs a replacement frontend, sends
4097 exact bytes over the same accepted stream through the preexisting epoll
registration, accepts another connection from the inherited listener, and
closes all capability references so the broker can finalize original Linux.
The test does not claim that arbitrary host applications or nginx can use this
limited API without a caller adapter.

The separate [`ker::socket-preload` caller adapter](native-socket-preload.md)
maps a documented POSIX subset onto this SDK. Its tested no-FF Nginx lifecycle
is a frontend prerequisite only; it does not qualify the F-Stack module or
complete graceful-reload migration.
