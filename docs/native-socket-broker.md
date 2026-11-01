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
are `SO_TYPE`, `SO_ERROR`, `SO_DOMAIN`, `SO_PROTOCOL`, and `SO_ACCEPTCONN`.
Both directions also support `IPPROTO_TCP` `TCP_NODELAY`, `TCP_CORK`,
`TCP_DEFER_ACCEPT`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`,
`TCP_FASTOPEN`, and `IPPROTO_IPV6` `IPV6_V6ONLY`. Unknown options and options
whose values contain pointers or descriptor numbers (including packet-filter
programs and reuse-port BPF descriptors) return `EOPNOTSUPP` before original
Linux is called. For supported options, original Linux still validates the
value length and contents.

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
host FD operations. A duplicated capability still addresses the same
broker-owned socket; it does not create a second original-Linux descriptor or
the distinct epoll-registration behavior of native POSIX `dup()`.

## Scope

The broker caller must quiesce socket users while adopting descriptors and
before the `ker_posix_run()` loop stops. Adoption requires an exact Ker
descriptor-table socket or epoll kind; host descriptors are rejected. Socket
adoption accepts only INET stream/datagram descriptors. Capabilities are
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
