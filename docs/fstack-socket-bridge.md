# F-Stack leaf socket bridge

`ker::fstack-socket-bridge` exposes a deliberately bounded subset of the
unchanged F-Stack `ff_api.h` socket ABI. The original `ff_api.h`, `ff_event.h`,
`ff_errno.h`, and `ff_flow_map.h` are installed together; their imported bytes
are audited against F-Stack commit
[`646a641cfff77f4815e1e29829a09e1ed15a2999`](https://github.com/F-Stack/f-stack/tree/646a641cfff77f4815e1e29829a09e1ed15a2999).
The bridge is a caller adapter over `ker::socket-preload`, not a complete
F-Stack runtime.

The selected leaf calls cover TCP `ff_socket` for IPv4/IPv6, bind/connect/listen,
accept/accept4, close/shutdown, socket names and the broker's flat socket-option
set, read/write/readv/writev/send/recv, and restricted fcntl/ioctl. They return
ordinary application descriptors tracked by the preload map. Buffer and
sockaddr validation therefore follows the same fault-aware caller path as the
POSIX adapter, while TCP state and packet processing remain in the one original
Linux runtime owned by the broker. The F-Stack Linux caller ABI receives normal
Linux `errno` values. Before preload initialization completes, supported calls
return `ENOTCONN`. After readiness, supported descriptor-taking `ff_*` calls
never fall back to host descriptors: valid non-broker FDs return
`EOPNOTSUPP`, invalid FDs return `EBADF`, and host objects remain untouched.

The bridge does not provide `ff_init`, `ff_run`, global F-Stack configuration,
reload/census hooks, UDP/datagram or ancillary I/O, poll/select, or kqueue.
Declared leaf calls outside the selected set return `EOPNOTSUPP`; runtime and
application lifecycle APIs are not stubbed into success. The preload socket
profile remains nonblocking and bounded as documented in
[`native-socket-preload.md`](native-socket-preload.md).

Bridge calls enter explicit `ker_sb_posix_*` symbols exported by the preload
DSO. Its POSIX interposition aliases point at those same namespaced
implementations, and internal sibling calls also remain namespaced. This is
required because the unchanged F-Stack Nginx executable defines POSIX symbols
such as `socket`, `read`, `write`, and `accept`; a bridge call through those
symbols would recurse into the executable instead of reaching the broker.

`native-fstack-socket-leaf-bridge` runs an adversarial executable that defines
those POSIX symbols to fail if reached. It uses the FF ABI against a
TAP-backed original-Linux TCP connection and an external host peer, verifies
the exact 4097-byte stream, descriptor duplication and final close, option and
FIONREAD calls, unsupported-call errors, and faulting user pointers. It also
checks original-Linux/DPDK traffic and complete pool cleanup. The opt-in
[`ker-fstack-nginx-runtime` profile](fstack-nginx-runtime.md) layers detached
`graceful_reload=0` initialization and the executable FD-offset adapter over
this bridge for one pinned Nginx worker. That separate bounded profile
demonstrates real Nginx lifecycle behavior; this leaf bridge test alone does
not qualify the FF runtime or the graceful-reload integration matrix.
