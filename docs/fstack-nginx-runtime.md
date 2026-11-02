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
