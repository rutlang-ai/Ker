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
It does not initialize EAL or a second Linux kernel. Build it with
`KER_BUILD_FSTACK_NGINX_RUNTIME=ON`; set
`KER_FSTACK_NGINX_BINARY` to an unchanged `--with-ff_module` Nginx executable
to register the native lifecycle CTest.

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

The supported profile accepts only `[ker_socket_broker] version=1` with a
broker `path` equal to `KER_SOCKET_BROKER_PATH`, and `[dpdk] graceful_reload=0`.
It rejects `FF_FAULT`, unsupported configuration keys, unreachable brokers,
secondary roles, and nonzero process IDs. Nginx's `ff_global_cfg` retains its
configuration filename after the caller frees its argument strings. Reload
state remains genuinely detached and inactive; no synthetic generation block
is installed. Unsupported flow-map, dispatcher, and drain/census hooks abort
with an explicit diagnostic if reached.

The lifecycle profile uses one Nginx worker and `reuseport`. In this pinned
FF-enabled caller, the unchanged worker startup opens every `reuseport` clone
in each worker, while the event initializer registers only the clone assigned
to that worker. With multiple workers, Linux `SO_REUSEPORT` can deliver traffic
to an unserviced clone. The runtime rejects secondary initialization instead
of claiming that profile works. Multiworker listener ownership remains an
explicit unsupported boundary.

The Nginx-specific adapter restores the original executable's FF descriptor
offset only for descriptors selected by Nginx's exported classifier. It sends
both host and FF epoll registrations through the composite preload adapter.
This pinned FF build selects kqueue event constants ahead of the Linux epoll
constants; the adapter fault-safely copies the event and maps `EV_CLEAR` (`0x20`)
to Linux `EPOLLET`, preserving the event data and other flags. Nginx's real
`timer_resolution 1ms` signal path services host control events; the adapter
does not synthesize readiness or shorten arbitrary waits.

The opt-in test runs the unchanged `--with-ff_module` Nginx binary over the
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

This qualifies a bounded one-worker, `graceful_reload=0` Nginx caller path. It
does not qualify the F-Stack generation-reload state machine, multiworker
listener ownership, fault injection, original shell matrix, or shell cleanup
oracle. Those requirements remain in
[`fstack-graceful-reload-gap.md`](fstack-graceful-reload-gap.md).
